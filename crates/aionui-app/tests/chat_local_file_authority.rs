//! A `Local` file ref names any path on the host (ADR-013): only the desktop app may send
//! one. A paired phone or browser and the agent helper get 403 `FS_OWNER_ONLY` before the
//! path is looked at, whether or not it exists, and nothing is stored or started. Uploads
//! stay open to devices; the desktop keeps sending local files. Runs with mock agents.

mod common;

use std::sync::Arc;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use aionui_db::models::TeamRow;
use aionui_db::{ITeamRepository, SqliteTeamRepository};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{body_json, build_app_with_mock_agents_at, desktop_and_phone, json_with_token};

const TEAM: &str = "team-local-files";

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    (resp.status(), body_json(resp).await)
}

fn as_helper(method: &str, uri: &str, body: &Value, token: &str, owner: &str, conversation: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-aionui-runtime-token", token)
        .header("x-aionui-user-id", owner)
        .header("x-aionui-conversation-id", conversation)
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn user_messages(app: &axum::Router, desktop: &str, conversation: &str) -> usize {
    let (_, list) = send(
        app,
        json_with_token(
            "GET",
            &format!("/api/conversations/{conversation}/messages"),
            json!({}),
            desktop,
            "c",
        ),
    )
    .await;
    list["data"]["items"]
        .as_array()
        .map_or(0, |items| items.iter().filter(|m| m["position"] == "right").count())
}

#[tokio::test]
async fn only_the_desktop_sends_local_host_files() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, services) = build_app_with_mock_agents_at(tmp.path()).await;
    let (desktop, phone) = desktop_and_phone(&app, tmp.path()).await;
    let existing = tmp.path().join("owner-notes.txt");
    std::fs::write(&existing, b"owner only").unwrap();
    let existing = existing.to_string_lossy().into_owned();
    let missing = tmp.path().join("no-such-file.txt").to_string_lossy().into_owned();
    let refused = (StatusCode::FORBIDDEN, json!("FS_OWNER_ONLY"));

    let (status, created) = send(
        &app,
        json_with_token(
            "POST",
            "/api/conversations",
            json!({"type": "acp", "name": "local files", "extra": {"backend": "gemini"}}),
            &desktop,
            "c",
        ),
    )
    .await;
    assert!(status.is_success(), "{status} {created}");
    let conversation = created["data"]["id"].as_str().unwrap().to_owned();
    let messages = format!("/api/conversations/{conversation}/messages");

    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    let helper = services.runtime_token_service.issue(
        owner.as_str(),
        &conversation,
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let helper_token = helper.token.as_str().to_owned();

    // A phone and the helper are refused alike for an existing and a missing path.
    for path in [&existing, &missing] {
        let body = json!({"content": "read this", "files": [{"kind": "local", "path": path}]});
        let (status, resp) = send(&app, json_with_token("POST", &messages, body.clone(), &phone, "c")).await;
        assert_eq!((status, resp["code"].clone()), refused, "phone {path}: {resp}");
        let (status, resp) = send(
            &app,
            as_helper("POST", &messages, &body, &helper_token, owner.as_str(), &conversation),
        )
        .await;
        assert_eq!((status, resp["code"].clone()), refused, "helper {path}: {resp}");
    }
    assert_eq!(
        user_messages(&app, &desktop, &conversation).await,
        0,
        "nothing was stored"
    );

    // An `upload` ref outside the upload dir is not an existence oracle either: an existing
    // and a missing outside path get the same answer (only the echoed path differs).
    let mut answers = Vec::new();
    for path in [&existing, &missing] {
        let body = json!({"content": "x", "files": [{"kind": "upload", "path": path}]});
        let (status, resp) = send(&app, json_with_token("POST", &messages, body, &phone, "c")).await;
        assert!(!status.is_success(), "outside upload {path}: {status} {resp}");
        let shape = (
            status,
            resp["code"].clone(),
            resp["error"].to_string().replace(path.as_str(), "<path>"),
        );
        answers.push(shape);
    }
    assert_eq!(answers[0], answers[1], "existing vs missing outside upload path");
    assert_eq!(
        user_messages(&app, &desktop, &conversation).await,
        0,
        "nothing was stored"
    );

    // Uploads stay open to the phone.
    let boundary = "aionx-boundary";
    let upload = Request::builder()
        .method("POST")
        .uri("/api/fs/upload")
        .header("authorization", format!("Bearer {phone}"))
        .header("x-csrf-token", "c")
        .header("cookie", "aionui-csrf-token=c")
        .header("content-type", format!("multipart/form-data; boundary={boundary}"))
        .body(Body::from(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--{boundary}--\r\n"
        )))
        .unwrap();
    let (status, uploaded) = send(&app, upload).await;
    assert_eq!(status, StatusCode::OK, "{uploaded}");
    let upload_path = uploaded["data"].as_str().unwrap().to_owned();
    let (status, resp) = send(
        &app,
        json_with_token(
            "POST",
            &messages,
            json!({"content": "see upload", "files": [{"kind": "upload", "path": upload_path}]}),
            &phone,
            "c",
        ),
    )
    .await;
    assert!(status.is_success(), "phone upload send: {status} {resp}");

    // The desktop still sends a local file (own conversation: the phone's turn is running).
    let (_, second) = send(
        &app,
        json_with_token(
            "POST",
            "/api/conversations",
            json!({"type": "acp", "name": "desktop files", "extra": {"backend": "gemini"}}),
            &desktop,
            "c",
        ),
    )
    .await;
    let second = second["data"]["id"].as_str().unwrap().to_owned();
    let (status, resp) = send(
        &app,
        json_with_token(
            "POST",
            &format!("/api/conversations/{second}/messages"),
            json!({"content": "desktop file", "files": [{"kind": "local", "path": existing}]}),
            &desktop,
            "c",
        ),
    )
    .await;
    assert!(status.is_success(), "desktop local send: {status} {resp}");

    // The helper still sends a real upload to its own conversation.
    let (_, third) = send(
        &app,
        json_with_token(
            "POST",
            "/api/conversations",
            json!({"type": "acp", "name": "helper upload", "extra": {"backend": "gemini"}}),
            &desktop,
            "c",
        ),
    )
    .await;
    let third = third["data"]["id"].as_str().unwrap().to_owned();
    let third_helper = services.runtime_token_service.issue(
        owner.as_str(),
        &third,
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let (status, resp) = send(
        &app,
        as_helper(
            "POST",
            &format!("/api/conversations/{third}/messages"),
            &json!({"content": "helper upload", "files": [{"kind": "upload", "path": upload_path}]}),
            third_helper.token.as_str(),
            owner.as_str(),
            &third,
        ),
    )
    .await;
    assert!(status.is_success(), "helper upload send: {status} {resp}");

    // Office preview stop resolves its file ref too (the routes stay open to devices so
    // a stop is never blocked): same rule for `Local`, no existence probe.
    for kind in ["word", "excel", "ppt"] {
        let uri = format!("/api/{kind}-preview/stop");
        for path in [&existing, &missing] {
            let body = json!({"file_path": "", "file": {"kind": "local", "path": path}});
            let (status, resp) = send(&app, json_with_token("POST", &uri, body.clone(), &phone, "c")).await;
            assert_eq!((status, resp["code"].clone()), refused, "phone {uri} {path}: {resp}");
            let (status, resp) = send(
                &app,
                as_helper("POST", &uri, &body, &helper_token, owner.as_str(), &conversation),
            )
            .await;
            assert_eq!((status, resp["code"].clone()), refused, "helper {uri} {path}: {resp}");
        }
    }

    // Project ref upgrade: same rule, no existence probe.
    for path in [&existing, &missing] {
        let body = json!({"file": {"kind": "local", "path": path}});
        let uri = "/api/projects/no-such-project/resolve-ref";
        let (status, resp) = send(&app, json_with_token("POST", uri, body.clone(), &phone, "c")).await;
        assert_eq!(
            (status, resp["code"].clone()),
            refused,
            "phone resolve-ref {path}: {resp}"
        );
        let (status, resp) = send(
            &app,
            as_helper("POST", uri, &body, &helper_token, owner.as_str(), &conversation),
        )
        .await;
        assert_eq!(
            (status, resp["code"].clone()),
            refused,
            "helper resolve-ref {path}: {resp}"
        );
    }

    // Team sends: devices are already refused for every team send (TEAM_DESKTOP_ONLY); the
    // helper reaches them, so a local ref is refused there too, before any session starts.
    let repo: Arc<dyn ITeamRepository> = Arc::new(SqliteTeamRepository::new(services.database.pool().clone()));
    repo.create_team(&TeamRow {
        id: TEAM.into(),
        user_id: owner.clone(),
        name: "Seeded".into(),
        workspace: String::new(),
        workspace_mode: "shared".into(),
        agents: "[]".into(),
        lead_agent_id: None,
        session_mode: None,
        agents_version: "1.0.1".into(),
        created_at: 1,
        updated_at: 1,
        project_id: None,
        folder_id: None,
    })
    .await
    .unwrap();
    for path in [&existing, &missing] {
        let files = json!([{"kind": "local", "path": path}]);
        for (uri, body) in [
            (
                format!("/api/teams/{TEAM}/messages"),
                json!({"content": "x", "files": files}),
            ),
            (
                format!("/api/teams/{TEAM}/agents/slot-x/messages"),
                json!({"content": "x", "files": files}),
            ),
            (
                format!("/api/teams/{TEAM}/agents/slot-x/interrupt"),
                json!({"message": "x", "files": files}),
            ),
        ] {
            let (status, resp) = send(
                &app,
                as_helper("POST", &uri, &body, &helper_token, owner.as_str(), &conversation),
            )
            .await;
            assert_eq!((status, resp["code"].clone()), refused, "helper {uri} {path}: {resp}");
        }
    }
}
