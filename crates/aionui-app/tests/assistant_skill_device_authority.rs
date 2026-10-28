//! Paired devices are read-only for assistants and skills (Jev 049): a paired phone or browser
//! gets 403 `FS_OWNER_ONLY` on every assistant write, assistant rule/skill write or delete, and
//! skill delete (a DB soft delete), and nothing changes. Reads stay open to paired devices. The
//! agent helper keeps these data-only writes, because the config CLI advertises them; writes that
//! choose a host command (custom agents) are desktop-only for it (agent_device_authority.rs).

mod common;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{body_json, build_app_with_skill_paths, json_with_token};

const ASSISTANT: &str = "authority-target";
const SKILL: &str = "authority-skill";
const RULE: &str = "original rule text";

fn public_post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn helper_request(method: &str, uri: &str, body: Value, helper: &[(&str, String); 3]) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    for (name, value) in helper {
        builder = builder.header(*name, value.as_str());
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

/// Every assistant and skill write a paired device must not make.
fn device_refused_writes() -> Vec<(&'static str, String, Value)> {
    let a = ASSISTANT;
    vec![
        (
            "POST",
            "/api/assistants".into(),
            json!({"id": "phone-made", "name": "Phone made", "agent_id": "632f31d2", "avatar": "🎨"}),
        ),
        (
            "PUT",
            format!("/api/assistants/{a}"),
            json!({"name": "renamed by phone"}),
        ),
        ("PATCH", format!("/api/assistants/{a}/state"), json!({"enabled": false})),
        (
            "POST",
            "/api/assistants/import".into(),
            json!({"assistants": [{"id": "phone-import", "name": "Phone import", "agent_id": "632f31d2"}]}),
        ),
        ("DELETE", format!("/api/assistants/{a}"), json!({})),
        (
            "POST",
            "/api/skills/assistant-rule/write".into(),
            json!({"assistant_id": a, "content": "phone rule"}),
        ),
        ("DELETE", format!("/api/skills/assistant-rule/{a}"), json!({})),
        (
            "POST",
            "/api/skills/assistant-skill/write".into(),
            json!({"assistant_id": a, "content": "phone skill"}),
        ),
        ("DELETE", format!("/api/skills/assistant-skill/{a}"), json!({})),
        ("DELETE", format!("/api/skills/{SKILL}"), json!({})),
    ]
}

#[tokio::test]
async fn paired_devices_cannot_change_assistants_or_delete_skills() {
    let dir = tempfile::tempdir().unwrap();
    let (app, services, _paths) = build_app_with_skill_paths(dir.path()).await;
    let bootstrap = std::fs::read_to_string(dir.path().join("app-bootstrap.token")).unwrap();
    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            (resp.status(), body_json(resp).await)
        }
    };

    let (_, desktop) = send(public_post(
        "/api/devices/app-session",
        json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
    ))
    .await;
    let desktop = desktop["data"]["access_token"].as_str().unwrap().to_owned();
    let (_, pairing) = send(json_with_token(
        "POST",
        "/api/devices/pairings",
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, paired) = send(public_post(
        "/api/devices/pair",
        json!({"secret": pairing["data"]["secret"], "device_name": "Phone", "device_kind": "mobile"}),
    ))
    .await;
    let pairing_id = paired["data"]["pairing_id"].as_str().unwrap();
    send(json_with_token(
        "POST",
        &format!("/api/devices/pairings/{pairing_id}/approve"),
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    let (_, claimed) = send(public_post(
        "/api/devices/pair/claim",
        json!({"pairing_id": pairing_id, "claim_token": paired["data"]["claim_token"]}),
    ))
    .await;
    let phone = claimed["data"]["session"]["access_token"].as_str().unwrap().to_owned();

    // The desktop app creates an assistant with a rule, and imports a custom skill.
    let (status, _) = send(json_with_token(
        "POST",
        "/api/assistants",
        json!({"id": ASSISTANT, "name": "Original", "agent_id": "632f31d2", "avatar": "🤖"}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::CREATED, "desktop creates an assistant");
    let (status, _) = send(json_with_token(
        "POST",
        "/api/skills/assistant-rule/write",
        json!({"assistant_id": ASSISTANT, "content": RULE}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "desktop writes an assistant rule");
    let skill_dir = dir.path().join("skill-source").join(SKILL);
    std::fs::create_dir_all(&skill_dir).unwrap();
    std::fs::write(
        skill_dir.join("SKILL.md"),
        format!("---\nname: {SKILL}\ndescription: Authority fixture\n---\nBody"),
    )
    .unwrap();
    let (status, body) = send(json_with_token(
        "POST",
        "/api/skills/import",
        json!({"skill_path": skill_dir.to_string_lossy()}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "desktop imports a skill: {body}");

    // A paired phone is refused every write.
    for (method, uri, body) in device_refused_writes() {
        let (status, body) = send(json_with_token(method, &uri, body, &phone, "c")).await;
        assert_eq!(
            (status, body["code"].clone()),
            (StatusCode::FORBIDDEN, json!("FS_OWNER_ONLY")),
            "paired phone: {method} {uri}"
        );
    }

    // Nothing changed.
    let (status, detail) = send(json_with_token(
        "GET",
        &format!("/api/assistants/{ASSISTANT}"),
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "the assistant still exists");
    assert_eq!(detail["data"]["profile"]["name"], "Original");
    assert_eq!(detail["data"]["state"]["enabled"], true);
    let (_, list) = send(json_with_token("GET", "/api/assistants", json!({}), &desktop, "c")).await;
    let ids: Vec<&str> = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["id"].as_str())
        .collect();
    assert!(
        !ids.contains(&"phone-made") && !ids.contains(&"phone-import"),
        "{ids:?}"
    );
    let (_, rule) = send(json_with_token(
        "POST",
        "/api/skills/assistant-rule/read",
        json!({"assistant_id": ASSISTANT}),
        &desktop,
        "c",
    ))
    .await;
    assert!(rule.to_string().contains(RULE), "the rule is unchanged: {rule}");
    let (_, skills) = send(json_with_token("GET", "/api/skills", json!({}), &desktop, "c")).await;
    assert!(skills.to_string().contains(SKILL), "the skill is still listed");

    // Reads stay open to the phone.
    for (method, uri, body) in [
        ("GET", "/api/assistants".to_owned(), json!({})),
        ("GET", format!("/api/assistants/{ASSISTANT}"), json!({})),
        (
            "POST",
            "/api/skills/assistant-rule/read".to_owned(),
            json!({"assistant_id": ASSISTANT}),
        ),
        ("GET", "/api/skills".to_owned(), json!({})),
    ] {
        let (status, _) = send(json_with_token(method, &uri, body, &phone, "c")).await;
        assert_eq!(status, StatusCode::OK, "paired phone reads {uri}");
    }

    // The agent helper keeps the writes its config CLI advertises.
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    let token = services.runtime_token_service.issue(
        owner.as_str(),
        "conv-helper-assistants",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let helper = [
        ("x-aionui-runtime-token", token.token.as_str().to_owned()),
        ("x-aionui-user-id", owner.as_str().to_owned()),
        ("x-aionui-conversation-id", "conv-helper-assistants".to_owned()),
    ];
    let (status, body) = send(helper_request(
        "PUT",
        &format!("/api/assistants/{ASSISTANT}"),
        json!({"name": "Renamed by helper"}),
        &helper,
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "agent helper updates an assistant: {body}");
    let (status, body) = send(helper_request(
        "DELETE",
        &format!("/api/skills/{SKILL}"),
        json!({}),
        &helper,
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "agent helper deletes a skill: {body}");

    // The desktop app keeps every write.
    let (status, _) = send(json_with_token(
        "PATCH",
        &format!("/api/assistants/{ASSISTANT}/state"),
        json!({"enabled": false}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "desktop disables the assistant");
    let (status, _) = send(json_with_token(
        "DELETE",
        &format!("/api/assistants/{ASSISTANT}"),
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "desktop deletes the assistant");
}
