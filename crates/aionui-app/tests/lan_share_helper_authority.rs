//! A LAN share grants a peer chat with one agent (ADR-009), not owner configuration. The
//! agent process of a LAN-share conversation still receives the helper credential, so the
//! host refuses that credential everywhere except read-only skill listing and reading
//! (owner decision on Jev 051). Owner conversations keep their helper. The credential used
//! here is the one the (mock) agent was actually built with.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{body_json, build_app_with_capturing_mock_agents_at, desktop_and_phone, json_with_token};

const REFUSED: &str = "HELPER_NOT_FOR_LAN_SHARE";

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    (resp.status(), body_json(resp).await)
}

fn as_helper(
    method: &str,
    uri: &str,
    body: Option<&Value>,
    token: &str,
    owner: &str,
    conversation: &str,
) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-aionui-runtime-token", token)
        .header("x-aionui-user-id", owner)
        .header("x-aionui-conversation-id", conversation);
    match body {
        Some(body) => builder.body(Body::from(body.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

#[tokio::test]
async fn a_lan_share_agent_helper_only_reads_skills() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, services, captured) = build_app_with_capturing_mock_agents_at(tmp.path()).await;
    let (desktop, _phone) = desktop_and_phone(&app, tmp.path()).await;
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;

    // A LAN-share conversation exactly as the network runner creates it, and an owner one.
    let lan = services
        .conversation_service
        .create(
            owner.as_str(),
            aionui_api_types::CreateConversationRequest {
                r#type: Some(aionui_common::AgentType::Acp),
                name: Some("peer share".into()),
                model: None,
                assistant: None,
                source: Some(aionui_common::ConversationSource::Aionui),
                channel_chat_id: None,
                extra: json!({
                    "backend": "gemini",
                    "workspace": tmp.path().to_string_lossy(),
                    "session_mode": "default",
                    "current_mode_id": "default",
                    "lan_remote": true,
                }),
            },
        )
        .await
        .unwrap()
        .id;
    let (status, created) = send(
        &app,
        json_with_token(
            "POST",
            "/api/conversations",
            json!({"type": "acp", "name": "owner chat", "extra": {"backend": "gemini"}}),
            &desktop,
            "c",
        ),
    )
    .await;
    assert!(status.is_success(), "{status} {created}");
    let mine = created["data"]["id"].as_str().unwrap().to_owned();

    // Build both agents and take the helper token each one was given.
    for conversation in [&lan, &mine] {
        services
            .conversation_service
            .warmup(owner.as_str(), conversation, &services.worker_task_manager)
            .await
            .unwrap();
    }
    let token_of = |conversation: &str| {
        captured.lock().unwrap()[conversation]
            .iter()
            .find(|(key, _)| key == "AIONUI_RUNTIME_TOKEN")
            .map(|(_, value)| value.clone())
            .expect("the agent received a helper token")
    };
    let lan_token = token_of(&lan);
    let my_token = token_of(&mine);

    let assistant = json!({"id": "from-helper", "name": "From helper", "agent_id": "632f31d2", "avatar": "🤖"});
    let writes_and_reads = [
        ("POST", "/api/assistants", Some(assistant.clone())),
        ("GET", "/api/assistants", None),
        ("POST", "/api/cron/jobs", Some(json!({}))),
        ("GET", "/api/mcp/servers", None),
    ];
    for (method, uri, body) in &writes_and_reads {
        let (status, resp) = send(
            &app,
            as_helper(method, uri, body.as_ref(), &lan_token, owner.as_str(), &lan),
        )
        .await;
        assert_eq!(
            (status, resp["code"].clone()),
            (StatusCode::FORBIDDEN, json!(REFUSED)),
            "LAN-share helper {method} {uri}: {resp}"
        );
    }
    let (_, list) = send(
        &app,
        json_with_token("GET", "/api/assistants", json!({}), &desktop, "c"),
    )
    .await;
    assert!(!list.to_string().contains("from-helper"), "nothing was created");

    // Read-only skills stay open to it.
    let (status, resp) = send(
        &app,
        as_helper("GET", "/api/runtime/skills", None, &lan_token, owner.as_str(), &lan),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "LAN-share helper lists skills: {resp}");

    // The owner conversation's helper is unchanged.
    let (status, resp) = send(
        &app,
        as_helper(
            "POST",
            "/api/assistants",
            Some(&assistant),
            &my_token,
            owner.as_str(),
            &mine,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "owner helper writes: {resp}");
    let (status, resp) = send(
        &app,
        as_helper("GET", "/api/runtime/skills", None, &my_token, owner.as_str(), &mine),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner helper lists skills: {resp}");
}
