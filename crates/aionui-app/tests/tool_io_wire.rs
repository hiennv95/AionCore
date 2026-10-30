//! L03.IO: tool input and output are redacted and bounded for clients on the history API, while the
//! stored row stays raw. (The live stream is covered by `stream_relay` unit tests and the shared
//! sanitizer by `tool_wire`/`tool_payload` tests; the parity test lives in `tool_wire`.)

mod common;

use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use aionui_db::{IConversationRepository, SqliteConversationRepository};
use common::{body_json, build_app, json_with_token, setup_and_login};

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Value,
    token: &str,
    csrf: &str,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(json_with_token(method, uri, body, token, csrf))
        .await
        .unwrap();
    (resp.status(), body_json(resp).await)
}

fn big() -> String {
    format!("{} Bearer RAWSECRET", "line of output\n".repeat(20_000))
}

#[tokio::test]
async fn history_redacts_and_bounds_tool_payloads_but_storage_stays_raw() {
    let (mut app, services) = build_app().await;
    let (token, csrf) = setup_and_login(&mut app, &services, "owner", "pw-owner-1").await;
    let body = json!({"type": "acp", "name": "tools", "extra": {"backend": "gemini"}});
    let (status, created) = call(&app, "POST", "/api/conversations", body, &token, &csrf).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let conv = created["data"]["id"].as_str().unwrap().to_owned();

    let repo = SqliteConversationRepository::new(services.database.pool().clone());
    let user_id = repo.owner_user_id(&conv).await.unwrap().unwrap();
    let rows = [
        (
            "t1",
            "tool_call",
            json!({"call_id": "t1", "name": "Run curl", "status": "completed",
            "input": {"command": "curl", "env": {"API_TOKEN": "ENVSECRET"}}, "output": big()}),
        ),
        (
            "a1",
            "acp_tool_call",
            json!({"session_id": "s", "update": {"session_update": "tool_call_update",
            "tool_call_id": "a1", "status": "completed", "title": "Run ls", "raw_input": {"command": "ls", "password": "hunter2"},
            "raw_output": big()}}),
        ),
    ];
    for (n, (id, kind, content)) in rows.iter().enumerate() {
        let row = aionui_db::models::MessageRow {
            id: (*id).into(),
            conversation_id: conv.clone(),
            msg_id: Some((*id).into()),
            r#type: (*kind).into(),
            content: content.to_string(),
            position: Some("left".into()),
            status: Some("finish".into()),
            hidden: false,
            created_at: 1_000 + n as i64,
            backend_turn_id: None,
        };
        repo.insert_message(&user_id, &row).await.unwrap();
    }

    let (status, list) = call(
        &app,
        "GET",
        &format!("/api/conversations/{conv}/messages?limit=50"),
        json!({}),
        &token,
        &csrf,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let wire = list.to_string();
    for leaked in ["RAWSECRET", "ENVSECRET", "hunter2"] {
        assert!(!wire.contains(leaked), "{leaked} leaked in the history list");
    }
    assert!(wire.len() < 400_000, "list size {}", wire.len());
    let items = list["data"]["items"].as_array().unwrap();
    let tool = items.iter().find(|m| m["id"] == "t1").unwrap();
    assert_eq!(tool["content"]["call_id"], "t1");
    assert_eq!(tool["content"]["status"], "completed");
    assert_eq!(tool["content"]["output_truncated"], true);
    let acp = items.iter().find(|m| m["id"] == "a1").unwrap();
    assert_eq!(acp["content"]["update"]["tool_call_id"], "a1");
    assert_eq!(acp["content"]["update"]["raw_output_truncated"], true);

    // An explicit fetch of one message keeps every byte but still masks secrets.
    let (status, full) = call(
        &app,
        "GET",
        &format!("/api/conversations/{conv}/messages/t1"),
        json!({}),
        &token,
        &csrf,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{full}");
    let out = full["data"]["content"]["output"].as_str().unwrap();
    assert!(out.len() > 100_000, "full fetch length {}", out.len());
    assert!(!full.to_string().contains("RAWSECRET") && !full.to_string().contains("ENVSECRET"));
    assert!(full["data"]["content"].get("output_truncated").is_none());

    // Storage is untouched.
    let stored = repo.get_message(&user_id, &conv, "t1").await.unwrap().unwrap();
    assert!(stored.content.contains("RAWSECRET") && stored.content.contains("ENVSECRET"));
}
