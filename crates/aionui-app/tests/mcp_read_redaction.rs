//! Cross-review F2 (Jev 047): paired phones/browsers and the agent helper read MCP servers
//! with every secret-bearing field masked; the desktop app keeps full values for editing.

mod common;

use std::sync::Arc;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use aionui_db::{CreateMcpServerParams, IMcpServerRepository, SqliteMcpServerRepository};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{build_app_with_skill_paths, json_with_token};

const SECRET: &str = "sentinel-secret-7f3a";

fn public_post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn bearer(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn non_desktop_readers_never_see_mcp_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, services, _) = build_app_with_skill_paths(tmp.path()).await;
    let bootstrap = std::fs::read_to_string(tmp.path().join("app-bootstrap.token")).unwrap();
    let json_of = |s: &str| serde_json::from_str::<Value>(s).unwrap_or(Value::Null);

    let (_, desktop) = send(
        &app,
        public_post(
            "/api/devices/app-session",
            json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
        ),
    )
    .await;
    let desktop = json_of(&desktop)["data"]["access_token"].as_str().unwrap().to_owned();
    let (_, pairing) = send(
        &app,
        json_with_token("POST", "/api/devices/pairings", json!({}), &desktop, "c"),
    )
    .await;
    let pairing = json_of(&pairing);
    let (_, paired) = send(
        &app,
        public_post(
            "/api/devices/pair",
            json!({"secret": pairing["data"]["secret"], "device_name": "Phone", "device_kind": "mobile"}),
        ),
    )
    .await;
    let paired = json_of(&paired);
    let pairing_id = paired["data"]["pairing_id"].as_str().unwrap();
    send(
        &app,
        json_with_token(
            "POST",
            &format!("/api/devices/pairings/{pairing_id}/approve"),
            json!({}),
            &desktop,
            "c",
        ),
    )
    .await;
    let (_, claimed) = send(
        &app,
        public_post(
            "/api/devices/pair/claim",
            json!({"pairing_id": pairing_id, "claim_token": paired["data"]["claim_token"]}),
        ),
    )
    .await;
    let phone = json_of(&claimed)["data"]["session"]["access_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    let repo: Arc<dyn IMcpServerRepository> =
        Arc::new(SqliteMcpServerRepository::new(services.database.pool().clone()));
    let stdio_config =
        json!({"command": "npx", "args": ["server", format!("--api-key={SECRET}")], "env": {"API_KEY": SECRET}});
    let http_config = json!({"url": format!("https://user:{SECRET}@mcp.example/sse?key={SECRET}#{SECRET}"), "headers": {"Authorization": format!("Bearer {SECRET}")}});
    let original = json!({"mcpServers": {"x": {"env": {"API_KEY": SECRET}}}}).to_string();
    let mut ids = Vec::new();
    for (name, kind, config) in [("stdio", "stdio", &stdio_config), ("remote", "http", &http_config)] {
        let row = repo
            .create(CreateMcpServerParams {
                user_id: &owner,
                name,
                description: None,
                enabled: true,
                transport_type: kind,
                transport_config: &config.to_string(),
                tools: None,
                original_json: Some(&original),
                builtin: false,
            })
            .await
            .unwrap();
        ids.push(row.id);
    }

    let mut paths = vec!["/api/mcp/servers".to_owned()];
    paths.extend(ids.iter().map(|id| format!("/api/mcp/servers/{id}")));

    // The desktop app reads full values (it edits them).
    for path in &paths {
        let (status, body) = send(&app, bearer(path, &desktop)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(body.contains(SECRET), "desktop sees full values on {path}");
    }

    // A paired phone and the agent helper never see the secret, anywhere in the body.
    let helper = services.runtime_token_service.issue(
        owner.as_str(),
        "conv-helper-mcp",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    for path in &paths {
        let (status, body) = send(&app, bearer(path, &phone)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(!body.contains(SECRET), "phone must not see secrets on {path}: {body}");
        let req = Request::builder()
            .uri(path)
            .header("x-aionui-runtime-token", helper.token.as_str())
            .header("x-aionui-user-id", owner.as_str())
            .header("x-aionui-conversation-id", "conv-helper-mcp")
            .body(Body::empty())
            .unwrap();
        let (status, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(!body.contains(SECRET), "helper must not see secrets on {path}: {body}");
    }

    // What remains is still useful: names, command, host, masked keys.
    let (_, list) = send(&app, bearer("/api/mcp/servers", &phone)).await;
    let list = json_of(&list)["data"].clone();
    let stdio = list.as_array().unwrap().iter().find(|s| s["name"] == "stdio").unwrap();
    assert_eq!(stdio["transport"]["command"], "npx");
    assert_eq!(stdio["transport"]["env"]["API_KEY"], "***");
    assert!(stdio.get("original_json").is_none());
    let remote = list.as_array().unwrap().iter().find(|s| s["name"] == "remote").unwrap();
    assert_eq!(remote["transport"]["url"], "https://mcp.example/sse");
    assert_eq!(remote["transport"]["headers"]["Authorization"], "***");
}
