//! ADR-013 / ADR-019 / Jev 038 (UX W-14): MCP server mutations and active connection tests
//! are desktop-only (403 `MCP_DESKTOP_ONLY`).
//! Paired phones and browsers and helper CLIs may inspect existing servers read-only, but may not
//! spawn commands or arm stdio servers on the host.

mod common;

use std::sync::Arc;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use aionui_db::{CreateMcpServerParams, IMcpServerRepository, SqliteMcpServerRepository};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{build_app_with_skill_paths, json_with_token};

fn public_post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn request(method: &str, uri: &str, token: &str, body: Option<Value>) -> Request<Body> {
    match body {
        Some(body) => json_with_token(method, uri, body, token, "c"),
        None => Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("cookie", "aionui-csrf-token=c")
            .header("x-csrf-token", "c")
            .body(Body::empty())
            .unwrap(),
    }
}

fn desktop_only_routes(server_id: &str) -> Vec<(&'static str, String, Option<Value>)> {
    vec![
        (
            "POST",
            "/api/mcp/servers".into(),
            Some(json!({
                "name": "device-added-mcp",
                "transport": {
                    "type": "stdio",
                    "command": "echo",
                    "args": ["hello"]
                }
            })),
        ),
        (
            "POST",
            "/api/mcp/servers/import".into(),
            Some(json!({
                "servers": [{
                    "name": "imported-mcp",
                    "transport": {
                        "type": "stdio",
                        "command": "echo"
                    }
                }]
            })),
        ),
        (
            "PUT",
            format!("/api/mcp/servers/{server_id}"),
            Some(json!({
                "description": "updated description"
            })),
        ),
        ("POST", format!("/api/mcp/servers/{server_id}/toggle"), None),
        ("DELETE", format!("/api/mcp/servers/{server_id}"), None),
        (
            "POST",
            "/api/mcp/test-connection".into(),
            Some(json!({
                "transport": {
                    "type": "stdio",
                    "command": "echo",
                    "args": ["test"]
                }
            })),
        ),
        ("GET", "/api/mcp/agent-configs".into(), None),
        (
            "POST",
            "/api/mcp/oauth/login".into(),
            Some(json!({
                "server_url": "http://127.0.0.1:9"
            })),
        ),
        (
            "POST",
            "/api/mcp/oauth/logout".into(),
            Some(json!({
                "server_url": "http://127.0.0.1:9"
            })),
        ),
    ]
}

fn read_only_routes(server_id: &str) -> Vec<(&'static str, String, Option<Value>)> {
    vec![
        ("GET", "/api/mcp/servers".into(), None),
        ("GET", format!("/api/mcp/servers/{server_id}"), None),
        ("GET", "/api/mcp/oauth/authenticated".into(), None),
        (
            "POST",
            "/api/mcp/oauth/check-status".into(),
            Some(json!({
                "server_url": "http://127.0.0.1:9"
            })),
        ),
    ]
}

#[tokio::test]
async fn a_paired_device_cannot_mutate_or_test_mcp_servers() {
    let tmp = tempfile::tempdir().unwrap();
    let (app, services, _) = build_app_with_skill_paths(tmp.path()).await;
    let bootstrap = std::fs::read_to_string(tmp.path().join("app-bootstrap.token")).unwrap();

    let send = {
        let app = app.clone();
        move |req: Request<Body>| {
            let app = app.clone();
            async move {
                let resp = app.oneshot(req).await.unwrap();
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
                (status, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
            }
        }
    };

    // 1. Desktop session setup
    let (_, desktop_resp) = send(public_post(
        "/api/devices/app-session",
        json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
    ))
    .await;
    let desktop_token = desktop_resp["data"]["access_token"].as_str().unwrap().to_owned();

    // 2. Mobile device pairing setup
    let (_, pairing) = send(json_with_token(
        "POST",
        "/api/devices/pairings",
        json!({}),
        &desktop_token,
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
        &desktop_token,
        "c",
    ))
    .await;
    let (_, claimed) = send(public_post(
        "/api/devices/pair/claim",
        json!({"pairing_id": pairing_id, "claim_token": paired["data"]["claim_token"]}),
    ))
    .await;
    let device_token = claimed["data"]["session"]["access_token"].as_str().unwrap().to_owned();

    // 3. Seed an existing MCP server in database
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    let repo: Arc<dyn IMcpServerRepository> =
        Arc::new(SqliteMcpServerRepository::new(services.database.pool().clone()));
    let seeded = repo
        .create(CreateMcpServerParams {
            user_id: &owner,
            name: "Seeded Server",
            description: Some("Initial test server"),
            enabled: true,
            transport_type: "stdio",
            transport_config: r#"{"command":"echo","args":[]}"#,
            tools: None,
            original_json: None,
            builtin: false,
        })
        .await
        .unwrap();
    let seeded_server_id = seeded.id;

    // 4. Paired device must receive 403 MCP_DESKTOP_ONLY on all mutation/test endpoints
    let refused = json!("MCP_DESKTOP_ONLY");
    for (method, uri, body) in desktop_only_routes(&seeded_server_id) {
        let (status, body) = send(request(method, &uri, &device_token, body)).await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "Paired device calling {method} {uri} must be refused with 403 MCP_DESKTOP_ONLY"
        );
    }

    // 5. Read-only endpoints must stay accessible to paired devices
    for (method, uri, body) in read_only_routes(&seeded_server_id) {
        let (status, body) = send(request(method, &uri, &device_token, body)).await;
        assert_ne!(
            body["code"], refused,
            "Paired device calling {method} {uri} must not be refused: {body}"
        );
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "Paired device calling {method} {uri} must not get 403: {body}"
        );
    }

    // 6. Agent helper token must also be refused on mutation & test endpoints
    let helper_issue = services.runtime_token_service.issue(
        owner.as_str(),
        "conv-helper-mcp",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    for (method, uri, body) in desktop_only_routes(&seeded_server_id) {
        let mut builder = Request::builder()
            .method(method)
            .uri(&uri)
            .header("x-aionui-runtime-token", helper_issue.token.as_str())
            .header("x-aionui-user-id", owner.as_str())
            .header("x-aionui-conversation-id", "conv-helper-mcp");
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let req = builder
            .body(match body {
                Some(b) => Body::from(b.to_string()),
                None => Body::empty(),
            })
            .unwrap();
        let (status, body) = send(req).await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "Helper token calling {method} {uri} must be refused with 403 MCP_DESKTOP_ONLY"
        );
    }

    // 7. Verify harmless marker test:
    // Device cannot execute touch in temp dir via test-connection
    let marker_path = tmp.path().join("device_marker.tmp");
    let (dev_status, _) = send(request(
        "POST",
        "/api/mcp/test-connection",
        &device_token,
        Some(json!({
            "name": "device-probe",
            "transport": {
                "type": "stdio",
                "command": "touch",
                "args": [marker_path.to_str().unwrap()]
            }
        })),
    ))
    .await;
    assert_eq!(dev_status, StatusCode::FORBIDDEN);
    assert!(
        !marker_path.exists(),
        "Device test-connection must NOT execute touch on host"
    );

    // Desktop caller CAN execute probe (host spawns command)
    let desktop_marker = tmp.path().join("desktop_marker.tmp");
    let (desk_status, _) = send(request(
        "POST",
        "/api/mcp/test-connection",
        &desktop_token,
        Some(json!({
            "name": "desktop-probe",
            "transport": {
                "type": "stdio",
                "command": "touch",
                "args": [desktop_marker.to_str().unwrap()]
            }
        })),
    ))
    .await;
    assert_ne!(desk_status, StatusCode::FORBIDDEN);
    assert!(
        desktop_marker.exists(),
        "Desktop test-connection probe must execute touch"
    );

    // 8. Desktop can successfully toggle and edit the server
    let (status, toggle_resp) = send(request(
        "POST",
        &format!("/api/mcp/servers/{seeded_server_id}/toggle"),
        &desktop_token,
        None,
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(toggle_resp["data"]["enabled"], false);
}
