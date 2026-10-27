//! ADR-013 / Jev 047 for agents. A paired phone or browser may not choose a command the host
//! runs: custom agent create/update/delete, command overrides and the connection probe are
//! refused with 403 `FS_OWNER_ONLY`. The agent helper keeps those (the config CLI advertises
//! them). Remote agents may only be listed and read from a phone or the helper: changing one,
//! or making the host connect to a URL to test or handshake, is desktop-only. Phones read
//! env override values masked; the desktop reads them in full.

mod common;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{build_app_with_skill_paths, json_with_token};

const ENV_SECRET: &str = "custom-agent-env-secret-789";

fn public_post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn phones_cannot_choose_host_commands_or_change_remote_agents_and_read_env_masked() {
    // Custom agent creation probes the command; this binary has one test, so the
    // process-wide switch cannot race another test.
    unsafe { std::env::set_var("AIONUI_BYPASS_PROBE", "1") };
    let tmp = tempfile::tempdir().unwrap();
    let (app, services, _) = build_app_with_skill_paths(tmp.path()).await;
    let bootstrap = std::fs::read_to_string(tmp.path().join("app-bootstrap.token")).unwrap();
    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
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

    // The desktop sets up a custom agent with a secret env override, and a remote agent.
    let (status, created) = send(json_with_token(
        "POST",
        "/api/agents/custom",
        json!({"name": "Desk Agent", "command": "true"}),
        &desktop,
        "c",
    ))
    .await;
    assert!(status.is_success(), "{status} {created}");
    let agent = created["data"]["id"].as_str().unwrap().to_owned();
    let overrides = format!("/api/agents/{agent}/overrides");
    let (status, resp) = send(json_with_token(
        "PUT",
        &overrides,
        json!({"env_override": [{"name": "API_TOKEN", "value": ENV_SECRET}]}),
        &desktop,
        "c",
    ))
    .await;
    assert!(status.is_success(), "{status} {resp}");
    let (status, created) = send(json_with_token(
        "POST",
        "/api/remote-agents",
        json!({"name": "Remote", "protocol": "acp", "url": "wss://remote.example.invalid", "auth_type": "none"}),
        &desktop,
        "c",
    ))
    .await;
    assert!(status.is_success(), "{status} {created}");
    let remote = created["data"]["id"].as_str().unwrap().to_owned();

    // Desktop reads the env value; the phone reads it masked.
    let (_, read) = send(get(&overrides, &desktop)).await;
    assert_eq!(read["data"]["env_override"][0]["value"], ENV_SECRET);
    let (status, read) = send(get(&overrides, &phone)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!read.to_string().contains(ENV_SECRET), "{read}");
    assert_eq!(
        read["data"]["env_override"][0],
        json!({"name": "API_TOKEN", "value": "***"})
    );

    let marker = tmp.path().join("phone-probe.marker");
    let touch = json!({"command": "touch", "acp_args": [marker.to_str().unwrap()]});
    let host_command_routes = [
        (
            "POST",
            "/api/agents/custom".to_owned(),
            json!({"name": "Phone Agent", "command": "touch"}),
        ),
        (
            "PUT",
            format!("/api/agents/custom/{agent}"),
            json!({"name": "x", "command": "touch"}),
        ),
        ("DELETE", format!("/api/agents/custom/{agent}"), json!({})),
        ("POST", "/api/agents/custom/try-connect".to_owned(), touch.clone()),
        (
            "PUT",
            format!("/api/agents/{agent}/overrides"),
            json!({"command_override": "touch"}),
        ),
    ];
    let remote_routes = [
        (
            "POST",
            "/api/remote-agents".to_owned(),
            json!({"name": "Phone", "protocol": "acp", "url": "ws://127.0.0.1:9", "auth_type": "none"}),
        ),
        (
            "POST",
            "/api/remote-agents/test-connection".to_owned(),
            json!({"url": "ws://127.0.0.1:9"}),
        ),
        (
            "PUT",
            format!("/api/remote-agents/{remote}"),
            json!({"url": "ws://127.0.0.1:9"}),
        ),
        ("DELETE", format!("/api/remote-agents/{remote}"), json!({})),
        ("POST", format!("/api/remote-agents/{remote}/handshake"), json!({})),
    ];
    let refused = json!("FS_OWNER_ONLY");
    for (method, uri, body) in host_command_routes.iter().chain(remote_routes.iter()) {
        let (status, resp) = send(json_with_token(method, uri, body.clone(), &phone, "c")).await;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "phone {method} {uri}: {resp}"
        );
    }
    assert!(!marker.exists(), "the phone's probe ran a command on the host");

    // The helper is refused on remote agents and keeps the custom agent routes it advertises.
    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
    let helper = services.runtime_token_service.issue(
        owner.as_str(),
        "conv-helper-agents",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let helper_call = |method: &str, uri: &str, body: &Value| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-aionui-runtime-token", helper.token.as_str())
            .header("x-aionui-user-id", owner.as_str())
            .header("x-aionui-conversation-id", "conv-helper-agents")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    for (method, uri, body) in &remote_routes {
        let (status, resp) = send(helper_call(method, uri, body)).await;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "helper {method} {uri}: {resp}"
        );
    }
    let (status, resp) = send(helper_call(
        "PUT",
        &format!("/api/agents/{agent}/overrides"),
        &json!({"env_override": []}),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "helper overrides: {resp}");

    // Nothing the phone sent changed anything.
    let (_, remote_now) = send(get(&format!("/api/remote-agents/{remote}"), &desktop)).await;
    assert_eq!(remote_now["data"]["url"], "wss://remote.example.invalid");
    let (_, rows) = send(get("/api/agents/management", &desktop)).await;
    let names: Vec<_> = rows["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].clone())
        .collect();
    assert!(names.contains(&json!("Desk Agent")) && !names.contains(&json!("Phone Agent")));

    // The desktop still manages both.
    let (status, resp) = send(json_with_token(
        "PUT",
        &format!("/api/remote-agents/{remote}"),
        json!({"description": "edited"}),
        &desktop,
        "c",
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let (status, resp) = send(json_with_token(
        "DELETE",
        &format!("/api/agents/custom/{agent}"),
        json!({}),
        &desktop,
        "c",
    ))
    .await;
    assert!(status.is_success(), "{status} {resp}");
}
