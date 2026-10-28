//! ADR-013 / Jev 047 for agents. Only the desktop app may choose a command the host runs:
//! custom agent create/update/delete, command overrides and the connection probe are refused
//! to a paired phone or browser and to the agent helper with 403 `AGENTS_DESKTOP_ONLY`, as for
//! MCP stdio servers (Jev 046). Remote agents may only be listed and read from a phone or the helper: changing one,
//! or making the host connect to a URL to test or handshake, is desktop-only. Phones read
//! env override values masked; the desktop reads them in full.

mod common;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{build_app_with_skill_paths, desktop_and_phone, json_with_token};

const ENV_SECRET: &str = "custom-agent-env-secret-789";

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
    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
        }
    };

    let (desktop, phone) = desktop_and_phone(&app, tmp.path()).await;

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
    let agents_refused = json!("AGENTS_DESKTOP_ONLY");
    for (method, uri, body) in &host_command_routes {
        let (status, resp) = send(json_with_token(method, uri, body.clone(), &phone, "c")).await;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &agents_refused),
            "phone {method} {uri}: {resp}"
        );
    }
    for (method, uri, body) in &remote_routes {
        let (status, resp) = send(json_with_token(method, uri, body.clone(), &phone, "c")).await;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "phone {method} {uri}: {resp}"
        );
    }
    assert!(!marker.exists(), "the phone's probe ran a command on the host");

    // The helper is refused on remote agents and on every custom agent change.
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
    for (method, uri, body) in &host_command_routes {
        let (status, resp) = send(helper_call(method, uri, body)).await;
        assert_eq!(
            (status, &resp["code"]),
            (StatusCode::FORBIDDEN, &agents_refused),
            "helper {method} {uri}: {resp}"
        );
    }
    assert!(!marker.exists(), "the helper's probe ran a command on the host");
    let req = Request::builder()
        .uri(format!("/api/agents/{agent}/overrides"))
        .header("x-aionui-runtime-token", helper.token.as_str())
        .header("x-aionui-user-id", owner.as_str())
        .header("x-aionui-conversation-id", "conv-helper-agents")
        .body(Body::empty())
        .unwrap();
    let (status, resp) = send(req).await;
    assert_eq!(status, StatusCode::OK, "helper reads overrides: {resp}");
    assert_eq!(resp["data"]["env_override"][0]["value"], "***", "{resp}");
    assert!(
        !resp.to_string().contains(ENV_SECRET),
        "helper reads the secret: {resp}"
    );

    // Nothing the phone or the helper sent changed anything.
    let (_, read) = send(get(&overrides, &desktop)).await;
    assert_eq!(read["data"]["env_override"][0]["value"], ENV_SECRET, "{read}");
    assert_ne!(read["data"]["command_override"], "touch", "{read}");
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

/// Cross-user isolation: bob neither lists nor reaches by id the owner's custom agent, its
/// overrides, or the owner's remote agent.
#[tokio::test]
async fn another_user_cannot_see_or_touch_the_owners_custom_and_remote_agents() {
    unsafe { std::env::set_var("AIONUI_BYPASS_PROBE", "1") };
    let (mut app, services) = common::build_app().await;
    let (owner, oc) = common::setup_and_login(&mut app, &services, "admin", "Pass123!").await;
    let (bob, bc) = common::setup_and_login(&mut app, &services, "bob", "StrongP@ss2").await;
    let send = |method: &str, uri: &str, body: Value, token: &str, csrf: &str| {
        let req = json_with_token(method, uri, body, token, csrf);
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            (status, common::body_json(resp).await)
        }
    };
    let (_, body) = send(
        "POST",
        "/api/agents/custom",
        json!({"name": "owner-custom-agent", "command": "true"}),
        &owner,
        &oc,
    )
    .await;
    let agent = body["data"]["id"].as_str().unwrap().to_owned();
    let (status, body) = send(
        "PUT",
        &format!("/api/agents/{agent}/overrides"),
        json!({"env_override": [{"name": "K", "value": ENV_SECRET}]}),
        &owner,
        &oc,
    )
    .await;
    assert!(status.is_success(), "{body}");
    let (_, body) = send(
        "POST",
        "/api/remote-agents",
        json!({"name": "owner-remote", "protocol": "acp", "url": "wss://owner-remote.invalid", "auth_type": "bearer", "auth_token": "owner-remote-token-9999"}),
        &owner,
        &oc,
    )
    .await;
    let remote = body["data"]["id"].as_str().unwrap().to_owned();

    for list in ["/api/agents/management", "/api/remote-agents"] {
        let (status, body) = send("GET", list, Value::Null, &bob, &bc).await;
        assert_eq!(status, StatusCode::OK, "{list}");
        let text = body.to_string();
        assert!(
            !text.contains("owner-custom-agent") && !text.contains("owner-remote"),
            "{list} leaks the owner's agents: {text}"
        );
    }
    let mut leaks = Vec::new();
    let probes = [
        format!("/api/agents/{agent}/overrides"),
        format!("/api/agents/{agent}/enabled"),
        format!("/api/agents/{agent}/health-check"),
        format!("/api/agents/custom/{agent}"),
        format!("/api/remote-agents/{remote}"),
        format!("/api/remote-agents/{remote}/handshake"),
    ];
    for uri in &probes {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            let body = json!({"name": "bob", "command": "true", "enabled": false, "env_override": [], "url": "ws://127.0.0.1:9"});
            let (status, resp) = send(method, uri, body, &bob, &bc).await;
            let text = resp.to_string();
            if status.is_success() || text.contains(ENV_SECRET) || text.contains("owner-remote") {
                leaks.push(format!("{method} {uri} -> {status} {text}"));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "bob reached the owner's agents:\n{}",
        leaks.join("\n")
    );

    // Still the owner's, unchanged.
    let (_, body) = send(
        "GET",
        &format!("/api/agents/{agent}/overrides"),
        Value::Null,
        &owner,
        &oc,
    )
    .await;
    assert_eq!(body["data"]["env_override"][0]["value"], ENV_SECRET);
    let (_, body) = send("GET", &format!("/api/remote-agents/{remote}"), Value::Null, &owner, &oc).await;
    assert_eq!(body["data"]["url"], "wss://owner-remote.invalid");
}
