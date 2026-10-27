//! Route authentication audit gate.
//!
//! Every route registered anywhere in `crates/*/src` is called without credentials on the
//! real app router, with every method. A route must refuse (401/403), or not exist for that
//! method or placeholder (404/405), unless it is on the public list below with a reason.
//! A new route that answers anonymous callers therefore fails this test until someone
//! decides it is public on purpose.
//!
//! A valid CSRF pair is sent so a 403 here means "no credentials", not "no CSRF token".

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;

/// Routes that answer without a session, each with its own authentication or a reason.
const PUBLIC: &[(&str, &str)] = &[
    ("/health", "liveness probe; version only"),
    ("/api/auth/status", "setup/login probe; no user data"),
    ("/login", "credential exchange"),
    ("/api/auth/refresh", "refresh token exchange (cookie or body)"),
    ("/api/auth/qr-login", "QR token exchange"),
    ("/qr-login", "static QR login page"),
    ("/api/devices/pair", "pairing code exchange (ADR-011)"),
    ("/api/devices/pair/claim", "pairing claim with a code (ADR-011)"),
    (
        "/api/devices/app-session",
        "desktop bootstrap secret exchange (ADR-011)",
    ),
    ("/api/devices/host-proof", "host identity proof for pinning (ADR-011)"),
    ("/ws", "authenticates in the upgrade; anonymous sockets are closed"),
    (
        "/internal/antigravity-hook/{conversation_id}",
        "per-conversation hook secret; denies otherwise",
    ),
    (
        "/api/runtime/",
        "prefix: agent helper routes authenticate on the runtime token header",
    ),
    (
        "/api/auth/internal/",
        "prefix: provisioning routes need the bootstrap secret",
    ),
    (
        "/api/webui/",
        "prefix: local-only credential routes, refused off loopback in the handler",
    ),
    ("/api/assets/", "prefix: bundled agent logos (static, no user data)"),
];

fn is_public(path: &str) -> bool {
    PUBLIC.iter().any(|(p, _)| {
        if p.ends_with('/') {
            path.starts_with(p)
        } else {
            path == *p
        }
    })
}

/// `.route("…"` paths in non-test source, test modules cut off at `#[cfg(test)]`.
fn route_paths(dir: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            route_paths(&path, out);
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy();
        if !name.ends_with(".rs") || name.ends_with("_test.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let text = text.split("#[cfg(test)]").next().unwrap_or_default();
        let mut rest = text;
        while let Some(at) = rest.find(".route(") {
            rest = &rest[at + ".route(".len()..];
            let trimmed = rest.trim_start();
            if let Some(quoted) = trimmed.strip_prefix('"')
                && let Some(end) = quoted.find('"')
            {
                out.insert(quoted[..end].to_owned());
            }
        }
    }
}

fn all_routes() -> BTreeSet<String> {
    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(&crates).unwrap() {
        let src = entry.unwrap().path().join("src");
        if src.is_dir() {
            route_paths(&src, &mut out);
        }
    }
    out
}

/// `{id}` and `{*rest}` placeholders become a dummy segment.
fn concrete(path: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for c in path.chars() {
        match c {
            '{' => {
                skipping = true;
                out.push('x');
            }
            '}' => skipping = false,
            _ if skipping => {}
            _ => out.push(c),
        }
    }
    out
}

#[tokio::test]
async fn every_route_refuses_anonymous_callers_unless_declared_public() {
    let (app, _services) = common::build_app().await;
    let routes = all_routes();
    assert!(routes.len() > 150, "route scan found too few routes: {}", routes.len());

    let mut open = Vec::new();
    for path in &routes {
        if is_public(path) {
            continue;
        }
        let uri = concrete(path);
        for method in [Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            let request = Request::builder()
                .method(method.clone())
                .uri(&uri)
                .header("content-type", "application/json")
                .header("x-csrf-token", "audit")
                .header("cookie", "aionui-csrf-token=audit")
                .body(Body::from("{}"))
                .unwrap();
            let status = app.clone().oneshot(request).await.unwrap().status();
            if !matches!(
                status,
                StatusCode::UNAUTHORIZED
                    | StatusCode::FORBIDDEN
                    | StatusCode::NOT_FOUND
                    | StatusCode::METHOD_NOT_ALLOWED
            ) {
                open.push(format!("{method} {path} -> {status}"));
            }
        }
    }
    assert!(
        open.is_empty(),
        "routes answering anonymous callers (add auth, or declare them in PUBLIC with a reason):\n{}",
        open.join("\n")
    );
}

/// Every PUBLIC entry still names a real route, so the list cannot rot into blanket exemptions.
#[test]
fn every_public_entry_matches_a_route() {
    let routes = all_routes();
    for (entry, _) in PUBLIC {
        let hit = if entry.ends_with('/') {
            routes.iter().any(|r| r.starts_with(entry))
        } else {
            routes.contains(*entry)
        };
        assert!(hit, "PUBLIC entry {entry} matches no route");
    }
}

/// Cross-user isolation: bob calls every conversation-scoped route with the owner's chat id,
/// with every method. None may succeed (2xx) or redirect.
#[tokio::test]
async fn another_user_cannot_use_any_conversation_route_of_the_owner() {
    let (mut app, services) = common::build_app().await;
    let (owner, owner_csrf) = common::setup_and_login(&mut app, &services, "admin", "Pass123!").await;
    let workspace = tempfile::tempdir().unwrap();
    let created = app
        .clone()
        .oneshot(common::json_with_token(
            "POST",
            "/api/conversations",
            serde_json::json!({"type": "acp", "name": "owner chat", "extra": {"workspace": workspace.path()}}),
            &owner,
            &owner_csrf,
        ))
        .await
        .unwrap();
    let id = common::body_json(created).await["data"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (bob, bob_csrf) = common::setup_and_login(&mut app, &services, "bob", "StrongP@ss2").await;

    let scoped: Vec<String> = all_routes()
        .into_iter()
        .filter(|r| r.starts_with("/api/conversations/{id}") || r.starts_with("/api/sidebar/conversation/{id}"))
        .collect();
    assert!(scoped.len() > 20, "too few conversation routes found: {}", scoped.len());

    let mut leaks = Vec::new();
    for path in &scoped {
        let uri = concrete(&path.replacen("{id}", &id, 1));
        for method in [Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            let request = Request::builder()
                .method(method.clone())
                .uri(&uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {bob}"))
                .header("x-csrf-token", &bob_csrf)
                .header("cookie", format!("aionui-csrf-token={bob_csrf}"))
                .body(Body::from("{}"))
                .unwrap();
            let status = app.clone().oneshot(request).await.unwrap().status();
            if status.is_success() || status.is_redirection() {
                leaks.push(format!("{method} {path} -> {status}"));
            }
        }
    }
    assert!(leaks.is_empty(), "bob reached the owner's chat:\n{}", leaks.join("\n"));

    // The owner's chat is untouched.
    let resp = app
        .clone()
        .oneshot(common::get_with_token(&format!("/api/conversations/{id}"), &owner))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(common::body_json(resp).await["data"]["name"], "owner chat");
}

async fn call(
    app: &axum::Router,
    method: Method,
    uri: &str,
    token: &str,
    csrf: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .header("x-csrf-token", csrf)
        .header("cookie", format!("aionui-csrf-token={csrf}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(request).await.unwrap();
    let status = resp.status();
    (status, common::body_json(resp).await)
}

/// Cross-user isolation for the owner's model providers (they hold API keys) and MCP
/// servers: bob neither sees them in his lists nor reaches them by id.
#[tokio::test]
async fn another_user_cannot_see_or_touch_the_owners_providers_and_mcp_servers() {
    let (mut app, services) = common::build_app().await;
    let (owner, oc) = common::setup_and_login(&mut app, &services, "admin", "Pass123!").await;
    let secret = "sk-owner-secret-key-123";
    let (status, body) = call(
        &app,
        Method::POST,
        "/api/providers",
        &owner,
        &oc,
        serde_json::json!({"platform": "openai", "name": "owner provider", "base_url": "https://api.example.invalid", "api_key": secret}),
    )
    .await;
    assert!(status.is_success(), "create provider: {status} {body}");
    let provider = body["data"]["id"].as_str().unwrap().to_owned();
    let (status, body) = call(
        &app,
        Method::POST,
        "/api/mcp/servers",
        &owner,
        &oc,
        serde_json::json!({"name": "owner-mcp", "transport": {"type": "stdio", "command": "echo", "env": {"TOKEN": "mcp-secret-456"}}}),
    )
    .await;
    assert!(status.is_success(), "create mcp: {status} {body}");
    let mcp = body["data"]["id"].as_str().unwrap().to_owned();

    let (bob, bc) = common::setup_and_login(&mut app, &services, "bob", "StrongP@ss2").await;
    for list in ["/api/providers", "/api/mcp/servers"] {
        let (status, body) = call(&app, Method::GET, list, &bob, &bc, serde_json::Value::Null).await;
        assert_eq!(status, StatusCode::OK, "{list}");
        let text = body.to_string();
        assert!(
            !text.contains(&provider) && !text.contains(&mcp),
            "{list} leaks the owner's rows: {text}"
        );
        assert!(
            !text.contains(secret) && !text.contains("mcp-secret-456"),
            "{list} leaks a secret"
        );
    }
    let mut leaks = Vec::new();
    for (path, id) in [
        ("/api/providers/{id}", &provider),
        ("/api/providers/{id}/models", &provider),
        ("/api/mcp/servers/{id}", &mcp),
        ("/api/mcp/servers/{id}/toggle", &mcp),
    ] {
        let uri = path.replace("{id}", id);
        for method in [Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            let (status, body) = call(
                &app,
                method.clone(),
                &uri,
                &bob,
                &bc,
                serde_json::json!({"name": "bob was here", "enabled": false}),
            )
            .await;
            if status.is_success() || body.to_string().contains(secret) {
                leaks.push(format!("{method} {path} -> {status}"));
            }
        }
    }
    assert!(
        leaks.is_empty(),
        "bob reached the owner's resources:\n{}",
        leaks.join("\n")
    );

    // Still the owner's, unchanged.
    let (_, body) = call(
        &app,
        Method::GET,
        "/api/providers",
        &owner,
        &oc,
        serde_json::Value::Null,
    )
    .await;
    assert!(body.to_string().contains("owner provider"), "{body}");
    let (_, body) = call(
        &app,
        Method::GET,
        "/api/mcp/servers",
        &owner,
        &oc,
        serde_json::Value::Null,
    )
    .await;
    assert!(body.to_string().contains("owner-mcp"), "{body}");
}

/// The feedback diagnostics report takes ids from the caller: bob naming the owner's chat,
/// provider and MCP server with every profile must get nothing of theirs back.
#[tokio::test]
async fn the_diagnostics_report_never_returns_another_users_rows() {
    let (mut app, services) = common::build_app().await;
    let (owner, oc) = common::setup_and_login(&mut app, &services, "admin", "Pass123!").await;
    let workspace = tempfile::tempdir().unwrap();
    let (_, body) = call(
        &app,
        Method::POST,
        "/api/conversations",
        &owner,
        &oc,
        serde_json::json!({"type": "acp", "name": "owner-secret-chat", "extra": {"workspace": workspace.path()}}),
    )
    .await;
    let chat = body["data"]["id"].as_str().unwrap().to_owned();
    let (_, body) = call(
        &app,
        Method::POST,
        "/api/providers",
        &owner,
        &oc,
        serde_json::json!({"platform": "openai", "name": "owner-secret-provider", "base_url": "https://owner-host.invalid", "api_key": "sk-owner-diag"}),
    )
    .await;
    let provider = body["data"]["id"].as_str().unwrap().to_owned();
    let (_, body) = call(
        &app,
        Method::POST,
        "/api/mcp/servers",
        &owner,
        &oc,
        serde_json::json!({"name": "owner-secret-mcp", "transport": {"type": "stdio", "command": "echo"}}),
    )
    .await;
    let mcp = body["data"]["id"].as_str().unwrap().to_owned();

    let profiles =
        "conversation-session,model-auth,agent-team,mcp-tools,client-ui-settings,workspace-summary,global-summary";
    let uri = format!(
        "/api/system/diagnostics/feedback-report?profiles={profiles}&conversation_id={chat}&provider_id={provider}&mcp_server_id={mcp}"
    );
    // The owner's own report does name them (so the probe can see a leak).
    let (status, report) = call(&app, Method::GET, &uri, &owner, &oc, serde_json::Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    let text = report.to_string();
    assert!(
        text.contains("owner-secret-chat")
            && text.contains("owner-secret-provider")
            && text.contains("owner-secret-mcp"),
        "the owner's report should name the owner's rows: {text}"
    );
    assert!(!text.contains("sk-owner-diag"), "the report carries an API key");

    let (bob, bc) = common::setup_and_login(&mut app, &services, "bob", "StrongP@ss2").await;
    let (status, report) = call(&app, Method::GET, &uri, &bob, &bc, serde_json::Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    let text = report.to_string();
    for leak in [
        "owner-secret-chat",
        "owner-secret-provider",
        "owner-host.invalid",
        "owner-secret-mcp",
        "sk-owner-diag",
    ] {
        assert!(!text.contains(leak), "bob's report contains {leak}: {text}");
    }
}

/// Cross-user isolation for assistants and their rule and skill files, which are addressed
/// by a caller-chosen assistant id: bob can neither read, overwrite nor delete the owner's,
/// nor take over the id by creating his own assistant with it.
#[tokio::test]
async fn another_user_cannot_read_or_replace_the_owners_assistant_rules() {
    let (mut app, services) = common::build_app().await;
    let (owner, oc) = common::setup_and_login(&mut app, &services, "admin", "Pass123!").await;
    let (bob, bc) = common::setup_and_login(&mut app, &services, "bob", "StrongP@ss2").await;
    let assistant = serde_json::json!({"id": "owner-a", "name": "owner-assistant", "agent_id": "632f31d2"});
    let (status, body) = call(&app, Method::POST, "/api/assistants", &owner, &oc, assistant.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    for kind in ["rule", "skill"] {
        let (status, body) = call(
            &app,
            Method::POST,
            &format!("/api/skills/assistant-{kind}/write"),
            &owner,
            &oc,
            serde_json::json!({"assistant_id": "owner-a", "content": format!("owner {kind} body")}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    let mut leaks = Vec::new();
    let (status, body) = call(&app, Method::POST, "/api/assistants", &bob, &bc, assistant).await;
    if status.is_success() {
        leaks.push(format!("bob created an assistant with the owner's id: {body}"));
    }
    let (status, body) = call(
        &app,
        Method::GET,
        "/api/assistants/owner-a",
        &bob,
        &bc,
        serde_json::Value::Null,
    )
    .await;
    if status.is_success() {
        leaks.push(format!("GET /api/assistants/owner-a -> {status} {body}"));
    }
    for kind in ["rule", "skill"] {
        let read = format!("/api/skills/assistant-{kind}/read");
        let (status, body) = call(
            &app,
            Method::POST,
            &read,
            &bob,
            &bc,
            serde_json::json!({"assistant_id": "owner-a"}),
        )
        .await;
        if body.to_string().contains("owner ") {
            leaks.push(format!("bob read the owner's {kind}: {status} {body}"));
        }
        call(
            &app,
            Method::POST,
            &format!("/api/skills/assistant-{kind}/write"),
            &bob,
            &bc,
            serde_json::json!({"assistant_id": "owner-a", "content": "bob was here"}),
        )
        .await;
        call(
            &app,
            Method::DELETE,
            &format!("/api/skills/assistant-{kind}/owner-a"),
            &bob,
            &bc,
            serde_json::Value::Null,
        )
        .await;
        let (_, body) = call(
            &app,
            Method::POST,
            &read,
            &owner,
            &oc,
            serde_json::json!({"assistant_id": "owner-a"}),
        )
        .await;
        if body["data"] != format!("owner {kind} body") {
            leaks.push(format!("the owner's {kind} changed: {body}"));
        }
    }
    let (_, body) = call(
        &app,
        Method::GET,
        "/api/assistants/owner-a",
        &owner,
        &oc,
        serde_json::Value::Null,
    )
    .await;
    if !body.to_string().contains("owner-assistant") {
        leaks.push(format!("the owner's assistant changed: {body}"));
    }
    assert!(leaks.is_empty(), "{}", leaks.join("\n"));
}
