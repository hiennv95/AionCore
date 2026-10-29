//! ADR-020 T1 (owner decision via Jev 037): a paired phone or browser may read teams and stop a
//! run; every other team route is for the desktop app (403 `TEAM_DESKTOP_ONLY`). The desktop app
//! and the agent helper keep their access (T2 unchanged). The team row is seeded through the
//! repository, so no team session or agent starts.

mod common;

use std::sync::Arc;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
use aionui_db::models::TeamRow;
use aionui_db::{ITeamRepository, SqliteTeamRepository};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{build_app_with_skill_paths, json_with_token};

const TEAM: &str = "team-device-authority";

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

/// Every team route except the read and stop routes a paired device keeps.
fn desktop_only_routes() -> Vec<(&'static str, String, Option<Value>)> {
    let t = TEAM;
    vec![
        ("POST", "/api/teams".into(), Some(json!({"name": "x", "agents": []}))),
        ("DELETE", format!("/api/teams/{t}"), None),
        (
            "PATCH",
            format!("/api/teams/{t}/name"),
            Some(json!({"name": "renamed"})),
        ),
        (
            "POST",
            format!("/api/teams/{t}/agents"),
            Some(json!({"name": "w", "role": "teammate", "model": "m"})),
        ),
        ("DELETE", format!("/api/teams/{t}/agents/slot-x"), None),
        (
            "PATCH",
            format!("/api/teams/{t}/agents/slot-x/name"),
            Some(json!({"name": "n"})),
        ),
        (
            "PATCH",
            format!("/api/teams/{t}/agents/slot-x/model"),
            Some(json!({"model": "m"})),
        ),
        (
            "POST",
            format!("/api/teams/{t}/messages"),
            Some(json!({"content": "hi"})),
        ),
        (
            "POST",
            format!("/api/teams/{t}/agents/slot-x/messages"),
            Some(json!({"content": "hi"})),
        ),
        (
            "POST",
            format!("/api/teams/{t}/agents/slot-x/interrupt"),
            Some(json!({"message": "stop"})),
        ),
        ("POST", format!("/api/teams/{t}/agents/slot-x/attach"), None),
        ("POST", format!("/api/teams/{t}/agents/slot-x/runtime/restart"), None),
        (
            "POST",
            format!("/api/teams/{t}/agents/slot-x/context/reset"),
            Some(json!({})),
        ),
        (
            "GET",
            format!("/api/teams/{t}/conversations/conv-x/config-options"),
            None,
        ),
        (
            "PUT",
            format!("/api/teams/{t}/conversations/conv-x/config-options/mode"),
            Some(json!({"value": "full"})),
        ),
        (
            "POST",
            format!("/api/teams/{t}/runs/run-x/agents/slot-x/cancel"),
            Some(json!({})),
        ),
        (
            "POST",
            format!("/api/teams/{t}/runs/run-x/agents/slot-x/pause"),
            Some(json!({})),
        ),
        ("POST", format!("/api/teams/{t}/session"), None),
        ("DELETE", format!("/api/teams/{t}/session"), None),
        ("POST", format!("/api/teams/{t}/active-lease"), None),
        (
            "POST",
            format!("/api/teams/{t}/session-mode"),
            Some(json!({"mode": "full"})),
        ),
    ]
}

/// The read routes and the run stop a paired device keeps (T1 option b).
fn device_routes() -> Vec<(&'static str, String, Option<Value>)> {
    let t = TEAM;
    vec![
        ("GET", "/api/teams".into(), None),
        ("GET", format!("/api/teams/{t}"), None),
        ("GET", format!("/api/teams/{t}/run-state"), None),
        ("GET", format!("/api/teams/{t}/tasks"), None),
        ("GET", format!("/api/teams/{t}/mailbox"), None),
        ("GET", format!("/api/teams/{t}/activity"), None),
        ("POST", format!("/api/teams/{t}/runs/run-x/cancel"), Some(json!({}))),
    ]
}

#[tokio::test]
async fn a_paired_device_may_read_teams_and_stop_a_run_only() {
    let dir = tempfile::tempdir().unwrap();
    let (app, services, _paths) = build_app_with_skill_paths(dir.path()).await;
    let bootstrap = std::fs::read_to_string(dir.path().join("app-bootstrap.token")).unwrap();
    let send = |req: Request<Body>| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
        }
    };

    // Desktop session, then a phone paired, approved and claimed through the real routes.
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
    let device = claimed["data"]["session"]["access_token"].as_str().unwrap().to_owned();

    let owner = services.user_repo.get_system_user().await.unwrap().unwrap().id;
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

    let refused = json!("TEAM_DESKTOP_ONLY");
    for (method, uri, body) in desktop_only_routes() {
        let (status, body) = send(request(method, &uri, &device, body)).await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::FORBIDDEN, &refused),
            "{method} {uri}"
        );
    }
    // Refused routes left the team untouched.
    let (_, team) = send(request("GET", &format!("/api/teams/{TEAM}"), &device, None)).await;
    assert_eq!(team["data"]["name"], "Seeded");

    for (method, uri, body) in device_routes() {
        let (status, body) = send(request(method, &uri, &device, body)).await;
        assert_ne!(
            body["code"], refused,
            "{method} {uri} must stay open to devices ({status})"
        );
        assert_ne!(status, StatusCode::FORBIDDEN, "{method} {uri}");
    }

    // The desktop app keeps every route: rename goes through.
    let (status, body) = send(request(
        "PATCH",
        &format!("/api/teams/{TEAM}/name"),
        &desktop,
        Some(json!({"name": "Renamed by desktop"})),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The agent helper keeps its access (ADR-020 T2 unchanged).
    common::ensure_conversation(&services, owner.as_str(), "conv-agent-helper").await;
    let issue = services.runtime_token_service.issue(
        owner.as_str(),
        "conv-agent-helper",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let helper = Request::builder()
        .method("PATCH")
        .uri(format!("/api/teams/{TEAM}/name"))
        .header("content-type", "application/json")
        .header("x-aionui-runtime-token", issue.token.as_str())
        .header("x-aionui-user-id", owner.as_str())
        .header("x-aionui-conversation-id", "conv-agent-helper")
        .body(Body::from(json!({"name": "Renamed by helper"}).to_string()))
        .unwrap();
    let (status, body) = send(helper).await;
    assert_ne!(body["code"], refused, "helper must not be refused ({status}): {body}");
}
