//! Security candidate C2 (ADR-013): the office preview proxies serve documents the desktop
//! opened, so paired phones/browsers and the agent helper are refused like other host reads.

mod common;

use aionui_ai_agent::{RuntimeTokenScope, TEAM_RUNTIME_TOKEN_SESSION_GENERATION};
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
async fn office_preview_proxies_are_desktop_only() {
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
    common::ensure_conversation(&services, owner.as_str(), "conv-helper-office").await;
    let helper = services.runtime_token_service.issue(
        owner.as_str(),
        "conv-helper-office",
        TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
        [RuntimeTokenScope::ConversationHelper],
    );
    let paths = [
        "/api/office-watch-proxy/45000",
        "/api/office-watch-proxy/45000/index.html",
        "/api/ppt-proxy/45000",
        "/api/ppt-proxy/45000/slide1.html",
    ];
    for path in paths {
        let (status, body) = send(&app, bearer(path, &phone)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        assert!(body.contains("FS_OWNER_ONLY"), "phone on {path}: {body}");
        let req = Request::builder()
            .uri(path)
            .header("x-aionui-runtime-token", helper.token.as_str())
            .header("x-aionui-user-id", owner.as_str())
            .header("x-aionui-conversation-id", "conv-helper-office")
            .body(Body::empty())
            .unwrap();
        let (_, body) = send(&app, req).await;
        assert!(body.contains("FS_OWNER_ONLY"), "helper on {path}: {body}");
        // The desktop app passes this gate, then finds the proxy turned off (Jev 055).
        let (status, body) = send(&app, bearer(path, &desktop)).await;
        assert!(!body.contains("FS_OWNER_ONLY"), "desktop on {path}: {body}");
        assert_eq!(status, StatusCode::GONE, "desktop on {path}: {body}");
        assert!(body.contains("OFFICE_PROXY_DISABLED"), "desktop on {path}: {body}");
    }
}
