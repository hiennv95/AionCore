//! ADR-022 through the real app: the desktop app's session and a refresh both issue
//! grant-bound refresh tokens kept in the app database, and the grace returns the same pair.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use common::build_app_with_skill_paths;

async fn post(app: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("cookie", "aionui-csrf-token=c")
        .header("x-csrf-token", "c")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn desktop_sessions_rotate_through_grants_in_the_app_database() {
    let dir = tempfile::tempdir().unwrap();
    let (app, services, _paths) = build_app_with_skill_paths(dir.path()).await;
    let bootstrap = std::fs::read_to_string(dir.path().join("app-bootstrap.token")).unwrap();
    let (status, session) = post(
        &app,
        "/api/devices/app-session",
        json!({"bootstrap_token": bootstrap, "device_name": "Test Mac"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let r0 = session["data"]["refresh_token"].as_str().unwrap().to_owned();
    let claims = services.jwt_service.verify_refresh(&r0).unwrap();
    let gid = claims.grant_id.clone().expect("grant-bound");
    assert!(claims.jti.is_some() && claims.device_id.is_some());

    let stored: (String, String) = sqlx::query_as("SELECT current_jti, device_id FROM refresh_grants WHERE id = ?")
        .bind(&gid)
        .fetch_one(services.database.pool())
        .await
        .unwrap();
    assert_eq!(Some(stored.0), claims.jti);
    assert_eq!(Some(stored.1), claims.device_id);

    let (status, first) = post(&app, "/api/auth/refresh", json!({"token": r0})).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, again) = post(&app, "/api/auth/refresh", json!({"token": r0})).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(
        first["refresh_token"], again["refresh_token"],
        "same successor inside the grace"
    );
    assert_eq!(first["token"], again["token"]);
    let next = services
        .jwt_service
        .verify_refresh(first["refresh_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(next.grant_id.as_deref(), Some(gid.as_str()));
    assert_ne!(next.jti, claims.jti);
}
