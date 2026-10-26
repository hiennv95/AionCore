//! Device-bound sessions (ADR-011): a token carrying `device_id` works only
//! while that device is live and belongs to the token's user.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::middleware;
use axum::routing::get;
use tower::ServiceExt;

use aionui_auth::{AuthIdentityMode, AuthState, JwtService, auth_middleware};
use aionui_db::{
    IDeviceRepository, IUserRepository, SqliteDeviceRepository, SqliteUserRepository, init_database_memory,
};

const OWNER: &str = "system_default_user";

struct Ctx {
    jwt: Arc<JwtService>,
    devices: Arc<SqliteDeviceRepository>,
    app_with_devices: Router,
    app_without_devices: Router,
    _db: aionui_db::Database,
}

async fn ctx() -> Ctx {
    let db = init_database_memory().await.unwrap();
    let users = Arc::new(SqliteUserRepository::new(db.pool().clone())) as Arc<dyn IUserRepository>;
    let devices = Arc::new(SqliteDeviceRepository::new(db.pool().clone()));
    let jwt = Arc::new(JwtService::new("device-session-test".into()));
    let app = |device_repo: Option<Arc<dyn IDeviceRepository>>| {
        let state = AuthState {
            jwt_service: jwt.clone(),
            user_repo: users.clone(),
            identity_mode: AuthIdentityMode::UserSession,
            runtime_token_verifier: None,
            device_repo,
        };
        Router::new()
            .route("/protected", get(|| async { "ok" }))
            .route_layer(middleware::from_fn_with_state(state, auth_middleware))
    };
    Ctx {
        app_with_devices: app(Some(devices.clone() as Arc<dyn IDeviceRepository>)),
        app_without_devices: app(None),
        jwt,
        devices,
        _db: db,
    }
}

async fn call(app: &Router, token: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::get("/protected")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
}

#[tokio::test]
async fn live_device_token_is_accepted_and_revoked_one_is_rejected() {
    let c = ctx().await;
    let device = c.devices.insert(OWNER, "Pixel", "mobile").await.unwrap();
    let (access, _) = c.jwt.sign_session_pair(OWNER, OWNER, 0, Some(&device.id)).unwrap();
    assert_eq!(call(&c.app_with_devices, &access).await.0, StatusCode::OK);

    c.devices.revoke(OWNER, &device.id, 1).await.unwrap();
    let (status, body) = call(&c.app_with_devices, &access).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "DEVICE_REVOKED");
}

#[tokio::test]
async fn unknown_or_foreign_device_is_rejected() {
    let c = ctx().await;
    let (access, _) = c.jwt.sign_session_pair(OWNER, OWNER, 0, Some("dev_missing")).unwrap();
    assert_eq!(call(&c.app_with_devices, &access).await.1["code"], "DEVICE_REVOKED");

    let foreign = c.devices.insert("someone_else", "Their phone", "mobile").await.unwrap();
    let (access, _) = c.jwt.sign_session_pair(OWNER, OWNER, 0, Some(&foreign.id)).unwrap();
    assert_eq!(call(&c.app_with_devices, &access).await.1["code"], "DEVICE_REVOKED");
}

#[tokio::test]
async fn device_tokens_fail_closed_without_a_device_registry() {
    let c = ctx().await;
    let device = c.devices.insert(OWNER, "Mac app", "desktop_app").await.unwrap();
    let (access, _) = c.jwt.sign_session_pair(OWNER, OWNER, 0, Some(&device.id)).unwrap();
    assert_eq!(call(&c.app_without_devices, &access).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn legacy_tokens_without_device_still_work() {
    let c = ctx().await;
    let token = c.jwt.sign(OWNER, OWNER).unwrap();
    assert_eq!(call(&c.app_with_devices, &token).await.0, StatusCode::OK);
}
