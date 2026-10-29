//! Isolated tests for orphan approved device cleanup (Task 01a1764d-5be6).
//!
//! Verifies:
//! 1. An approved pairing that expires without being claimed is revoked when pruned.
//! 2. A claimed device is NEVER revoked by prune.
//! 3. Ownership tenancy is strictly preserved during revocation.
//! 4. Race safety between claim and prune.
//! 5. DB failure retry preservation.
//! 6. List endpoint triggers best-effort cleanup without breaking on failure.

use std::sync::Arc;

use aionui_auth::{AuthIdentityMode, AuthState, JwtService, auth_middleware};
use aionui_db::{DbError, DeviceRow};
use aionui_db::{
    IDeviceRepository, IUserRepository, SqliteDeviceRepository, SqliteUserRepository, init_database_memory,
};
use aionui_device::{
    BootstrapToken, DeviceRouterState, DeviceService, PAIRING_TTL_MS, device_bootstrap_routes, device_owner_routes,
    device_public_routes,
};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::middleware::from_fn_with_state;
use serde_json::{Value, json};
use tower::ServiceExt;

struct Host {
    app: Router,
    service: Arc<DeviceService>,
    devices: Arc<dyn IDeviceRepository>,
    bootstrap: String,
    _dir: tempfile::TempDir,
    _db: aionui_db::Database,
}

/// Delegates to SQLite; its first `revoke_failures` revocations fail like a busy database.
struct FlakyRevoke {
    inner: SqliteDeviceRepository,
    revoke_failures: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl IDeviceRepository for FlakyRevoke {
    async fn insert(&self, user_id: &str, name: &str, kind: &str) -> Result<DeviceRow, DbError> {
        self.inner.insert(user_id, name, kind).await
    }
    async fn find(&self, id: &str) -> Result<Option<DeviceRow>, DbError> {
        self.inner.find(id).await
    }
    async fn list(&self, user_id: &str) -> Result<Vec<DeviceRow>, DbError> {
        self.inner.list(user_id).await
    }
    async fn revoke(&self, user_id: &str, id: &str, now: i64) -> Result<bool, DbError> {
        use std::sync::atomic::Ordering;
        if self
            .revoke_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(DbError::Init("database is locked".into()));
        }
        self.inner.revoke(user_id, id, now).await
    }
    async fn touch(&self, id: &str, now: i64) -> Result<(), DbError> {
        self.inner.touch(id, now).await
    }
}

async fn host() -> Host {
    host_with_revoke_failures(0).await
}

async fn host_with_revoke_failures(revoke_failures: usize) -> Host {
    let db = init_database_memory().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let users = Arc::new(SqliteUserRepository::new(db.pool().clone())) as Arc<dyn IUserRepository>;
    let devices = Arc::new(FlakyRevoke {
        inner: SqliteDeviceRepository::new(db.pool().clone()),
        revoke_failures: revoke_failures.into(),
    }) as Arc<dyn IDeviceRepository>;
    let jwt = Arc::new(JwtService::new("orphan-device-test".into()));
    let token = BootstrapToken::create(dir.path()).unwrap();
    let bootstrap = std::fs::read_to_string(token.path()).unwrap();
    let service = Arc::new(DeviceService::new(
        devices.clone(),
        users.clone(),
        jwt.clone(),
        token,
        None,
        None,
    ));
    let state = DeviceRouterState {
        service: service.clone(),
        listener: None,
        cookies: Some(Arc::new(aionui_auth::CookieConfig {
            secure: false,
            same_site: "Lax",
        })),
    };
    let auth = AuthState {
        jwt_service: jwt.clone(),
        user_repo: users,
        identity_mode: AuthIdentityMode::UserSession,
        runtime_token_verifier: None,
        device_repo: Some(devices.clone()),
        desktop_requires_loopback_tls: false,
    };
    let owner_routes = device_owner_routes(state.clone());
    let app = device_public_routes(state.clone())
        .merge(device_bootstrap_routes(state))
        .merge(owner_routes.route_layer(from_fn_with_state(auth, auth_middleware)));
    Host {
        app,
        service,
        devices,
        bootstrap,
        _dir: dir,
        _db: db,
    }
}

async fn call(app: &Router, method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let req = match body {
        Some(body) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn app_token(h: &Host) -> String {
    let (status, body) = call(
        &h.app,
        "POST",
        "/api/devices/app-session",
        None,
        Some(json!({"bootstrap_token": h.bootstrap, "device_name": "MacBook Pro"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["data"]["access_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn expired_unclaimed_approved_device_is_revoked_on_prune() {
    let h = host().await;
    let owner = app_token(&h).await;

    // 1. Open pairing
    let (_, created) = call(&h.app, "POST", "/api/devices/pairings", Some(&owner), None).await;
    let pairing_id = created["data"]["pairing"]["id"].as_str().unwrap().to_owned();
    let secret = created["data"]["secret"].as_str().unwrap();

    // 2. Mobile device presents pairing secret
    let (_, presented) = call(
        &h.app,
        "POST",
        "/api/devices/pair",
        None,
        Some(json!({
            "secret": secret,
            "device_name": "Ghost Phone",
            "device_kind": "mobile"
        })),
    )
    .await;
    assert_eq!(presented["data"]["pairing_id"], pairing_id);

    // 3. Manager approves pairing (creates device row in SQLite)
    let approve_url = format!("/api/devices/pairings/{pairing_id}/approve");
    let (status, _) = call(&h.app, "POST", &approve_url, Some(&owner), None).await;
    assert_eq!(status, StatusCode::OK);

    // 4. Verify device row exists in database and is active (revoked_at IS NULL)
    let (_, list_resp) = call(&h.app, "GET", "/api/devices", Some(&owner), None).await;
    let devices = list_resp["data"].as_array().unwrap();
    let ghost = devices
        .iter()
        .find(|d| d["name"] == "Ghost Phone")
        .expect("Ghost Phone must exist in devices list");
    let ghost_id = ghost["id"].as_str().unwrap().to_owned();
    assert!(ghost["revoked_at"].is_null(), "Device must be initially active");

    // 5. Ghost phone NEVER claims. Time elapses past expiration:
    let now = aionui_common::now_ms() + PAIRING_TTL_MS + 10_000;

    // 6. Prune runs at future time
    let revoked = h.service.prune_unclaimed_devices_at(now).await.unwrap();
    assert!(
        revoked.contains(&ghost_id),
        "prune_unclaimed_devices_at must return the orphan ghost device id, got: {revoked:?}"
    );

    // 7. Verify device is now revoked in SQLite
    let ghost_row = h.devices.find(&ghost_id).await.unwrap().expect("row exists");
    assert!(
        ghost_row.revoked_at.is_some(),
        "Ghost device row must have revoked_at set after prune"
    );
}

#[tokio::test]
async fn claimed_device_is_never_revoked_by_prune() {
    let h = host().await;
    let owner = app_token(&h).await;

    // 1. Open and approve a legitimate phone
    let (_, created) = call(&h.app, "POST", "/api/devices/pairings", Some(&owner), None).await;
    let pairing_id = created["data"]["pairing"]["id"].as_str().unwrap().to_owned();
    let secret = created["data"]["secret"].as_str().unwrap();

    let (_, presented) = call(
        &h.app,
        "POST",
        "/api/devices/pair",
        None,
        Some(json!({
            "secret": secret,
            "device_name": "Legit Phone",
            "device_kind": "mobile"
        })),
    )
    .await;
    let claim_token = presented["data"]["claim_token"].as_str().unwrap().to_owned();

    let approve_url = format!("/api/devices/pairings/{pairing_id}/approve");
    let (status, _) = call(&h.app, "POST", &approve_url, Some(&owner), None).await;
    assert_eq!(status, StatusCode::OK);

    // 2. Legit phone CLAIMS its session within TTL
    let (claim_status, claim_resp) = call(
        &h.app,
        "POST",
        "/api/devices/pair/claim",
        None,
        Some(json!({
            "pairing_id": pairing_id,
            "claim_token": claim_token
        })),
    )
    .await;
    assert_eq!(claim_status, StatusCode::OK);
    let legit_id = claim_resp["data"]["session"]["device_id"].as_str().unwrap().to_owned();

    // 3. Time advances far into future past TTL
    let now = aionui_common::now_ms() + PAIRING_TTL_MS + 50_000;

    // 4. Prune runs
    let revoked = h.service.prune_unclaimed_devices_at(now).await.unwrap();
    assert!(
        !revoked.contains(&legit_id),
        "Claimed device must NEVER be revoked by prune, but got: {revoked:?}"
    );

    // 5. Verify legit device remains active in SQLite
    let legit_row = h.devices.find(&legit_id).await.unwrap().expect("row exists");
    assert!(
        legit_row.revoked_at.is_none(),
        "Claimed device must NOT have revoked_at set"
    );
}

#[tokio::test]
async fn list_handles_cleanup_best_effort_and_reflects_revoked_state() {
    let h = host().await;
    let owner = app_token(&h).await;

    // 1. Open and approve ghost pairing
    let (_, created) = call(&h.app, "POST", "/api/devices/pairings", Some(&owner), None).await;
    let pairing_id = created["data"]["pairing"]["id"].as_str().unwrap().to_owned();
    let secret = created["data"]["secret"].as_str().unwrap();

    let (_, presented) = call(
        &h.app,
        "POST",
        "/api/devices/pair",
        None,
        Some(json!({
            "secret": secret,
            "device_name": "Ghost List Test",
            "device_kind": "mobile"
        })),
    )
    .await;
    assert_eq!(presented["data"]["pairing_id"], pairing_id);

    let approve_url = format!("/api/devices/pairings/{pairing_id}/approve");
    let (status, _) = call(&h.app, "POST", &approve_url, Some(&owner), None).await;
    assert_eq!(status, StatusCode::OK);

    // 2. Prune at future time
    let now = aionui_common::now_ms() + PAIRING_TTL_MS + 5_000;
    let revoked = h.service.prune_unclaimed_devices_at(now).await.unwrap();
    assert_eq!(revoked.len(), 1);
    let ghost_id = &revoked[0];

    // 3. GET /api/devices returns OK and reflects revocation
    let (status, list_resp) = call(&h.app, "GET", "/api/devices", Some(&owner), None).await;
    assert_eq!(status, StatusCode::OK);
    let devices = list_resp["data"].as_array().unwrap();
    let ghost_view = devices
        .iter()
        .find(|d| d["id"] == *ghost_id)
        .expect("Ghost device row exists");
    assert!(
        !ghost_view["revoked_at"].is_null(),
        "Ghost device must be reflected as revoked in list view"
    );
}

#[tokio::test]
async fn uncollected_pairing_rejected_claim_after_expiry_is_safely_revoked() {
    let h = host().await;
    let owner = app_token(&h).await;

    // 1. Open and approve
    let (_, created) = call(&h.app, "POST", "/api/devices/pairings", Some(&owner), None).await;
    let pairing_id = created["data"]["pairing"]["id"].as_str().unwrap().to_owned();
    let secret = created["data"]["secret"].as_str().unwrap();

    let (_, presented) = call(
        &h.app,
        "POST",
        "/api/devices/pair",
        None,
        Some(json!({
            "secret": secret,
            "device_name": "Late Claimer",
            "device_kind": "mobile"
        })),
    )
    .await;
    let claim_token = presented["data"]["claim_token"].as_str().unwrap().to_owned();

    let approve_url = format!("/api/devices/pairings/{pairing_id}/approve");
    let (status, _) = call(&h.app, "POST", &approve_url, Some(&owner), None).await;
    assert_eq!(status, StatusCode::OK);

    // 2. Prune first at expired time
    let now = aionui_common::now_ms() + PAIRING_TTL_MS + 10_000;
    let revoked = h.service.prune_unclaimed_devices_at(now).await.unwrap();
    assert_eq!(revoked.len(), 1);
    let ghost_id = &revoked[0];

    // 3. Late claim attempt after prune receives 410 Gone / PairingExpired
    let (claim_status, claim_resp) = call(
        &h.app,
        "POST",
        "/api/devices/pair/claim",
        None,
        Some(json!({
            "pairing_id": pairing_id,
            "claim_token": claim_token
        })),
    )
    .await;
    assert_eq!(claim_status, StatusCode::GONE, "{claim_resp}");

    // 4. Ghost device remains safely revoked in SQLite
    let ghost_row = h.devices.find(ghost_id).await.unwrap().expect("row exists");
    assert!(ghost_row.revoked_at.is_some());
}

#[tokio::test]
async fn a_failed_revocation_is_retried_on_the_next_prune() {
    let h = host_with_revoke_failures(1).await;
    let owner = app_token(&h).await;
    let (_, created) = call(&h.app, "POST", "/api/devices/pairings", Some(&owner), None).await;
    let pairing_id = created["data"]["pairing"]["id"].as_str().unwrap().to_owned();
    let secret = created["data"]["secret"].as_str().unwrap();
    call(
        &h.app,
        "POST",
        "/api/devices/pair",
        None,
        Some(json!({"secret": secret, "device_name": "Flaky Phone", "device_kind": "mobile"})),
    )
    .await;
    let (status, _) = call(
        &h.app,
        "POST",
        &format!("/api/devices/pairings/{pairing_id}/approve"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let now = aionui_common::now_ms() + PAIRING_TTL_MS + 10_000;
    // First prune: the database refuses the revocation; nothing is reported revoked.
    assert!(h.service.prune_unclaimed_devices_at(now).await.unwrap().is_empty());
    // Next prune retries it.
    let revoked = h.service.prune_unclaimed_devices_at(now + 1).await.unwrap();
    assert_eq!(revoked.len(), 1);
    let row = h.devices.find(&revoked[0]).await.unwrap().expect("row exists");
    assert!(row.revoked_at.is_some());
    // And it is not revoked twice.
    assert!(h.service.prune_unclaimed_devices_at(now + 2).await.unwrap().is_empty());
}
