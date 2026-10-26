//! HTTP-level flow of ADR-011: desktop bootstrap, pairing, claim, revoke.

use std::sync::Arc;

use aionui_auth::{AuthIdentityMode, AuthState, JwtService, auth_middleware};
use aionui_db::{
    IDeviceRepository, IUserRepository, SqliteDeviceRepository, SqliteUserRepository, init_database_memory,
};
use aionui_device::{
    BootstrapToken, DeviceRouterState, DeviceService, device_bootstrap_routes, device_owner_routes,
    device_public_routes,
};
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use serde_json::{Value, json};
use tower::ServiceExt;

struct Host {
    app: Router,
    bootstrap: String,
    _dir: tempfile::TempDir,
    _db: aionui_db::Database,
}

async fn host() -> Host {
    let db = init_database_memory().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let users = Arc::new(SqliteUserRepository::new(db.pool().clone())) as Arc<dyn IUserRepository>;
    let devices = Arc::new(SqliteDeviceRepository::new(db.pool().clone())) as Arc<dyn IDeviceRepository>;
    let jwt = Arc::new(JwtService::new("device-flow".into()));
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
        service,
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
        device_repo: Some(devices),
    };
    // Runs after auth_middleware, before the handler (see `revoke_token`).
    let owner_routes = device_owner_routes(state.clone()).route_layer(from_fn_with_state(jwt, revoke_token));
    let app = device_public_routes(state.clone())
        .merge(device_bootstrap_routes(state))
        .merge(owner_routes.route_layer(from_fn_with_state(auth, auth_middleware)));
    Host {
        app,
        bootstrap,
        _dir: dir,
        _db: db,
    }
}

const REVOKE_AFTER_AUTH: &str = "x-test-revoke-after-auth";

/// Blacklists the request's token after auth_middleware accepted it, as a
/// concurrent `/logout` landing in that window would. Only for requests that
/// carry the test header.
async fn revoke_token(State(jwt): State<Arc<JwtService>>, request: Request<Body>, next: Next) -> Response {
    if request.headers().contains_key(REVOKE_AFTER_AUTH)
        && let Some(token) = aionui_auth::extract_token_from_headers(request.headers())
    {
        jwt.blacklist_token(&token);
    }
    next.run(request).await
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
        Some(json!({"bootstrap_token": h.bootstrap, "device_name": "MacBook"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["data"]["access_token"].as_str().unwrap().to_owned()
}

/// Pairs a phone through the owner-approved flow and returns its access token.
async fn paired_phone(h: &Host, owner: &str) -> String {
    let (_, created) = call(&h.app, "POST", "/api/devices/pairings", Some(owner), None).await;
    let pairing_id = created["data"]["pairing"]["id"].as_str().unwrap().to_owned();
    let pair = json!({"secret": created["data"]["secret"], "device_name": "Pixel 9", "device_kind": "mobile"});
    let (_, presented) = call(&h.app, "POST", "/api/devices/pair", None, Some(pair)).await;
    let claim = json!({
        "pairing_id": presented["data"]["pairing_id"],
        "claim_token": presented["data"]["claim_token"],
    });
    let approve = format!("/api/devices/pairings/{pairing_id}/approve");
    let (status, _) = call(&h.app, "POST", &approve, Some(owner), None).await;
    assert_eq!(status, StatusCode::OK);
    let (_, claimed) = call(&h.app, "POST", "/api/devices/pair/claim", None, Some(claim)).await;
    claimed["data"]["session"]["access_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn wrong_bootstrap_is_refused() {
    let h = host().await;
    let (status, body) = call(
        &h.app,
        "POST",
        "/api/devices/app-session",
        None,
        Some(json!({"bootstrap_token": "guess"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "BOOTSTRAP_INVALID");
}

#[tokio::test]
async fn relaunched_desktop_app_reuses_its_device_until_revoked() {
    let h = host().await;
    let first = app_token(&h).await;
    let _second = app_token(&h).await;
    let (_, list) = call(&h.app, "GET", "/api/devices", Some(&first), None).await;
    let desktops: Vec<&Value> = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["kind"] == "desktop_app")
        .collect();
    assert_eq!(desktops.len(), 1, "one row per desktop install: {list}");
    let id = desktops[0]["id"].as_str().unwrap().to_owned();

    let (status, _) = call(&h.app, "POST", &format!("/api/devices/{id}/revoke"), Some(&first), None).await;
    assert_eq!(status, StatusCode::OK);
    // The revoked row stays revoked: the next launch gets a new device.
    let third = app_token(&h).await;
    let (_, list) = call(&h.app, "GET", "/api/devices", Some(&third), None).await;
    let rows = list["data"].as_array().unwrap();
    let live: Vec<&Value> = rows
        .iter()
        .filter(|d| d["kind"] == "desktop_app" && d["revoked_at"].is_null())
        .collect();
    assert_eq!(live.len(), 1);
    assert_ne!(live[0]["id"], id.as_str());
    assert!(
        rows.iter()
            .any(|d| d["id"] == id.as_str() && !d["revoked_at"].is_null())
    );
}

#[tokio::test]
async fn owner_routes_need_a_session() {
    let h = host().await;
    let (status, _) = call(&h.app, "POST", "/api/devices/pairings", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn phone_pairs_after_owner_approval_and_is_revocable() {
    let h = host().await;
    let owner = app_token(&h).await;

    let (_, created) = call(&h.app, "POST", "/api/devices/pairings", Some(&owner), None).await;
    let secret = created["data"]["secret"].as_str().unwrap().to_owned();
    let pairing_id = created["data"]["pairing"]["id"].as_str().unwrap().to_owned();
    assert!(
        created["data"]["qr_uri"]
            .as_str()
            .unwrap()
            .starts_with("aionx://pair?v=1&secret=")
    );
    assert_eq!(created["data"]["pairing"]["state"], "open");

    let pair = json!({"secret": secret, "device_name": "Pixel 9", "device_kind": "mobile"});
    let (status, presented) = call(&h.app, "POST", "/api/devices/pair", None, Some(pair.clone())).await;
    assert_eq!(status, StatusCode::OK, "{presented}");
    let claim = json!({
        "pairing_id": presented["data"]["pairing_id"],
        "claim_token": presented["data"]["claim_token"],
    });

    // Replaying the QR secret fails; the claim waits for the owner.
    let (status, body) = call(&h.app, "POST", "/api/devices/pair", None, Some(pair)).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("PAIRING_USED"))
    );
    let (_, pending) = call(&h.app, "POST", "/api/devices/pair/claim", None, Some(claim.clone())).await;
    assert_eq!(pending["data"]["state"], "requested");
    assert!(pending["data"]["session"].is_null());

    let (_, seen) = call(
        &h.app,
        "GET",
        &format!("/api/devices/pairings/{pairing_id}"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(seen["data"]["device_name"], "Pixel 9");
    let (status, _) = call(
        &h.app,
        "POST",
        &format!("/api/devices/pairings/{pairing_id}/approve"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, claimed) = call(&h.app, "POST", "/api/devices/pair/claim", None, Some(claim.clone())).await;
    assert_eq!(claimed["data"]["state"], "claimed");
    let phone = claimed["data"]["session"]["access_token"].as_str().unwrap().to_owned();
    let phone_id = claimed["data"]["session"]["device_id"].as_str().unwrap().to_owned();
    let (status, body) = call(&h.app, "POST", "/api/devices/pair/claim", None, Some(claim)).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("PAIRING_USED"))
    );

    // The phone works, sees itself as current, and stops working once revoked.
    let (status, list) = call(&h.app, "GET", "/api/devices", Some(&phone), None).await;
    assert_eq!(status, StatusCode::OK);
    let me = list["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == phone_id.as_str())
        .unwrap();
    assert_eq!(me["current"], true);
    assert_eq!(me["kind"], "mobile");

    let (status, _) = call(
        &h.app,
        "POST",
        &format!("/api/devices/{phone_id}/revoke"),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = call(&h.app, "GET", "/api/devices", Some(&phone), None).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("DEVICE_REVOKED"))
    );
    // The owner's desktop app is unaffected.
    assert_eq!(
        call(&h.app, "GET", "/api/devices", Some(&owner), None).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn rejected_device_gets_nothing() {
    let h = host().await;
    let owner = app_token(&h).await;
    let (_, created) = call(&h.app, "POST", "/api/devices/pairings", Some(&owner), None).await;
    let code = created["data"]["code"].as_str().unwrap().to_lowercase();
    let pairing_id = created["data"]["pairing"]["id"].as_str().unwrap().to_owned();
    let (_, presented) = call(
        &h.app,
        "POST",
        "/api/devices/pair",
        None,
        Some(json!({"secret": code, "device_name": "Laptop browser", "device_kind": "browser"})),
    )
    .await;
    call(
        &h.app,
        "POST",
        &format!("/api/devices/pairings/{pairing_id}/reject"),
        Some(&owner),
        None,
    )
    .await;
    let (status, body) = call(
        &h.app,
        "POST",
        "/api/devices/pair/claim",
        None,
        Some(json!({"pairing_id": presented["data"]["pairing_id"], "claim_token": presented["data"]["claim_token"]})),
    )
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::GONE, json!("PAIRING_REJECTED"))
    );
}

#[tokio::test]
async fn invalid_device_names_are_rejected() {
    let h = host().await;
    let owner = app_token(&h).await;
    let (_, created) = call(&h.app, "POST", "/api/devices/pairings", Some(&owner), None).await;
    let (status, body) = call(
        &h.app,
        "POST",
        "/api/devices/pair",
        None,
        Some(json!({"secret": created["data"]["secret"], "device_name": "  ", "device_kind": "mobile"})),
    )
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::BAD_REQUEST, json!("INVALID_REQUEST"))
    );
}

#[tokio::test]
async fn the_host_proves_it_knows_the_bootstrap_secret() {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    let h = host().await;
    let nonce = "00112233445566778899aabbccddeeff";
    let (status, body) = call(
        &h.app,
        "POST",
        "/api/devices/host-proof",
        None,
        Some(json!({"nonce": nonce})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // What the desktop app computes from the file it read.
    let key: [u8; 32] = Sha256::digest(h.bootstrap.trim().as_bytes()).into();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(format!("aionx-host-proof:{nonce}").as_bytes());
    assert_eq!(body["data"]["proof"], json!(hex::encode(mac.finalize().into_bytes())));

    let (status, _) = call(
        &h.app,
        "POST",
        "/api/devices/host-proof",
        None,
        Some(json!({"nonce": "short"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_paired_device_cannot_claim_the_desktop_app_kind() {
    let h = host().await;
    let owner = app_token(&h).await;
    let (_, created) = call(&h.app, "POST", "/api/devices/pairings", Some(&owner), None).await;
    let (status, body) = call(
        &h.app,
        "POST",
        "/api/devices/pair",
        None,
        Some(json!({"secret": created["data"]["secret"], "device_name": "Test Mac", "device_kind": "desktop_app"})),
    )
    .await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::BAD_REQUEST, json!("INVALID_REQUEST"))
    );
}

#[tokio::test]
async fn browser_gets_cookies_not_tokens_and_can_sign_itself_out() {
    let h = host().await;
    let owner = app_token(&h).await;
    let (_, created) = call(&h.app, "POST", "/api/devices/pairings", Some(&owner), None).await;
    let pairing_id = created["data"]["pairing"]["id"].as_str().unwrap().to_owned();
    let (_, presented) = call(
        &h.app,
        "POST",
        "/api/devices/pair",
        None,
        Some(json!({"secret": created["data"]["code"], "device_name": "Firefox", "device_kind": "browser"})),
    )
    .await;
    call(
        &h.app,
        "POST",
        &format!("/api/devices/pairings/{pairing_id}/approve"),
        Some(&owner),
        None,
    )
    .await;

    let req = Request::post("/api/devices/pair/claim")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"pairing_id": presented["data"]["pairing_id"], "claim_token": presented["data"]["claim_token"]})
                .to_string(),
        ))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    let cookies: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["data"]["session"]["access_token"], "");
    assert_eq!(body["data"]["session"]["refresh_token"], "");
    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("aionui-session="))
        .expect("session cookie");
    assert!(session_cookie.contains("HttpOnly"));
    assert!(cookies.iter().any(|c| c.starts_with("aionui-refresh=")));

    // The browser (by its cookie token) cannot pair others but may sign itself out.
    let token = session_cookie
        .trim_start_matches("aionui-session=")
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let device_id = body["data"]["session"]["device_id"].as_str().unwrap().to_owned();
    let (status, _) = call(&h.app, "POST", "/api/devices/pairings", Some(&token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &h.app,
        "POST",
        &format!("/api/devices/{device_id}/revoke"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&h.app, "GET", "/api/devices", Some(&token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A paired phone's request authenticated by the middleware stays a phone's
/// request even if its token is revoked before the handler runs; it never
/// becomes the manager session.
#[tokio::test]
async fn a_token_revoked_after_auth_does_not_make_a_phone_the_manager() {
    let h = host().await;
    let owner = app_token(&h).await;
    let phone = paired_phone(&h, &owner).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/devices/pairings")
        .header(header::AUTHORIZATION, format!("Bearer {phone}"))
        .header(REVOKE_AFTER_AUTH, "1")
        .body(Body::empty())
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body: Value = serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap())
        .unwrap_or(Value::Null);
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::FORBIDDEN, json!("DEVICE_OWNER_ONLY"))
    );
}
