//! C7 (Jev 048): auth rate limits must not let one loopback caller lock out
//! another. Every loopback socket shares the IP key `127.0.0.1`, so the status
//! probe is exempt from loopback and refresh is keyed by the presented token.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

use aionui_auth::{
    AuthIdentityMode, AuthRouterState, CookieConfig, JwtService, QrTokenStore, RefreshCoalescer, auth_routes,
    hash_password,
};
use aionui_db::{IUserRepository, SqliteUserRepository, init_database_memory};

struct Host {
    app: Router,
    _db: aionui_db::Database,
}

async fn host() -> Host {
    let db = init_database_memory().await.unwrap();
    let user_repo = Arc::new(SqliteUserRepository::new(db.pool().clone())) as Arc<dyn IUserRepository>;
    let hash = hash_password("StrongP@ss1").unwrap();
    user_repo.set_system_user_credentials("admin", &hash).await.unwrap();
    let state = AuthRouterState {
        jwt_service: Arc::new(JwtService::new("test_secret_for_c7".into())),
        refresh_coalescer: RefreshCoalescer::new(),
        user_repo,
        fs_adopter: None,
        cookie_config: Arc::new(CookieConfig {
            secure: false,
            same_site: "Lax",
        }),
        qr_token_store: Arc::new(QrTokenStore::new()),
        identity_mode: AuthIdentityMode::UserSession,
        bootstrap_secret: None,
        session_revoked_hook: None,
        local: false,
        aionpro_mode: false,
        device_repo: Some(Arc::new(aionui_db::SqliteDeviceRepository::new(db.pool().clone()))),
    };
    Host {
        app: auth_routes(state),
        _db: db,
    }
}

fn from_peer(mut request: Request<Body>, peer: &str) -> Request<Body> {
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    request
}

fn status(peer: &str) -> Request<Body> {
    from_peer(Request::get("/api/auth/status").body(Body::empty()).unwrap(), peer)
}

fn refresh_body(token: &str, peer: &str) -> Request<Body> {
    let request = Request::post("/api/auth/refresh")
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"token":"{token}"}}"#)))
        .unwrap();
    from_peer(request, peer)
}

fn refresh_cookie(refresh_token: &str, peer: &str) -> Request<Body> {
    let request = Request::post("/api/auth/refresh")
        .header(header::COOKIE, format!("aionui-refresh={refresh_token}"))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    from_peer(request, peer)
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// Logs in and returns (access token, refresh token).
async fn login(app: &Router, peer: &str) -> (String, String) {
    let request = Request::post("/login")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"username":"admin","password":"StrongP@ss1"}"#))
        .unwrap();
    let response = app.clone().oneshot(from_peer(request, peer)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let refresh = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            c.strip_prefix("aionui-refresh=")
                .map(|rest| rest.split(';').next().unwrap().to_owned())
        })
        .expect("login sets the refresh cookie");
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (json["token"].as_str().unwrap().to_owned(), refresh)
}

#[tokio::test]
async fn a_local_flood_of_status_probes_does_not_mark_the_host_down() {
    let host = host().await;
    for _ in 0..70 {
        assert_eq!(send(&host.app, status("127.0.0.1:50000")).await.0, StatusCode::OK);
    }
    assert_eq!(send(&host.app, status("127.0.0.1:50001")).await.0, StatusCode::OK);
    assert_eq!(send(&host.app, status("[::1]:50002")).await.0, StatusCode::OK);
}

#[tokio::test]
async fn remote_status_probes_stay_limited() {
    let host = host().await;
    for _ in 0..60 {
        assert_eq!(send(&host.app, status("192.168.1.50:40000")).await.0, StatusCode::OK);
    }
    let (code, json) = send(&host.app, status("192.168.1.50:40001")).await;
    assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["code"], "RATE_LIMITED");
    // Another remote address has its own bucket; loopback stays exempt.
    assert_eq!(send(&host.app, status("192.168.1.51:40000")).await.0, StatusCode::OK);
    assert_eq!(send(&host.app, status("127.0.0.1:50000")).await.0, StatusCode::OK);
}

#[tokio::test]
async fn junk_refreshes_from_another_local_caller_do_not_block_the_owner() {
    let host = host().await;
    let (_, refresh) = login(&host.app, "127.0.0.1:50001").await;

    // The attacker: 20 invalid tokens are refused, then its IP bucket is full.
    for _ in 0..20 {
        let (code, json) = send(&host.app, refresh_body("fake.jwt.token", "127.0.0.1:50000")).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert_eq!(json["code"], "UNAUTHORIZED");
    }
    let (code, json) = send(&host.app, refresh_body("fake.jwt.token", "127.0.0.1:50000")).await;
    assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["code"], "RATE_LIMITED");

    // The owner, on the same loopback IP, still refreshes with its own grant.
    let (code, json) = send(&host.app, refresh_cookie(&refresh, "127.0.0.1:50001")).await;
    assert_eq!(code, StatusCode::OK, "{json}");
    assert_eq!(json["success"], true);
}

#[tokio::test]
async fn forged_forwarding_headers_do_not_reset_the_invalid_refresh_bucket() {
    let host = host().await;
    for _ in 0..20 {
        send(&host.app, refresh_body("fake.jwt.token", "127.0.0.1:50000")).await;
    }
    let mut request = refresh_body("fake.jwt.token", "127.0.0.1:50000");
    request
        .headers_mut()
        .insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
    let (code, json) = send(&host.app, request).await;
    assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["code"], "RATE_LIMITED");
}

#[tokio::test]
async fn verified_refreshes_are_limited_per_session() {
    let host = host().await;
    // Legacy body path: an access token without a grant is keyed by its user.
    let (access, _) = login(&host.app, "127.0.0.1:50001").await;
    for _ in 0..20 {
        let (code, json) = send(&host.app, refresh_body(&access, "127.0.0.1:50001")).await;
        assert_eq!(code, StatusCode::OK, "{json}");
    }
    let (code, json) = send(&host.app, refresh_body(&access, "127.0.0.1:50001")).await;
    assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["code"], "RATE_LIMITED");
    // That session's limit does not touch the per-IP bucket for invalid tokens.
    let (code, json) = send(&host.app, refresh_body("fake.jwt.token", "127.0.0.1:50001")).await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    assert_eq!(json["code"], "UNAUTHORIZED");
}
