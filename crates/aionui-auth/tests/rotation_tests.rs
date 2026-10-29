//! Refresh-token rotation (ADR-022): per-session grants, a bounded grace that returns
//! the same successor, replay revoking only that grant, restart safety, and bounded
//! compatibility for refresh tokens issued before rotation.

use std::sync::Arc;
use std::time::Duration;

use aionui_auth::{
    AuthIdentityMode, AuthRouterState, CookieConfig, JwtService, QrTokenStore, RefreshCoalescer, auth_routes,
};
use aionui_db::{
    IRefreshGrantRepository, IUserRepository, SqliteRefreshGrantRepository, SqliteUserRepository, init_database_memory,
};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "rotation_test_secret";

struct Ctx {
    app: Router,
    jwt: Arc<JwtService>,
    grants: Arc<SqliteRefreshGrantRepository>,
    users: Arc<dyn IUserRepository>,
    db: aionui_db::Database,
}

fn app_for(db: &aionui_db::Database, jwt: Arc<JwtService>) -> Router {
    let users = Arc::new(SqliteUserRepository::new(db.pool().clone())) as Arc<dyn IUserRepository>;
    auth_routes(AuthRouterState {
        jwt_service: jwt,
        refresh_coalescer: RefreshCoalescer::new(),
        user_repo: users,
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
        desktop_requires_loopback_tls: false,
    })
}

fn jwt_for(grants: &Arc<SqliteRefreshGrantRepository>) -> Arc<JwtService> {
    let jwt = Arc::new(JwtService::new(SECRET.into()));
    jwt.set_strict_refresh(true);
    jwt.set_grant_repository(grants.clone());
    jwt
}

async fn ctx() -> Ctx {
    let db = init_database_memory().await.unwrap();
    let grants = Arc::new(SqliteRefreshGrantRepository::new(db.pool().clone()));
    let jwt = jwt_for(&grants);
    let users = Arc::new(SqliteUserRepository::new(db.pool().clone())) as Arc<dyn IUserRepository>;
    Ctx {
        app: app_for(&db, jwt.clone()),
        jwt,
        grants,
        users,
        db,
    }
}

impl Ctx {
    async fn owner(&self) -> (String, i64) {
        let u = self.users.get_system_user().await.unwrap().unwrap();
        (u.id, u.session_generation)
    }

    /// A fresh grant-bound session, as login / pairing issue it.
    async fn session(&self) -> (String, String) {
        let (id, generation) = self.owner().await;
        self.jwt
            .issue_session_pair(&id, "admin", generation, None)
            .await
            .unwrap()
    }

    async fn refresh(&self, refresh: &str) -> (StatusCode, Value) {
        refresh_on(&self.app, refresh).await
    }
}

async fn refresh_on(app: &Router, refresh: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/refresh")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "token": refresh }).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn pair(body: &Value) -> (String, String) {
    (
        body["token"].as_str().expect("access token").to_owned(),
        body["refresh_token"].as_str().expect("refresh token").to_owned(),
    )
}

#[tokio::test]
async fn issued_refresh_tokens_carry_a_jti_and_a_persisted_grant() {
    let c = ctx().await;
    let (_, refresh) = c.session().await;
    let claims = c.jwt.verify_refresh(&refresh).unwrap();
    let (jti, gid) = (claims.jti.expect("jti"), claims.grant_id.expect("grant id"));
    let row = c.grants.find(&gid).await.unwrap().expect("grant row");
    assert_eq!(row.current_jti, jti);
    assert!(row.revoked_at.is_none());
}

#[tokio::test]
async fn rotation_and_the_grace_window_return_the_same_successor() {
    let c = ctx().await;
    let (_, r0) = c.session().await;

    let (status, body) = c.refresh(&r0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (a1, r1) = pair(&body);
    assert_ne!(r1, r0);

    // A lost response or a second tab presents r0 again inside the grace: same successor.
    let (status, body) = c.refresh(&r0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(pair(&body), (a1.clone(), r1.clone()), "byte-identical successor");

    // The grant did not advance twice; the successor rotates normally.
    let (status, body) = c.refresh(&r1).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, r2) = pair(&body);
    let gid = c.jwt.verify_refresh(&r2).unwrap().grant_id.unwrap();
    let row = c.grants.find(&gid).await.unwrap().unwrap();
    assert_eq!(Some(row.current_jti), c.jwt.verify_refresh(&r2).unwrap().jti);
    assert_eq!(row.previous_jti, c.jwt.verify_refresh(&r1).unwrap().jti);
}

#[tokio::test]
async fn concurrent_refreshes_of_one_token_advance_the_grant_once() {
    let c = ctx().await;
    let (_, r0) = c.session().await;
    let other = app_for(&c.db, c.jwt.clone()); // its own coalescer: only the database orders them
    let ((s1, b1), (s2, b2)) = tokio::join!(c.refresh(&r0), refresh_on(&other, &r0));
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK), "{b1} {b2}");
    assert_eq!(pair(&b1), pair(&b2), "both callers get the one successor");
}

#[tokio::test]
async fn replay_after_the_grace_revokes_only_that_grant() {
    let c = ctx().await;
    c.jwt.set_refresh_grace(Duration::ZERO);
    let (_, r0) = c.session().await;
    let (_, sibling) = c.session().await;

    let (_, body) = c.refresh(&r0).await;
    let (_, r1) = pair(&body);

    let (status, body) = c.refresh(&r0).await;
    assert_eq!(
        (status, body["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("REFRESH_TOKEN_REUSED"))
    );
    // The grant is gone for the holder of the current token too.
    let (status, _) = c.refresh(&r1).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A sibling session of the same user is untouched.
    let (status, body) = c.refresh(&sibling).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_token_older_than_the_previous_one_is_a_replay_even_inside_the_grace() {
    let c = ctx().await;
    let (_, r0) = c.session().await;
    let (_, b1) = c.refresh(&r0).await;
    let (_, r1) = pair(&b1);
    let (status, _) = c.refresh(&r1).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = c.refresh(&r0).await;
    assert_eq!(body["code"], "REFRESH_TOKEN_REUSED", "{status} {body}");
}

#[tokio::test]
async fn a_restart_keeps_grants_and_the_same_successor() {
    let c = ctx().await;
    let (_, r0) = c.session().await;
    let (_, body) = c.refresh(&r0).await;
    let before = pair(&body);

    // A new process: fresh JwtService and router over the same database and secret.
    let restarted = app_for(&c.db, jwt_for(&c.grants));
    let (status, body) = refresh_on(&restarted, &r0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(pair(&body), before, "inside the grace the successor survives a restart");
}

#[tokio::test]
async fn legacy_refresh_tokens_keep_working_and_get_independent_grants() {
    let c = ctx().await;
    let (id, generation) = c.owner().await;
    let legacy = c.jwt.sign_refresh(&id, "admin", generation).unwrap();
    assert!(c.jwt.verify_refresh(&legacy).unwrap().jti.is_none());

    let (status, first) = c.refresh(&legacy).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, second) = c.refresh(&legacy).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let g1 = c.jwt.verify_refresh(&pair(&first).1).unwrap().grant_id.unwrap();
    let g2 = c.jwt.verify_refresh(&pair(&second).1).unwrap().grant_id.unwrap();
    assert_ne!(g1, g2, "no adoption: each legacy refresh starts its own grant");

    // The original checks still apply: a bumped session generation ends it.
    c.users.increment_session_generation(&id).await.unwrap();
    let (status, _) = c.refresh(&legacy).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn half_claims_fail_closed() {
    let c = ctx().await;
    let (id, generation) = c.owner().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for extra in [json!({"jti": "j-only"}), json!({"gid": "g-only"})] {
        let mut claims = json!({
            "user_id": id, "username": "admin", "iat": now, "exp": now + 600,
            "iss": "aionui", "aud": "aionui-webui", "session_generation": generation,
            "token_type": "refresh",
        });
        claims
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let forged = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();
        assert!(
            c.jwt.verify_refresh(&forged).is_ok(),
            "signature and claims are otherwise valid"
        );
        let (status, body) = c.refresh(&forged).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{extra} must not fall back to legacy: {body}"
        );
    }
}

#[tokio::test]
async fn the_database_holds_no_token() {
    let c = ctx().await;
    let (access, r0) = c.session().await;
    let (_, body) = c.refresh(&r0).await;
    let (a1, r1) = pair(&body);
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT json_object('a', id, 'b', user_id, 'c', current_jti, 'd', previous_jti) FROM refresh_grants",
    )
    .fetch_all(c.db.pool())
    .await
    .unwrap();
    for (row,) in rows {
        for token in [&access, &r0, &a1, &r1] {
            assert!(!row.contains(token.as_str()));
            // Not even the signature part.
            assert!(!row.contains(token.rsplit('.').next().unwrap()));
        }
    }
}
