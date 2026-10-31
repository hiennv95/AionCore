#![allow(clippy::disallowed_types)]

use std::sync::Arc;
use std::time::Duration;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Json, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Router};
use serde::{Deserialize, Serialize};

use aionui_api_types::{
    ApiResponse, AuthStatusResponse, CallerCapabilitiesResponse, ChangePasswordRequest, EnsureExternalSessionRequest,
    EnsureExternalSessionResponse, EnsureExternalUserRequest, EnsureExternalUserResponse, LoginRequest, LoginResponse,
    PublicUser, QrLoginRequest, RefreshResponse, RefreshTokenRequest, RevokeExternalSessionRequest,
    RevokeExternalSessionResponse, UserInfoResponse, WebuiChangePasswordRequest, WebuiChangeUsernameRequest,
    WebuiChangeUsernameResponse, WebuiGenerateQrTokenResponse, WebuiResetPasswordResponse, WsTokenResponse,
};
use aionui_common::ApiError;
use aionui_common::constants::REFRESH_COOKIE_NAME;
use aionui_db::{DbError, IDeviceRepository, IUserRepository, UserStatus, UserType, models::User};

use crate::error::AuthError;
use crate::extract::{extract_client_ip, extract_cookie_value, extract_token_from_headers};
use crate::jwt::TokenType;
use crate::middleware::{
    AuthIdentityMode, AuthState, CurrentDevice, CurrentUser, DevicelessSession, RuntimeHelperCaller, auth_middleware,
};
use crate::password::{dummy_password_hash, generate_password, hash_password, verify_password_timed};
use crate::qr_token::QrTokenStore;
use crate::rate_limit::{
    RateLimiter, RefreshLimiter, api_rate_limit_middleware, auth_rate_limit_middleware,
    authenticated_action_rate_limit_middleware, status_rate_limit_middleware,
};
use crate::rotation::RotateError;
use crate::service::{AuthProvisionService, ProvisionError};
use crate::singleflight::{RefreshCoalescer, RefreshError, RefreshedTokens};
use crate::validation::{validate_password, validate_username};
use crate::{CookieConfig, JwtService};

const BOOTSTRAP_SECRET_HEADER: &str = "x-aioncore-bootstrap-secret";

pub type SessionRevokedHook = dyn Fn(&str) + Send + Sync;

impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidCredentials => ApiError::Unauthorized("Invalid username or password".into()),
            AuthError::WeakPassword(msg) => ApiError::BadRequest(msg),
            AuthError::InvalidUsername(msg) => ApiError::BadRequest(msg),
            AuthError::TokenExpired => ApiError::Unauthorized("Token expired".into()),
            AuthError::TokenInvalid(msg) => ApiError::Unauthorized(msg),
            AuthError::TokenBlacklisted => ApiError::Unauthorized("Token has been revoked".into()),
            AuthError::RateLimited => ApiError::RateLimited,
            AuthError::HashError(msg) => ApiError::Internal(format!("Password hash error: {msg}")),
        }
    }
}

impl From<RefreshError> for ApiError {
    fn from(err: RefreshError) -> Self {
        match err {
            RefreshError::Unauthorized(msg) => ApiError::Unauthorized(msg.into()),
            RefreshError::DeviceRevoked => ApiError::coded(
                axum::http::StatusCode::UNAUTHORIZED,
                "DEVICE_REVOKED",
                "This device is no longer allowed on this host.",
                None,
            ),
            RefreshError::UserContextRequired => user_context_required(),
            RefreshError::Replayed => ApiError::coded(
                axum::http::StatusCode::UNAUTHORIZED,
                "REFRESH_TOKEN_REUSED",
                "This session was signed out because an old sign-in token was used again.",
                None,
            ),
            RefreshError::DesktopRequiresLoopbackTls => crate::middleware::desktop_requires_loopback_tls(),
            RefreshError::Internal(msg) => ApiError::Internal(msg.into()),
        }
    }
}

fn db_error_to_api_error(err: DbError) -> ApiError {
    match err {
        DbError::NotFound(msg) => ApiError::NotFound(msg),
        DbError::Conflict(msg) => ApiError::Conflict(msg),
        DbError::Query(e) => ApiError::Internal(format!("Database error: {e}")),
        DbError::Migration(e) => ApiError::Internal(format!("Migration error: {e}")),
        DbError::Init(msg) => ApiError::Internal(format!("Database init error: {msg}")),
    }
}

/// Shared state for all auth route handlers.
#[derive(Clone)]
pub struct AuthRouterState {
    pub jwt_service: Arc<JwtService>,
    /// Coalesces concurrent refreshes for the same token (refresh-storm guard).
    pub refresh_coalescer: RefreshCoalescer,
    pub user_repo: Arc<dyn IUserRepository>,
    /// Optional on-disk adoption side-effect (AionUi → AionPro upgrade).
    pub fs_adopter: Option<Arc<dyn crate::service::SystemDefaultFilesystemAdopter>>,
    pub cookie_config: Arc<CookieConfig>,
    pub qr_token_store: Arc<QrTokenStore>,
    pub identity_mode: AuthIdentityMode,
    pub bootstrap_secret: Option<Arc<str>>,
    pub session_revoked_hook: Option<Arc<SessionRevokedHook>>,
    pub local: bool,
    pub aionpro_mode: bool,
    /// Client devices (ADR-011); refresh of a device-bound token requires a live device.
    pub device_repo: Option<Arc<dyn IDeviceRepository>>,
    /// `--loopback-tls` is running: a desktop app refreshes only over that listener.
    pub desktop_requires_loopback_tls: bool,
}

#[derive(Debug, Deserialize)]
struct CreateInternalUserRequest {
    username: String,
    password_hash: String,
}

#[derive(Debug, Deserialize)]
struct SetSystemUserCredentialsRequest {
    username: String,
    password_hash: String,
}

#[derive(Debug, Deserialize)]
struct UpdatePasswordHashRequest {
    password_hash: String,
}

#[derive(Debug, Deserialize)]
struct UpdateUsernameRequest {
    username: String,
}

#[derive(Debug, Deserialize)]
struct UpdateJwtSecretRequest {
    jwt_secret: String,
}

#[derive(Debug, Serialize)]
struct InternalUserResponse {
    id: String,
    user_type: UserType,
    external_user_id: Option<String>,
    username: Option<String>,
    email: Option<String>,
    avatar_path: Option<String>,
    status: UserStatus,
    session_generation: i64,
    created_at: i64,
    updated_at: i64,
    last_login: Option<i64>,
}

impl From<User> for InternalUserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            user_type: user.user_type,
            external_user_id: user.external_user_id,
            username: user.username,
            email: user.email,
            avatar_path: user.avatar_path,
            status: user.status,
            session_generation: user.session_generation,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login: user.last_login,
        }
    }
}

fn ensure_local_mode(local: bool) -> Result<(), ApiError> {
    if local {
        return Ok(());
    }
    Err(ApiError::Forbidden(
        "This endpoint is only available in local mode".into(),
    ))
}

fn require_bootstrap_secret(headers: &HeaderMap, expected: Option<&str>) -> Result<(), ApiError> {
    let Some(expected) = expected else {
        return Err(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "BOOTSTRAP_SECRET_REQUIRED",
            "Bootstrap secret required.",
            None,
        ));
    };
    let Some(actual) = headers.get(BOOTSTRAP_SECRET_HEADER).and_then(|v| v.to_str().ok()) else {
        return Err(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "BOOTSTRAP_SECRET_REQUIRED",
            "Bootstrap secret required.",
            None,
        ));
    };
    if constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "INVALID_BOOTSTRAP_SECRET",
            "Invalid bootstrap secret.",
            None,
        ))
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for idx in 0..max_len {
        let l = left.get(idx).copied().unwrap_or(0);
        let r = right.get(idx).copied().unwrap_or(0);
        diff |= usize::from(l ^ r);
    }
    diff == 0
}

fn provision_error_to_api_error(err: ProvisionError) -> ApiError {
    match err {
        ProvisionError::UnsupportedUserType => ApiError::BadRequest("Unsupported external user type".into()),
        ProvisionError::UserDisabled => ApiError::coded(StatusCode::FORBIDDEN, "USER_DISABLED", "User disabled.", None),
        ProvisionError::UserNotProvisioned => ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "USER_CONTEXT_REQUIRED",
            "User context required.",
            None,
        ),
        ProvisionError::Db(DbError::Conflict(_)) => ApiError::coded(
            StatusCode::CONFLICT,
            "EXTERNAL_USER_CONFLICT",
            "External user conflict.",
            None,
        ),
        ProvisionError::Db(e) => db_error_to_api_error(e),
        ProvisionError::Token(e) => ApiError::Internal(format!("Token signing error: {e}")),
    }
}

fn user_context_required() -> ApiError {
    ApiError::coded(
        StatusCode::UNAUTHORIZED,
        "USER_CONTEXT_REQUIRED",
        "User context required.",
        None,
    )
}

/// Build the auth router with all endpoints and middleware layers.
///
/// Returns a `Router` with these endpoints:
/// - `POST /login`
/// - `POST /logout`
/// - `GET /api/auth/status`
/// - `GET /api/auth/user`
/// - `POST /api/auth/change-password`
/// - `POST /api/auth/refresh`
/// - `GET /api/ws-token`
/// - `POST /api/auth/qr-login`
/// - `GET /qr-login`
/// - `POST /api/webui/change-password` (local-only)
/// - `POST /api/webui/change-username` (local-only)
/// - `POST /api/webui/reset-password` (local-only)
/// - `POST /api/webui/generate-qr-token` (local-only)
pub fn auth_routes(state: AuthRouterState) -> Router {
    let auth_limiter = Arc::new(RateLimiter::auth());
    let api_limiter = Arc::new(RateLimiter::api());
    let action_limiter = Arc::new(RateLimiter::authenticated_action());
    let refresh_limiter = Arc::new(RefreshLimiter::new());

    // Start periodic cleanup for rate limiters
    let cleanup_interval = Duration::from_secs(60);
    auth_limiter.start_cleanup_task(cleanup_interval);
    api_limiter.start_cleanup_task(cleanup_interval);
    action_limiter.start_cleanup_task(cleanup_interval);
    refresh_limiter.start_cleanup_task(cleanup_interval);

    let auth_state = AuthState {
        jwt_service: state.jwt_service.clone(),
        user_repo: state.user_repo.clone(),
        identity_mode: if state.aionpro_mode {
            AuthIdentityMode::AionPro
        } else {
            AuthIdentityMode::UserSession
        },
        // Auth endpoints manage sessions themselves; the helper CLI never
        // calls them, so the runtime-token channel stays disabled here.
        runtime_token_verifier: None,
        device_repo: state.device_repo.clone(),
        desktop_requires_loopback_tls: state.desktop_requires_loopback_tls,
    };

    // Auth rate limited routes (login, qr-login)
    let auth_rate_limited = Router::new()
        .route("/login", post(login_handler))
        .route("/api/auth/qr-login", post(qr_login_handler))
        .route_layer(from_fn_with_state(auth_limiter, auth_rate_limit_middleware))
        .with_state(state.clone());

    // The public liveness probe: limited per IP, except from this machine (C7).
    let status_public = Router::new()
        .route("/api/auth/status", get(status_handler))
        .route_layer(from_fn_with_state(api_limiter.clone(), status_rate_limit_middleware))
        .with_state(state.clone());

    // API rate limited public routes (no auth required)
    let api_public = Router::new()
        .route(
            "/api/auth/internal/external-users/{external_user_id}",
            put(ensure_external_user_handler),
        )
        .route(
            "/api/auth/internal/external-sessions",
            post(create_external_session_handler),
        )
        .route(
            "/api/auth/internal/external-sessions/revoke",
            post(revoke_external_session_handler),
        )
        .route(
            "/api/auth/internal/users",
            get(list_internal_users_handler).post(create_internal_user_handler),
        )
        .route("/api/auth/internal/users/system", get(get_system_user_handler))
        .route(
            "/api/auth/internal/users/system/credentials",
            post(set_system_user_credentials_handler),
        )
        .route(
            "/api/auth/internal/users/by-username/{username}",
            get(find_user_by_username_handler),
        )
        .route("/api/auth/internal/users/{id}", get(find_user_by_id_handler))
        .route(
            "/api/auth/internal/users/{id}/password",
            post(update_user_password_hash_handler),
        )
        .route(
            "/api/auth/internal/users/{id}/username",
            post(update_user_username_handler),
        )
        .route(
            "/api/auth/internal/users/{id}/jwt-secret",
            post(update_user_jwt_secret_handler),
        )
        .route(
            "/api/auth/internal/users/{id}/last-login",
            post(update_user_last_login_handler),
        )
        // WebUI admin credential endpoints — local-only, enforced inside each handler.
        .route("/api/webui/change-password", post(webui_change_password_handler))
        .route("/api/webui/change-username", post(webui_change_username_handler))
        .route("/api/webui/reset-password", post(webui_reset_password_handler))
        .route("/api/webui/generate-qr-token", post(webui_generate_qr_token_handler))
        .route_layer(from_fn_with_state(api_limiter.clone(), api_rate_limit_middleware))
        .with_state(state.clone());

    // Authenticated routes: auth -> action limiter keyed by the user. No per-IP limiter
    // in front of auth: every loopback caller shares one IP key, so another local
    // process could fill it and cut the owner's ws-token and user reads (C7 residual,
    // Jev 048's "stop sharing the key" principle). Unauthenticated requests stop at auth.
    // route_layer order: last added = outermost (first to process)
    let authenticated = Router::new()
        .route("/logout", post(logout_handler))
        .route("/api/auth/user", get(user_handler))
        .route("/api/auth/capabilities", get(capabilities_handler))
        .route("/api/auth/change-password", post(change_password_handler))
        .route("/api/ws-token", get(ws_token_handler))
        .route_layer(from_fn_with_state(
            action_limiter.clone(),
            authenticated_action_rate_limit_middleware,
        ))
        .route_layer(from_fn_with_state(auth_state, auth_middleware))
        .with_state(state.clone());

    // Refresh (token in cookie or body, no auth middleware): limited inside the
    // handler by the presented token's grant, not by IP (C7, Jev 048).
    let refresh_limited = Router::new()
        .route("/api/auth/refresh", post(refresh_handler))
        .route_layer(axum::middleware::from_fn(attach_client_ip))
        .layer(Extension(refresh_limiter))
        .with_state(state);

    // Static page (no middleware)
    let static_routes = Router::new().route("/qr-login", get(qr_login_page));

    Router::new()
        .merge(auth_rate_limited)
        .merge(status_public)
        .merge(api_public)
        .merge(authenticated)
        .merge(refresh_limited)
        .merge(static_routes)
}

// ---------------------------------------------------------------------------
// PUT /api/auth/internal/external-users/{external_user_id}
// ---------------------------------------------------------------------------

async fn ensure_external_user_handler(
    State(state): State<AuthRouterState>,
    headers: HeaderMap,
    Path(external_user_id): Path<String>,
    body: Result<Json<EnsureExternalUserRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<EnsureExternalUserResponse>>, ApiError> {
    require_bootstrap_secret(&headers, state.bootstrap_secret.as_deref().map(AsRef::as_ref))?;
    let Json(req) = body.map_err(ApiError::from)?;
    let mut service = AuthProvisionService::new(state.user_repo);
    if let Some(fs_adopter) = state.fs_adopter {
        service = service.with_filesystem_adopter(fs_adopter);
    }
    let response = service
        .ensure_external_user(&external_user_id, req)
        .await
        .map_err(provision_error_to_api_error)?;
    tracing::info!(
        user_id = %response.user_id,
        user_type = ?response.user_type,
        "external user provision succeeded"
    );
    Ok(Json(ApiResponse::ok(response)))
}

// ---------------------------------------------------------------------------
// POST /api/auth/internal/external-sessions
// ---------------------------------------------------------------------------

async fn create_external_session_handler(
    State(state): State<AuthRouterState>,
    headers: HeaderMap,
    body: Result<Json<EnsureExternalSessionRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    require_bootstrap_secret(&headers, state.bootstrap_secret.as_deref().map(AsRef::as_ref))?;
    let Json(req) = body.map_err(ApiError::from)?;
    let service = AuthProvisionService::new(state.user_repo.clone());
    let user = service
        .find_external_session_user(req)
        .await
        .map_err(provision_error_to_api_error)?;
    let (token, refresh_token) = issue_device_session_pair(&state, &user, "External account").await?;
    let username = user.username.clone().unwrap_or_else(|| "external_user".to_string());
    tracing::info!(user_id = %user.id, "external core session exchange succeeded");
    let session_cookie = state.cookie_config.build_session_cookie(&token);
    let refresh_cookie = state.cookie_config.build_refresh_cookie(&refresh_token);
    let response = EnsureExternalSessionResponse {
        user: PublicUser { id: user.id, username },
        session_generation: user.session_generation,
    };
    Ok((
        AppendHeaders([
            (header::SET_COOKIE, session_cookie),
            (header::SET_COOKIE, refresh_cookie),
        ]),
        Json(ApiResponse::ok(response)),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// POST /api/auth/internal/external-sessions/revoke
// ---------------------------------------------------------------------------

async fn revoke_external_session_handler(
    State(state): State<AuthRouterState>,
    headers: HeaderMap,
    body: Result<Json<RevokeExternalSessionRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<RevokeExternalSessionResponse>>, ApiError> {
    require_bootstrap_secret(&headers, state.bootstrap_secret.as_deref().map(AsRef::as_ref))?;
    let Json(req) = body.map_err(ApiError::from)?;
    let service = AuthProvisionService::new(state.user_repo);
    let response = service
        .revoke_external_session(req)
        .await
        .map_err(provision_error_to_api_error)?;
    tracing::info!(
        user_id = %response.user_id,
        session_generation = response.session_generation,
        "external core session revoked"
    );
    if let Some(hook) = &state.session_revoked_hook {
        hook(&response.user_id);
    }
    Ok(Json(ApiResponse::ok(response)))
}

// ---------------------------------------------------------------------------
// POST /login
// ---------------------------------------------------------------------------

async fn login_handler(
    State(state): State<AuthRouterState>,
    headers: HeaderMap,
    body: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    if state.aionpro_mode {
        return Err(user_context_required());
    }

    let Json(req) = body.map_err(ApiError::from)?;

    // Input length validation (per API spec)
    if req.username.len() > 32 {
        return Err(ApiError::BadRequest("Username must not exceed 32 characters".into()));
    }
    if req.password.len() > 128 {
        return Err(ApiError::BadRequest("Password must not exceed 128 characters".into()));
    }

    // Look up user; run dummy verify on miss to prevent timing attacks
    let user = state
        .user_repo
        .find_by_username(&req.username)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    let (found_user, password_valid) = match user {
        Some(u) if u.password_hash.as_deref().unwrap_or_default().trim().is_empty() => {
            // Seeded user with no password yet (first-run local mode).
            // Treat as invalid credentials; run dummy verify for timing symmetry
            // and to avoid bcrypt error on empty hash leaking as a 500.
            let _ = verify_password_timed(&req.password, dummy_password_hash()).await;
            (None, false)
        }
        Some(u) => {
            let Some(password_hash) = u.password_hash.as_deref() else {
                let _ = verify_password_timed(&req.password, dummy_password_hash()).await;
                return Err(ApiError::Unauthorized("Invalid username or password".into()));
            };
            let valid = verify_password_timed(&req.password, password_hash).await?;
            (Some(u), valid)
        }
        None => {
            // Prevent user enumeration via timing
            let _ = verify_password_timed(&req.password, dummy_password_hash()).await;
            (None, false)
        }
    };

    if !password_valid {
        return Err(ApiError::Unauthorized("Invalid username or password".into()));
    }

    let user = found_user.ok_or_else(|| ApiError::Unauthorized("Invalid username or password".into()))?;

    issue_session(&state, user, &headers, "password").await
}

/// Device-list label for a login: the user-agent family plus the login method.
/// Display only: the user agent never grants or decides anything.
fn login_device_name(headers: &HeaderMap, method: &str) -> String {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let family = [
        ("Edg/", "Edge"),
        ("Firefox/", "Firefox"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
    ]
    .into_iter()
    .find(|(marker, _)| ua.contains(marker))
    .map_or("Browser", |(_, family)| family);
    format!("{family} ({method})")
}

/// Sign access + refresh tokens for `user` and return the login response with
/// both cookies.
/// Policy B (Jev 057): outside local mode the session is bound to a new
/// `browser` device, so it is listed, revocable alone, and restricted like a
/// paired browser.
async fn issue_session(
    state: &AuthRouterState,
    user: User,
    headers: &HeaderMap,
    method: &str,
) -> Result<Response, ApiError> {
    let (token, refresh_token) = issue_device_session_pair(state, &user, &login_device_name(headers, method)).await?;

    let session_cookie = state.cookie_config.build_session_cookie(&token);
    let refresh_cookie = state.cookie_config.build_refresh_cookie(&refresh_token);
    let resp = LoginResponse::new(
        PublicUser {
            id: user.id,
            username: user.username.unwrap_or_else(|| "external_user".to_string()),
        },
        token,
    );

    Ok((
        AppendHeaders([
            (header::SET_COOKIE, session_cookie),
            (header::SET_COOKIE, refresh_cookie),
        ]),
        Json(resp),
    )
        .into_response())
}

/// Policy B (Jev 057): outside local mode, register a `browser` device named
/// `device_name` and sign an access + refresh pair bound to it.
async fn issue_device_session_pair(
    state: &AuthRouterState,
    user: &User,
    device_name: &str,
) -> Result<(String, String), ApiError> {
    let device_id = match state.device_repo.as_ref() {
        Some(repo) if !state.local => Some(
            repo.insert(&user.id, device_name, aionui_api_types::DeviceKind::Browser.as_str())
                .await
                .map_err(|e| ApiError::Internal(format!("Device registration error: {e}")))?
                .id,
        ),
        _ => None,
    };
    let (token, refresh_token) = state
        .jwt_service
        .issue_session_pair(
            &user.id,
            user.username.as_deref().unwrap_or("external_user"),
            user.session_generation,
            device_id.as_deref(),
        )
        .await
        .map_err(|e| ApiError::Internal(format!("Token signing error: {e}")))?;

    // Update last login (best-effort)
    if let Err(e) = state.user_repo.update_last_login(&user.id).await {
        tracing::warn!("Failed to update last login for {}: {e}", user.id);
    }
    Ok((token, refresh_token))
}

// ---------------------------------------------------------------------------
// POST /logout
// ---------------------------------------------------------------------------

async fn logout_handler(State(state): State<AuthRouterState>, headers: HeaderMap) -> Result<Response, ApiError> {
    if let Some(token) = extract_token_from_headers(&headers) {
        state.jwt_service.blacklist_token(&token);
    }

    // Clear both credential cookies. The refresh cookie is path-scoped to the
    // refresh endpoint, so the browser does not send it here to be blacklisted;
    // clearing it drops it client-side, and full server-side revocation is via
    // the user's session generation (password change / session revoke).
    let session_cookie = state.cookie_config.clear_session_cookie();
    let refresh_cookie = state.cookie_config.clear_refresh_cookie();
    let resp = ApiResponse::message("Logged out successfully");

    Ok((
        AppendHeaders([
            (header::SET_COOKIE, session_cookie),
            (header::SET_COOKIE, refresh_cookie),
        ]),
        Json(resp),
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// GET /api/auth/status
// ---------------------------------------------------------------------------

async fn status_handler(
    State(state): State<AuthRouterState>,
    headers: HeaderMap,
) -> Result<Json<AuthStatusResponse>, ApiError> {
    let has_users = state
        .user_repo
        .has_users()
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    let user_count = state
        .user_repo
        .count_users()
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    // Check authentication without requiring it. Only an access token counts as
    // "authenticated" — a refresh token is not a request credential.
    let is_authenticated = extract_token_from_headers(&headers)
        .and_then(|token| state.jwt_service.verify_access(&token).ok())
        .is_some();

    Ok(Json(AuthStatusResponse {
        success: true,
        needs_setup: !has_users,
        user_count: user_count as u64,
        is_authenticated,
    }))
}

// GET /api/auth/capabilities
async fn capabilities_handler(
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
) -> Json<CallerCapabilitiesResponse> {
    let manager = helper.is_none() && (device.as_ref().is_none_or(|d| d.kind == "desktop_app") && deviceless.is_none());
    Json(CallerCapabilitiesResponse {
        manager,
        cron: if manager { "manage" } else { "pause" }.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Local-only internal user routes
// ---------------------------------------------------------------------------

async fn list_internal_users_handler(
    State(state): State<AuthRouterState>,
) -> Result<Json<ApiResponse<Vec<InternalUserResponse>>>, ApiError> {
    ensure_local_mode(state.local)?;
    let users = state.user_repo.list_users().await.map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(
        users.into_iter().map(InternalUserResponse::from).collect(),
    )))
}

async fn get_system_user_handler(
    State(state): State<AuthRouterState>,
) -> Result<Json<ApiResponse<Option<InternalUserResponse>>>, ApiError> {
    ensure_local_mode(state.local)?;
    let user = state.user_repo.get_system_user().await.map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(user.map(InternalUserResponse::from))))
}

async fn find_user_by_username_handler(
    State(state): State<AuthRouterState>,
    Path(username): Path<String>,
) -> Result<Json<ApiResponse<Option<InternalUserResponse>>>, ApiError> {
    ensure_local_mode(state.local)?;
    let user = state
        .user_repo
        .find_by_username(&username)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(user.map(InternalUserResponse::from))))
}

async fn find_user_by_id_handler(
    State(state): State<AuthRouterState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Option<InternalUserResponse>>>, ApiError> {
    ensure_local_mode(state.local)?;
    let user = state.user_repo.find_by_id(&id).await.map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(user.map(InternalUserResponse::from))))
}

async fn create_internal_user_handler(
    State(state): State<AuthRouterState>,
    body: Result<Json<CreateInternalUserRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<InternalUserResponse>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;
    let user = state
        .user_repo
        .create_user(&req.username, &req.password_hash)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(InternalUserResponse::from(user))))
}

async fn set_system_user_credentials_handler(
    State(state): State<AuthRouterState>,
    body: Result<Json<SetSystemUserCredentialsRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;
    state
        .user_repo
        .set_system_user_credentials(&req.username, &req.password_hash)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(())))
}

async fn update_user_password_hash_handler(
    State(state): State<AuthRouterState>,
    Path(id): Path<String>,
    body: Result<Json<UpdatePasswordHashRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;
    state
        .user_repo
        .update_password(&id, &req.password_hash)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(())))
}

async fn update_user_username_handler(
    State(state): State<AuthRouterState>,
    Path(id): Path<String>,
    body: Result<Json<UpdateUsernameRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;
    state
        .user_repo
        .update_username(&id, &req.username)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(())))
}

async fn update_user_jwt_secret_handler(
    State(state): State<AuthRouterState>,
    Path(id): Path<String>,
    body: Result<Json<UpdateJwtSecretRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;
    state
        .user_repo
        .update_jwt_secret(&id, &req.jwt_secret)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(())))
}

async fn update_user_last_login_handler(
    State(state): State<AuthRouterState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    state
        .user_repo
        .update_last_login(&id)
        .await
        .map_err(db_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(())))
}

// ---------------------------------------------------------------------------
// GET /api/auth/user
// ---------------------------------------------------------------------------

async fn user_handler(Extension(user): Extension<CurrentUser>) -> Json<UserInfoResponse> {
    Json(UserInfoResponse {
        success: true,
        user: PublicUser {
            id: user.id,
            username: user.username,
        },
    })
}

// ---------------------------------------------------------------------------
// POST /api/auth/change-password
// ---------------------------------------------------------------------------

async fn change_password_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    body: Result<Json<ChangePasswordRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;

    // Validate new password strength
    validate_password(&req.new_password)?;

    // Fetch user record
    let user = state
        .user_repo
        .find_by_id(&current_user.id)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| ApiError::NotFound("User not found".into()))?;

    // Verify current password
    // A passwordless owner (empty seeded hash) answers like a wrong password (audit H16).
    let Some(password_hash) = user.password_hash.as_deref().filter(|hash| !hash.trim().is_empty()) else {
        return Err(ApiError::Unauthorized("Current password is incorrect".into()));
    };
    let valid = verify_password_timed(&req.current_password, password_hash).await?;
    if !valid {
        return Err(ApiError::Unauthorized("Current password is incorrect".into()));
    }

    // Hash new password on blocking thread
    let password = req.new_password.clone();
    let new_hash = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| ApiError::Internal(format!("Task join error: {e}")))??;

    // Persist new password hash
    state
        .user_repo
        .update_password(&current_user.id, &new_hash)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;
    // Revoke old access and refresh tokens (audit H15).
    state
        .user_repo
        .increment_session_generation(&current_user.id)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    // Rotate JWT secret to invalidate all sessions
    let new_secret = state
        .jwt_service
        .rotate_secret()
        .map_err(|e| ApiError::Internal(format!("Secret rotation error: {e}")))?;

    // Persist new secret to database
    state
        .user_repo
        .update_jwt_secret(&current_user.id, &new_secret)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    Ok(Json(ApiResponse::message("Password changed successfully")))
}

// ---------------------------------------------------------------------------
// POST /api/auth/refresh
// ---------------------------------------------------------------------------

/// The rate-limit client IP, resolved from the socket before the handler runs.
#[derive(Clone)]
struct ClientIp(String);

async fn attach_client_ip(mut request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let ip = ClientIp(extract_client_ip(&request));
    request.extensions_mut().insert(ip);
    next.run(request).await
}

async fn refresh_handler(
    State(state): State<AuthRouterState>,
    Extension(limiter): Extension<Arc<RefreshLimiter>>,
    Extension(ClientIp(client_ip)): Extension<ClientIp>,
    via: Option<Extension<aionui_api_types::ViaLoopbackTls>>,
    headers: HeaderMap,
    body: Result<Json<RefreshTokenRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let via_loopback_tls = via.is_some();
    // Prefer the HttpOnly refresh cookie; fall back to the request body for
    // legacy clients that posted the token explicitly.
    let (raw_token, from_cookie) = match extract_cookie_value(&headers, REFRESH_COOKIE_NAME) {
        Some(cookie_token) => (cookie_token, true),
        None => {
            let Json(req) = body.map_err(ApiError::from)?;
            (req.token, false)
        }
    };

    // Count the request against the token's own grant when it verifies, so
    // other callers on the same IP cannot exhaust the owner's refreshes; only
    // unverifiable tokens share the per-IP bucket. `refresh_tokens` repeats
    // the (stateless) verification and does the real checks.
    match verify_refresh_credential(&state, &raw_token, from_cookie) {
        Ok(payload) => limiter.check_verified(&payload.user_id, payload.grant_id.as_deref()),
        Err(_) => limiter.check_invalid(&client_ip),
    }
    .map_err(ApiError::from)?;

    // Coalesce concurrent refreshes carrying the same token: one expired access
    // token can fail many in-flight requests at once, and without this each
    // would independently hit the database and re-sign, stampeding the hottest
    // auth path. Same token -> one execution, shared result.
    let tokens = state
        .refresh_coalescer
        .run(&coalesce_key(&raw_token, from_cookie, via_loopback_tls), || {
            refresh_tokens(&state, &raw_token, from_cookie, via_loopback_tls)
        })
        .await?;

    let session_cookie = state.cookie_config.build_session_cookie(&tokens.access);
    let refresh_cookie = state.cookie_config.build_refresh_cookie(&tokens.refresh);
    Ok((
        AppendHeaders([
            (header::SET_COOKIE, session_cookie),
            (header::SET_COOKIE, refresh_cookie),
        ]),
        Json(RefreshResponse {
            success: true,
            token: tokens.access,
            refresh_token: tokens.refresh,
        }),
    )
        .into_response())
}

/// Refreshes share one execution only when everything that decides their outcome
/// matches: the token, the channel (a cookie must carry a refresh token; the body path
/// may accept an access token) and the transport (desktop credentials need the loopback
/// TLS listener). Otherwise a caller could receive a result it would not get alone.
fn coalesce_key(raw_token: &str, from_cookie: bool, via_loopback_tls: bool) -> String {
    let channel = if from_cookie { "cookie" } else { "body" };
    let transport = if via_loopback_tls { "tls" } else { "plain" };
    format!("{channel}:{transport}:{raw_token}")
}

/// Verify the signature and type of a presented refresh credential.
///
/// The body path stays lenient for legacy clients that post their access
/// token, unless the host opted into strict refresh (--strict-refresh).
fn verify_refresh_credential(
    state: &AuthRouterState,
    raw_token: &str,
    from_cookie: bool,
) -> Result<crate::jwt::TokenPayload, AuthError> {
    if from_cookie || state.jwt_service.strict_refresh() {
        state.jwt_service.verify_refresh(raw_token)
    } else {
        state.jwt_service.verify(raw_token)
    }
}

/// Verify a refresh request and mint a fresh access + refresh token pair.
///
/// A cookie-borne token must be a refresh token (`verify_refresh`); the legacy
/// body path stays lenient (`verify`) because older clients posted their access
/// session token here. Runs behind [`RefreshCoalescer`] so an expiry storm
/// collapses into a single execution — hence the crate-owned [`RefreshError`]:
/// it is `Clone`, so one execution's outcome (success *or* failure) can be
/// shared by every coalesced caller, and the route layer maps it to `ApiError`.
async fn refresh_tokens(
    state: &AuthRouterState,
    raw_token: &str,
    from_cookie: bool,
    via_loopback_tls: bool,
) -> Result<RefreshedTokens, RefreshError> {
    let payload = verify_refresh_credential(state, raw_token, from_cookie)
        .map_err(|_| RefreshError::Unauthorized("Invalid or expired token"))?;

    let user = state
        .user_repo
        .find_active_by_id(&payload.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "refresh token user lookup failed");
            RefreshError::Internal("Authentication service unavailable")
        })?
        .ok_or(RefreshError::Unauthorized("Invalid authentication subject"))?;

    if state.aionpro_mode && user.user_type != UserType::Aionpro {
        return Err(RefreshError::UserContextRequired);
    }

    if payload.session_generation != user.session_generation {
        return Err(RefreshError::Unauthorized("Invalid authentication session"));
    }

    if let Some(device_id) = payload.device_id.as_deref() {
        let device = crate::middleware::active_device(state.device_repo.as_ref(), device_id, &user.id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "refresh device lookup failed");
                RefreshError::Internal("Authentication service unavailable")
            })?
            .ok_or(RefreshError::DeviceRevoked)?;
        // Before the device is touched or the grant rotated, so a refused attempt burns
        // nothing and the desktop can retry the same token over TLS.
        if !crate::middleware::desktop_transport_allowed(
            state.desktop_requires_loopback_tls,
            &device.kind,
            via_loopback_tls,
        ) {
            tracing::info!(device_id, "desktop refresh refused outside the loopback TLS listener");
            return Err(RefreshError::DesktopRequiresLoopbackTls);
        }
        if let Some(repo) = state.device_repo.as_ref()
            && let Err(e) = repo.touch(device_id, aionui_common::now_ms()).await
        {
            tracing::warn!(error = %e, "failed to record device last-seen on refresh");
        }
    }

    // The renewed pair stays bound to the same device (or to none).
    let username = user.username.as_deref().unwrap_or("external_user");
    let rotated = match (payload.token_type, &payload.jti, &payload.grant_id) {
        // Grant-bound refresh token (ADR-022): rotate, or answer inside the grace.
        (TokenType::Refresh, Some(_), Some(_)) => state
            .jwt_service
            .rotate_refresh(&payload, username, user.session_generation)
            .await
            .map_err(|e| match e {
                RotateError::Replayed => RefreshError::Replayed,
                RotateError::Invalid => RefreshError::Unauthorized("Invalid authentication session"),
                RotateError::Internal(e) => {
                    tracing::error!(error = %e, "refresh grant rotation failed");
                    RefreshError::Internal("Authentication service unavailable")
                }
            }),
        // Half a grant binding is malformed: never treat it as a legacy token.
        (TokenType::Refresh, Some(_), None) | (TokenType::Refresh, None, Some(_)) => {
            Err(RefreshError::Unauthorized("Invalid or expired token"))
        }
        // A refresh token from before rotation, or an access token on the lenient
        // body path: keeps its original checks above and starts a new, independent
        // grant. The presented token itself is not tracked and stays usable until it expires.
        _ => state
            .jwt_service
            .issue_session_pair(
                &user.id,
                username,
                user.session_generation,
                payload.device_id.as_deref(),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "refresh token signing failed");
                RefreshError::Internal("Token signing error")
            }),
    };
    let (access, refresh) = rotated?;

    Ok(RefreshedTokens { access, refresh })
}

// ---------------------------------------------------------------------------
// GET /api/ws-token
// ---------------------------------------------------------------------------

async fn ws_token_handler(
    State(state): State<AuthRouterState>,
    Extension(current_user): Extension<CurrentUser>,
    headers: HeaderMap,
) -> Result<Json<WsTokenResponse>, ApiError> {
    // Reuse the existing session token for WebSocket connections
    let token = extract_token_from_headers(&headers).ok_or_else(|| ApiError::Unauthorized("No token found".into()))?;

    // Ensure user still exists
    state
        .user_repo
        .find_by_id(&current_user.id)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| ApiError::Unauthorized("User not found".into()))?;

    // Access-token lifetime in milliseconds: the ws token is the access token, so
    // a host that shortens it (--access-token-ttl-secs) must not advertise 30 days.
    let expires_in = u64::try_from(state.jwt_service.access_ttl().as_millis()).unwrap_or(u64::MAX);

    Ok(Json(WsTokenResponse {
        success: true,
        ws_token: token,
        expires_in,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/auth/qr-login
// ---------------------------------------------------------------------------

async fn qr_login_handler(
    State(state): State<AuthRouterState>,
    headers: HeaderMap,
    body: Result<Json<QrLoginRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    if state.aionpro_mode {
        return Err(user_context_required());
    }

    let Json(req) = body.map_err(ApiError::from)?;

    // Validate and consume QR token (one-time use)
    state.qr_token_store.validate_and_consume(&req.qr_token)?;

    // Get primary WebUI user for QR login
    let user = state
        .user_repo
        .get_primary_webui_user()
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| ApiError::Internal("No primary user configured".into()))?;

    issue_session(&state, user, &headers, "QR").await
}

// ---------------------------------------------------------------------------
// GET /qr-login (static HTML page)
// ---------------------------------------------------------------------------

async fn qr_login_page() -> Html<&'static str> {
    Html(QR_LOGIN_HTML)
}

const QR_LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QR Login - AionUI</title>
<style>
  body { font-family: system-ui, sans-serif; display: flex; justify-content: center;
         align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
  .card { background: white; padding: 2rem; border-radius: 8px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; max-width: 400px; }
  .status { margin-top: 1rem; color: #666; }
  .error { color: #d32f2f; }
  .success { color: #388e3c; }
</style>
</head>
<body>
<div class="card">
  <h1>AionUI</h1>
  <p id="status" class="status">Processing login...</p>
</div>
<script>
(function() {
  var el = document.getElementById('status');
  var params = new URLSearchParams(window.location.search);
  var token = params.get('token');
  if (!token) {
    el.textContent = 'Error: No token provided';
    el.className = 'status error';
    return;
  }
  fetch('/api/auth/qr-login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ qrToken: token })
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data.success) {
      el.textContent = 'Login successful! Redirecting...';
      el.className = 'status success';
      setTimeout(function() { window.location.href = '/'; }, 1000);
    } else {
      el.textContent = 'Login failed: ' + (data.error || 'Unknown error');
      el.className = 'status error';
    }
  })
  .catch(function(err) {
    el.textContent = 'Error: ' + err.message;
    el.className = 'status error';
  });
})();
</script>
</body>
</html>"#;

// ---------------------------------------------------------------------------
// WebUI admin credential endpoints (local-only)
// ---------------------------------------------------------------------------

/// Random password length for `/api/webui/reset-password`.
const RESET_PASSWORD_LEN: usize = 16;

/// Resolve the WebUI admin user, falling back to NotFound when absent.
async fn resolve_webui_admin(user_repo: &dyn IUserRepository) -> Result<User, ApiError> {
    user_repo
        .get_primary_webui_user()
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?
        .ok_or_else(|| ApiError::NotFound("No WebUI admin user configured".into()))
}

// ---------------------------------------------------------------------------
// POST /api/webui/change-password
// ---------------------------------------------------------------------------

async fn webui_change_password_handler(
    State(state): State<AuthRouterState>,
    body: Result<Json<WebuiChangePasswordRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;

    validate_password(&req.new_password)?;

    let user = resolve_webui_admin(&*state.user_repo).await?;

    let password = req.new_password;
    let new_hash = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| ApiError::Internal(format!("Task join error: {e}")))??;

    state
        .user_repo
        .update_password(&user.id, &new_hash)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;
    // Revoke old access and refresh tokens (audit H15).
    state
        .user_repo
        .increment_session_generation(&user.id)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    Ok(Json(ApiResponse::message("Password changed successfully")))
}

// ---------------------------------------------------------------------------
// POST /api/webui/change-username
// ---------------------------------------------------------------------------

async fn webui_change_username_handler(
    State(state): State<AuthRouterState>,
    body: Result<Json<WebuiChangeUsernameRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<WebuiChangeUsernameResponse>>, ApiError> {
    ensure_local_mode(state.local)?;
    let Json(req) = body.map_err(ApiError::from)?;

    let trimmed = req.new_username.trim().to_owned();
    validate_username(&trimmed)?;

    let user = resolve_webui_admin(&*state.user_repo).await?;

    if user.username.as_deref() != Some(trimmed.as_str()) {
        state
            .user_repo
            .update_username(&user.id, &trimmed)
            .await
            .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;
    }

    Ok(Json(ApiResponse::ok(WebuiChangeUsernameResponse { username: trimmed })))
}

// ---------------------------------------------------------------------------
// POST /api/webui/reset-password
// ---------------------------------------------------------------------------

async fn webui_reset_password_handler(
    State(state): State<AuthRouterState>,
) -> Result<Json<ApiResponse<WebuiResetPasswordResponse>>, ApiError> {
    ensure_local_mode(state.local)?;

    let user = resolve_webui_admin(&*state.user_repo).await?;

    let new_password = generate_password(RESET_PASSWORD_LEN);
    let password_for_hash = new_password.clone();
    let new_hash = tokio::task::spawn_blocking(move || hash_password(&password_for_hash))
        .await
        .map_err(|e| ApiError::Internal(format!("Task join error: {e}")))??;

    state
        .user_repo
        .update_password(&user.id, &new_hash)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;
    // Revoke old access and refresh tokens (audit H15).
    state
        .user_repo
        .increment_session_generation(&user.id)
        .await
        .map_err(|e| ApiError::Internal(format!("Database error: {e}")))?;

    Ok(Json(ApiResponse::ok(WebuiResetPasswordResponse { new_password })))
}

// ---------------------------------------------------------------------------
// POST /api/webui/generate-qr-token
// ---------------------------------------------------------------------------

async fn webui_generate_qr_token_handler(
    State(state): State<AuthRouterState>,
) -> Result<Json<ApiResponse<WebuiGenerateQrTokenResponse>>, ApiError> {
    ensure_local_mode(state.local)?;

    let (token, expires_at_ms) = state.qr_token_store.generate_with_expiry();

    Ok(Json(ApiResponse::ok(WebuiGenerateQrTokenResponse {
        token,
        expires_at_ms,
    })))
}

#[cfg(test)]
mod error_mapping_tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn invalid_credentials_maps_to_unauthorized() {
        let api_err = ApiError::from(AuthError::InvalidCredentials);
        assert_eq!(api_err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn weak_password_maps_to_bad_request() {
        let api_err = ApiError::from(AuthError::WeakPassword("too short".into()));
        assert_eq!(api_err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn invalid_username_maps_to_bad_request() {
        let api_err = ApiError::from(AuthError::InvalidUsername("bad chars".into()));
        assert_eq!(api_err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn token_expired_maps_to_unauthorized() {
        let api_err = ApiError::from(AuthError::TokenExpired);
        assert_eq!(api_err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn token_invalid_maps_to_unauthorized() {
        let api_err = ApiError::from(AuthError::TokenInvalid("bad".into()));
        assert_eq!(api_err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn token_blacklisted_maps_to_unauthorized() {
        let api_err = ApiError::from(AuthError::TokenBlacklisted);
        assert_eq!(api_err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn rate_limited_maps_to_rate_limited() {
        let api_err = ApiError::from(AuthError::RateLimited);
        assert_eq!(api_err.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn hash_error_maps_to_internal() {
        let api_err = ApiError::from(AuthError::HashError("failed".into()));
        assert_eq!(api_err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn refreshes_coalesce_only_with_the_same_channel_and_transport() {
        let keys = [
            coalesce_key("t", true, true),
            coalesce_key("t", true, false),
            coalesce_key("t", false, true),
            coalesce_key("t", false, false),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b, "each channel and transport gets its own execution");
            }
        }
        assert_eq!(coalesce_key("t", true, true), coalesce_key("t", true, true));
        assert_ne!(coalesce_key("t", false, false), coalesce_key("u", false, false));
    }
}
