#![allow(clippy::disallowed_types)]

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

use aionui_common::ApiError;
use aionui_db::{IDeviceRepository, IUserRepository, UserStatus, UserType};

use crate::JwtService;
use crate::extract::extract_token_from_headers;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthIdentityMode {
    Local,
    UserSession,
    AionPro,
}

/// Header carrying the conversation-runtime helper token minted by the backend
/// and injected into agent subprocess environments as `AIONUI_RUNTIME_TOKEN`.
pub const RUNTIME_TOKEN_HEADER: &str = "x-aionui-runtime-token";
/// Header carrying the acting user id asserted by the helper CLI.
pub const RUNTIME_USER_ID_HEADER: &str = "x-aionui-user-id";
/// Header carrying the conversation id the helper CLI runs inside.
pub const RUNTIME_CONVERSATION_ID_HEADER: &str = "x-aionui-conversation-id";

/// Port for validating conversation-runtime helper tokens.
///
/// Implemented in the composition layer over the agent runtime's token
/// service; `aionui-auth` must not depend on `aionui-ai-agent` directly.
/// A verifier must confirm the token is a live, conversation-helper-scoped
/// token bound to exactly this (user_id, conversation_id) pair.
pub trait IRuntimeTokenVerifier: Send + Sync {
    fn verify_conversation_helper(&self, token: &str, user_id: &str, conversation_id: &str) -> bool;
}

/// Authenticated user injected into request extensions by the auth middleware.
///
/// Route handlers extract this from `request.extensions()` to identify
/// the current user.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// User ID from the database.
    pub id: String,
    /// Username.
    pub username: String,
    /// Internal identity source for the current user.
    pub user_type: UserType,
    /// Current account status. Authenticated requests only receive active users.
    pub status: UserStatus,
}

impl CurrentUser {
    pub fn local_default() -> Self {
        Self {
            id: "system_default_user".to_string(),
            username: "system_default_user".to_string(),
            user_type: UserType::Local,
            status: UserStatus::Active,
        }
    }
}

/// Marks a request authenticated through the runtime-token channel: an agent's
/// helper CLI, not the owner at a client. Inserted only after the token was
/// verified (request extensions cannot be set by a client); never present on a
/// JWT-authenticated request. Owner-management routes refuse it.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeHelperCaller;

/// Shared state for the authentication middleware.
#[derive(Clone)]
pub struct AuthState {
    pub jwt_service: Arc<JwtService>,
    pub user_repo: Arc<dyn IUserRepository>,
    pub identity_mode: AuthIdentityMode,
    /// Optional second credential channel for agent-subprocess helper CLIs
    /// (`aioncore config` / `diagnose`), which cannot carry a JWT or cookies.
    /// `None` disables the channel (requests without a JWT are rejected).
    pub runtime_token_verifier: Option<Arc<dyn IRuntimeTokenVerifier>>,
    /// Client devices (ADR-011). When set, a token bound to a device is only
    /// accepted while that device exists, belongs to the token's user and is not
    /// revoked. `None` rejects every device-bound token.
    pub device_repo: Option<Arc<dyn IDeviceRepository>>,
}

/// The device a device-bound request comes from (ADR-011). Absent for tokens
/// without a device (legacy login, local mode, runtime tokens).
#[derive(Debug, Clone)]
pub struct CurrentDevice {
    pub id: String,
    /// `desktop_app`, `mobile` or `browser`.
    pub kind: String,
}

/// The live device `device_id` of `user_id`, if any. Fails closed.
async fn active_device(
    repo: Option<&Arc<dyn IDeviceRepository>>,
    device_id: &str,
    user_id: &str,
) -> Result<Option<aionui_db::DeviceRow>, aionui_db::DbError> {
    let Some(repo) = repo else { return Ok(None) };
    Ok(repo
        .find(device_id)
        .await?
        .filter(|device| device.user_id == user_id && device.revoked_at.is_none()))
}

/// Whether `device_id` names a live device of `user_id`. Fails closed.
pub(crate) async fn device_is_active(
    repo: Option<&Arc<dyn IDeviceRepository>>,
    device_id: &str,
    user_id: &str,
) -> Result<bool, aionui_db::DbError> {
    Ok(active_device(repo, device_id, user_id).await?.is_some())
}

/// Authentication middleware that verifies JWT tokens and injects `CurrentUser`.
///
/// Flow:
/// 1. Extract bearer token from `Authorization` header or `aionui-session` cookie
/// 2. Verify JWT signature, expiration, and blacklist
/// 3. Look up user in the database to ensure they still exist
/// 4. Insert [`CurrentUser`] into request extensions
///
/// Returns HTTP 401 for authentication failures.
///
/// Use with `axum::middleware::from_fn_with_state`.
pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // In local mode, skip JWT verification and inject a fixed default user.
    if state.identity_mode == AuthIdentityMode::Local {
        request.extensions_mut().insert(CurrentUser::local_default());
        return Ok(next.run(request).await);
    }

    let Some(token) = extract_token_from_headers(request.headers()) else {
        // No JWT/cookie: fall back to the conversation-helper runtime-token
        // channel used by agent subprocess CLIs.
        return runtime_token_channel(&state, request, next).await;
    };

    // Require an *access* token here: a refresh token must never authenticate an
    // ordinary request — it is accepted only at the refresh endpoint.
    let payload = state.jwt_service.verify_access(&token).map_err(|e| {
        tracing::debug!("Token verification failed: {e}");
        ApiError::Unauthorized("Invalid or expired token".into())
    })?;

    let user = state
        .user_repo
        .find_active_by_id(&payload.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth middleware user lookup failed");
            ApiError::Internal("Authentication service unavailable".into())
        })?
        .ok_or_else(|| ApiError::Unauthorized("Invalid authentication subject".into()))?;

    if state.identity_mode == AuthIdentityMode::AionPro && user.user_type != UserType::Aionpro {
        return Err(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "USER_CONTEXT_REQUIRED",
            "User context required.",
            None,
        ));
    }

    if payload.session_generation != user.session_generation {
        return Err(ApiError::Unauthorized("Invalid authentication session".into()));
    }

    if let Some(device_id) = payload.device_id.as_deref() {
        let device = active_device(state.device_repo.as_ref(), device_id, &user.id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "auth middleware device lookup failed");
                ApiError::Internal("Authentication service unavailable".into())
            })?;
        let Some(device) = device else {
            return Err(ApiError::coded(
                StatusCode::UNAUTHORIZED,
                "DEVICE_REVOKED",
                "This device is no longer allowed on this host.",
                None,
            ));
        };
        request.extensions_mut().insert(CurrentDevice {
            id: device.id,
            kind: device.kind,
        });
    }

    request.extensions_mut().insert(CurrentUser {
        id: user.id,
        username: user.username.unwrap_or_else(|| "external_user".to_string()),
        user_type: user.user_type,
        status: user.status,
    });

    Ok(next.run(request).await)
}

/// Authenticate a JWT-less request via the conversation-helper runtime token.
///
/// The helper CLI sends the token the backend minted for its conversation
/// runtime plus the (user, conversation) pair the token was bound to. The
/// verifier enforces that binding, so a forged user or conversation header
/// fails closed. On success the token's user is loaded and injected as
/// [`CurrentUser`], making ordinary user-scoped handlers work unchanged.
async fn runtime_token_channel(state: &AuthState, mut request: Request, next: Next) -> Result<Response, ApiError> {
    let headers = request.headers();
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let (Some(verifier), Some(token), Some(user_id), Some(conversation_id)) = (
        state.runtime_token_verifier.as_ref(),
        header(RUNTIME_TOKEN_HEADER),
        header(RUNTIME_USER_ID_HEADER),
        header(RUNTIME_CONVERSATION_ID_HEADER),
    ) else {
        return Err(ApiError::Unauthorized("Authentication required".into()));
    };

    if !verifier.verify_conversation_helper(&token, &user_id, &conversation_id) {
        return Err(ApiError::Unauthorized("Invalid runtime token".into()));
    }

    let user = state
        .user_repo
        .find_active_by_id(&user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "runtime token channel user lookup failed");
            ApiError::Internal("Authentication service unavailable".into())
        })?
        .ok_or_else(|| ApiError::Unauthorized("Invalid authentication subject".into()))?;

    if state.identity_mode == AuthIdentityMode::AionPro && user.user_type != UserType::Aionpro {
        return Err(ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "USER_CONTEXT_REQUIRED",
            "User context required.",
            None,
        ));
    }

    request.extensions_mut().insert(CurrentUser {
        id: user.id,
        username: user.username.unwrap_or_else(|| "external_user".to_string()),
        user_type: user.user_type,
        status: user.status,
    });
    request.extensions_mut().insert(RuntimeHelperCaller);

    Ok(next.run(request).await)
}

/// Local-mode authentication middleware that skips JWT verification.
///
/// Injects a fixed `CurrentUser` with id and username `system_default_user`.
/// Used when the server runs as an embedded subprocess inside Electron.
pub async fn local_auth_middleware(mut request: Request, next: Next) -> Response {
    request.extensions_mut().insert(CurrentUser::local_default());
    next.run(request).await
}

/// Whether the request comes from a paired phone or browser (a device other
/// than the desktop app).
fn from_paired_device(extensions: &axum::http::Extensions) -> bool {
    is_paired_device(extensions.get::<CurrentDevice>())
}

/// Whether this session's device is a paired phone or browser. Desktop-app
/// and device-less sessions (and the agent helper) are not.
pub fn is_paired_device(device: Option<&CurrentDevice>) -> bool {
    device.is_some_and(|device| device.kind != aionui_api_types::DeviceKind::DesktopApp.as_str())
}

fn fs_owner_only() -> ApiError {
    ApiError::coded(
        StatusCode::FORBIDDEN,
        "FS_OWNER_ONLY",
        "Only the desktop app can use the host filesystem.",
        None,
    )
}

/// Host file effects (read, write, open, reveal, link, attach roots) are for
/// the desktop app only (ADR-013). Paired phones and browsers, and agents'
/// helper CLIs, are refused; desktop and device-less sessions pass. Route
/// groups add this as a route layer after `auth_middleware`.
pub async fn desktop_only(request: Request, next: Next) -> Result<Response, ApiError> {
    let extensions = request.extensions();
    if extensions.get::<RuntimeHelperCaller>().is_some() || from_paired_device(extensions) {
        return Err(fs_owner_only());
    }
    Ok(next.run(request).await)
}

/// Like [`desktop_only`] but lets agents' helper CLIs through, for host-path
/// routes the helper CLI itself uses (e.g. skill import and scan).
pub async fn no_paired_devices(request: Request, next: Next) -> Result<Response, ApiError> {
    if from_paired_device(request.extensions()) {
        return Err(fs_owner_only());
    }
    Ok(next.run(request).await)
}

/// A `Local` file ref names any path on the host, so only callers with host file
/// authority may send one (ADR-013): the desktop app and device-less sessions. Paired
/// phones and browsers, and agents' helper CLIs, get the same 403 whatever the path, so
/// the refusal never says whether a file exists. Call before the path is looked at.
pub fn ensure_no_local_files<'a>(
    files: impl IntoIterator<Item = &'a aionui_api_types::ChatFileRef>,
    device: Option<&CurrentDevice>,
    helper: Option<&RuntimeHelperCaller>,
) -> Result<(), ApiError> {
    let has_local = files
        .into_iter()
        .any(|file| matches!(file, aionui_api_types::ChatFileRef::Local { .. }));
    if has_local && (helper.is_some() || is_paired_device(device)) {
        return Err(fs_owner_only());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    async fn echo_user(request: Request<Body>) -> String {
        let user = request.extensions().get::<CurrentUser>().unwrap();
        format!("{}:{}", user.id, user.username)
    }

    #[tokio::test]
    async fn test_local_auth_middleware_injects_default_user() {
        let app = Router::new()
            .route("/test", get(echo_user))
            .route_layer(axum::middleware::from_fn(local_auth_middleware));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "system_default_user:system_default_user"
        );
    }
}
