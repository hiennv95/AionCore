// `ApiError` is the intended error type at this HTTP boundary (routes map the
// crate-owned `DeviceError` to it here).
#![allow(clippy::disallowed_types)]

//! `/api/devices/*` (ADR-011). Three routers: `device_bootstrap_routes` (the
//! desktop app's bootstrap), `device_public_routes` (the new device's side of
//! pairing; the caller adds rate limiting), both without a session yet, and
//! `device_owner_routes` (owner only; the caller adds auth and CSRF).

use std::sync::Arc;

use aionui_api_types::{
    ApiResponse, AppSessionRequest, ClaimRequest, ClaimResponse, CreatePairingResponse, DeviceListenerStatus,
    DeviceSession, DeviceView, HostProofRequest, HostProofResponse, PairRequest, PairResponse, PairingView,
    UpdateDeviceListenerRequest,
};
use aionui_auth::{CookieConfig, CurrentDevice, CurrentUser, RuntimeHelperCaller};
use aionui_common::ApiError;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{AppendHeaders, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};

use crate::error::DeviceError;
use crate::listener::DeviceListener;
use crate::service::{Caller, DeviceService};

#[derive(Clone)]
pub struct DeviceRouterState {
    pub service: Arc<DeviceService>,
    /// Started by the server command once the full router (with static web) exists.
    pub listener: Option<Arc<DeviceListener>>,
    /// Cookie settings for browser sessions; `None` disables browser pairing.
    pub cookies: Option<Arc<CookieConfig>>,
}

/// The desktop app's bootstrap. Proven by the 256-bit bootstrap secret, so
/// failures are not rate limited: counting them would only let another local
/// caller lock the desktop app out of its own host.
pub fn device_bootstrap_routes(state: DeviceRouterState) -> Router {
    Router::new()
        .route("/api/devices/app-session", post(app_session))
        .route("/api/devices/host-proof", post(host_proof))
        .with_state(state)
}

/// The new device's side of pairing (the caller adds rate limiting).
pub fn device_public_routes(state: DeviceRouterState) -> Router {
    Router::new()
        .route("/api/devices/pair", post(pair))
        .route("/api/devices/pair/claim", post(claim))
        .with_state(state)
}

pub fn device_owner_routes(state: DeviceRouterState) -> Router {
    Router::new()
        .route("/api/devices", get(list))
        .route("/api/devices/listener", get(listener_status).put(update_listener))
        .route("/api/devices/{id}/revoke", post(revoke))
        .route("/api/devices/pairings", post(create_pairing))
        .route("/api/devices/pairings/{id}", get(pairing))
        .route("/api/devices/pairings/{id}/approve", post(approve))
        .route("/api/devices/pairings/{id}/reject", post(reject))
        .with_state(state)
}

fn to_api_error(error: DeviceError) -> ApiError {
    if matches!(error, DeviceError::Db(_) | DeviceError::Internal(_)) {
        tracing::error!(%error, "device: API failed");
    }
    let status = StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    ApiError::coded(status, error.code(), error.public_message(), None)
}

type ApiResult<T> = Result<Json<ApiResponse<T>>, ApiError>;

fn ok<T>(value: T) -> ApiResult<T> {
    Ok(Json(ApiResponse::ok(value)))
}

async fn app_session(
    State(state): State<DeviceRouterState>,
    Json(req): Json<AppSessionRequest>,
) -> ApiResult<DeviceSession> {
    ok(state.service.app_session(req).await.map_err(to_api_error)?)
}

async fn host_proof(
    State(state): State<DeviceRouterState>,
    Json(req): Json<HostProofRequest>,
) -> ApiResult<HostProofResponse> {
    ok(state.service.host_proof(req).map_err(to_api_error)?)
}

async fn pair(State(state): State<DeviceRouterState>, Json(req): Json<PairRequest>) -> ApiResult<PairResponse> {
    ok(state.service.pair(req).await.map_err(to_api_error)?)
}

async fn claim(State(state): State<DeviceRouterState>, Json(req): Json<ClaimRequest>) -> Result<Response, ApiError> {
    let (response, cookie_session) = state.service.claim(req).await.map_err(to_api_error)?;
    let body = Json(ApiResponse::<ClaimResponse>::ok(response));
    match (cookie_session, state.cookies.as_ref()) {
        (Some(session), Some(cookies)) => Ok((
            AppendHeaders([
                (header::SET_COOKIE, cookies.build_session_cookie(&session.access_token)),
                (header::SET_COOKIE, cookies.build_refresh_cookie(&session.refresh_token)),
            ]),
            body,
        )
            .into_response()),
        (Some(_), None) => Err(to_api_error(DeviceError::Internal(
            "browser sessions are unavailable".into(),
        ))),
        (None, _) => Ok(body.into_response()),
    }
}

/// Who makes this request, as auth_middleware established it: an agent's
/// helper CLI, else the session's device if it is device-bound. The token is
/// never re-verified here, so a disagreement cannot fail open to the manager.
fn caller(device: Option<Extension<CurrentDevice>>, helper: Option<Extension<RuntimeHelperCaller>>) -> Caller {
    if helper.is_some() {
        return Caller::RuntimeHelper;
    }
    device.map_or(Caller::Session, |Extension(device)| Caller::Device(device.id))
}

async fn list(
    State(state): State<DeviceRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
) -> ApiResult<Vec<DeviceView>> {
    let caller = caller(device, helper);
    ok(state.service.list(&user.id, &caller).await.map_err(to_api_error)?)
}

async fn revoke(
    State(state): State<DeviceRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    Path(id): Path<String>,
) -> ApiResult<()> {
    let caller = caller(device, helper);
    ok(state
        .service
        .revoke(&user.id, &caller, &id)
        .await
        .map_err(to_api_error)?)
}

async fn create_pairing(
    State(state): State<DeviceRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
) -> ApiResult<CreatePairingResponse> {
    let caller = caller(device, helper);
    ok(state
        .service
        .create_pairing(&user.id, &caller)
        .await
        .map_err(to_api_error)?)
}

async fn pairing(
    State(state): State<DeviceRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    Path(id): Path<String>,
) -> ApiResult<PairingView> {
    let caller = caller(device, helper);
    ok(state
        .service
        .pairing(&user.id, &caller, &id)
        .await
        .map_err(to_api_error)?)
}

async fn approve(
    State(state): State<DeviceRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    Path(id): Path<String>,
) -> ApiResult<PairingView> {
    let caller = caller(device, helper);
    ok(state
        .service
        .approve(&user.id, &caller, &id)
        .await
        .map_err(to_api_error)?)
}

async fn reject(
    State(state): State<DeviceRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    Path(id): Path<String>,
) -> ApiResult<PairingView> {
    let caller = caller(device, helper);
    ok(state
        .service
        .reject(&user.id, &caller, &id)
        .await
        .map_err(to_api_error)?)
}

async fn listener_status(
    State(state): State<DeviceRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
) -> ApiResult<DeviceListenerStatus> {
    let caller = caller(device, helper);
    ok(state
        .service
        .listener_status(&user.id, &caller)
        .await
        .map_err(to_api_error)?)
}

async fn update_listener(
    State(state): State<DeviceRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    device: Option<Extension<CurrentDevice>>,
    Json(req): Json<UpdateDeviceListenerRequest>,
) -> ApiResult<DeviceListenerStatus> {
    let caller = caller(device, helper);
    ok(state
        .service
        .update_listener(&user.id, &caller, req)
        .await
        .map_err(to_api_error)?)
}
