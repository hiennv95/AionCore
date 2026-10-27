#![allow(clippy::disallowed_types)]

//! Remote agent management API routes.
//!
//! Endpoints:
//!
//! - `GET  /api/remote-agents`                    — list remote agents
//! - `POST /api/remote-agents`                    — create new remote agent
//! - `GET  /api/remote-agents/{id}`                 — get remote agent details
//! - `PUT  /api/remote-agents/{id}`                 — update remote agent
//! - `DELETE /api/remote-agents/{id}`                 — delete remote agent
//! - `POST /api/remote-agents/test-connection`          — test connection to remote agent (without saving it)
//! - `POST /api/remote-agents/{id}/handshake`          — perform handshake with the remote agent to verify connectivity and retrieve agent info

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Json, Path, State};
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::routing::{MethodRouter, get, post};

use aionui_api_types::{
    ApiResponse, CreateRemoteAgentRequest, HandshakeResponse, RemoteAgentListItem, RemoteAgentResponse,
    TestRemoteAgentConnectionRequest, UpdateRemoteAgentRequest,
};
use aionui_auth::{CurrentUser, desktop_only};
use aionui_common::ApiError;

use super::error_mapping::agent_error_to_api_error;
use super::state::RemoteAgentRouterState;

/// Build the remote agent router.
///
/// All routes require authentication (applied by the caller).
pub fn remote_agent_routes(state: RemoteAgentRouterState) -> Router {
    Router::new()
        .route("/api/remote-agents", get(list).merge(desktop(post(create))))
        .route("/api/remote-agents/test-connection", desktop(post(test_connection)))
        .route(
            "/api/remote-agents/{id}",
            get(get_one).merge(desktop(axum::routing::put(update).delete(delete_one))),
        )
        .route("/api/remote-agents/{id}/handshake", desktop(post(handshake)))
        .with_state(state)
}

/// Changing a remote agent, or making the host connect to a URL to test or handshake with
/// it, stays with the desktop app; phones, browsers and the agent helper only list them.
fn desktop<S: Clone + Send + Sync + 'static>(route: MethodRouter<S>) -> MethodRouter<S> {
    route.route_layer(from_fn(desktop_only))
}

async fn list(
    State(state): State<RemoteAgentRouterState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Vec<RemoteAgentListItem>>>, ApiError> {
    let items = state.service.list(&user.id).await.map_err(agent_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(items)))
}

async fn get_one(
    State(state): State<RemoteAgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<RemoteAgentResponse>>, ApiError> {
    let agent = state
        .service
        .get(&user.id, &id)
        .await
        .map_err(agent_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(agent)))
}

async fn create(
    State(state): State<RemoteAgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    body: Result<Json<CreateRemoteAgentRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<ApiResponse<RemoteAgentResponse>>), ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    let agent = state
        .service
        .create(&user.id, req)
        .await
        .map_err(agent_error_to_api_error)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(agent))))
}

async fn update(
    State(state): State<RemoteAgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
    body: Result<Json<UpdateRemoteAgentRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<RemoteAgentResponse>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    let agent = state
        .service
        .update(&user.id, &id, req)
        .await
        .map_err(agent_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(agent)))
}

async fn delete_one(
    State(state): State<RemoteAgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    state
        .service
        .delete(&user.id, &id)
        .await
        .map_err(agent_error_to_api_error)?;
    Ok(Json(ApiResponse::success()))
}

async fn test_connection(
    State(state): State<RemoteAgentRouterState>,
    Extension(_user): Extension<CurrentUser>,
    body: Result<Json<TestRemoteAgentConnectionRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    state
        .service
        .test_connection(req)
        .await
        .map_err(agent_error_to_api_error)?;
    Ok(Json(ApiResponse::success()))
}

async fn handshake(
    State(state): State<RemoteAgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<HandshakeResponse>>, ApiError> {
    let resp = state
        .service
        .handshake(&user.id, &id)
        .await
        .map_err(agent_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(resp)))
}
