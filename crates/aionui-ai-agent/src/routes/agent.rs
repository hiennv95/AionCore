#![allow(clippy::disallowed_types)]

//! Agent-related API routes.
//!
//! Endpoints:
//!
//! - `GET  /api/agents/management` — list diagnostics-first agent rows
//! - `POST /api/agents/custom/try-connect` — test custom agent configuration (e.g. ACP connection)

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Json, Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{Next, from_fn};
use axum::response::Response;
use axum::routing::{MethodRouter, get, patch, post, put};

use aionui_api_types::{
    AgentEnvEntry, AgentLogoEntry, AgentManagementRow, AgentMetadata, AgentOverridesResponse, ApiResponse,
    CustomAgentUpsertRequest, DeleteCustomAgentResponse, ProviderHealthCheckRequest, ProviderHealthCheckResponse,
    SetAgentOverridesRequest, SetEnabledRequest, TryConnectCustomAgentRequest, TryConnectCustomAgentResponse,
};
use aionui_auth::{CurrentDevice, CurrentUser, RuntimeHelperCaller, is_paired_device};
use aionui_common::ApiError;

use crate::routes::error_mapping::agent_error_to_api_error;
use crate::routes::state::AgentRouterState;

pub fn agent_routes(state: AgentRouterState) -> Router {
    Router::new()
        .route("/api/agents/logos", get(list_agent_logos))
        .route("/api/agents/management", get(list_management_agents))
        .route("/api/agents/{id}/health-check", post(health_check_by_id))
        .route("/api/agents/provider-health-check", post(provider_health_check))
        .route("/api/agents/{id}/enabled", patch(set_agent_enabled))
        .route(
            "/api/agents/{id}/overrides",
            get(get_agent_overrides).merge(host_only(put(set_agent_overrides))),
        )
        .route("/api/agents/custom", host_only(post(create_custom)))
        .route(
            "/api/agents/custom/{id}",
            host_only(put(update_custom).delete(delete_custom)),
        )
        .route("/api/agents/custom/try-connect", host_only(post(try_connect_custom)))
        .with_state(state)
}

/// Routes that choose a command the host runs (custom agents, command overrides, the
/// connection probe) are for the desktop app only (ADR-013): paired phones and browsers
/// and the agent helper are refused, as for MCP stdio servers (Jev 046).
fn host_only<S: Clone + Send + Sync + 'static>(route: MethodRouter<S>) -> MethodRouter<S> {
    route.route_layer(from_fn(agents_desktop_only))
}

/// `*_DESKTOP_ONLY`, so the agent config CLI reports `CONFIG_DESKTOP_ONLY`.
async fn agents_desktop_only(request: Request, next: Next) -> Result<Response, ApiError> {
    let extensions = request.extensions();
    if is_paired_device(extensions.get::<CurrentDevice>()) || extensions.get::<RuntimeHelperCaller>().is_some() {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "AGENTS_DESKTOP_ONLY",
            "Custom agents and agent command overrides are managed from the desktop app.",
            None,
        ));
    }
    Ok(next.run(request).await)
}

const MASK: &str = "***";

/// Paired devices and the agent helper read env override values masked (Jev 047, as for
/// MCP and providers); the config CLI already redacts them in its output.
fn mask_env(env: &mut [AgentEnvEntry]) {
    for entry in env {
        entry.value = MASK.to_owned();
    }
}

async fn list_agent_logos(
    State(state): State<AgentRouterState>,
    Extension(_user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Vec<AgentLogoEntry>>>, ApiError> {
    Ok(Json(ApiResponse::ok(
        state
            .service
            .list_agent_logos()
            .await
            .map_err(agent_error_to_api_error)?,
    )))
}

async fn list_management_agents(
    State(state): State<AgentRouterState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Vec<AgentManagementRow>>>, ApiError> {
    Ok(Json(ApiResponse::ok(
        state
            .service
            .list_management_agents(&user.id)
            .await
            .map_err(agent_error_to_api_error)?,
    )))
}

async fn health_check_by_id(
    State(state): State<AgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<AgentManagementRow>>, ApiError> {
    Ok(Json(ApiResponse::ok(
        state
            .service
            .health_check_agent_by_id(&user.id, &id)
            .await
            .map_err(agent_error_to_api_error)?,
    )))
}

async fn provider_health_check(
    State(state): State<AgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    body: Result<Json<ProviderHealthCheckRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<ProviderHealthCheckResponse>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(
        state
            .service
            .provider_health_check(&user.id, req)
            .await
            .map_err(agent_error_to_api_error)?,
    )))
}

async fn try_connect_custom(
    State(state): State<AgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    body: Result<Json<TryConnectCustomAgentRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<TryConnectCustomAgentResponse>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(
        state
            .service
            .try_connect_custom_agent(&user.id, req)
            .await
            .map_err(agent_error_to_api_error)?,
    )))
}

async fn create_custom(
    State(state): State<AgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    body: Result<Json<CustomAgentUpsertRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<AgentMetadata>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(
        state
            .service
            .create_custom_agent(&user.id, req)
            .await
            .map_err(agent_error_to_api_error)?,
    )))
}

async fn update_custom(
    State(state): State<AgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
    body: Result<Json<CustomAgentUpsertRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<AgentMetadata>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(
        state
            .service
            .update_custom_agent(&user.id, &id, req)
            .await
            .map_err(agent_error_to_api_error)?,
    )))
}

async fn delete_custom(
    State(state): State<AgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<DeleteCustomAgentResponse>>, ApiError> {
    state
        .service
        .delete_custom_agent(&user.id, &id)
        .await
        .map_err(agent_error_to_api_error)?;
    Ok(Json(ApiResponse::ok(DeleteCustomAgentResponse { deleted: true })))
}

async fn set_agent_enabled(
    State(state): State<AgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
    body: Result<Json<SetEnabledRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<AgentMetadata>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(
        state
            .service
            .set_agent_enabled(&user.id, &id, req.enabled)
            .await
            .map_err(agent_error_to_api_error)?,
    )))
}

async fn get_agent_overrides(
    State(state): State<AgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<AgentOverridesResponse>>, ApiError> {
    let mut overrides = state
        .service
        .get_agent_overrides(&user.id, &id)
        .await
        .map_err(agent_error_to_api_error)?;
    if helper.is_some() || is_paired_device(device.as_ref().map(|Extension(d)| d)) {
        mask_env(&mut overrides.env_override);
    }
    Ok(Json(ApiResponse::ok(overrides)))
}

async fn set_agent_overrides(
    State(state): State<AgentRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
    body: Result<Json<SetAgentOverridesRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<AgentManagementRow>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(
        state
            .service
            .set_agent_overrides(&user.id, &id, req)
            .await
            .map_err(agent_error_to_api_error)?,
    )))
}
