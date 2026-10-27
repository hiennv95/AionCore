#![allow(clippy::disallowed_types)]

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Json, Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, post, put};

use aionui_api_types::{
    ApiResponse, BatchImportMcpServersRequest, CreateMcpServerRequest, DetectedMcpServerResponse, ErrorResponse,
    McpConnectionTestErrorCode, McpServerResponse, McpTransport, OAuthCheckStatusRequest, OAuthLoginRequest,
    OAuthLoginResponse, OAuthLogoutRequest, OAuthStatusResponse, TestMcpConnectionRequest, UpdateMcpServerRequest,
};
use aionui_auth::{CurrentDevice, CurrentUser, RuntimeHelperCaller, is_paired_device};
use aionui_common::ApiError;

use crate::connection_test::McpConnectionTestService;
use crate::error::McpError;
use crate::oauth_service::McpOAuthService;
use crate::service::McpConfigService;
use crate::sync_service::McpSyncService;
use crate::types::McpServerTransport;

impl From<McpError> for ApiError {
    fn from(err: McpError) -> Self {
        match err {
            McpError::NotFound(msg) => ApiError::NotFound(msg),
            McpError::Conflict(msg) => ApiError::Conflict(msg),
            McpError::InvalidEdit(msg) => ApiError::BadRequest(msg),
            McpError::InvalidTransport(msg) => ApiError::BadRequest(msg),
            McpError::AgentNotInstalled(msg) => ApiError::BadRequest(msg),
            McpError::AgentOperationFailed(msg) => ApiError::Internal(msg),
            McpError::ConnectionFailed(msg) => ApiError::BadGateway(msg),
            McpError::OAuth(msg) => ApiError::Internal(format!("OAuth error: {msg}")),
            McpError::Database(db_err) => ApiError::Internal(db_err.to_string()),
            McpError::Json(e) => ApiError::Internal(format!("JSON error: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Router state
// ---------------------------------------------------------------------------

/// Shared state for MCP route handlers.
#[derive(Clone)]
pub struct McpRouterState {
    pub config_service: McpConfigService,
    pub sync_service: McpSyncService,
    pub connection_test_service: McpConnectionTestService,
    pub oauth_service: McpOAuthService,
}

// ---------------------------------------------------------------------------
// Route gates
// ---------------------------------------------------------------------------

/// Paired phones and browsers, as well as runtime helper CLIs, may inspect
/// MCP server definitions and passive OAuth status, but creating, editing,
/// deleting, toggling, running connection tests, discovering host configs, or
/// initiating OAuth flows are reserved for the desktop host session (ADR-013,
/// ADR-038).
fn mcp_desktop_only_error() -> ApiError {
    ApiError::coded(
        StatusCode::FORBIDDEN,
        "MCP_DESKTOP_ONLY",
        "MCP servers are managed and tested from the desktop app; this device can view them.",
        None,
    )
}

async fn mcp_desktop_only(request: Request, next: Next) -> Result<Response, ApiError> {
    let extensions = request.extensions();
    if is_paired_device(extensions.get::<CurrentDevice>()) || extensions.get::<RuntimeHelperCaller>().is_some() {
        return Err(mcp_desktop_only_error());
    }
    Ok(next.run(request).await)
}

fn desktop<S: Clone + Send + Sync + 'static>(route: MethodRouter<S>) -> MethodRouter<S> {
    route.route_layer(from_fn(mcp_desktop_only))
}

// ---------------------------------------------------------------------------
// Router builder
// ---------------------------------------------------------------------------

/// Build the MCP router with all `/api/mcp/*` routes.
///
/// Includes CRUD routes, agent config detection, connection tests, and OAuth.
/// All routes require authentication (applied by the caller).
pub fn mcp_routes(state: McpRouterState) -> Router {
    Router::new()
        .route("/api/mcp/servers", get(list_servers).merge(desktop(post(add_server))))
        .route("/api/mcp/servers/import", desktop(post(batch_import)))
        .route(
            "/api/mcp/servers/{id}",
            get(get_server).merge(desktop(put(edit_server).delete(delete_server))),
        )
        .route("/api/mcp/servers/{id}/toggle", desktop(post(toggle_server)))
        // Connection test route
        .route("/api/mcp/test-connection", desktop(post(test_connection)))
        // Agent config discovery route
        .route("/api/mcp/agent-configs", desktop(get(get_agent_configs)))
        // OAuth routes
        .route("/api/mcp/oauth/check-status", post(oauth_check_status))
        .route("/api/mcp/oauth/login", desktop(post(oauth_login)))
        .route("/api/mcp/oauth/logout", desktop(post(oauth_logout)))
        .route("/api/mcp/oauth/authenticated", get(oauth_authenticated))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// CRUD Handlers
// ---------------------------------------------------------------------------

/// `GET /api/mcp/servers` — list all MCP servers.
async fn list_servers(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
) -> Result<Json<ApiResponse<Vec<McpServerResponse>>>, ApiError> {
    let servers = state
        .config_service
        .list_servers(&user.id)
        .await
        .map_err(ApiError::from)?;
    let masked = masks_secrets(device.as_ref().map(|Extension(d)| d), helper.is_some());
    Ok(Json(ApiResponse::ok(
        servers.into_iter().map(|s| project(s, masked)).collect(),
    )))
}

/// `GET /api/mcp/servers/:id` — get a single MCP server.
async fn get_server(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<McpServerResponse>>, ApiError> {
    let server = state
        .config_service
        .get_server(&user.id, &id)
        .await
        .map_err(ApiError::from)?;
    let masked = masks_secrets(device.as_ref().map(|Extension(d)| d), helper.is_some());
    Ok(Json(ApiResponse::ok(project(server, masked))))
}

/// Paired phones and browsers and the agent helper read MCP servers with every
/// secret-bearing field masked (Jev 047); the desktop app keeps full values to edit them.
fn masks_secrets(device: Option<&CurrentDevice>, helper: bool) -> bool {
    helper || is_paired_device(device)
}

const MASK: &str = "***";

fn project(mut server: McpServerResponse, masked: bool) -> McpServerResponse {
    if !masked {
        return server;
    }
    server.original_json = None;
    server.transport = match server.transport {
        McpTransport::Stdio { command, args, env } => McpTransport::Stdio {
            command,
            args: args.iter().map(|_| MASK.to_owned()).collect(),
            env: env.into_keys().map(|k| (k, MASK.to_owned())).collect(),
        },
        McpTransport::Sse { url, headers } => McpTransport::Sse {
            url: strip_url_secrets(&url),
            headers: headers.into_keys().map(|k| (k, MASK.to_owned())).collect(),
        },
        McpTransport::Http { url, headers } => McpTransport::Http {
            url: strip_url_secrets(&url),
            headers: headers.into_keys().map(|k| (k, MASK.to_owned())).collect(),
        },
    };
    server
}

/// Drops userinfo, query and fragment: `https://u:p@host/p?k=v#f` -> `https://host/p`.
fn strip_url_secrets(url: &str) -> String {
    let url = url.split(['?', '#']).next().unwrap_or_default();
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
            format!("{scheme}://{host}{path}")
        }
        None => url.to_owned(),
    }
}

/// `POST /api/mcp/servers` — create (or upsert by name) an MCP server.
async fn add_server(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
    body: Result<Json<CreateMcpServerRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<ApiResponse<McpServerResponse>>), ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    let server = state
        .config_service
        .add_server(&user.id, req)
        .await
        .map_err(ApiError::from)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(server))))
}

/// `PUT /api/mcp/servers/:id` — partial update an MCP server.
async fn edit_server(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
    body: Result<Json<UpdateMcpServerRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<McpServerResponse>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    let server = state
        .config_service
        .edit_server(&user.id, &id, req)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(server)))
}

/// `DELETE /api/mcp/servers/:id` — delete an MCP server.
async fn delete_server(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    state
        .config_service
        .delete_server(&user.id, &id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(ApiResponse::success()))
}

/// `POST /api/mcp/servers/:id/toggle` — toggle enabled state.
async fn toggle_server(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<McpServerResponse>>, ApiError> {
    let server = state
        .config_service
        .toggle_server(&user.id, &id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(server)))
}

/// `POST /api/mcp/servers/import` — batch import MCP servers.
async fn batch_import(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
    body: Result<Json<BatchImportMcpServersRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<Vec<McpServerResponse>>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    let servers = state
        .config_service
        .batch_import(&user.id, req)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(servers)))
}

// ---------------------------------------------------------------------------
// Connection Test Handler
// ---------------------------------------------------------------------------

/// `POST /api/mcp/test-connection` — test MCP server connectivity.
///
/// Creates a temporary MCP client, connects, lists tools, and closes.
async fn test_connection(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
    body: Result<Json<TestMcpConnectionRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    let transport = McpServerTransport::from(req.transport);
    let result = state
        .connection_test_service
        .test_connection_with_runtime_scope(
            &req.name,
            &transport,
            Some(&user.id),
            req.runtime_scope_id.as_deref().or(req.id.as_deref()),
        )
        .await;
    if let Some(server_id) = req.id.as_deref() {
        state
            .config_service
            .persist_test_result(&user.id, server_id, &result)
            .await
            .map_err(ApiError::from)?;
    }
    if result.success || result.needs_auth == Some(true) {
        return Ok(Json(ApiResponse::ok(result)).into_response());
    }

    let status = result
        .code
        .map(connection_test_failure_status)
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let error = result
        .error
        .clone()
        .unwrap_or_else(|| "MCP connection test failed".to_string());
    let code = result
        .code
        .map(McpConnectionTestErrorCode::as_str)
        .unwrap_or("MCP_CONNECTION_FAILED");

    Ok((
        status,
        Json(ErrorResponse::new_with_details(error, code, result.details.clone())),
    )
        .into_response())
}

fn connection_test_failure_status(code: McpConnectionTestErrorCode) -> StatusCode {
    match code {
        McpConnectionTestErrorCode::CommandNotFound
        | McpConnectionTestErrorCode::CommandPermissionDenied
        | McpConnectionTestErrorCode::CommandStartFailed => StatusCode::UNPROCESSABLE_ENTITY,
        McpConnectionTestErrorCode::Timeout => StatusCode::GATEWAY_TIMEOUT,
        McpConnectionTestErrorCode::ConnectionFailed
        | McpConnectionTestErrorCode::HttpError
        | McpConnectionTestErrorCode::RpcError
        | McpConnectionTestErrorCode::ProtocolError => StatusCode::BAD_GATEWAY,
    }
}

// ---------------------------------------------------------------------------
// Agent Sync Handlers
// ---------------------------------------------------------------------------

/// `GET /api/mcp/agent-configs` — scan all installed Agent CLIs
/// and return their current MCP server configurations.
async fn get_agent_configs(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Vec<DetectedMcpServerResponse>>>, ApiError> {
    let configs = state
        .sync_service
        .get_agent_configs(&user.id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(configs)))
}

// ---------------------------------------------------------------------------
// OAuth Handlers
// ---------------------------------------------------------------------------

/// `POST /api/mcp/oauth/check-status` — check OAuth authentication status.
async fn oauth_check_status(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
    body: Result<Json<OAuthCheckStatusRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<OAuthStatusResponse>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    let status = state
        .oauth_service
        .check_oauth_status(&user.id, &req.server_url)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(status)))
}

/// `POST /api/mcp/oauth/login` — start OAuth PKCE login flow.
///
/// Discovers endpoints, opens the browser for authorization, waits for
/// the callback, and exchanges the code for tokens.
async fn oauth_login(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
    body: Result<Json<OAuthLoginRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<OAuthLoginResponse>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    let result = state
        .oauth_service
        .login(&user.id, &req.server_url)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(result)))
}

/// `POST /api/mcp/oauth/logout` — delete stored OAuth token.
async fn oauth_logout(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
    body: Result<Json<OAuthLogoutRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    let Json(req) = body.map_err(ApiError::from)?;
    state
        .oauth_service
        .logout(&user.id, &req.server_url)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(ApiResponse::success()))
}

/// `GET /api/mcp/oauth/authenticated` — list server URLs with stored tokens.
async fn oauth_authenticated(
    State(state): State<McpRouterState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<ApiResponse<Vec<String>>>, ApiError> {
    let urls = state
        .oauth_service
        .get_authenticated_servers(&user.id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(ApiResponse::ok(urls)))
}

#[cfg(test)]
mod error_mapping_tests {
    use super::*;

    #[test]
    fn url_secrets_are_stripped() {
        assert_eq!(
            strip_url_secrets("https://u:p@h.example:8443/sse?key=s#f"),
            "https://h.example:8443/sse"
        );
        assert_eq!(strip_url_secrets("https://h.example?token=s"), "https://h.example");
        assert_eq!(strip_url_secrets("https://a@b@h.example/x"), "https://h.example/x");
        assert_eq!(strip_url_secrets("h.example/path?k=v"), "h.example/path");
    }

    #[test]
    fn not_found_maps_to_app_not_found() {
        let err = ApiError::from(McpError::NotFound("mcp_123".into()));
        assert!(matches!(err, ApiError::NotFound(msg) if msg == "mcp_123"));
    }

    #[test]
    fn conflict_maps_to_app_conflict() {
        let err = ApiError::from(McpError::Conflict("test-server".into()));
        assert!(matches!(err, ApiError::Conflict(_)));
    }

    #[test]
    fn invalid_transport_maps_to_bad_request() {
        let err = ApiError::from(McpError::InvalidTransport("missing command".into()));
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn invalid_edit_maps_to_bad_request() {
        let err = ApiError::from(McpError::InvalidEdit("rename forbidden".into()));
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn agent_not_installed_maps_to_bad_request() {
        let err = ApiError::from(McpError::AgentNotInstalled("claude".into()));
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn agent_operation_failed_maps_to_internal() {
        let err = ApiError::from(McpError::AgentOperationFailed("exit code 1".into()));
        assert!(matches!(err, ApiError::Internal(_)));
    }

    #[test]
    fn connection_failed_maps_to_bad_gateway() {
        let err = ApiError::from(McpError::ConnectionFailed("timeout".into()));
        assert!(matches!(err, ApiError::BadGateway(_)));
    }

    #[test]
    fn oauth_maps_to_internal() {
        let err = ApiError::from(McpError::OAuth("discovery failed".into()));
        assert!(matches!(err, ApiError::Internal(_)));
    }

    #[test]
    fn json_error_maps_to_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = ApiError::from(McpError::Json(json_err));
        assert!(matches!(err, ApiError::Internal(_)));
    }
}
