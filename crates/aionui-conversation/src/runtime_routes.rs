//! `POST /api/runtime/conversations/create` — the agent-facing create route.
//!
//! Authenticates on the three `x-aionui-*` headers itself, exactly like
//! `aionui-session-message/src/routes.rs`, and is therefore mounted OUTSIDE the
//! ordinary auth and CSRF middleware in `aionui-app`. The caller conversation is
//! the token-bound header — the body cannot name a different caller.

use std::sync::Arc;

use aionui_ai_agent::{HelperAccess, HelperDenied, HelperUse};
use aionui_api_types::{
    ConversationCliEnvelope, ConversationCreateRequest, ConversationCreateResponse, ConversationToolErrorCode,
    ConversationToolErrorPayload,
};
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use tracing::warn;

use crate::runtime_create::ConversationCreateError;
use crate::service::ConversationService;

const HEADER_USER_ID: &str = "x-aionui-user-id";
const HEADER_CONVERSATION_ID: &str = "x-aionui-conversation-id";
const HEADER_RUNTIME_TOKEN: &str = "x-aionui-runtime-token";
const COMMAND: &str = "conversation create";

/// Separate from `ConversationRouterState` so the ordinary conversation routes
/// keep their shape and this one carries only what it needs.
#[derive(Clone)]
pub struct ConversationRuntimeRouterState {
    pub service: ConversationService,
    pub helper_access: Arc<HelperAccess>,
}

pub fn conversation_runtime_routes(state: ConversationRuntimeRouterState) -> Router {
    Router::new()
        .route("/api/runtime/conversations/create", post(create))
        .with_state(state)
}

struct RuntimeCaller {
    user_id: String,
    conversation_id: String,
}

async fn runtime_caller(
    state: &ConversationRuntimeRouterState,
    headers: &HeaderMap,
) -> Result<RuntimeCaller, HelperDenied> {
    let header = |name| required_header(headers, name).ok_or(HelperDenied::Unauthenticated);
    let user_id = header(HEADER_USER_ID)?;
    let conversation_id = header(HEADER_CONVERSATION_ID)?;
    let token = header(HEADER_RUNTIME_TOKEN)?;
    state
        .helper_access
        .authorize(Some(&token), &user_id, &conversation_id, HelperUse::Other)
        .await?;
    Ok(RuntimeCaller {
        user_id,
        conversation_id,
    })
}

fn required_header(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

type Reply = (StatusCode, Json<ConversationCliEnvelope<ConversationCreateResponse>>);

async fn create(
    State(state): State<ConversationRuntimeRouterState>,
    headers: HeaderMap,
    body: Result<Json<ConversationCreateRequest>, JsonRejection>,
) -> Reply {
    let caller = match runtime_caller(&state, &headers).await {
        Ok(caller) => caller,
        Err(HelperDenied::LanShare) => {
            return failure(
                StatusCode::FORBIDDEN,
                ConversationToolErrorPayload::new(
                    ConversationToolErrorCode::HelperNotForLanShare,
                    "an agent in a LAN share can only read skills",
                ),
            );
        }
        Err(HelperDenied::ConversationGone) => {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                ConversationToolErrorPayload::new(
                    ConversationToolErrorCode::TransportUnavailable,
                    "the calling conversation no longer exists",
                ),
            );
        }
        Err(_) => {
            // No header values are logged — the token must never reach the logs.
            warn!(
                outcome = "rejected",
                error_code = "runtime_auth_failed",
                "agent conversation create refused"
            );
            return failure(
                StatusCode::UNAUTHORIZED,
                ConversationToolErrorPayload::new(ConversationToolErrorCode::RuntimeAuthFailed, "runtime auth failed"),
            );
        }
    };
    // Body parsing is deliberately AFTER auth so an unauthenticated caller
    // learns nothing about the schema; `deny_unknown_fields` on the request
    // type turns stray fields into this same 400.
    let request = match body {
        Ok(Json(request)) => request,
        Err(rejection) => {
            return failure(
                StatusCode::BAD_REQUEST,
                ConversationToolErrorPayload::new(
                    ConversationToolErrorCode::SchemaValidationFailed,
                    format!("request body does not match the schema: {}", rejection.body_text()),
                ),
            );
        }
    };
    match state
        .service
        .create_for_conversation_helper(&caller.user_id, &caller.conversation_id, &request)
        .await
    {
        Ok(data) => (
            StatusCode::OK,
            Json(ConversationCliEnvelope::success(data, Some(COMMAND.to_owned()))),
        ),
        Err(error) => envelope_failure(error),
    }
}

fn envelope_failure(error: ConversationCreateError) -> Reply {
    let status = StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    failure(
        status,
        ConversationToolErrorPayload::new(error.code(), error.to_string()),
    )
}

fn failure(status: StatusCode, error: ConversationToolErrorPayload) -> Reply {
    (
        status,
        Json(ConversationCliEnvelope::failure(error, Some(COMMAND.to_owned()))),
    )
}
