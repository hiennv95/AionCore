#![allow(clippy::disallowed_types)]

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Json, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};

use aionui_api_types::{ApiResponse, InboxResponse, InboxSeenRequest, TurnReceipt};
use aionui_auth::{CurrentUser, RuntimeHelperCaller};
use aionui_common::ApiError;

use crate::error::InboxError;
use crate::state::InboxRouterState;

pub fn inbox_routes(state: InboxRouterState) -> Router {
    Router::new()
        .route("/api/inbox", get(inbox))
        .route("/api/inbox/seen", post(seen))
        .route("/api/conversations/{id}/turns/{turn_id}/receipt", get(receipt))
        .route("/api/conversations/{id}/turns/{turn_id}/receipt/accept", post(accept))
        .with_state(state)
}

impl From<InboxError> for ApiError {
    fn from(err: InboxError) -> Self {
        match err {
            InboxError::ConversationNotFound => ApiError::NotFound("Conversation not found".into()),
            InboxError::ReceiptNotFound => ApiError::coded(
                StatusCode::NOT_FOUND,
                "RECEIPT_NOT_FOUND",
                "No result receipt for this turn.",
                None,
            ),
            InboxError::Database(e) => ApiError::Internal(format!("Database error: {e}")),
        }
    }
}

/// The inbox spans every chat of the owner, so an agent's helper (scoped to one
/// conversation, ADR-013) never reads it.
fn ensure_not_helper(helper: Option<Extension<RuntimeHelperCaller>>) -> Result<(), ApiError> {
    if helper.is_some() {
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "INBOX_OWNER_ONLY",
            "Only the owner's apps can read the inbox.",
            None,
        ));
    }
    Ok(())
}

async fn inbox(
    State(state): State<InboxRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
) -> Result<Json<ApiResponse<InboxResponse>>, ApiError> {
    ensure_not_helper(helper)?;
    Ok(Json(ApiResponse::ok(state.service.inbox(&user.id).await?)))
}

async fn seen(
    State(state): State<InboxRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    body: Result<Json<InboxSeenRequest>, JsonRejection>,
) -> Result<Json<ApiResponse<()>>, ApiError> {
    ensure_not_helper(helper)?;
    let Json(req) = body.map_err(ApiError::from)?;
    state.service.mark_seen(&user.id, &req.conversation_id).await?;
    Ok(Json(ApiResponse::success()))
}

async fn receipt(
    State(state): State<InboxRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path((id, turn_id)): Path<(String, String)>,
) -> Result<Json<ApiResponse<TurnReceipt>>, ApiError> {
    ensure_not_helper(helper)?;
    Ok(Json(ApiResponse::ok(
        state.service.receipts().receipt(&user.id, &id, &turn_id).await?,
    )))
}

/// Acceptance is the owner's own call on the result, never a check that passed.
async fn accept(
    State(state): State<InboxRouterState>,
    Extension(user): Extension<CurrentUser>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path((id, turn_id)): Path<(String, String)>,
) -> Result<Json<ApiResponse<TurnReceipt>>, ApiError> {
    ensure_not_helper(helper)?;
    let receipts = state.service.receipts();
    receipts.accept(&user.id, &id, &turn_id).await?;
    Ok(Json(ApiResponse::ok(receipts.receipt(&user.id, &id, &turn_id).await?)))
}
