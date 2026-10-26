// `aionui_common::ApiError` is not used here: the peer protocol has its own
// error body (`PeerErrorBody`) with stable codes, independent of the owner API.

//! Router served on the mutual-TLS peer listener (never on the owner API).
//! Every handler authorizes by the caller's TLS fingerprint ([`PeerCaller`]);
//! user sessions, cookies and payload-supplied identities are never accepted.

use std::sync::Arc;
use std::time::Duration;

use aionui_api_types::{PeerErrorBody, PeerPairingRequest, PeerSubmitRequest};
use aionui_peer::PeerCaller;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;

use crate::error::NetworkError;
use crate::inbound::InboundService;
use crate::policy::MAX_CONTENT_BYTES;

pub fn peer_routes(inbound: Arc<InboundService>) -> Router {
    Router::new()
        .route("/peer/v1/hello", get(hello))
        .route("/peer/v1/pairing", post(pair))
        .route("/peer/v1/pairing/reveal", post(reveal))
        .route("/peer/v1/shares", get(shares))
        .route("/peer/v1/requests", post(submit))
        .route("/peer/v1/requests/{request_id}", get(status))
        .route("/peer/v1/requests/{request_id}/cancel", post(cancel))
        // JSON envelope + escaping headroom over the content limit.
        .layer(DefaultBodyLimit::max(MAX_CONTENT_BYTES * 2 + 4096))
        .with_state(inbound)
}

struct PeerApiError(NetworkError);

impl IntoResponse for PeerApiError {
    fn into_response(self) -> Response {
        if matches!(self.0, NetworkError::Db(_) | NetworkError::Internal(_)) {
            tracing::error!(error = %self.0, "network: peer request failed");
        }
        let status = StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = PeerErrorBody {
            code: self.0.code().to_owned(),
            message: self.0.public_message(),
        };
        (status, Json(body)).into_response()
    }
}

impl From<NetworkError> for PeerApiError {
    fn from(error: NetworkError) -> Self {
        Self(error)
    }
}

type PeerResult<T> = Result<Json<T>, PeerApiError>;

async fn hello(
    State(inbound): State<Arc<InboundService>>,
    Extension(caller): Extension<PeerCaller>,
) -> PeerResult<aionui_api_types::PeerHelloResponse> {
    Ok(Json(inbound.hello(&caller.fingerprint).await?))
}

async fn pair(
    State(inbound): State<Arc<InboundService>>,
    Extension(caller): Extension<PeerCaller>,
    Json(body): Json<PeerPairingRequest>,
) -> PeerResult<aionui_api_types::PeerPairingResponse> {
    Ok(Json(inbound.pair(&caller.fingerprint, body).await?))
}

async fn reveal(
    State(inbound): State<Arc<InboundService>>,
    Extension(caller): Extension<PeerCaller>,
    Json(body): Json<aionui_api_types::PeerPairingReveal>,
) -> PeerResult<aionui_api_types::PeerPairingRevealResponse> {
    Ok(Json(inbound.reveal(&caller.fingerprint, body).await?))
}

async fn shares(
    State(inbound): State<Arc<InboundService>>,
    Extension(caller): Extension<PeerCaller>,
) -> PeerResult<aionui_api_types::PeerSharesResponse> {
    Ok(Json(inbound.list_shares(&caller.fingerprint).await?))
}

async fn submit(
    State(inbound): State<Arc<InboundService>>,
    Extension(caller): Extension<PeerCaller>,
    Json(body): Json<PeerSubmitRequest>,
) -> PeerResult<aionui_api_types::PeerRequestStatus> {
    Ok(Json(inbound.submit(&caller.fingerprint, body).await?))
}

#[derive(Deserialize)]
struct StatusQuery {
    #[serde(default)]
    after_version: i64,
    #[serde(default)]
    wait_ms: u64,
}

async fn status(
    State(inbound): State<Arc<InboundService>>,
    Extension(caller): Extension<PeerCaller>,
    Path(request_id): Path<String>,
    Query(query): Query<StatusQuery>,
) -> PeerResult<aionui_api_types::PeerRequestStatus> {
    Ok(Json(
        inbound
            .status(
                &caller.fingerprint,
                &request_id,
                query.after_version,
                Duration::from_millis(query.wait_ms),
            )
            .await?,
    ))
}

async fn cancel(
    State(inbound): State<Arc<InboundService>>,
    Extension(caller): Extension<PeerCaller>,
    Path(request_id): Path<String>,
) -> PeerResult<aionui_api_types::PeerRequestStatus> {
    Ok(Json(inbound.cancel(&caller.fingerprint, &request_id).await?))
}
