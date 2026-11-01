// `ApiError` is the intended error type at this HTTP boundary (routes map the
// crate-owned `NetworkError` to it here).
#![allow(clippy::disallowed_types)]

//! Owner API: `/api/network/*`. Mounted behind the auth middleware and the
//! CSRF guard like every other `/api` route; the service additionally limits
//! it to the host owner. Changing who and what this host trusts (settings,
//! peers, shares) is for the desktop app only, as for devices (ADR-011); paired
//! phones and browsers may read and use LAN sharing. Peer certificates are never
//! accepted here.

use std::sync::Arc;

use aionui_api_types::DeviceKind;
use aionui_api_types::{
    AddPeerRequest, ApiResponse, CreateShareRequest, InboundRequestView, NetworkStatusResponse, OutboundRequestView,
    PeerView, RemoteAgentView, SendRemoteRequest, ShareView, UpdateNetworkSettingsRequest,
};
use aionui_auth::{CurrentDevice, CurrentUser, DevicelessSession, RuntimeHelperCaller};
use aionui_common::ApiError;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};

use crate::error::NetworkError;
use crate::service::NetworkService;

#[derive(Clone)]
pub struct NetworkRouterState {
    pub service: Arc<NetworkService>,
}

pub fn network_routes(state: NetworkRouterState) -> Router {
    Router::new()
        .route("/api/network/status", get(status).put(update_settings))
        .route("/api/network/peers", get(list_peers).post(add_peer))
        .route("/api/network/peers/observe", post(observe_known_peer))
        .route("/api/network/peers/pinned", post(add_pinned_peer))
        .route("/api/network/peers/{id}", delete(forget_peer))
        .route("/api/network/peers/{id}/approve", post(approve_peer))
        .route("/api/network/peers/{id}/revoke", post(revoke_peer))
        .route("/api/network/peers/{id}/remote-agents", get(remote_agents))
        .route("/api/network/peers/{id}/teams", get(remote_teams))
        .route("/api/network/peers/{id}/team-invitations", get(remote_team_invitations).post(vote_team_invitation))
        .route("/api/network/peers/{id}/team-invitations/{invitation_id}/connect", post(reconcile_team_invitation))
        .route("/api/network/teams", get(shared_teams))
        .route("/api/network/teams/{id}", axum::routing::put(set_team_shared))
        .route("/api/network/teams/{id}/invitations", get(pending_local_team_invitation).post(create_team_invitation))
        .route("/api/network/teams/{id}/invitations/{invitation_id}", delete(cancel_team_invitation))
        .route("/api/network/teams/{id}/deliveries", get(team_deliveries))
        .route("/api/network/team-invitation-votes", post(vote_local_team_invitation))
        .route("/api/network/shares", get(list_shares).post(create_share))
        .route("/api/network/shares/{id}", delete(unshare))
        .route("/api/network/requests", get(list_requests).post(send_request))
        .route("/api/network/requests/{id}", get(get_request))
        .route("/api/network/requests/{id}/cancel", post(cancel_request))
        .route("/api/network/inbound", get(list_inbound))
        .with_state(state)
}

fn to_api_error(error: NetworkError) -> ApiError {
    if matches!(error, NetworkError::Db(_) | NetworkError::Internal(_)) {
        tracing::error!(%error, "network: owner API failed");
    }
    let status = StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    ApiError::coded(status, error.code(), error.public_message(), None)
}

/// Device-bound callers other than the desktop app, and agents' helper CLIs,
/// may not change LAN trust.
fn ensure_manager(
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
) -> Result<(), ApiError> {
    if deviceless.is_some() {
        return Err(to_api_error(NetworkError::OwnerOnly));
    }
    match (device, helper) {
        (_, Some(_)) => Err(to_api_error(NetworkError::OwnerOnly)),
        (Some(Extension(device)), None) if device.kind != DeviceKind::DesktopApp.as_str() => {
            Err(to_api_error(NetworkError::OwnerOnly))
        }
        _ => Ok(()),
    }
}

type ApiResult<T> = Result<Json<ApiResponse<T>>, ApiError>;

async fn observe_known_peer(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Json(request): Json<AddPeerRequest>,
) -> ApiResult<Option<aionui_api_types::DiscoveredLanPeer>> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.observe_known_peer(&user.id, request).await.map_err(to_api_error)?)
}

async fn add_pinned_peer(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Json(request): Json<aionui_api_types::AddPinnedPeerRequest>,
) -> ApiResult<PeerView> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.add_pinned_peer(&user.id, request).await.map_err(to_api_error)?)
}

fn ok<T>(value: T) -> ApiResult<T> {
    Ok(Json(ApiResponse::ok(value)))
}

async fn status(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
) -> ApiResult<NetworkStatusResponse> {
    ok(state.service.status(&user.id).map_err(to_api_error)?)
}

async fn update_settings(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Json(req): Json<UpdateNetworkSettingsRequest>,
) -> ApiResult<NetworkStatusResponse> {
    ensure_manager(device, deviceless, helper)?;
    ok(state
        .service
        .update_settings(&user.id, req)
        .await
        .map_err(to_api_error)?)
}

async fn list_peers(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
) -> ApiResult<Vec<PeerView>> {
    ok(state.service.list_peers(&user.id).await.map_err(to_api_error)?)
}

async fn add_peer(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Json(req): Json<AddPeerRequest>,
) -> ApiResult<PeerView> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.add_peer(&user.id, req).await.map_err(to_api_error)?)
}

async fn approve_peer(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path(id): Path<String>,
) -> ApiResult<PeerView> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.approve_peer(&user.id, &id).await.map_err(to_api_error)?)
}

async fn revoke_peer(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path(id): Path<String>,
) -> ApiResult<PeerView> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.revoke_peer(&user.id, &id).await.map_err(to_api_error)?)
}

async fn forget_peer(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path(id): Path<String>,
) -> ApiResult<()> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.forget_peer(&user.id, &id).await.map_err(to_api_error)?)
}

async fn remote_agents(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> ApiResult<Vec<RemoteAgentView>> {
    ok(state.service.remote_agents(&user.id, &id).await.map_err(to_api_error)?)
}

async fn remote_teams(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> ApiResult<Vec<aionui_api_types::LanTeam>> {
    ok(state.service.remote_teams(&user.id, &id).await.map_err(to_api_error)?)
}

async fn shared_teams(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
) -> ApiResult<Vec<aionui_api_types::LanTeam>> {
    ok(state.service.shared_teams(&user.id).await.map_err(to_api_error)?)
}

async fn pending_local_team_invitation(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path(id): Path<String>,
) -> ApiResult<Option<aionui_api_types::PendingLocalLanInvitation>> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.pending_local_team_invitation(&user.id, &id).await.map_err(to_api_error)?)
}

async fn create_team_invitation(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path(id): Path<String>,
    Json(request): Json<aionui_api_types::CreateLanTeamInvitationRequest>,
) -> ApiResult<aionui_api_types::CreateLanTeamInvitationResponse> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.create_team_invitation(&user.id, &id, &request.peer_id).await.map_err(to_api_error)?)
}

async fn cancel_team_invitation(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path((id, invitation_id)): Path<(String, String)>,
) -> ApiResult<()> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.cancel_team_invitation(&user.id, &id, &invitation_id).await.map_err(to_api_error)?)
}

async fn vote_local_team_invitation(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Json(request): Json<aionui_api_types::PeerInvitationVoteRequest>,
) -> ApiResult<aionui_api_types::PeerInvitationVoteResponse> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.vote_local_team_invitation(&user.id, request).await.map_err(to_api_error)?)
}

async fn remote_team_invitations(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> ApiResult<Vec<aionui_api_types::PeerTeamInvitation>> {
    ok(state.service.remote_team_invitations(&user.id, &id).await.map_err(to_api_error)?)
}

async fn team_deliveries(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> ApiResult<Vec<aionui_api_types::LanTeamDeliveryStatus>> {
    ok(state.service.lan_team_delivery_statuses(&user.id, &id).await.map_err(to_api_error)?)
}

async fn vote_team_invitation(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path(id): Path<String>,
    Json(request): Json<aionui_api_types::PeerInvitationVoteRequest>,
) -> ApiResult<aionui_api_types::PeerInvitationVoteResponse> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.vote_remote_team_invitation(&user.id, &id, request).await.map_err(to_api_error)?)
}

async fn reconcile_team_invitation(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path((peer_id, invitation_id)): Path<(String, String)>,
) -> ApiResult<()> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.reconcile_team_invitation(&user.id, &peer_id, &invitation_id).await.map_err(to_api_error)?)
}

async fn set_team_shared(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path(id): Path<String>,
    Json(req): Json<aionui_api_types::SetLanTeamSharingRequest>,
) -> ApiResult<()> {
    ensure_manager(device, deviceless, helper)?;
    ok(state
        .service
        .set_team_shared(&user.id, &id, req.enabled)
        .await
        .map_err(to_api_error)?)
}

async fn list_shares(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
) -> ApiResult<Vec<ShareView>> {
    ok(state.service.list_shares(&user.id).await.map_err(to_api_error)?)
}

async fn create_share(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Json(req): Json<CreateShareRequest>,
) -> ApiResult<ShareView> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.create_share(&user.id, req).await.map_err(to_api_error)?)
}

async fn unshare(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    device: Option<Extension<CurrentDevice>>,
    deviceless: Option<Extension<DevicelessSession>>,
    helper: Option<Extension<RuntimeHelperCaller>>,
    Path(id): Path<String>,
) -> ApiResult<()> {
    ensure_manager(device, deviceless, helper)?;
    ok(state.service.unshare(&user.id, &id).await.map_err(to_api_error)?)
}

async fn list_requests(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
) -> ApiResult<Vec<OutboundRequestView>> {
    ok(state.service.list_outbound(&user.id).await.map_err(to_api_error)?)
}

async fn get_request(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> ApiResult<OutboundRequestView> {
    ok(state.service.get_outbound(&user.id, &id).await.map_err(to_api_error)?)
}

async fn send_request(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<SendRemoteRequest>,
) -> ApiResult<OutboundRequestView> {
    ok(state.service.send(&user.id, req).await.map_err(to_api_error)?)
}

async fn cancel_request(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> ApiResult<OutboundRequestView> {
    ok(state
        .service
        .cancel_outbound(&user.id, &id)
        .await
        .map_err(to_api_error)?)
}

async fn list_inbound(
    State(state): State<NetworkRouterState>,
    Extension(user): Extension<CurrentUser>,
) -> ApiResult<Vec<InboundRequestView>> {
    ok(state.service.list_inbound(&user.id).await.map_err(to_api_error)?)
}
