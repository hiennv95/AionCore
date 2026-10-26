//! Assembly of the private-LAN network domain (ADR-009).

use std::sync::Arc;

use aionui_db::{INetworkRepository, SqliteNetworkRepository};
use aionui_network::{
    HostContext, HttpsPeerTransport, InboundService, NetworkRouterState, NetworkService, OutboundService,
};

use super::network_runner::ConversationTurnRunner;
use crate::services::AppServices;

/// Build the network state. The identity lives in `<data_dir>/peer/`; remote
/// turns run as the host owner (the primary WebUI user). Returns `None` (LAN
/// unavailable, local use unaffected) if the identity cannot be prepared.
pub(crate) async fn build_network_state(services: &AppServices) -> Option<NetworkRouterState> {
    let owner = match services.user_repo.get_primary_webui_user().await {
        Ok(Some(user)) => user.id,
        Ok(None) => "system_default_user".to_owned(),
        Err(error) => {
            tracing::warn!(%error, "network: owner lookup failed; LAN collaboration unavailable");
            return None;
        }
    };
    let host = match HostContext::load(
        &services.data_dir.join("peer"),
        owner,
        services.data_dir.join("network-workspaces"),
    ) {
        Ok(host) => Arc::new(host),
        Err(error) => {
            tracing::warn!(code = error.code(), %error, "network: identity unavailable; LAN collaboration off");
            return None;
        }
    };
    let repo: Arc<dyn INetworkRepository> = Arc::new(SqliteNetworkRepository::new(services.database.pool().clone()));
    let runner = Arc::new(ConversationTurnRunner::new(
        services.conversation_service.clone(),
        services.worker_task_manager.clone(),
    ));
    let transport = Arc::new(HttpsPeerTransport::new(host.identity().clone()));
    let inbound = Arc::new(InboundService::new(repo.clone(), runner, host.clone()));
    let outbound = Arc::new(OutboundService::new(repo.clone(), transport.clone()));
    let service = Arc::new(NetworkService::new(repo, host, inbound, outbound, transport));
    Some(NetworkRouterState { service })
}
