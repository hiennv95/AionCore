//! Owner-side business logic: settings + listener, peers and pairing, shares,
//! and the requests this host sends. Only the host owner may call it.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use aionui_api_types::{
    AddPeerRequest, CreateShareRequest, InboundRequestView, NetworkStatusResponse, OutboundRequestView,
    PEER_CONTRACT_VERSION, PeerPairingRequest, PeerPairingReveal, PeerState, PeerView, RemoteAgentView,
    RemoteRequestState, SendRemoteRequest, ShareView, UpdateNetworkSettingsRequest, WaitingKind,
};
use aionui_common::now_ms;
use aionui_db::models::{NetworkInboundRequestRow, NetworkOutboundRequestRow, NetworkPeerRow, NetworkShareRow};
use aionui_db::{
    INetworkRepository, InsertOutboundParams, InsertPeerParams, InsertShareParams, OutboundUpdate, RequestUpdate,
    UpdatePeerParams,
};
use aionui_peer::Fingerprint;
use tracing::{info, warn};

use crate::error::NetworkError;
use crate::host::HostContext;
use crate::inbound::{InboundService, clean_display_name};
use crate::listener::PeerListener;
use crate::outbound::OutboundService;
use crate::peer_routes::peer_routes;
use crate::policy;
use crate::ports::PeerTransport;

const LIST_LIMIT: i64 = 100;

pub struct NetworkService {
    repo: Arc<dyn INetworkRepository>,
    host: Arc<HostContext>,
    inbound: Arc<InboundService>,
    outbound: Arc<OutboundService>,
    transport: Arc<dyn PeerTransport>,
    listener: PeerListener,
    /// `--peer-listen` fixes the listener; the UI cannot toggle it.
    cli_listen: OnceLock<SocketAddr>,
}

impl NetworkService {
    pub fn new(
        repo: Arc<dyn INetworkRepository>,
        host: Arc<HostContext>,
        inbound: Arc<InboundService>,
        outbound: Arc<OutboundService>,
        transport: Arc<dyn PeerTransport>,
    ) -> Self {
        let listener = PeerListener::new(host.identity().clone());
        Self {
            repo,
            host,
            inbound,
            outbound,
            transport,
            listener,
            cli_listen: OnceLock::new(),
        }
    }

    /// Boot: recover the inbox, resume the outbox, start the dispatcher and,
    /// when enabled, the listener. A listener failure (port in use) is
    /// reported in status but does not stop the host: local use keeps working.
    pub async fn start(&self, cli_listen: Option<SocketAddr>) -> Result<(), NetworkError> {
        if let Some(addr) = cli_listen {
            let _ = self.cli_listen.set(addr);
        }
        self.inbound.recover().await?;
        tokio::spawn(Arc::clone(&self.inbound).run());
        self.outbound.resume_all().await?;
        if let Some(addr) = self.listen_addr()
            && let Err(error) = self.listener.start(addr, peer_routes(self.inbound.clone())).await
        {
            // An explicit `--peer-listen` that cannot bind is a configuration error.
            if self.cli_listen.get().is_some() {
                return Err(error);
            }
            warn!(code = error.code(), %error, "network: peer listener not started");
        }
        Ok(())
    }

    fn listen_addr(&self) -> Option<SocketAddr> {
        self.cli_listen.get().copied().or_else(|| {
            let settings = self.host.settings();
            settings
                .enabled
                .then(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, settings.listen_port)))
        })
    }

    fn ensure_owner(&self, user_id: &str) -> Result<(), NetworkError> {
        if user_id == self.host.owner_user_id() {
            Ok(())
        } else {
            Err(NetworkError::OwnerOnly)
        }
    }

    // ── settings ────────────────────────────────────────────────────────────

    pub fn status(&self, user_id: &str) -> Result<NetworkStatusResponse, NetworkError> {
        self.ensure_owner(user_id)?;
        let settings = self.host.settings();
        let running = self.listener.running_addr();
        Ok(NetworkStatusResponse {
            enabled: running.is_some(),
            host_fingerprint: self.host.fingerprint().to_string(),
            display_name: settings.display_name,
            listen_port: running.map(|addr| addr.port()).or(Some(settings.listen_port)),
            managed_by_cli: self.cli_listen.get().is_some(),
            last_error: self.listener.last_error(),
        })
    }

    pub async fn update_settings(
        &self,
        user_id: &str,
        req: UpdateNetworkSettingsRequest,
    ) -> Result<NetworkStatusResponse, NetworkError> {
        self.ensure_owner(user_id)?;
        let mut settings = self.host.settings();
        let before = (settings.enabled, settings.listen_port);
        if let Some(name) = req.display_name.as_deref() {
            settings.display_name = clean_display_name(name)?;
        }
        if let Some(port) = req.listen_port {
            if port < 1024 {
                return Err(NetworkError::InvalidRequest("port must be 1024-65535".into()));
            }
            settings.listen_port = port;
        }
        if let Some(enabled) = req.enabled {
            if self.cli_listen.get().is_some() {
                return Err(NetworkError::InvalidRequest(
                    "the peer listener is fixed by --peer-listen on this host".into(),
                ));
            }
            settings.enabled = enabled;
        }
        // Only touch the listener when its state really changes: re-sending the same
        // value must not cut open peer connections (or fail on its own port).
        let wanted = SocketAddr::from((Ipv4Addr::UNSPECIFIED, settings.listen_port));
        let running_as_wanted = settings.enabled && self.listener.running_addr() == Some(wanted);
        let restart = (req.enabled.is_some() || req.listen_port.is_some())
            && ((settings.enabled, settings.listen_port) != before || (settings.enabled != running_as_wanted));
        self.host.save_settings(settings.clone())?;
        if restart && self.cli_listen.get().is_none() {
            if settings.enabled {
                let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, settings.listen_port));
                self.listener.start(addr, peer_routes(self.inbound.clone())).await?;
            } else {
                self.listener.stop().await;
            }
            info!(
                enabled = settings.enabled,
                port = settings.listen_port,
                "network: LAN collaboration setting changed"
            );
        }
        self.status(user_id)
    }

    // ── peers ───────────────────────────────────────────────────────────────

    pub async fn list_peers(&self, user_id: &str) -> Result<Vec<PeerView>, NetworkError> {
        self.ensure_owner(user_id)?;
        policy::prune_expired_pairings(self.repo.as_ref()).await?;
        Ok(self.repo.list_peers().await?.into_iter().map(peer_view).collect())
    }

    /// Contact another host by address and send it a pairing request. Nothing is
    /// trusted until this owner approves after comparing the verification code.
    pub async fn add_peer(&self, user_id: &str, req: AddPeerRequest) -> Result<PeerView, NetworkError> {
        self.ensure_owner(user_id)?;
        let url = normalize_peer_url(&req.url)?;
        let (fingerprint, hello) = self.transport.observe(&url).await?;
        if &fingerprint == self.host.fingerprint() {
            return Err(NetworkError::InvalidRequest("that address is this host".into()));
        }
        let remote_name = clean_display_name(&hello.display_name).unwrap_or_else(|_| fingerprint.short().to_owned());
        // A known peer is never re-keyed (ADR-016): refresh its address and name only.
        if let Some(peer) = self.repo.find_peer_by_fingerprint(fingerprint.as_str()).await? {
            // Revoked here, or the peer's hello says it revoked us.
            if peer.state == PeerState::Revoked.as_str() || hello.caller_state == Some(PeerState::Revoked) {
                return Err(NetworkError::PeerRevoked);
            }
            self.repo
                .update_peer(
                    &peer.id,
                    UpdatePeerParams {
                        peer_url: Some(&url),
                        display_name: Some(&remote_name),
                        ..Default::default()
                    },
                )
                .await?;
            return Ok(peer_view(self.peer(&peer.id).await?));
        }
        // Commit-then-reveal exchange (ADR-016): the peer commits to its nonce,
        // we send ours, it opens the commitment. Neither side can steer the code.
        let nonce = policy::new_pairing_nonce()?;
        let exchange = async {
            let pairing = PeerPairingRequest {
                protocol_version: PEER_CONTRACT_VERSION,
                display_name: self.host.display_name(),
            };
            let answer = self.transport.pair(&url, &fingerprint, &pairing).await?;
            let reveal = PeerPairingReveal {
                nonce: hex::encode(nonce),
            };
            let opened = self.transport.reveal(&url, &fingerprint, &reveal).await?;
            let responder_nonce = hex::decode(&opened.responder_nonce)
                .ok()
                .filter(|n| n.len() == 32 && policy::pairing_commitment(n) == answer.responder_commitment)
                .ok_or_else(|| NetworkError::InvalidRequest("peer nonce does not match its commitment".into()))?;
            Ok::<_, NetworkError>(policy::verification_code(
                self.host.fingerprint(),
                &fingerprint,
                &nonce,
                &responder_nonce,
            ))
        };
        let code = match exchange.await {
            Ok(code) => code,
            Err(error) => {
                info!(peer = %fingerprint.short(), code = error.code(), "network: pairing request not accepted by peer");
                return Err(error);
            }
        };
        self.repo
            .insert_peer(InsertPeerParams {
                fingerprint: fingerprint.as_str(),
                display_name: &remote_name,
                peer_url: Some(&url),
                state: PeerState::PendingOutbound.as_str(),
                verification_code: &code,
            })
            .await?;
        info!(peer = %fingerprint.short(), "network: pairing request sent; awaiting both owners");
        let peer = self
            .repo
            .find_peer_by_fingerprint(fingerprint.as_str())
            .await?
            .ok_or(NetworkError::PeerNotFound)?;
        Ok(peer_view(peer))
    }

    async fn peer(&self, id: &str) -> Result<NetworkPeerRow, NetworkError> {
        self.repo.find_peer(id).await?.ok_or(NetworkError::PeerNotFound)
    }

    pub async fn approve_peer(&self, user_id: &str, id: &str) -> Result<PeerView, NetworkError> {
        self.ensure_owner(user_id)?;
        policy::prune_expired_pairings(self.repo.as_ref()).await?;
        let peer = self.peer(id).await?;
        match PeerState::parse(&peer.state) {
            Some(PeerState::PendingInbound | PeerState::PendingOutbound) => {}
            Some(PeerState::Trusted) => return Ok(peer_view(peer)),
            _ => return Err(NetworkError::PeerRevoked),
        }
        self.repo
            .update_peer(
                id,
                UpdatePeerParams {
                    state: Some(PeerState::Trusted.as_str()),
                    ..Default::default()
                },
            )
            .await?;
        info!(peer = %&peer.fingerprint[..16], "network: peer trusted by owner");
        Ok(peer_view(self.peer(id).await?))
    }

    pub async fn revoke_peer(&self, user_id: &str, id: &str) -> Result<PeerView, NetworkError> {
        self.ensure_owner(user_id)?;
        let peer = self.peer(id).await?;
        self.repo
            .update_peer(
                id,
                UpdatePeerParams {
                    state: Some(PeerState::Revoked.as_str()),
                    ..Default::default()
                },
            )
            .await?;
        info!(peer = %&peer.fingerprint[..16], "network: peer revoked by owner");
        self.inbound.cancel_live_for(id, None).await?;
        self.wake_outbound_for(id).await?;
        Ok(peer_view(self.peer(id).await?))
    }

    /// Delete a peer and its history. Allows pairing with it again later.
    pub async fn forget_peer(&self, user_id: &str, id: &str) -> Result<(), NetworkError> {
        self.ensure_owner(user_id)?;
        let peer = self.peer(id).await?;
        self.inbound.cancel_live_for(id, None).await?;
        self.repo.delete_peer(id).await?;
        info!(peer = %&peer.fingerprint[..16], "network: peer forgotten by owner");
        Ok(())
    }

    async fn wake_outbound_for(&self, peer_id: &str) -> Result<(), NetworkError> {
        for row in self.repo.list_outbound_in_states(&policy::LIVE_OUTBOUND_STATES).await? {
            if row.peer_id == peer_id {
                self.outbound.drive(row.id);
            }
        }
        Ok(())
    }

    // ── shares ──────────────────────────────────────────────────────────────

    pub async fn list_shares(&self, user_id: &str) -> Result<Vec<ShareView>, NetworkError> {
        self.ensure_owner(user_id)?;
        let peers = self.repo.list_peers().await?;
        Ok(self
            .repo
            .list_shares(None)
            .await?
            .into_iter()
            .map(|share| share_view(share, &peers))
            .collect())
    }

    pub async fn create_share(&self, user_id: &str, req: CreateShareRequest) -> Result<ShareView, NetworkError> {
        self.ensure_owner(user_id)?;
        let peer = self.peer(&req.peer_id).await?;
        if peer.state != PeerState::Trusted.as_str() {
            return Err(NetworkError::PeerUntrusted);
        }
        let mode = policy::share_mode_for_backend(&req.backend).ok_or_else(|| {
            NetworkError::InvalidRequest("only codex and claude agents can be shared in this release".into())
        })?;
        let label = clean_display_name(&req.label)?;
        if let Some(at) = req.expires_at
            && at <= now_ms()
        {
            return Err(NetworkError::InvalidRequest("expiry must be in the future".into()));
        }
        let workspace = match req.workspace.as_deref().map(str::trim).filter(|w| !w.is_empty()) {
            Some(path) => {
                let path = Path::new(path);
                if !path.is_absolute() || !path.is_dir() {
                    return Err(NetworkError::InvalidRequest(
                        "workspace must be an existing absolute directory".into(),
                    ));
                }
                path.to_string_lossy().into_owned()
            }
            None => {
                let dir = self.host.workspace_root().join(uuid::Uuid::now_v7().to_string());
                std::fs::create_dir_all(&dir).map_err(|e| NetworkError::Internal(format!("create workspace: {e}")))?;
                dir.to_string_lossy().into_owned()
            }
        };
        let share = self
            .repo
            .insert_share(InsertShareParams {
                peer_id: &peer.id,
                label: &label,
                backend: &req.backend,
                mode,
                workspace: &workspace,
                expires_at: req.expires_at,
            })
            .await?;
        info!(share_id = %share.id, peer = %&peer.fingerprint[..16], backend = %share.backend, "network: agent shared");
        Ok(share_view(share, &[peer]))
    }

    pub async fn unshare(&self, user_id: &str, id: &str) -> Result<(), NetworkError> {
        self.ensure_owner(user_id)?;
        let share = self.repo.find_share(id).await?.ok_or(NetworkError::ShareNotFound)?;
        if self.repo.revoke_share(id, now_ms()).await? {
            info!(share_id = %id, "network: share revoked by owner");
        }
        self.inbound.cancel_live_for(&share.peer_id, Some(id)).await?;
        Ok(())
    }

    // ── remote agents and requests (this host as requester) ────────────────

    pub async fn remote_agents(&self, user_id: &str, peer_id: &str) -> Result<Vec<RemoteAgentView>, NetworkError> {
        self.ensure_owner(user_id)?;
        let peer = self.peer(peer_id).await?;
        let (url, fingerprint) = callable_peer(&peer)?;
        let shares = self.transport.list_shares(&url, &fingerprint).await?;
        Ok(shares
            .shares
            .into_iter()
            .map(|entry| RemoteAgentView {
                peer_id: peer.id.clone(),
                peer_display_name: peer.display_name.clone(),
                share_id: entry.share_id,
                label: entry.label,
                backend: entry.backend,
                expires_at: entry.expires_at,
            })
            .collect())
    }

    pub async fn list_outbound(&self, user_id: &str) -> Result<Vec<OutboundRequestView>, NetworkError> {
        self.ensure_owner(user_id)?;
        let peers = self.repo.list_peers().await?;
        Ok(self
            .repo
            .list_outbound(user_id, LIST_LIMIT)
            .await?
            .into_iter()
            .map(|row| outbound_view(row, &peers))
            .collect())
    }

    pub async fn get_outbound(&self, user_id: &str, id: &str) -> Result<OutboundRequestView, NetworkError> {
        self.ensure_owner(user_id)?;
        let row = self.own_outbound(user_id, id).await?;
        let peers = self.repo.list_peers().await?;
        Ok(outbound_view(row, &peers))
    }

    async fn own_outbound(&self, user_id: &str, id: &str) -> Result<NetworkOutboundRequestRow, NetworkError> {
        match self.repo.find_outbound(id).await? {
            Some(row) if row.user_id == user_id => Ok(row),
            _ => Err(NetworkError::RequestNotFound),
        }
    }

    /// Persist the request first, then deliver it in the background.
    pub async fn send(&self, user_id: &str, req: SendRemoteRequest) -> Result<OutboundRequestView, NetworkError> {
        self.ensure_owner(user_id)?;
        let peer = self.peer(&req.peer_id).await?;
        callable_peer(&peer)?;
        if req.content.trim().is_empty() {
            return Err(NetworkError::InvalidRequest("content is empty".into()));
        }
        if req.content.len() > policy::MAX_CONTENT_BYTES {
            return Err(NetworkError::PayloadTooLarge);
        }
        if req.share_id.is_empty() || req.share_id.len() > 64 {
            return Err(NetworkError::InvalidRequest("bad share id".into()));
        }
        let thread_id = match req.thread_id {
            Some(thread) if policy::valid_request_id(&thread) => thread,
            Some(_) => return Err(NetworkError::InvalidRequest("bad thread id".into())),
            None => uuid::Uuid::now_v7().to_string(),
        };
        let deadline_secs = req
            .deadline_secs
            .unwrap_or(policy::DEFAULT_DEADLINE.as_secs())
            .clamp(60, policy::MAX_DEADLINE.as_secs());
        let label = clean_display_name(&req.share_label).unwrap_or_else(|_| "agent".to_owned());
        let request_id = uuid::Uuid::now_v7().to_string();
        let row = self
            .repo
            .insert_outbound(InsertOutboundParams {
                user_id,
                peer_id: &peer.id,
                share_id: &req.share_id,
                share_label: &label,
                request_id: &request_id,
                thread_id: &thread_id,
                content: &req.content,
                deadline_at: now_ms() + (deadline_secs as i64) * 1000,
            })
            .await?;
        info!(request_id = %row.request_id, peer = %&peer.fingerprint[..16], "network: remote request created");
        self.outbound.drive(row.id.clone());
        Ok(outbound_view(row, &[peer]))
    }

    pub async fn cancel_outbound(&self, user_id: &str, id: &str) -> Result<OutboundRequestView, NetworkError> {
        self.ensure_owner(user_id)?;
        let row = self.own_outbound(user_id, id).await?;
        if RemoteRequestState::parse(&row.state).is_some_and(RemoteRequestState::is_terminal) {
            return Err(NetworkError::AlreadyFinished);
        }
        self.repo
            .update_outbound(
                &row.id,
                &OutboundUpdate {
                    request: RequestUpdate {
                        updated_at: now_ms(),
                        ..Default::default()
                    },
                    cancel_requested: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        info!(request_id = %row.request_id, "network: cancel requested by requester");
        self.outbound.cancel_now(&row.id).await?;
        self.outbound.drive(row.id.clone());
        self.get_outbound(user_id, id).await
    }

    /// Requests peers sent to this host (owner view; content and results stay in
    /// the linked conversation).
    pub async fn list_inbound(&self, user_id: &str) -> Result<Vec<InboundRequestView>, NetworkError> {
        self.ensure_owner(user_id)?;
        let peers = self.repo.list_peers().await?;
        let shares = self.repo.list_shares(None).await?;
        Ok(self
            .repo
            .list_inbound(LIST_LIMIT)
            .await?
            .into_iter()
            .map(|row| inbound_view(row, &peers, &shares))
            .collect())
    }
}

fn callable_peer(peer: &NetworkPeerRow) -> Result<(String, Fingerprint), NetworkError> {
    match PeerState::parse(&peer.state) {
        Some(PeerState::Trusted) => {}
        Some(PeerState::Revoked) => return Err(NetworkError::PeerRevoked),
        _ => return Err(NetworkError::PeerUntrusted),
    }
    let url = peer
        .peer_url
        .clone()
        .ok_or_else(|| NetworkError::InvalidRequest("add this peer by its address first".into()))?;
    let fingerprint = Fingerprint::parse(&peer.fingerprint).map_err(|e| NetworkError::Internal(e.to_string()))?;
    Ok((url, fingerprint))
}

/// Accept `https://host:port` only (no path, query or credentials).
fn normalize_peer_url(raw: &str) -> Result<String, NetworkError> {
    let url =
        reqwest::Url::parse(raw.trim()).map_err(|_| NetworkError::InvalidRequest("invalid peer address".into()))?;
    let bad = url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.path().is_empty() || url.path() == "/");
    if bad {
        return Err(NetworkError::InvalidRequest(
            "peer address must look like https://192.168.1.20:25820".into(),
        ));
    }
    let port = url.port_or_known_default().unwrap_or(policy::DEFAULT_PEER_PORT);
    let host = url.host_str().unwrap_or_default();
    Ok(format!("https://{host}:{port}"))
}

fn peer_name(peers: &[NetworkPeerRow], id: &str) -> String {
    peers
        .iter()
        .find(|peer| peer.id == id)
        .map(|peer| peer.display_name.clone())
        .unwrap_or_default()
}

fn peer_view(row: NetworkPeerRow) -> PeerView {
    PeerView {
        state: PeerState::parse(&row.state).unwrap_or(PeerState::Revoked),
        id: row.id,
        fingerprint: row.fingerprint,
        display_name: row.display_name,
        peer_url: row.peer_url,
        verification_code: row.verification_code,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn share_view(row: NetworkShareRow, peers: &[NetworkPeerRow]) -> ShareView {
    ShareView {
        peer_display_name: peer_name(peers, &row.peer_id),
        id: row.id,
        peer_id: row.peer_id,
        label: row.label,
        backend: row.backend,
        mode: row.mode,
        workspace: row.workspace,
        expires_at: row.expires_at,
        revoked_at: row.revoked_at,
        created_at: row.created_at,
    }
}

fn outbound_view(row: NetworkOutboundRequestRow, peers: &[NetworkPeerRow]) -> OutboundRequestView {
    OutboundRequestView {
        peer_display_name: peer_name(peers, &row.peer_id),
        state: RemoteRequestState::parse(&row.state).unwrap_or(RemoteRequestState::Failed),
        waiting_kind: row.waiting_kind.as_deref().and_then(WaitingKind::parse),
        id: row.id,
        peer_id: row.peer_id,
        share_id: row.share_id,
        share_label: row.share_label,
        request_id: row.request_id,
        thread_id: row.thread_id,
        content: row.content,
        error_code: row.error_code,
        result_text: row.result_text,
        peer_reachable: row.peer_reachable,
        cancel_requested: row.cancel_requested,
        deadline_at: row.deadline_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
        finished_at: row.finished_at,
    }
}

fn inbound_view(
    row: NetworkInboundRequestRow,
    peers: &[NetworkPeerRow],
    shares: &[NetworkShareRow],
) -> InboundRequestView {
    let share_label = shares
        .iter()
        .find(|share| share.id == row.share_id)
        .map(|share| share.label.clone())
        .unwrap_or_default();
    InboundRequestView {
        peer_display_name: peer_name(peers, &row.peer_id),
        state: RemoteRequestState::parse(&row.state).unwrap_or(RemoteRequestState::Failed),
        waiting_kind: row.waiting_kind.as_deref().and_then(WaitingKind::parse),
        share_label,
        id: row.id,
        peer_id: row.peer_id,
        share_id: row.share_id,
        request_id: row.request_id,
        error_code: row.error_code,
        conversation_id: row.conversation_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
        finished_at: row.finished_at,
    }
}
