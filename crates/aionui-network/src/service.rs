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
use futures_util::{StreamExt, stream};
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
    poll_worker_started: OnceLock<()>,
    poll_reconcile_lock: tokio::sync::Mutex<()>,
}

impl NetworkService {
    pub fn set_team_sink(&self, sink: Arc<dyn crate::ports::LanTeamMessageSink>) -> Result<(), Arc<dyn crate::ports::LanTeamMessageSink>> {
        self.inbound.set_team_sink(sink)
    }

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
            poll_worker_started: OnceLock::new(),
            poll_reconcile_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Boot: recover the inbox, resume the outbox, start the dispatcher and,
    /// when enabled, the listener. A listener failure (port in use) is
    /// reported in status but does not stop the host: local use keeps working.
    pub async fn start(self: &Arc<Self>, cli_listen: Option<SocketAddr>) -> Result<(), NetworkError> {
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
        if self.poll_worker_started.set(()).is_ok() {
            let service = Arc::downgrade(self);
            tokio::spawn(async move {
                loop {
                    let Some(service) = service.upgrade() else { break };
                    if let Err(error) = service.inbound.recover_team_messages().await {
                        warn!(code = error.code(), "network: LAN team recovery scan failed");
                    }
                    if service.listener.running_addr().is_some() {
                        if let Err(error) = service.inbound.sync_team_members().await {
                            warn!(code = error.code(), "network: LAN team member sync failed");
                        }
                        if let Err(error) = service.dispatch_lan_team_outbound().await {
                            warn!(code = error.code(), "network: LAN team outbox dispatch failed");
                        }
                    }
                    drop(service);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            });
            let service = Arc::downgrade(self);
            tokio::spawn(async move {
                loop {
                    let Some(service) = service.upgrade() else { break };
                    if service.listener.running_addr().is_some() {
                        let owner = service.host.owner_user_id();
                        match service.repo.list_team_poll_consents(owner).await {
                            Ok(consents) => {
                                if !consents.is_empty() {
                                    let _ = tokio::time::timeout(
                                        std::time::Duration::from_secs(3), service.list_peers(owner),
                                    ).await;
                                }
                                for (peer, invitation) in consents {
                                    let _ = tokio::time::timeout(
                                        std::time::Duration::from_secs(5),
                                        service.reconcile_team_invitation(owner, &peer, &invitation),
                                    ).await;
                                }
                            }
                            Err(error) => warn!(%error, "network: unable to load LAN poll consents"),
                        }
                    }
                    drop(service);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            });
        }
        Ok(())
    }

    pub async fn send_lan_team_message(
        &self, user_id: &str, team_id: &str, peer_id: &str, remote_team_id: &str, content: &str,
    ) -> Result<String, NetworkError> {
        self.ensure_owner(user_id)?;
        if content.trim().is_empty() { return Err(NetworkError::InvalidRequest("message is empty".into())); }
        if content.len() > policy::MAX_CONTENT_BYTES { return Err(NetworkError::PayloadTooLarge); }
        let id = uuid::Uuid::now_v7().to_string();
        if !self.repo.enqueue_lan_team_outbound(&id, user_id, team_id, peer_id, remote_team_id, content).await? {
            return Err(NetworkError::TeamNotFound);
        }
        Ok(id)
    }

    pub async fn lan_team_delivery_statuses(&self, user_id: &str, team_id: &str)
        -> Result<Vec<aionui_api_types::LanTeamDeliveryStatus>, NetworkError> {
        self.ensure_owner(user_id)?;
        Ok(self.repo.lan_team_delivery_statuses(user_id, team_id).await?.into_iter()
            .map(|(message_id, state)| aionui_api_types::LanTeamDeliveryStatus { message_id, state }).collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_lan_team_message_with_mailbox(
        &self, user_id: &str, team_id: &str, peer_id: &str, remote_team_id: &str,
        from_slot_id: &str, to_slot_id: &str, content: &str,
    ) -> Result<aionui_db::models::MailboxMessageRow, NetworkError> {
        self.ensure_owner(user_id)?;
        if content.trim().is_empty() { return Err(NetworkError::InvalidRequest("message is empty".into())); }
        if content.len() > policy::MAX_CONTENT_BYTES { return Err(NetworkError::PayloadTooLarge); }
        let message = aionui_db::models::MailboxMessageRow {
            id: uuid::Uuid::now_v7().to_string(), team_id: team_id.to_owned(), to_agent_id: to_slot_id.to_owned(),
            from_agent_id: from_slot_id.to_owned(), msg_type: "message".into(), content: content.to_owned(),
            summary: None, files: None, read: false, created_at: now_ms(),
        };
        if !self.repo.enqueue_lan_team_outbound_with_mailbox(user_id, peer_id, remote_team_id, &message).await? {
            return Err(NetworkError::TeamNotFound);
        }
        Ok(message)
    }

    async fn dispatch_lan_team_outbound(&self) -> Result<(), NetworkError> {
        let rows = self.repo.pending_lan_team_outbound(now_ms(), 8).await?;
        let results = stream::iter(rows).map(|row| async move {
            let Some(peer) = self.repo.find_peer(&row.peer_id).await? else { return Ok(()) };
            if self.repo.authorized_lan_team_member(&row.user_id, &row.team_id, &peer.fingerprint, &row.remote_team_id).await?.as_deref() != Some(row.peer_id.as_str()) {
                self.repo.finish_lan_team_outbound(&row.id, "revoked").await?;
                return Ok(());
            }
            let Ok((url, fingerprint)) = callable_peer(&peer) else {
                self.repo.defer_lan_team_outbound(&row.id, now_ms() + 3_000).await?;
                return Ok(());
            };
            let message = aionui_api_types::PeerTeamMessage {
                request_id: row.id.clone(), team_id: row.remote_team_id, remote_team_id: row.team_id, content: row.content,
            };
            match tokio::time::timeout(std::time::Duration::from_secs(5), self.transport.send_team_message(&url, &fingerprint, &message)).await {
                Ok(Ok(_)) => { self.repo.finish_lan_team_outbound(&row.id, "delivered").await?; }
                Ok(Err(NetworkError::PeerRevoked | NetworkError::PeerUntrusted)) => {
                    self.repo.finish_lan_team_outbound(&row.id, "revoked").await?;
                }
                _ => { self.repo.defer_lan_team_outbound(&row.id, now_ms() + 3_000).await?; }
            }
            Ok::<(), NetworkError>(())
        }).buffer_unordered(8).collect::<Vec<_>>().await;
        for result in results {
            result?;
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

    /// Refresh the address of a known peer after LAN discovery without pairing
    /// with unknown hosts. The observed certificate remains the identity.
    pub async fn observe_known_peer(&self, user_id: &str, req: AddPeerRequest) -> Result<Option<aionui_api_types::DiscoveredLanPeer>, NetworkError> {
        self.ensure_owner(user_id)?;
        let url = normalize_peer_url(&req.url)?;
        let (fingerprint, hello) = self.transport.observe(&url).await?;
        if &fingerprint == self.host.fingerprint() {
            return Ok(None);
        }
        let peer = self.repo.find_peer_by_fingerprint(fingerprint.as_str()).await?;
        let state = peer.as_ref().and_then(|p| PeerState::parse(&p.state));
        if let Some(peer) = &peer
            && state != Some(PeerState::Revoked)
            && hello.caller_state != Some(PeerState::Revoked)
        {
            self.repo.update_peer(&peer.id, UpdatePeerParams {
                peer_url: Some(&url),
                ..Default::default()
            }).await?;
        }
        Ok(Some(aionui_api_types::DiscoveredLanPeer {
            url,
            fingerprint: fingerprint.to_string(),
            display_name: clean_display_name(&hello.display_name).unwrap_or_else(|_| fingerprint.short().to_owned()),
            state: if hello.caller_state == Some(PeerState::Revoked) { Some(PeerState::Revoked) } else { state },
        }))
    }

    pub async fn list_peers(&self, user_id: &str) -> Result<Vec<PeerView>, NetworkError> {
        self.ensure_owner(user_id)?;
        policy::prune_expired_pairings(self.repo.as_ref()).await?;
        let peers = self.repo.list_peers().await?;
        // The responder is the only owner who approves a new connection. The
        // initiator learns that decision through the authenticated hello on the
        // next poll and becomes trusted locally without a second click.
        let mut approvals = tokio::task::JoinSet::new();
        for peer in peers.iter().filter(|p| p.state == PeerState::PendingOutbound.as_str()) {
            let Some(url) = peer.peer_url.clone() else { continue };
            let transport = self.transport.clone();
            let id = peer.id.clone();
            let expected = peer.fingerprint.clone();
            approvals.spawn(async move {
                let result = tokio::time::timeout(std::time::Duration::from_secs(1), transport.observe(&url)).await;
                match result {
                    Ok(Ok((fingerprint, hello)))
                        if fingerprint.as_str() == expected && hello.caller_state == Some(PeerState::Trusted) => Some(id),
                    _ => None,
                }
            });
        }
        while let Some(result) = approvals.join_next().await {
            if let Ok(Some(id)) = result {
                self.repo.compare_and_set_peer_state(
                    &id, PeerState::PendingOutbound.as_str(), PeerState::Trusted.as_str(),
                ).await?;
            }
        }
        // A trusted peer can revoke us independently. An unreachable peer is
        // not a revocation; require both its certificate and explicit state.
        let mut checks = tokio::task::JoinSet::new();
        for peer in peers.iter().filter(|p| p.state == PeerState::Trusted.as_str()) {
            let Some(url) = peer.peer_url.clone() else { continue };
            let transport = self.transport.clone();
            let id = peer.id.clone();
            let expected = peer.fingerprint.clone();
            checks.spawn(async move {
                let result = tokio::time::timeout(std::time::Duration::from_secs(1), transport.observe(&url)).await;
                match result {
                    Ok(Ok((fingerprint, hello)))
                        if fingerprint.as_str() == expected && hello.caller_state == Some(PeerState::Revoked) =>
                    {
                        Some(id)
                    }
                    _ => None,
                }
            });
        }
        while let Some(result) = checks.join_next().await {
            if let Ok(Some(id)) = result
                && self
                    .repo
                    .revoke_peer_and_memberships(&id, Some(PeerState::Trusted.as_str()))
                    .await?
            {
                self.inbound.cancel_live_for(&id, None).await?;
                self.wake_outbound_for(&id).await?;
            }
        }
        Ok(self.repo.list_peers().await?.into_iter().map(peer_view).collect())
    }

    /// Contact another host by address and send it a pairing request. Nothing is
    /// trusted until this owner approves after comparing the verification code.
    pub async fn add_peer(&self, user_id: &str, req: AddPeerRequest) -> Result<PeerView, NetworkError> {
        self.add_peer_checked(user_id, &req.url, None).await
    }

    pub async fn add_pinned_peer(
        &self,
        user_id: &str,
        req: aionui_api_types::AddPinnedPeerRequest,
    ) -> Result<PeerView, NetworkError> {
        self.add_peer_checked(user_id, &req.url, Some(&req.fingerprint)).await
    }

    async fn add_peer_checked(&self, user_id: &str, address: &str, expected: Option<&str>) -> Result<PeerView, NetworkError> {
        self.ensure_owner(user_id)?;
        let url = normalize_peer_url(address)?;
        let (fingerprint, hello) = self.transport.observe(&url).await?;
        if expected.is_some_and(|expected| expected != fingerprint.as_str()) {
            return Err(NetworkError::FingerprintMismatch);
        }
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
            Some(PeerState::PendingInbound) => {}
            Some(PeerState::PendingOutbound) => {
                return Err(NetworkError::InvalidRequest(
                    "the other host must approve this connection".into(),
                ));
            }
            Some(PeerState::Trusted) => return Ok(peer_view(peer)),
            _ => return Err(NetworkError::PeerRevoked),
        }
        if !self
            .repo
            .compare_and_set_peer_state(id, PeerState::PendingInbound.as_str(), PeerState::Trusted.as_str())
            .await?
        {
            let current = self.peer(id).await?;
            return if current.state == PeerState::Trusted.as_str() {
                Ok(peer_view(current))
            } else {
                Err(NetworkError::PeerRevoked)
            };
        }
        info!(peer = %&peer.fingerprint[..16], "network: peer trusted by owner");
        Ok(peer_view(self.peer(id).await?))
    }

    pub async fn revoke_peer(&self, user_id: &str, id: &str) -> Result<PeerView, NetworkError> {
        self.ensure_owner(user_id)?;
        let peer = self.peer(id).await?;
        if !self.repo.revoke_peer_and_memberships(id, None).await? {
            return Err(NetworkError::PeerNotFound);
        }
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
        self.repo.revoke_peer_and_memberships(id, None).await?;
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

    pub async fn set_team_shared(&self, user_id: &str, team_id: &str, enabled: bool) -> Result<(), NetworkError> {
        self.ensure_owner(user_id)?;
        self.repo
            .set_team_shared(user_id, team_id, enabled)
            .await
            .map_err(|error| match error {
                aionui_db::DbError::NotFound(_) => NetworkError::TeamNotFound,
                other => NetworkError::Db(other),
            })?;
        Ok(())
    }

    pub async fn shared_teams(&self, user_id: &str) -> Result<Vec<aionui_api_types::LanTeam>, NetworkError> {
        self.ensure_owner(user_id)?;
        Ok(self
            .repo
            .list_shared_teams(user_id)
            .await?
            .into_iter()
            .map(|(id, name)| aionui_api_types::LanTeam { id, name })
            .collect())
    }

    pub async fn remote_teams(
        &self,
        user_id: &str,
        peer_id: &str,
    ) -> Result<Vec<aionui_api_types::LanTeam>, NetworkError> {
        self.ensure_owner(user_id)?;
        let peer = self.peer(peer_id).await?;
        let (url, fingerprint) = callable_peer(&peer)?;
        self.transport.list_teams(&url, &fingerprint).await
    }

    pub async fn remote_team_invitations(
        &self,
        user_id: &str,
        peer_id: &str,
    ) -> Result<Vec<aionui_api_types::PeerTeamInvitation>, NetworkError> {
        self.ensure_owner(user_id)?;
        let peer = self.peer(peer_id).await?;
        let (url, fingerprint) = callable_peer(&peer)?;
        Ok(self.transport.list_team_invitations(&url, &fingerprint).await?
            .into_iter().filter(|poll| poll.state != "completed").collect())
    }

    pub async fn pending_local_team_invitation(&self, user_id: &str, team_id: &str)
        -> Result<Option<aionui_api_types::PendingLocalLanInvitation>, NetworkError> {
        self.ensure_owner(user_id)?;
        let Some((id, candidate_fingerprint, state)) = self.repo.pending_local_team_invitation(user_id, team_id).await? else {
            return Ok(None);
        };
        let mut participants = Vec::new();
        for (fingerprint, decision) in self.repo.team_invitation_votes(user_id, &id).await? {
            let display_name = if fingerprint == self.host.fingerprint().as_str() {
                Some(self.host.display_name())
            } else {
                self.repo.find_peer_by_fingerprint(&fingerprint).await?.map(|peer| peer.display_name)
            };
            participants.push(aionui_api_types::PeerInvitationParticipant {
                fingerprint, display_name, decision, peer_url: None, team_id: None,
            });
        }
        Ok(Some(aionui_api_types::PendingLocalLanInvitation { id, candidate_fingerprint, state, participants }))
    }

    pub async fn cancel_team_invitation(&self, user_id: &str, team_id: &str, invitation_id: &str) -> Result<(), NetworkError> {
        self.ensure_owner(user_id)?;
        if !self.repo.cancel_team_invitation(user_id, team_id, invitation_id).await? {
            return Err(NetworkError::RequestNotFound);
        }
        Ok(())
    }

    pub async fn create_team_invitation(
        &self,
        user_id: &str,
        team_id: &str,
        peer_id: &str,
    ) -> Result<aionui_api_types::CreateLanTeamInvitationResponse, NetworkError> {
        self.ensure_owner(user_id)?;
        let peer = self.peer(peer_id).await?;
        if peer.state != PeerState::Trusted.as_str() {
            return Err(NetworkError::PeerUntrusted);
        }
        let id = uuid::Uuid::now_v7().to_string();
        self.repo
            .create_team_invitation(user_id, team_id, &id, self.host.fingerprint().as_str(), peer_id)
            .await
            .map_err(|error| match error {
                aionui_db::DbError::NotFound(_) => NetworkError::TeamNotFound,
                aionui_db::DbError::Conflict(_) => NetworkError::RequestConflict,
                other => NetworkError::Db(other),
            })?;
        if !self.repo
            .decide_team_invitation(user_id, &id, self.host.fingerprint().as_str(), true, Some(team_id))
            .await?
        {
            return Err(NetworkError::RequestConflict);
        }
        Ok(aionui_api_types::CreateLanTeamInvitationResponse { id })
    }

    pub async fn vote_remote_team_invitation(
        &self,
        user_id: &str,
        peer_id: &str,
        request: aionui_api_types::PeerInvitationVoteRequest,
    ) -> Result<aionui_api_types::PeerInvitationVoteResponse, NetworkError> {
        self.ensure_owner(user_id)?;
        let _withdraw_guard = if request.approve { None } else { Some(self.poll_reconcile_lock.lock().await) };
        if request.approve {
            let team_id = request.team_id.as_deref().filter(|id| !id.trim().is_empty())
                .ok_or_else(|| NetworkError::InvalidRequest("a conversation is required to approve".into()))?;
            if !self.repo.list_shared_teams(user_id).await?.iter().any(|(id, _)| id == team_id) {
                return Err(NetworkError::TeamNotFound);
            }
        }
        let peer = self.peer(peer_id).await?;
        let (url, fingerprint) = callable_peer(&peer)?;
        if request.approve {
            let invitations = self.transport.list_team_invitations(&url, &fingerprint).await?;
            let invitation = invitations.iter().find(|poll| poll.id == request.invitation_id)
                .ok_or(NetworkError::RequestNotFound)?;
            let mut expected: Vec<_> = invitation.participants.iter().map(|v| v.fingerprint.clone()).collect();
            let mut displayed = request.participants.clone();
            expected.sort_unstable();
            displayed.sort_unstable();
            if expected != displayed || expected.is_empty()
                || !expected.iter().any(|p| p == self.host.fingerprint().as_str())
                || invitation.decision != "pending"
            {
                return Err(NetworkError::InvalidRequest("invitation participants or decision changed".into()));
            }
            let participants = serde_json::to_string(&expected).map_err(|e| NetworkError::Internal(e.to_string()))?;
            if !self.repo.record_team_poll_consent(user_id, request.team_id.as_deref().unwrap_or_default(), fingerprint.as_str(), &request.invitation_id, &participants).await? {
                return Err(NetworkError::InvalidRequest("Choose a conversation whose LAN members are in this invitation, and resolve any other pending invitation first".into()));
            }
        }
        let response = self.transport.vote_invitation(&url, &fingerprint, &request).await?;
        if !request.approve && response.recorded {
            self.repo.remove_team_poll_consent(user_id, fingerprint.as_str(), &request.invitation_id).await?;
        }
        Ok(response)
    }

    pub async fn vote_local_team_invitation(
        &self,
        user_id: &str,
        request: aionui_api_types::PeerInvitationVoteRequest,
    ) -> Result<aionui_api_types::PeerInvitationVoteResponse, NetworkError> {
        self.ensure_owner(user_id)?;
        if request.approve {
            let team_id = self.repo.team_invitation_team_id(user_id, &request.invitation_id).await?
                .ok_or(NetworkError::RequestNotFound)?;
            if request.team_id.as_deref() != Some(team_id.as_str()) {
                return Err(NetworkError::InvalidRequest("invitation belongs to a different conversation".into()));
            }
        }
        let recorded = self.repo
            .decide_team_invitation(user_id, &request.invitation_id, self.host.fingerprint().as_str(), request.approve, request.team_id.as_deref().filter(|_| request.approve))
            .await?;
        Ok(aionui_api_types::PeerInvitationVoteResponse { recorded })
    }

    pub async fn reconcile_team_invitation(
        &self,
        user_id: &str,
        coordinator_id: &str,
        invitation_id: &str,
    ) -> Result<(), NetworkError> {
        let _guard = self.poll_reconcile_lock.lock().await;
        self.ensure_owner(user_id)?;
        let coordinator = self.peer(coordinator_id).await?;
        let (url, fingerprint) = callable_peer(&coordinator)?;
        let (_, consent) = self.repo.team_poll_consent(user_id, fingerprint.as_str(), invitation_id).await?
            .ok_or(NetworkError::RequestNotFound)?;
        let expected: Vec<String> = serde_json::from_str(&consent)
            .map_err(|error| NetworkError::Internal(error.to_string()))?;
        let invitations = self.transport.list_team_invitations(&url, &fingerprint).await?;
        let Some(invitation) = invitations.into_iter().find(|poll| poll.id == invitation_id) else {
            self.repo.remove_team_poll_consent(user_id, fingerprint.as_str(), invitation_id).await?;
            return Ok(());
        };
        let mut actual: Vec<String> = invitation.participants.iter().map(|participant| participant.fingerprint.clone()).collect();
        actual.sort_unstable();
        if !invitation.ready_for_pairing || invitation.decision != "approved" || actual != expected {
            return Err(NetworkError::RequestConflict);
        }
        for participant in &invitation.participants {
            let Some(url) = participant.peer_url.as_deref() else { continue };
            let Some(peer) = self.repo.find_peer_by_fingerprint(&participant.fingerprint).await? else { continue };
            if peer.peer_url.is_some() || peer.state == PeerState::Revoked.as_str() { continue; }
            if let Ok((observed, hello)) = self.transport.observe(url).await
                && observed.as_str() == participant.fingerprint
                && hello.caller_state != Some(PeerState::Revoked)
            {
                self.repo.update_peer(&peer.id, UpdatePeerParams { peer_url: Some(url), ..Default::default() }).await?;
            }
        }
        if invitation.state == "completed" {
            let members = invitation.participants.iter().map(|participant| {
                participant.team_id.clone().map(|team| (participant.fingerprint.clone(), team))
            }).collect::<Option<Vec<_>>>().ok_or(NetworkError::RequestConflict)?;
            if !self.repo.apply_team_poll_membership(user_id, fingerprint.as_str(), invitation_id, self.host.fingerprint().as_str(), &members).await? {
                return Err(NetworkError::RequestConflict);
            }
            tracing::info!(invitation_id, "network: LAN team roster synchronized");
            return Ok(());
        }
        for participant in invitation.participants {
            if participant.fingerprint == self.host.fingerprint().as_str() || participant.fingerprint == fingerprint.as_str() {
                continue;
            }
            // Recheck the local owner decision before each trust-changing action.
            if self.repo.team_poll_consent(user_id, fingerprint.as_str(), invitation_id).await?.is_none() {
                return Err(NetworkError::RequestConflict);
            }
            if let Some(peer) = self.repo.find_peer_by_fingerprint(&participant.fingerprint).await? {
                match PeerState::parse(&peer.state) {
                    Some(PeerState::PendingInbound) => { self.approve_peer(user_id, &peer.id).await?; }
                    Some(PeerState::Revoked) => return Err(NetworkError::PeerRevoked),
                    _ => {}
                }
            } else if self.host.fingerprint().as_str() < participant.fingerprint.as_str()
                && let Some(url) = participant.peer_url
            {
                self.add_pinned_peer(user_id, aionui_api_types::AddPinnedPeerRequest {
                    url,
                    fingerprint: participant.fingerprint,
                }).await?;
            }
        }
        let peers = self.repo.list_peers().await?;
        if expected.iter().all(|member| member == self.host.fingerprint().as_str()
            || peers.iter().any(|peer| peer.fingerprint == *member && peer.state == PeerState::Trusted.as_str()))
        {
            if self.repo.team_poll_consent(user_id, fingerprint.as_str(), invitation_id).await?.is_none() {
                return Err(NetworkError::RequestConflict);
            }
            let response = self.transport.attest_team_pairs(&url, &fingerprint, &aionui_api_types::PeerPairAttestationRequest {
                invitation_id: invitation_id.to_owned(), participants: expected,
            }).await?;
            if !response.recorded {
                return Err(NetworkError::RequestConflict);
            }
        }
        Ok(())
    }

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
