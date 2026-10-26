//! Owner-host side of the peer protocol: pairing requests, the share directory,
//! the durable inbox, and the dispatcher that runs remote turns locally.
//!
//! Execution rules (ADR-009):
//! - a request is persisted before it is acknowledged; a retry with the same
//!   `request_id` returns the stored request, different content conflicts;
//! - a turn starts only after a `queued → running` claim fenced by this
//!   process's `claim_token`; every later write is fenced by it too;
//! - after a restart, requests that were running are failed with
//!   `HOST_RESTARTED` and never re-run (side effects may have happened);
//! - the grant (trusted peer + active share) is checked before dispatch and
//!   re-checked by the sweep while a turn runs; revoke/unshare cancel at once.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aionui_api_types::{
    PEER_CONTRACT_VERSION, PeerHelloResponse, PeerPairingRequest, PeerPairingResponse, PeerPairingReveal,
    PeerPairingRevealResponse, PeerRequestStatus, PeerShareEntry, PeerSharesResponse, PeerState, PeerSubmitRequest,
    RemoteRequestState, WaitingKind,
};
use aionui_common::now_ms;
use aionui_db::models::{NetworkInboundRequestRow, NetworkPeerRow, NetworkShareRow};
use aionui_db::{DbError, INetworkRepository, InsertInboundParams, InsertPeerParams, RequestUpdate};
use aionui_peer::Fingerprint;
use tokio::sync::{Notify, mpsc, watch};
use tracing::{debug, info, warn};

use crate::error::NetworkError;
use crate::host::HostContext;
use crate::policy::{self, codes};
use crate::ports::{RemoteConversationSpec, RemoteTurnRunner, TurnEvent};

/// Why a running turn is being stopped.
type CancelReason = Option<&'static str>;

pub struct InboundService {
    repo: Arc<dyn INetworkRepository>,
    runner: Arc<dyn RemoteTurnRunner>,
    host: Arc<HostContext>,
    /// Fences every execution write to this process (fresh per boot).
    claim_token: String,
    wake: Notify,
    /// Bumped on every inbound change; long-polls wait on it.
    changes: watch::Sender<u64>,
    running: Mutex<HashMap<String, watch::Sender<CancelReason>>>,
    /// Pairing exchanges waiting for the initiator's reveal, by caller fingerprint (ADR-016).
    pairings: Mutex<HashMap<String, PairingExchange>>,
}

/// The responder's half of a commit-then-reveal pairing exchange (ADR-016).
struct PairingExchange {
    nonce: [u8; 32],
    display_name: String,
    at_ms: i64,
}

impl InboundService {
    pub fn new(repo: Arc<dyn INetworkRepository>, runner: Arc<dyn RemoteTurnRunner>, host: Arc<HostContext>) -> Self {
        Self {
            repo,
            runner,
            host,
            claim_token: format!("boot-{}", uuid::Uuid::now_v7()),
            wake: Notify::new(),
            changes: watch::channel(0).0,
            running: Mutex::new(HashMap::new()),
            pairings: Mutex::new(HashMap::new()),
        }
    }

    fn changed(&self) {
        self.changes.send_modify(|v| *v += 1);
        self.wake.notify_one();
    }

    // ── authorization ───────────────────────────────────────────────────────

    /// Authorize a caller by its TLS fingerprint. Only trusted peers pass.
    async fn authorize(&self, caller: &Fingerprint) -> Result<NetworkPeerRow, NetworkError> {
        let peer = self
            .repo
            .find_peer_by_fingerprint(caller.as_str())
            .await?
            .ok_or(NetworkError::PeerUntrusted)?;
        match PeerState::parse(&peer.state) {
            Some(PeerState::Trusted) => Ok(peer),
            Some(PeerState::Revoked) => Err(NetworkError::PeerRevoked),
            _ => Err(NetworkError::PeerUntrusted),
        }
    }

    /// The share, when it is active for `peer` right now.
    async fn active_share(&self, peer: &NetworkPeerRow, share_id: &str) -> Result<NetworkShareRow, NetworkError> {
        let share = self
            .repo
            .find_share(share_id)
            .await?
            .ok_or(NetworkError::ShareNotFound)?;
        if share_is_active(&share, &peer.id, now_ms()) {
            Ok(share)
        } else {
            Err(NetworkError::ShareNotFound)
        }
    }

    /// Re-read peer + share and decide whether `row` may still run.
    async fn grant_still_valid(&self, row: &NetworkInboundRequestRow) -> Result<bool, NetworkError> {
        let Some(peer) = self.repo.find_peer(&row.peer_id).await? else {
            return Ok(false);
        };
        if peer.state != PeerState::Trusted.as_str() {
            return Ok(false);
        }
        Ok(match self.repo.find_share(&row.share_id).await? {
            Some(share) => share_is_active(&share, &peer.id, now_ms()),
            None => false,
        })
    }

    // ── peer protocol ───────────────────────────────────────────────────────

    pub async fn hello(&self, caller: &Fingerprint) -> Result<PeerHelloResponse, NetworkError> {
        let caller_state = self
            .repo
            .find_peer_by_fingerprint(caller.as_str())
            .await?
            .and_then(|peer| PeerState::parse(&peer.state));
        Ok(PeerHelloResponse {
            protocol_version: PEER_CONTRACT_VERSION,
            host_fingerprint: self.host.fingerprint().to_string(),
            display_name: self.host.display_name(),
            caller_fingerprint: caller.to_string(),
            caller_state,
        })
    }

    /// A peer asks to pair: step 1 of the commit-then-reveal exchange (ADR-016).
    /// This host picks its nonce and answers only with a commitment to it;
    /// nothing is recorded for the owner until step 2. Never grants trust.
    pub async fn pair(
        &self,
        caller: &Fingerprint,
        body: PeerPairingRequest,
    ) -> Result<PeerPairingResponse, NetworkError> {
        if body.protocol_version != PEER_CONTRACT_VERSION {
            return Err(NetworkError::VersionUnsupported);
        }
        let name = clean_display_name(&body.display_name)?;
        if caller == self.host.fingerprint() {
            return Err(NetworkError::InvalidRequest("a host cannot pair with itself".into()));
        }
        if let Some(peer) = self.repo.find_peer_by_fingerprint(caller.as_str()).await? {
            if peer.state == PeerState::Revoked.as_str() {
                info!(peer = %caller.short(), "network: pairing from revoked peer refused");
                return Err(NetworkError::PeerRevoked);
            }
            // An existing pairing is never re-keyed: the owners forget it to pair again.
            return Err(NetworkError::InvalidRequest(
                "this host already knows the caller; forget the peer to pair again".into(),
            ));
        }
        self.ensure_pairing_slot(caller).await?;
        let nonce = policy::new_pairing_nonce()?;
        {
            let now = now_ms();
            let mut pairings = self.pairings.lock().unwrap_or_else(|e| e.into_inner());
            pairings.retain(|_, exchange| now - exchange.at_ms <= policy::PAIRING_EXCHANGE_TTL_MS);
            // A full map drops its oldest exchange; real exchanges finish within one round trip.
            if pairings.len() >= policy::MAX_PENDING_PAIRINGS as usize
                && !pairings.contains_key(caller.as_str())
                && let Some(oldest) = pairings
                    .iter()
                    .min_by_key(|(_, exchange)| exchange.at_ms)
                    .map(|(key, _)| key.clone())
            {
                pairings.remove(&oldest);
            }
            pairings.insert(
                caller.as_str().to_owned(),
                PairingExchange {
                    nonce,
                    display_name: name,
                    at_ms: now,
                },
            );
        }
        Ok(PeerPairingResponse {
            host_fingerprint: self.host.fingerprint().to_string(),
            display_name: self.host.display_name(),
            state: PeerState::PendingInbound,
            responder_commitment: policy::pairing_commitment(&nonce),
        })
    }

    /// Step 2 of pairing (ADR-016): the caller sends its nonce; this host fixes
    /// the code, records the request for the owner and opens its commitment.
    pub async fn reveal(
        &self,
        caller: &Fingerprint,
        body: PeerPairingReveal,
    ) -> Result<PeerPairingRevealResponse, NetworkError> {
        let exchange = self
            .pairings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(caller.as_str())
            .ok_or_else(|| NetworkError::InvalidRequest("no pairing exchange in progress".into()))?;
        if now_ms() - exchange.at_ms > policy::PAIRING_EXCHANGE_TTL_MS {
            return Err(NetworkError::InvalidRequest("pairing exchange expired".into()));
        }
        let nonce = hex::decode(&body.nonce)
            .ok()
            .filter(|nonce| nonce.len() == 32)
            .ok_or_else(|| NetworkError::InvalidRequest("pairing nonce must be 32 hex bytes".into()))?;
        if self.repo.find_peer_by_fingerprint(caller.as_str()).await?.is_some() {
            return Err(NetworkError::InvalidRequest(
                "this host already knows the caller; forget the peer to pair again".into(),
            ));
        }
        self.ensure_pairing_slot(caller).await?;
        let code = policy::verification_code(caller, self.host.fingerprint(), &nonce, &exchange.nonce);
        match self
            .repo
            .insert_peer(InsertPeerParams {
                fingerprint: caller.as_str(),
                display_name: &exchange.display_name,
                peer_url: None,
                state: PeerState::PendingInbound.as_str(),
                verification_code: &code,
            })
            .await
        {
            Ok(_) => {}
            Err(DbError::Conflict(_)) => {
                return Err(NetworkError::InvalidRequest(
                    "this host already knows the caller; forget the peer to pair again".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        }
        info!(peer = %caller.short(), "network: pairing request recorded, awaiting owner approval");
        Ok(PeerPairingRevealResponse {
            state: PeerState::PendingInbound,
            responder_nonce: hex::encode(exchange.nonce),
        })
    }

    /// Room for one more pending pairing request (after dropping expired ones).
    async fn ensure_pairing_slot(&self, caller: &Fingerprint) -> Result<(), NetworkError> {
        policy::prune_expired_pairings(self.repo.as_ref()).await?;
        if self
            .repo
            .count_peers_in_state(PeerState::PendingInbound.as_str())
            .await?
            >= policy::MAX_PENDING_PAIRINGS
        {
            warn!(peer = %caller.short(), "network: pairing refused, too many pending requests");
            return Err(NetworkError::PairingLimit);
        }
        Ok(())
    }

    pub async fn list_shares(&self, caller: &Fingerprint) -> Result<PeerSharesResponse, NetworkError> {
        let peer = self.authorize(caller).await?;
        let now = now_ms();
        let shares = self
            .repo
            .list_shares(Some(&peer.id))
            .await?
            .into_iter()
            .filter(|share| share_is_active(share, &peer.id, now))
            .map(|share| PeerShareEntry {
                share_id: share.id,
                label: share.label,
                backend: share.backend,
                expires_at: share.expires_at,
            })
            .collect();
        Ok(PeerSharesResponse { shares })
    }

    pub async fn submit(
        &self,
        caller: &Fingerprint,
        body: PeerSubmitRequest,
    ) -> Result<PeerRequestStatus, NetworkError> {
        if body.protocol_version != PEER_CONTRACT_VERSION {
            return Err(NetworkError::VersionUnsupported);
        }
        if !policy::valid_request_id(&body.request_id) || !policy::valid_request_id(&body.thread_id) {
            return Err(NetworkError::InvalidRequest(
                "request_id / thread_id must be 1-64 chars [A-Za-z0-9-]".into(),
            ));
        }
        if body.content.trim().is_empty() {
            return Err(NetworkError::InvalidRequest("content is empty".into()));
        }
        if body.content.len() > policy::MAX_CONTENT_BYTES {
            return Err(NetworkError::PayloadTooLarge);
        }
        let peer = self.authorize(caller).await?;
        let hash = policy::content_hash(&body.share_id, &body.thread_id, &body.content);

        // Idempotency first: a retry must get its receipt even if the share changed since.
        if let Some(existing) = self.repo.find_inbound_by_request(&peer.id, &body.request_id).await? {
            return self.duplicate_receipt(&peer, existing, &hash).await;
        }

        let now = now_ms();
        if body.deadline_at <= now {
            return Err(NetworkError::InvalidRequest("deadline already passed".into()));
        }
        let max_deadline = now + policy::MAX_DEADLINE.as_millis() as i64;
        let share = self.active_share(&peer, &body.share_id).await?;
        let live: Vec<&str> = policy::LIVE_INBOUND_STATES.to_vec();
        if self.repo.count_inbound_in_states(Some(&peer.id), &live).await? >= policy::MAX_LIVE_REQUESTS_PER_PEER
            || self.repo.count_inbound_in_states(None, &live).await? >= policy::MAX_LIVE_REQUESTS_TOTAL
        {
            info!(peer = %caller.short(), request_id = %body.request_id, "network: request refused, queue full");
            return Err(NetworkError::QueueFull);
        }
        let inserted = self
            .repo
            .insert_inbound(InsertInboundParams {
                peer_id: &peer.id,
                share_id: &share.id,
                request_id: &body.request_id,
                thread_id: &body.thread_id,
                content: &body.content,
                content_hash: &hash,
                state: RemoteRequestState::Queued.as_str(),
                deadline_at: body.deadline_at.min(max_deadline),
            })
            .await;
        let row = match inserted {
            Ok(row) => row,
            // Concurrent retry won the insert: answer like a duplicate.
            Err(DbError::Conflict(_)) => {
                let existing = self
                    .repo
                    .find_inbound_by_request(&peer.id, &body.request_id)
                    .await?
                    .ok_or(NetworkError::RequestNotFound)?;
                return self.duplicate_receipt(&peer, existing, &hash).await;
            }
            Err(e) => return Err(e.into()),
        };
        info!(
            peer = %caller.short(),
            request_id = %row.request_id,
            share_id = %share.id,
            "network: request accepted and queued"
        );
        self.changed();
        Ok(self.status_of(&row, true))
    }

    async fn duplicate_receipt(
        &self,
        peer: &NetworkPeerRow,
        existing: NetworkInboundRequestRow,
        hash: &str,
    ) -> Result<PeerRequestStatus, NetworkError> {
        if existing.content_hash != hash {
            warn!(peer = %&peer.fingerprint[..16], request_id = %existing.request_id, "network: request id reused with different content");
            return Err(NetworkError::RequestConflict);
        }
        debug!(request_id = %existing.request_id, "network: duplicate submit answered from inbox");
        let visible = self.result_visible(&existing).await?;
        Ok(self.status_of(&existing, visible))
    }

    /// Long-poll the state of one of the caller's requests.
    pub async fn status(
        &self,
        caller: &Fingerprint,
        request_id: &str,
        after_version: i64,
        wait: Duration,
    ) -> Result<PeerRequestStatus, NetworkError> {
        let mut changes = self.changes.subscribe();
        let deadline = tokio::time::Instant::now() + wait.min(policy::MAX_STATUS_WAIT);
        loop {
            // Re-checked on every wake: a revocation must end an open long-poll too.
            let peer = self.authorize(caller).await?;
            let row = self
                .repo
                .find_inbound_by_request(&peer.id, request_id)
                .await?
                .ok_or(NetworkError::RequestNotFound)?;
            let terminal = RemoteRequestState::parse(&row.state).is_some_and(RemoteRequestState::is_terminal);
            if row.version > after_version || terminal {
                let visible = self.result_visible(&row).await?;
                return Ok(self.status_of(&row, visible));
            }
            match tokio::time::timeout_at(deadline, changes.changed()).await {
                Ok(Ok(())) => continue,
                _ => {
                    self.authorize(caller).await?;
                    let visible = self.result_visible(&row).await?;
                    return Ok(self.status_of(&row, visible));
                }
            }
        }
    }

    /// The requester asks to stop a request. Best effort for a running turn.
    pub async fn cancel(&self, caller: &Fingerprint, request_id: &str) -> Result<PeerRequestStatus, NetworkError> {
        let peer = self.authorize(caller).await?;
        let row = self
            .repo
            .find_inbound_by_request(&peer.id, request_id)
            .await?
            .ok_or(NetworkError::RequestNotFound)?;
        self.cancel_row(&row, codes::CANCELLED_BY_REQUESTER).await?;
        let row = self
            .repo
            .find_inbound(&row.id)
            .await?
            .ok_or(NetworkError::RequestNotFound)?;
        let visible = self.result_visible(&row).await?;
        Ok(self.status_of(&row, visible))
    }

    /// Stop one live request: queued ones end at once, running ones are signalled.
    async fn cancel_row(&self, row: &NetworkInboundRequestRow, code: &'static str) -> Result<(), NetworkError> {
        if !self.repo.request_inbound_cancel(&row.id, now_ms()).await? {
            return Ok(()); // already terminal
        }
        let finished = self
            .repo
            .update_inbound_if_state(
                &row.id,
                RemoteRequestState::Queued.as_str(),
                &terminal_update(RemoteRequestState::Cancelled, Some(code), None),
            )
            .await?;
        if finished {
            info!(request_id = %row.request_id, code, "network: queued request cancelled");
        } else if let Some(signal) = self.running.lock().unwrap_or_else(|e| e.into_inner()).get(&row.id) {
            let _ = signal.send(Some(code));
        }
        self.changed();
        Ok(())
    }

    /// Owner revoked a peer or unshared: stop its live requests now.
    pub async fn cancel_live_for(&self, peer_id: &str, share_id: Option<&str>) -> Result<usize, NetworkError> {
        let live = self.repo.list_inbound_in_states(&policy::LIVE_INBOUND_STATES).await?;
        let mut count = 0;
        for row in live
            .iter()
            .filter(|row| row.peer_id == peer_id && share_id.is_none_or(|s| s == row.share_id))
        {
            self.cancel_row(row, codes::GRANT_REVOKED).await?;
            count += 1;
        }
        if count > 0 {
            info!(peer_id, count, "network: live requests cancelled after revocation");
        }
        // Wake open long-polls even when nothing was live, so they re-authorize.
        self.changed();
        Ok(count)
    }

    async fn result_visible(&self, row: &NetworkInboundRequestRow) -> Result<bool, NetworkError> {
        // Results stay with the owner once the grant is gone.
        Ok(match self.repo.find_share(&row.share_id).await? {
            Some(share) => share.revoked_at.is_none(),
            None => false,
        })
    }

    fn status_of(&self, row: &NetworkInboundRequestRow, result_visible: bool) -> PeerRequestStatus {
        PeerRequestStatus {
            request_id: row.request_id.clone(),
            state: RemoteRequestState::parse(&row.state).unwrap_or(RemoteRequestState::Failed),
            error_code: row.error_code.clone(),
            waiting_kind: row.waiting_kind.as_deref().and_then(WaitingKind::parse),
            result_text: if result_visible { row.result_text.clone() } else { None },
            version: row.version,
        }
    }

    // ── dispatcher ──────────────────────────────────────────────────────────

    /// Recover after a restart, then dispatch on every change and on a bounded sweep.
    pub async fn run(self: Arc<Self>) {
        if let Err(error) = self.recover().await {
            warn!(%error, "network: inbound recovery failed");
        }
        loop {
            if let Err(error) = self.dispatch_ready().await {
                warn!(%error, "network: dispatch pass failed");
            }
            if let Err(error) = self.sweep_running_grants().await {
                warn!(%error, "network: grant sweep failed");
            }
            tokio::select! {
                () = self.wake.notified() => {}
                () = tokio::time::sleep(policy::SWEEP_INTERVAL) => {}
            }
        }
    }

    /// Requests left running by a previous process: fail, never re-run.
    pub async fn recover(&self) -> Result<usize, NetworkError> {
        let stale = self
            .repo
            .list_inbound_in_states(&["running", "waiting_for_owner"])
            .await?;
        let mut recovered = 0;
        for row in stale {
            if row.claim_token.as_deref() == Some(self.claim_token.as_str()) {
                continue;
            }
            let update = terminal_update(RemoteRequestState::Failed, Some(codes::HOST_RESTARTED), None);
            if self.repo.update_inbound_if_state(&row.id, &row.state, &update).await? {
                recovered += 1;
                info!(request_id = %row.request_id, "network: interrupted request marked failed after restart");
            }
        }
        if recovered > 0 {
            self.changed();
        }
        Ok(recovered)
    }

    async fn dispatch_ready(self: &Arc<Self>) -> Result<(), NetworkError> {
        let live = self
            .repo
            .list_inbound_in_states(&["running", "waiting_for_owner"])
            .await?;
        let mut busy_threads: HashSet<(String, String, String)> = live
            .iter()
            .map(|row| (row.peer_id.clone(), row.share_id.clone(), row.thread_id.clone()))
            .collect();
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner()).len();
        let now = now_ms();
        for row in self.repo.list_inbound_in_states(&["queued"]).await? {
            let terminal = if row.deadline_at <= now {
                Some((RemoteRequestState::Expired, codes::DEADLINE_EXCEEDED))
            } else if row.cancel_requested {
                Some((RemoteRequestState::Cancelled, codes::CANCELLED_BY_REQUESTER))
            } else if !self.grant_still_valid(&row).await? {
                Some((RemoteRequestState::Cancelled, codes::GRANT_REVOKED))
            } else {
                None
            };
            if let Some((state, code)) = terminal {
                if self
                    .repo
                    .update_inbound_if_state(&row.id, "queued", &terminal_update(state, Some(code), None))
                    .await?
                {
                    info!(request_id = %row.request_id, code, "network: queued request ended before dispatch");
                    self.changed();
                }
                continue;
            }
            let thread = (row.peer_id.clone(), row.share_id.clone(), row.thread_id.clone());
            if running >= policy::MAX_RUNNING_TURNS || busy_threads.contains(&thread) {
                continue;
            }
            if !self.repo.claim_inbound(&row.id, &self.claim_token, now_ms()).await? {
                continue;
            }
            let (signal, cancel_rx) = watch::channel(None);
            self.running
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(row.id.clone(), signal);
            busy_threads.insert(thread);
            running += 1;
            info!(request_id = %row.request_id, "network: request claimed for execution");
            self.changed();
            let this = Arc::clone(self);
            tokio::spawn(async move {
                let id = row.id.clone();
                this.execute(row, cancel_rx).await;
                this.running.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                this.changed();
            });
        }
        Ok(())
    }

    /// Signal running turns whose grant disappeared (e.g. a share expired).
    async fn sweep_running_grants(&self) -> Result<(), NetworkError> {
        let live = self
            .repo
            .list_inbound_in_states(&["running", "waiting_for_owner"])
            .await?;
        for row in live {
            if !self.grant_still_valid(&row).await? {
                self.cancel_row(&row, codes::GRANT_REVOKED).await?;
            }
        }
        Ok(())
    }

    async fn execute(&self, row: NetworkInboundRequestRow, mut cancel_rx: watch::Receiver<CancelReason>) {
        let outcome = self.run_turn(&row, &mut cancel_rx).await;
        let (state, code, text) = match outcome {
            Ok(done) => done,
            Err(error) => {
                warn!(request_id = %row.request_id, code = error.code(), "network: remote turn could not start");
                (RemoteRequestState::Failed, Some(codes::AGENT_FAILED), None)
            }
        };
        let update = terminal_update(state, code, text.as_deref());
        match self
            .repo
            .update_inbound_fenced(&row.id, &self.claim_token, &update)
            .await
        {
            Ok(true) => info!(
                request_id = %row.request_id,
                state = state.as_str(),
                code = code.unwrap_or(""),
                "network: remote request finished"
            ),
            Ok(false) => warn!(request_id = %row.request_id, "network: terminal write rejected (claim lost)"),
            Err(error) => warn!(request_id = %row.request_id, %error, "network: terminal write failed"),
        }
    }

    /// Run one claimed request to an outcome.
    async fn run_turn(
        &self,
        row: &NetworkInboundRequestRow,
        cancel_rx: &mut watch::Receiver<CancelReason>,
    ) -> Result<(RemoteRequestState, Option<&'static str>, Option<String>), NetworkError> {
        let owner = self.host.owner_user_id();
        // Grant re-check right before the consequential step.
        if !self.grant_still_valid(row).await? {
            return Ok((RemoteRequestState::Cancelled, Some(codes::GRANT_REVOKED), None));
        }
        let conversation_id = match self
            .repo
            .find_thread_conversation(&row.peer_id, &row.share_id, &row.thread_id)
            .await?
        {
            Some(id) => id,
            None => {
                let share = self
                    .repo
                    .find_share(&row.share_id)
                    .await?
                    .ok_or(NetworkError::ShareNotFound)?;
                let peer = self
                    .repo
                    .find_peer(&row.peer_id)
                    .await?
                    .ok_or(NetworkError::PeerNotFound)?;
                let spec = RemoteConversationSpec {
                    name: format!("LAN · {} · {}", peer.display_name, share.label),
                    backend: share.backend.clone(),
                    mode: share.mode.clone(),
                    workspace: share.workspace.clone(),
                };
                self.runner.create_conversation(owner, &spec).await?
            }
        };
        let persisted = self
            .repo
            .update_inbound_fenced(
                &row.id,
                &self.claim_token,
                &RequestUpdate {
                    conversation_id: Some(&conversation_id),
                    updated_at: now_ms(),
                    ..Default::default()
                },
            )
            .await?;
        if !persisted {
            // Cancelled or claim lost between claim and send: do not send.
            return Ok((RemoteRequestState::Cancelled, Some(codes::CANCELLED_BY_REQUESTER), None));
        }
        if let Some(code) = *cancel_rx.borrow() {
            return Ok((RemoteRequestState::Cancelled, Some(code), None));
        }
        info!(request_id = %row.request_id, conversation_id = %conversation_id, "network: dispatching remote turn");
        let mut events = self.runner.start_turn(owner, &conversation_id, &row.content).await?;
        self.follow_turn(row, &conversation_id, &mut events, cancel_rx).await
    }

    async fn follow_turn(
        &self,
        row: &NetworkInboundRequestRow,
        conversation_id: &str,
        events: &mut mpsc::Receiver<TurnEvent>,
        cancel_rx: &mut watch::Receiver<CancelReason>,
    ) -> Result<(RemoteRequestState, Option<&'static str>, Option<String>), NetworkError> {
        let owner = self.host.owner_user_id();
        let deadline = deadline_instant(row.deadline_at);
        let mut text = String::new();
        let mut dirty = false;
        let mut flush = tokio::time::interval(policy::RESULT_FLUSH_INTERVAL);
        loop {
            tokio::select! {
                event = events.recv() => match event {
                    Some(TurnEvent::Text(chunk)) => {
                        text.push_str(&chunk);
                        policy::truncate_utf8(&mut text, policy::MAX_RESULT_BYTES);
                        dirty = true;
                    }
                    Some(TurnEvent::WaitingForOwner(kind)) => {
                        self.write_progress(row, RemoteRequestState::WaitingForOwner, Some(kind), dirty.then_some(text.as_str())).await?;
                        dirty = false;
                        info!(request_id = %row.request_id, kind = kind.as_str(), "network: remote turn waiting for owner");
                    }
                    Some(TurnEvent::Activity) => {
                        self.write_progress_if_waiting(row).await?;
                    }
                    Some(TurnEvent::Finished) => {
                        return Ok((RemoteRequestState::Succeeded, None, Some(text)));
                    }
                    Some(TurnEvent::Failed) | None => {
                        return Ok((RemoteRequestState::Failed, Some(codes::AGENT_FAILED), Some(text)));
                    }
                },
                changed = cancel_rx.changed() => {
                    let code = if changed.is_ok() { (*cancel_rx.borrow()).unwrap_or(codes::CANCELLED_BY_REQUESTER) } else { codes::CANCELLED_BY_REQUESTER };
                    self.stop_turn(row, conversation_id, owner).await;
                    return Ok((RemoteRequestState::Cancelled, Some(code), Some(text)));
                }
                () = tokio::time::sleep_until(deadline) => {
                    self.stop_turn(row, conversation_id, owner).await;
                    return Ok((RemoteRequestState::Expired, Some(codes::DEADLINE_EXCEEDED), Some(text)));
                }
                _ = flush.tick(), if dirty => {
                    self.write_progress(row, RemoteRequestState::Running, None, Some(&text)).await?;
                    dirty = false;
                }
            }
        }
    }

    async fn stop_turn(&self, row: &NetworkInboundRequestRow, conversation_id: &str, owner: &str) {
        if let Err(error) = self.runner.cancel_turn(owner, conversation_id).await {
            warn!(request_id = %row.request_id, code = error.code(), "network: stopping remote turn failed");
        }
    }

    async fn write_progress(
        &self,
        row: &NetworkInboundRequestRow,
        state: RemoteRequestState,
        waiting: Option<WaitingKind>,
        text: Option<&str>,
    ) -> Result<(), NetworkError> {
        let update = RequestUpdate {
            state: Some(state.as_str()),
            waiting_kind: Some(waiting.map(WaitingKind::as_str)),
            result_text: text,
            updated_at: now_ms(),
            ..Default::default()
        };
        if self
            .repo
            .update_inbound_fenced(&row.id, &self.claim_token, &update)
            .await?
        {
            self.changed();
        }
        Ok(())
    }

    async fn write_progress_if_waiting(&self, row: &NetworkInboundRequestRow) -> Result<(), NetworkError> {
        let update = RequestUpdate {
            state: Some(RemoteRequestState::Running.as_str()),
            waiting_kind: Some(None),
            updated_at: now_ms(),
            ..Default::default()
        };
        if self
            .repo
            .update_inbound_if_state(&row.id, RemoteRequestState::WaitingForOwner.as_str(), &update)
            .await?
        {
            debug!(request_id = %row.request_id, "network: remote turn resumed");
            self.changed();
        }
        Ok(())
    }
}

pub(crate) fn share_is_active(share: &NetworkShareRow, peer_id: &str, now: i64) -> bool {
    share.peer_id == peer_id && share.revoked_at.is_none() && share.expires_at.is_none_or(|at| at > now)
}

fn terminal_update<'a>(state: RemoteRequestState, code: Option<&'a str>, text: Option<&'a str>) -> RequestUpdate<'a> {
    let now = now_ms();
    RequestUpdate {
        state: Some(state.as_str()),
        error_code: Some(code),
        waiting_kind: Some(None),
        result_text: text,
        finished_at: Some(now),
        updated_at: now,
        ..Default::default()
    }
}

fn deadline_instant(deadline_at: i64) -> tokio::time::Instant {
    let remaining = (deadline_at - now_ms()).max(0) as u64;
    tokio::time::Instant::now() + Duration::from_millis(remaining)
}

pub(crate) fn clean_display_name(value: &str) -> Result<String, NetworkError> {
    let name: String = value.trim().chars().filter(|c| !c.is_control()).take(64).collect();
    if name.is_empty() {
        return Err(NetworkError::InvalidRequest("display name is empty".into()));
    }
    Ok(name)
}
