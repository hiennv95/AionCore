//! Requester side: the durable outbox. One driver task per live request
//! delivers it (idempotent retries with the same `request_id`) and then
//! reconciles its state with the owner host by long-polling.
//!
//! A delivery retry never becomes an execution retry: the owner host dedups by
//! `request_id`, and once a request is acknowledged this side only re-queries.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aionui_api_types::{PEER_CONTRACT_VERSION, PeerRequestStatus, PeerState, PeerSubmitRequest, RemoteRequestState};
use aionui_common::now_ms;
use aionui_db::models::{NetworkOutboundRequestRow, NetworkPeerRow};
use aionui_db::{INetworkRepository, OutboundUpdate, RequestUpdate};
use aionui_peer::Fingerprint;
use tracing::{debug, info, warn};

use crate::error::NetworkError;
use crate::policy::{self, codes};
use crate::ports::PeerTransport;

/// Peer error codes are short machine names; anything longer is cut.
const MAX_ERROR_CODE_BYTES: usize = 64;

const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Long-poll window asked from the owner host.
const STATUS_WAIT_MS: u64 = 20_000;
/// After the deadline, keep reconciling an unreachable owner host this long.
const RECONCILE_GRACE_MS: i64 = 24 * 60 * 60 * 1000;

pub struct OutboundService {
    repo: Arc<dyn INetworkRepository>,
    transport: Arc<dyn PeerTransport>,
    driving: Mutex<HashSet<String>>,
}

enum Step {
    Continue,
    Backoff,
    Stop,
}

impl OutboundService {
    pub fn new(repo: Arc<dyn INetworkRepository>, transport: Arc<dyn PeerTransport>) -> Self {
        Self {
            repo,
            transport,
            driving: Mutex::new(HashSet::new()),
        }
    }

    /// Resume driving every live request (called once at startup).
    pub async fn resume_all(self: &Arc<Self>) -> Result<usize, NetworkError> {
        let live = self.repo.list_outbound_in_states(&policy::LIVE_OUTBOUND_STATES).await?;
        let count = live.len();
        for row in live {
            self.drive(row.id);
        }
        if count > 0 {
            info!(count, "network: resumed outbound requests after start");
        }
        Ok(count)
    }

    /// Start (or keep) the driver task of one request.
    pub fn drive(self: &Arc<Self>, id: String) {
        if !self
            .driving
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.clone())
        {
            return;
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.drive_loop(&id).await;
            this.driving.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        });
    }

    /// Send a cancel right away (best effort). The driver may be inside a
    /// long-poll; it keeps retrying the cancel on its next step if this fails.
    pub async fn cancel_now(&self, id: &str) -> Result<(), NetworkError> {
        let Some(row) = self.repo.find_outbound(id).await? else {
            return Err(NetworkError::RequestNotFound);
        };
        let Some((_, url, fingerprint)) = self.repo.find_peer(&row.peer_id).await?.and_then(callable) else {
            return Ok(());
        };
        match self.transport.cancel(&url, &fingerprint, &row.request_id).await {
            Ok(status) => self.apply(&row, &status).await,
            Err(NetworkError::RequestNotFound) if row.state == RemoteRequestState::PendingDelivery.as_str() => {
                self.finish(&row, RemoteRequestState::Cancelled, codes::CANCELLED_BY_REQUESTER)
                    .await
            }
            Err(error) => {
                debug!(request_id = %row.request_id, code = error.code(), "network: immediate cancel not delivered");
                Ok(())
            }
        }
    }

    async fn drive_loop(&self, id: &str) {
        let mut backoff = MIN_BACKOFF;
        loop {
            let step = match self.step(id).await {
                Ok(step) => step,
                Err(error) => {
                    warn!(id, code = error.code(), "network: outbound step failed");
                    Step::Backoff
                }
            };
            match step {
                Step::Continue => backoff = MIN_BACKOFF,
                Step::Backoff => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                Step::Stop => return,
            }
        }
    }

    async fn step(&self, id: &str) -> Result<Step, NetworkError> {
        let Some(row) = self.repo.find_outbound(id).await? else {
            return Ok(Step::Stop);
        };
        let state = RemoteRequestState::parse(&row.state).unwrap_or(RemoteRequestState::Failed);
        if state.is_terminal() {
            return Ok(Step::Stop);
        }
        let now = now_ms();
        let peer = self.repo.find_peer(&row.peer_id).await?;
        let Some((peer, url, fingerprint)) = peer.and_then(callable) else {
            self.finish(&row, RemoteRequestState::Failed, codes::GRANT_REVOKED)
                .await?;
            return Ok(Step::Stop);
        };

        if state == RemoteRequestState::PendingDelivery {
            if row.cancel_requested {
                return self.cancel_undelivered(&row, &url, &fingerprint).await;
            }
            if now >= row.deadline_at {
                // Never acknowledged and past its deadline: the owner host
                // rejects late submits, so it can never run.
                self.finish(&row, RemoteRequestState::Expired, codes::NEVER_DELIVERED)
                    .await?;
                return Ok(Step::Stop);
            }
            return self.deliver(&row, &peer, &url, &fingerprint).await;
        }

        if row.cancel_requested
            && let Err(error) = self.transport.cancel(&url, &fingerprint, &row.request_id).await
        {
            debug!(request_id = %row.request_id, code = error.code(), "network: cancel not delivered yet");
        }
        match self
            .transport
            .status(&url, &fingerprint, &row.request_id, row.remote_version, STATUS_WAIT_MS)
            .await
        {
            Ok(status) => {
                self.apply(&row, &status).await?;
                Ok(Step::Continue)
            }
            Err(NetworkError::RequestNotFound) => {
                warn!(request_id = %row.request_id, "network: owner host no longer knows the request");
                self.finish(&row, RemoteRequestState::Failed, codes::REQUEST_LOST)
                    .await?;
                Ok(Step::Stop)
            }
            Err(error @ (NetworkError::PeerRevoked | NetworkError::PeerUntrusted)) => {
                info!(request_id = %row.request_id, code = error.code(), "network: owner host refused status");
                self.finish(&row, RemoteRequestState::Failed, error.code()).await?;
                Ok(Step::Stop)
            }
            Err(error) => {
                self.mark_unreachable(&row, &error).await?;
                if now > row.deadline_at + RECONCILE_GRACE_MS {
                    info!(request_id = %row.request_id, "network: stopped reconciling an unreachable request");
                    return Ok(Step::Stop);
                }
                Ok(Step::Backoff)
            }
        }
    }

    async fn deliver(
        &self,
        row: &NetworkOutboundRequestRow,
        peer: &NetworkPeerRow,
        url: &str,
        fingerprint: &Fingerprint,
    ) -> Result<Step, NetworkError> {
        let body = PeerSubmitRequest {
            protocol_version: PEER_CONTRACT_VERSION,
            request_id: row.request_id.clone(),
            share_id: row.share_id.clone(),
            thread_id: row.thread_id.clone(),
            content: row.content.clone(),
            deadline_at: row.deadline_at,
        };
        match self.transport.submit(url, fingerprint, &body).await {
            Ok(status) => {
                info!(request_id = %row.request_id, peer = %&peer.fingerprint[..16], "network: request acknowledged by owner host");
                self.apply(row, &status).await?;
                Ok(Step::Continue)
            }
            Err(
                error @ (NetworkError::PeerUntrusted
                | NetworkError::PeerRevoked
                | NetworkError::ShareNotFound
                | NetworkError::RequestConflict
                | NetworkError::QueueFull
                | NetworkError::PayloadTooLarge
                | NetworkError::VersionUnsupported
                | NetworkError::InvalidRequest(_)
                | NetworkError::Disabled
                | NetworkError::PeerRejected { .. }),
            ) => {
                // A definitive answer: the request was not accepted. Not retried.
                info!(request_id = %row.request_id, code = error.code(), "network: request rejected by owner host");
                self.finish(row, RemoteRequestState::Failed, error.code()).await?;
                Ok(Step::Stop)
            }
            Err(error) => {
                self.mark_unreachable(row, &error).await?;
                Ok(Step::Backoff)
            }
        }
    }

    /// Cancel before an acknowledgement: ask the owner host, which may have
    /// stored it even if our earlier submit lost its response.
    async fn cancel_undelivered(
        &self,
        row: &NetworkOutboundRequestRow,
        url: &str,
        fingerprint: &Fingerprint,
    ) -> Result<Step, NetworkError> {
        match self.transport.cancel(url, fingerprint, &row.request_id).await {
            Ok(status) => {
                self.apply(row, &status).await?;
                Ok(Step::Continue)
            }
            Err(NetworkError::RequestNotFound) => {
                self.finish(row, RemoteRequestState::Cancelled, codes::CANCELLED_BY_REQUESTER)
                    .await?;
                Ok(Step::Stop)
            }
            Err(error) => {
                self.mark_unreachable(row, &error).await?;
                Ok(Step::Backoff)
            }
        }
    }

    async fn apply(&self, row: &NetworkOutboundRequestRow, status: &PeerRequestStatus) -> Result<(), NetworkError> {
        if status.version < row.remote_version {
            return Ok(()); // stale answer
        }
        let now = now_ms();
        // Peer replies are untrusted data (ADR-009): store them bounded.
        let bounded = |text: &Option<String>, max: usize| {
            text.clone().map(|mut text| {
                crate::policy::truncate_utf8(&mut text, max);
                text
            })
        };
        let error_code = bounded(&status.error_code, MAX_ERROR_CODE_BYTES);
        let result_text = bounded(&status.result_text, crate::policy::MAX_RESULT_BYTES);
        let update = OutboundUpdate {
            request: RequestUpdate {
                state: Some(status.state.as_str()),
                error_code: Some(error_code.as_deref()),
                waiting_kind: Some(status.waiting_kind.map(|k| k.as_str())),
                result_text: result_text.as_deref(),
                finished_at: status.state.is_terminal().then_some(now),
                updated_at: now,
                ..Default::default()
            },
            remote_version: Some(status.version),
            peer_reachable: Some(true),
            cancel_requested: None,
        };
        self.repo.update_outbound(&row.id, &update).await?;
        if status.state.is_terminal() {
            info!(request_id = %row.request_id, state = status.state.as_str(), "network: remote request reached a final state");
        }
        Ok(())
    }

    async fn mark_unreachable(
        &self,
        row: &NetworkOutboundRequestRow,
        error: &NetworkError,
    ) -> Result<(), NetworkError> {
        if row.peer_reachable {
            info!(request_id = %row.request_id, code = error.code(), "network: owner host unreachable, will retry");
        }
        self.repo
            .update_outbound(
                &row.id,
                &OutboundUpdate {
                    request: RequestUpdate {
                        updated_at: now_ms(),
                        ..Default::default()
                    },
                    peer_reachable: Some(false),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    async fn finish(
        &self,
        row: &NetworkOutboundRequestRow,
        state: RemoteRequestState,
        code: &str,
    ) -> Result<(), NetworkError> {
        let now = now_ms();
        self.repo
            .update_outbound(
                &row.id,
                &OutboundUpdate {
                    request: RequestUpdate {
                        state: Some(state.as_str()),
                        error_code: Some(Some(code)),
                        waiting_kind: Some(None),
                        finished_at: Some(now),
                        updated_at: now,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await?;
        info!(request_id = %row.request_id, state = state.as_str(), code, "network: outbound request ended locally");
        Ok(())
    }
}

/// A peer this host may call: trusted, with a URL and a valid pinned fingerprint.
fn callable(peer: NetworkPeerRow) -> Option<(NetworkPeerRow, String, Fingerprint)> {
    if PeerState::parse(&peer.state) != Some(PeerState::Trusted) {
        return None;
    }
    let url = peer.peer_url.clone()?;
    let fingerprint = Fingerprint::parse(&peer.fingerprint).ok()?;
    Some((peer, url, fingerprint))
}
