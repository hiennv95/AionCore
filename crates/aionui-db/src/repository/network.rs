use aionui_common::TimestampMs;

use crate::error::DbError;
use crate::models::{NetworkInboundRequestRow, NetworkOutboundRequestRow, NetworkPeerRow, NetworkShareRow};

/// Data access for private-LAN peers, shares and remote requests (ADR-009).
///
/// Every state-changing request update bumps `version` so long-pollers can wait
/// for news. Fenced updates only apply while the row is still claimed by the
/// given `claim_token`.
#[async_trait::async_trait]
pub trait INetworkRepository: Send + Sync {
    // ── peers ─────────────────────────────────────────────────────────────
    async fn list_peers(&self) -> Result<Vec<NetworkPeerRow>, DbError>;
    async fn find_peer(&self, id: &str) -> Result<Option<NetworkPeerRow>, DbError>;
    async fn find_peer_by_fingerprint(&self, fingerprint: &str) -> Result<Option<NetworkPeerRow>, DbError>;
    async fn insert_peer(&self, params: InsertPeerParams<'_>) -> Result<NetworkPeerRow, DbError>;
    /// Update state and, when given, the display name / URL. `NotFound` if missing.
    async fn update_peer(&self, id: &str, params: UpdatePeerParams<'_>) -> Result<(), DbError>;
    async fn delete_peer(&self, id: &str) -> Result<(), DbError>;
    async fn count_peers_in_state(&self, state: &str) -> Result<i64, DbError>;

    // ── shares ────────────────────────────────────────────────────────────
    async fn list_shares(&self, peer_id: Option<&str>) -> Result<Vec<NetworkShareRow>, DbError>;
    async fn find_share(&self, id: &str) -> Result<Option<NetworkShareRow>, DbError>;
    async fn insert_share(&self, params: InsertShareParams<'_>) -> Result<NetworkShareRow, DbError>;
    /// Mark a share revoked. Returns `false` when it was already revoked or missing.
    async fn revoke_share(&self, id: &str, now: TimestampMs) -> Result<bool, DbError>;

    // ── inbound requests (this host executes) ─────────────────────────────
    /// Insert a new request. `Conflict` when (peer_id, request_id) already exists.
    async fn insert_inbound(&self, params: InsertInboundParams<'_>) -> Result<NetworkInboundRequestRow, DbError>;
    async fn find_inbound(&self, id: &str) -> Result<Option<NetworkInboundRequestRow>, DbError>;
    async fn find_inbound_by_request(
        &self,
        peer_id: &str,
        request_id: &str,
    ) -> Result<Option<NetworkInboundRequestRow>, DbError>;
    async fn list_inbound(&self, limit: i64) -> Result<Vec<NetworkInboundRequestRow>, DbError>;
    async fn list_inbound_in_states(&self, states: &[&str]) -> Result<Vec<NetworkInboundRequestRow>, DbError>;
    async fn count_inbound_in_states(&self, peer_id: Option<&str>, states: &[&str]) -> Result<i64, DbError>;
    /// Conversation already backing (peer, share, thread), if any.
    async fn find_thread_conversation(
        &self,
        peer_id: &str,
        share_id: &str,
        thread_id: &str,
    ) -> Result<Option<String>, DbError>;
    /// `queued` → `running` owned by `claim_token`. `false` if the row was not queued.
    async fn claim_inbound(&self, id: &str, claim_token: &str, now: TimestampMs) -> Result<bool, DbError>;
    /// Apply `update` only while the row is claimed by `claim_token` and not terminal.
    async fn update_inbound_fenced(
        &self,
        id: &str,
        claim_token: &str,
        update: &RequestUpdate<'_>,
    ) -> Result<bool, DbError>;
    /// Apply `update` only while the row is in `expected_state`.
    async fn update_inbound_if_state(
        &self,
        id: &str,
        expected_state: &str,
        update: &RequestUpdate<'_>,
    ) -> Result<bool, DbError>;
    /// Record a cancel request on a non-terminal row. Returns `false` if terminal or missing.
    async fn request_inbound_cancel(&self, id: &str, now: TimestampMs) -> Result<bool, DbError>;

    // ── outbound requests (this host asked a peer) ────────────────────────
    async fn insert_outbound(&self, params: InsertOutboundParams<'_>) -> Result<NetworkOutboundRequestRow, DbError>;
    async fn find_outbound(&self, id: &str) -> Result<Option<NetworkOutboundRequestRow>, DbError>;
    async fn list_outbound(&self, user_id: &str, limit: i64) -> Result<Vec<NetworkOutboundRequestRow>, DbError>;
    async fn list_outbound_in_states(&self, states: &[&str]) -> Result<Vec<NetworkOutboundRequestRow>, DbError>;
    async fn update_outbound(&self, id: &str, update: &OutboundUpdate<'_>) -> Result<(), DbError>;
}

#[derive(Debug)]
pub struct InsertPeerParams<'a> {
    pub fingerprint: &'a str,
    pub display_name: &'a str,
    pub peer_url: Option<&'a str>,
    pub state: &'a str,
    pub verification_code: &'a str,
}

/// `None` keeps the current value.
#[derive(Debug, Default)]
pub struct UpdatePeerParams<'a> {
    pub state: Option<&'a str>,
    pub display_name: Option<&'a str>,
    pub peer_url: Option<&'a str>,
    /// A new code from a fresh pairing exchange (ADR-016).
    pub verification_code: Option<&'a str>,
}

#[derive(Debug)]
pub struct InsertShareParams<'a> {
    pub peer_id: &'a str,
    pub label: &'a str,
    pub backend: &'a str,
    pub mode: &'a str,
    pub workspace: &'a str,
    pub expires_at: Option<TimestampMs>,
}

#[derive(Debug)]
pub struct InsertInboundParams<'a> {
    pub peer_id: &'a str,
    pub share_id: &'a str,
    pub request_id: &'a str,
    pub thread_id: &'a str,
    pub content: &'a str,
    pub content_hash: &'a str,
    pub state: &'a str,
    pub deadline_at: TimestampMs,
}

/// Partial update of a request row. `None` keeps the value; for nullable
/// columns `Some(None)` clears it.
#[derive(Debug, Default)]
pub struct RequestUpdate<'a> {
    pub state: Option<&'a str>,
    pub error_code: Option<Option<&'a str>>,
    pub waiting_kind: Option<Option<&'a str>>,
    pub conversation_id: Option<&'a str>,
    pub result_text: Option<&'a str>,
    pub finished_at: Option<TimestampMs>,
    pub updated_at: TimestampMs,
}

#[derive(Debug)]
pub struct InsertOutboundParams<'a> {
    pub user_id: &'a str,
    pub peer_id: &'a str,
    pub share_id: &'a str,
    pub share_label: &'a str,
    pub request_id: &'a str,
    pub thread_id: &'a str,
    pub content: &'a str,
    pub deadline_at: TimestampMs,
}

/// Partial update of an outbound row (`None` keeps the value).
#[derive(Debug, Default)]
pub struct OutboundUpdate<'a> {
    pub request: RequestUpdate<'a>,
    pub remote_version: Option<i64>,
    pub peer_reachable: Option<bool>,
    pub cancel_requested: Option<bool>,
}
