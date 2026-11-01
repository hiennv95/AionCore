use aionui_common::TimestampMs;

use crate::error::DbError;
use crate::models::{MailboxMessageRow, NetworkInboundRequestRow, NetworkOutboundRequestRow, NetworkPeerRow, NetworkShareRow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanMessageEnqueue {
    Inserted,
    Duplicate,
    Conflict,
    Unauthorized,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LanTeamOutboxRow {
    pub id: String,
    pub user_id: String,
    pub team_id: String,
    pub peer_id: String,
    pub remote_team_id: String,
    pub content: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ActiveLanTeamMember {
    pub team_id: String,
    pub peer_id: String,
    pub peer_name: String,
    pub fingerprint: String,
    pub remote_team_id: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingLanInvitation {
    pub id: String,
    pub state: String,
    pub team_name: String,
    pub candidate_fingerprint: String,
    pub candidate_name: Option<String>,
    pub decision: String,
}

/// Data access for private-LAN peers, shares and remote requests (ADR-009).
///
/// Every state-changing request update bumps `version` so long-pollers can wait
/// for news. Fenced updates only apply while the row is still claimed by the
/// given `claim_token`.
#[async_trait::async_trait]
pub trait INetworkRepository: Send + Sync {
    /// Snapshot the active LAN roster and candidate while creating an invitation.
    async fn create_team_invitation(
        &self,
        user_id: &str,
        team_id: &str,
        invitation_id: &str,
        local_fingerprint: &str,
        candidate_peer_id: &str,
    ) -> Result<(), DbError>;
    async fn team_invitation_votes(
        &self,
        user_id: &str,
        invitation_id: &str,
    ) -> Result<Vec<(String, String)>, DbError>;
    async fn team_invitation_conversations(
        &self,
        user_id: &str,
        invitation_id: &str,
    ) -> Result<Vec<(String, String)>, DbError>;
    async fn team_invitation_team_id(&self, user_id: &str, invitation_id: &str) -> Result<Option<String>, DbError>;
    async fn pending_local_team_invitation(&self, user_id: &str, team_id: &str) -> Result<Option<(String, String, String)>, DbError>;
    async fn cancel_team_invitation(&self, user_id: &str, team_id: &str, invitation_id: &str) -> Result<bool, DbError>;
    async fn record_team_poll_consent(
        &self, user_id: &str, team_id: &str, coordinator: &str, invitation_id: &str, participants: &str,
    ) -> Result<bool, DbError>;
    async fn team_poll_consent(
        &self, user_id: &str, coordinator: &str, invitation_id: &str,
    ) -> Result<Option<(String, String)>, DbError>;
    async fn remove_team_poll_consent(&self, user_id: &str, coordinator: &str, invitation_id: &str) -> Result<bool, DbError>;
    /// Apply an authenticated completed poll against the owner's persisted consent.
    async fn apply_team_poll_membership(
        &self, user_id: &str, coordinator: &str, invitation_id: &str, local_fingerprint: &str,
        members: &[(String, String)],
    ) -> Result<bool, DbError>;
    /// Resolve a currently trusted remote conversation member for message delivery.
    async fn authorized_lan_team_member(
        &self, user_id: &str, team_id: &str, fingerprint: &str, remote_team_id: &str,
    ) -> Result<Option<String>, DbError>;
    async fn active_lan_team_members(&self, user_id: &str) -> Result<Vec<ActiveLanTeamMember>, DbError>;
    /// Teams with an acknowledged LAN message that has not yet been read.
    async fn teams_with_unread_lan_messages(&self, user_id: &str) -> Result<Vec<String>, DbError>;
    /// Atomically authorize and persist a peer message and its idempotency receipt.
    async fn enqueue_lan_team_message(
        &self, user_id: &str, fingerprint: &str, remote_team_id: &str, request_id: &str,
        message: &MailboxMessageRow,
    ) -> Result<LanMessageEnqueue, DbError>;
    async fn enqueue_lan_team_outbound(
        &self, id: &str, user_id: &str, team_id: &str, peer_id: &str, remote_team_id: &str, content: &str,
    ) -> Result<bool, DbError>;
    async fn enqueue_lan_team_outbound_with_mailbox(
        &self, user_id: &str, peer_id: &str, remote_team_id: &str, message: &MailboxMessageRow,
    ) -> Result<bool, DbError>;
    async fn pending_lan_team_outbound(&self, now: i64, limit: i64) -> Result<Vec<LanTeamOutboxRow>, DbError>;
    async fn defer_lan_team_outbound(&self, id: &str, until: i64) -> Result<bool, DbError>;
    async fn finish_lan_team_outbound(&self, id: &str, state: &str) -> Result<bool, DbError>;
    async fn lan_team_delivery_statuses(&self, user_id: &str, team_id: &str) -> Result<Vec<(String, String)>, DbError>;
    async fn list_team_poll_consents(&self, user_id: &str) -> Result<Vec<(String, String)>, DbError>;
    async fn record_team_pair_attestation(
        &self, user_id: &str, invitation_id: &str, fingerprint: &str, participants: &str, local: bool, now: i64,
    ) -> Result<bool, DbError>;
    async fn team_pair_attestations_complete(&self, user_id: &str, invitation_id: &str, since: i64) -> Result<bool, DbError>;
    /// Complete a poll and update the coordinator roster in one transaction.
    async fn complete_team_invitation(
        &self, user_id: &str, invitation_id: &str, local_fingerprint: &str, since: i64,
    ) -> Result<bool, DbError>;
    async fn pending_team_invitations(
        &self,
        user_id: &str,
        fingerprint: &str,
    ) -> Result<Vec<PendingLanInvitation>, DbError>;
    /// Returns false if the invitation or vote is no longer pending.
    async fn decide_team_invitation(
        &self,
        user_id: &str,
        invitation_id: &str,
        fingerprint: &str,
        approve: bool,
        remote_team_id: Option<&str>,
    ) -> Result<bool, DbError>;
    /// Only teams owned by `user_id` can have their LAN visibility changed.
    async fn set_team_shared(&self, user_id: &str, team_id: &str, enabled: bool) -> Result<(), DbError>;
    /// IDs and names only; conversation history and members are never exposed.
    async fn list_shared_teams(&self, user_id: &str) -> Result<Vec<(String, String)>, DbError>;

    // ── peers ─────────────────────────────────────────────────────────────
    async fn list_peers(&self) -> Result<Vec<NetworkPeerRow>, DbError>;
    async fn find_peer(&self, id: &str) -> Result<Option<NetworkPeerRow>, DbError>;
    async fn find_peer_by_fingerprint(&self, fingerprint: &str) -> Result<Option<NetworkPeerRow>, DbError>;
    async fn insert_peer(&self, params: InsertPeerParams<'_>) -> Result<NetworkPeerRow, DbError>;
    /// Update state and, when given, the display name / URL. `NotFound` if missing.
    async fn update_peer(&self, id: &str, params: UpdatePeerParams<'_>) -> Result<(), DbError>;
    /// Change state only if it has not changed since it was observed.
    async fn compare_and_set_peer_state(&self, id: &str, expected: &str, next: &str) -> Result<bool, DbError>;
    /// Revoke the peer, its team memberships and affected pending invitations atomically.
    /// An expected state fences observations made before a newer local decision.
    async fn revoke_peer_and_memberships(&self, id: &str, expected: Option<&str>) -> Result<bool, DbError>;
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
