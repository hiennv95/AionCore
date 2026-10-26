use aionui_common::TimestampMs;
use serde::{Deserialize, Serialize};

/// Row mapping for `network_peers` (ADR-009). `state` is one of
/// `pending_inbound`, `pending_outbound`, `trusted`, `revoked`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct NetworkPeerRow {
    pub id: String,
    pub fingerprint: String,
    pub display_name: String,
    pub peer_url: Option<String>,
    pub state: String,
    pub verification_code: String,
    pub created_at: TimestampMs,
    pub updated_at: TimestampMs,
}

/// Row mapping for `network_shares`: one agent this host shares with one peer.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct NetworkShareRow {
    pub id: String,
    pub peer_id: String,
    pub label: String,
    pub backend: String,
    pub mode: String,
    pub workspace: String,
    pub scope: String,
    pub expires_at: Option<TimestampMs>,
    pub revoked_at: Option<TimestampMs>,
    pub created_at: TimestampMs,
    pub updated_at: TimestampMs,
}

/// Row mapping for `network_inbound_requests` (durable inbox).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct NetworkInboundRequestRow {
    pub id: String,
    pub peer_id: String,
    pub share_id: String,
    pub request_id: String,
    pub thread_id: String,
    pub content: String,
    pub content_hash: String,
    pub state: String,
    pub error_code: Option<String>,
    pub waiting_kind: Option<String>,
    pub conversation_id: Option<String>,
    pub result_text: Option<String>,
    pub deadline_at: TimestampMs,
    pub claim_token: Option<String>,
    pub cancel_requested: bool,
    pub version: i64,
    pub created_at: TimestampMs,
    pub updated_at: TimestampMs,
    pub finished_at: Option<TimestampMs>,
}

/// Row mapping for `network_outbound_requests` (durable outbox).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct NetworkOutboundRequestRow {
    pub id: String,
    pub user_id: String,
    pub peer_id: String,
    pub share_id: String,
    pub share_label: String,
    pub request_id: String,
    pub thread_id: String,
    pub content: String,
    pub state: String,
    pub error_code: Option<String>,
    pub waiting_kind: Option<String>,
    pub result_text: Option<String>,
    pub remote_version: i64,
    pub peer_reachable: bool,
    pub cancel_requested: bool,
    pub deadline_at: TimestampMs,
    pub created_at: TimestampMs,
    pub updated_at: TimestampMs,
    pub finished_at: Option<TimestampMs>,
}
