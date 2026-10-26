//! Private-LAN host network (ADR-009): owner API on `/api/network/*` and the
//! host-to-host peer protocol v1 served on the mutual-TLS peer listener.

use serde::{Deserialize, Serialize};

/// Version of the host-to-host request contract carried in every peer body.
pub const PEER_CONTRACT_VERSION: u32 = 2;

/// Trust state of a peer host on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    /// The peer asked to pair; this host's owner has not approved yet.
    PendingInbound,
    /// This host asked to pair; this host's owner has not confirmed the code yet.
    PendingOutbound,
    Trusted,
    Revoked,
}

impl PeerState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingInbound => "pending_inbound",
            Self::PendingOutbound => "pending_outbound",
            Self::Trusted => "trusted",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending_inbound" => Some(Self::PendingInbound),
            "pending_outbound" => Some(Self::PendingOutbound),
            "trusted" => Some(Self::Trusted),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Lifecycle of a remote request. Terminal: succeeded, failed, cancelled, expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteRequestState {
    /// Requester side only: persisted locally, not yet acknowledged by the owner host.
    PendingDelivery,
    Queued,
    Running,
    WaitingForOwner,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
}

impl RemoteRequestState {
    pub const TERMINAL: [Self; 4] = [Self::Succeeded, Self::Failed, Self::Cancelled, Self::Expired];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingDelivery => "pending_delivery",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::WaitingForOwner => "waiting_for_owner",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending_delivery" => Some(Self::PendingDelivery),
            "queued" => Some(Self::Queued),
            "running" => Some(Self::Running),
            "waiting_for_owner" => Some(Self::WaitingForOwner),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        Self::TERMINAL.contains(&self)
    }
}

/// What the owner host is waiting for while a remote turn is paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitingKind {
    /// A tool call needs the owner's approval.
    Approval,
    /// The agent asked a structured question the owner must answer.
    Question,
}

impl WaitingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Question => "question",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "approval" => Some(Self::Approval),
            "question" => Some(Self::Question),
            _ => None,
        }
    }
}

// ── owner API (`/api/network/*`, loopback/browser, auth + CSRF) ────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatusResponse {
    /// Whether this host accepts peer connections right now.
    pub enabled: bool,
    pub host_fingerprint: String,
    pub display_name: String,
    /// Port the peer listener runs on, or the configured port while it is off (so
    /// the UI can show it). Whether it is listening is `enabled` with no `last_error`.
    pub listen_port: Option<u16>,
    /// The listener was fixed by `--peer-listen` and cannot be toggled from the UI.
    pub managed_by_cli: bool,
    /// Last listener error, e.g. the port is in use.
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateNetworkSettingsRequest {
    pub enabled: Option<bool>,
    pub listen_port: Option<u16>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerView {
    pub id: String,
    pub fingerprint: String,
    pub display_name: String,
    pub peer_url: Option<String>,
    pub state: PeerState,
    /// Compare with the code shown on the other host before approving.
    pub verification_code: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPeerRequest {
    /// Base URL of the other host's peer listener, e.g. `https://192.168.1.20:25820`.
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareView {
    pub id: String,
    pub peer_id: String,
    pub peer_display_name: String,
    pub label: String,
    pub backend: String,
    pub mode: String,
    pub workspace: String,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateShareRequest {
    pub peer_id: String,
    pub label: String,
    /// Agent backend to run for the peer (`codex` or `claude`).
    pub backend: String,
    /// Absolute directory the shared agent works in. Defaults to a dedicated
    /// empty directory under the host data dir.
    #[serde(default)]
    pub workspace: Option<String>,
    /// Unix ms after which the share stops accepting requests.
    #[serde(default)]
    pub expires_at: Option<i64>,
}

/// An agent another host shares with this host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteAgentView {
    pub peer_id: String,
    pub peer_display_name: String,
    pub share_id: String,
    pub label: String,
    pub backend: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRemoteRequest {
    pub peer_id: String,
    pub share_id: String,
    pub share_label: String,
    pub content: String,
    /// Continue an earlier thread (same remote conversation); omitted = new thread.
    #[serde(default)]
    pub thread_id: Option<String>,
    /// Seconds the owner host may take, default 1800, max 86400.
    #[serde(default)]
    pub deadline_secs: Option<u64>,
}

/// A request this host sent to a peer, as last reconciled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundRequestView {
    pub id: String,
    pub peer_id: String,
    pub peer_display_name: String,
    pub share_id: String,
    pub share_label: String,
    pub request_id: String,
    pub thread_id: String,
    pub content: String,
    pub state: RemoteRequestState,
    pub error_code: Option<String>,
    pub waiting_kind: Option<WaitingKind>,
    pub result_text: Option<String>,
    /// `false` while the owner host cannot be reached; the state is the last known one.
    pub peer_reachable: bool,
    pub cancel_requested: bool,
    pub deadline_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub finished_at: Option<i64>,
}

/// A request a peer sent to this host (owner-side view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundRequestView {
    pub id: String,
    pub peer_id: String,
    pub peer_display_name: String,
    pub share_id: String,
    pub share_label: String,
    pub request_id: String,
    pub state: RemoteRequestState,
    pub error_code: Option<String>,
    pub waiting_kind: Option<WaitingKind>,
    /// The owner-host conversation that runs this request (open it to approve tools).
    pub conversation_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub finished_at: Option<i64>,
}

// ── peer protocol v1 (mutual TLS, `/peer/v1/*`) ─────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHelloResponse {
    pub protocol_version: u32,
    pub host_fingerprint: String,
    pub display_name: String,
    /// Caller's fingerprint as seen by this host's TLS layer.
    pub caller_fingerprint: String,
    /// Caller's trust state on this host, `None` when unknown.
    pub caller_state: Option<PeerState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPairingRequest {
    pub protocol_version: u32,
    pub display_name: String,
}

/// Second pairing step: the initiator sends its nonce (ADR-016).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPairingReveal {
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPairingRevealResponse {
    /// The caller's state on this host after the exchange.
    pub state: PeerState,
    /// The responder's nonce, opening the commitment from step 1 (ADR-016).
    pub responder_nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPairingResponse {
    pub host_fingerprint: String,
    pub display_name: String,
    /// The caller's state on this host after the request.
    pub state: PeerState,
    /// `hex(SHA-256("aionx-sas-commit-v1" ‖ responder nonce))`: the responder is
    /// bound to its nonce before it sees the initiator's (ADR-016).
    pub responder_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerShareEntry {
    pub share_id: String,
    pub label: String,
    pub backend: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSharesResponse {
    pub shares: Vec<PeerShareEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSubmitRequest {
    pub protocol_version: u32,
    /// Requester-chosen idempotency key (UUID), unique per requester host.
    pub request_id: String,
    pub share_id: String,
    pub thread_id: String,
    pub content: String,
    /// Absolute deadline, unix ms.
    pub deadline_at: i64,
}

/// Receipt and execution state of one request on the owner host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRequestStatus {
    pub request_id: String,
    pub state: RemoteRequestState,
    pub error_code: Option<String>,
    pub waiting_kind: Option<WaitingKind>,
    pub result_text: Option<String>,
    /// Increases on every change; pass it back as `after_version` to wait for news.
    pub version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerErrorBody {
    pub code: String,
    pub message: String,
}
