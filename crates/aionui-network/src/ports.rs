//! Ports this domain needs from the rest of the host. Implementations live in
//! the composition layer (`aionui-app`) so this crate never depends on the
//! conversation or agent crates directly.

use aionui_api_types::{
    PeerHelloResponse, PeerPairingRequest, PeerPairingResponse, PeerPairingReveal, PeerPairingRevealResponse,
    PeerRequestStatus, PeerSharesResponse, PeerSubmitRequest, WaitingKind,
};
use aionui_peer::Fingerprint;
use tokio::sync::mpsc;

use crate::error::NetworkError;

/// The owner-host conversation that runs a shared agent for one peer thread.
#[derive(Debug, Clone)]
pub struct RemoteConversationSpec {
    /// Shown in the owner's sidebar, e.g. `LAN · Alice · codex`.
    pub name: String,
    pub backend: String,
    /// Agent mode; never a full-access / auto-approve mode.
    pub mode: String,
    pub workspace: String,
}

/// Normalized progress of one agent turn, projected for a remote requester.
/// Tool payloads, thinking and internal events never cross this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnEvent {
    /// A chunk of the assistant's reply text.
    Text(String),
    /// The turn paused for the owner (tool approval or structured question).
    WaitingForOwner(WaitingKind),
    /// The agent is working again (after a pause, or tool activity).
    Activity,
    Finished,
    /// The agent reported an error; the message stays on the owner host.
    Failed,
}

/// Runs remote turns on this host's existing conversation runtime.
#[async_trait::async_trait]
pub trait RemoteTurnRunner: Send + Sync {
    /// Create the owner-host conversation for a new peer thread.
    async fn create_conversation(
        &self,
        owner_user_id: &str,
        spec: &RemoteConversationSpec,
    ) -> Result<String, NetworkError>;

    /// Send `content` as a user message and stream the turn's events. The
    /// stream ends after `Finished` / `Failed` or when the runtime goes away.
    async fn start_turn(
        &self,
        owner_user_id: &str,
        conversation_id: &str,
        content: &str,
    ) -> Result<mpsc::Receiver<TurnEvent>, NetworkError>;

    /// Best-effort stop of the running turn.
    async fn cancel_turn(&self, owner_user_id: &str, conversation_id: &str) -> Result<(), NetworkError>;
}

/// Outgoing peer-protocol calls (requester side), over mutual TLS.
#[async_trait::async_trait]
pub trait PeerTransport: Send + Sync {
    /// First contact: accept any server certificate and report its fingerprint.
    async fn observe(&self, url: &str) -> Result<(Fingerprint, PeerHelloResponse), NetworkError>;
    async fn pair(
        &self,
        url: &str,
        expected: &Fingerprint,
        body: &PeerPairingRequest,
    ) -> Result<PeerPairingResponse, NetworkError>;
    /// Second pairing step: reveal the committed nonce (ADR-016).
    async fn reveal(
        &self,
        url: &str,
        expected: &Fingerprint,
        body: &PeerPairingReveal,
    ) -> Result<PeerPairingRevealResponse, NetworkError>;
    async fn list_shares(&self, url: &str, expected: &Fingerprint) -> Result<PeerSharesResponse, NetworkError>;
    async fn submit(
        &self,
        url: &str,
        expected: &Fingerprint,
        body: &PeerSubmitRequest,
    ) -> Result<PeerRequestStatus, NetworkError>;
    /// Long-poll: returns once `version > after_version` or after `wait_ms`.
    async fn status(
        &self,
        url: &str,
        expected: &Fingerprint,
        request_id: &str,
        after_version: i64,
        wait_ms: u64,
    ) -> Result<PeerRequestStatus, NetworkError>;
    async fn cancel(
        &self,
        url: &str,
        expected: &Fingerprint,
        request_id: &str,
    ) -> Result<PeerRequestStatus, NetworkError>;
}
