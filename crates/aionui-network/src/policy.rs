//! Fixed limits and pure rules of the LAN network domain.

use std::time::Duration;

use aionui_peer::Fingerprint;
use sha2::{Digest, Sha256};

/// Max prompt size a peer may send (bytes).
pub const MAX_CONTENT_BYTES: usize = 64 * 1024;
/// Max reply text kept and returned per request (bytes).
pub const MAX_RESULT_BYTES: usize = 256 * 1024;
/// Max unapproved inbound pairing requests kept at once.
pub const MAX_PENDING_PAIRINGS: i64 = 16;
/// Max live (queued + running + waiting) requests per peer.
pub const MAX_LIVE_REQUESTS_PER_PEER: i64 = 8;
/// Max live requests across all peers.
pub const MAX_LIVE_REQUESTS_TOTAL: i64 = 32;
/// Max remote turns running at once on this host.
pub const MAX_RUNNING_TURNS: usize = 2;
/// Default / max deadline a requester may ask for.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(30 * 60);
pub const MAX_DEADLINE: Duration = Duration::from_secs(24 * 60 * 60);
/// Longest long-poll a peer may hold open.
pub const MAX_STATUS_WAIT: Duration = Duration::from_secs(25);
/// Bounded recovery sweep for deadlines (no model calls, DB only).
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// How often accumulated reply text is persisted while a turn streams.
pub const RESULT_FLUSH_INTERVAL: Duration = Duration::from_millis(750);
/// Default port of the peer listener.
pub const DEFAULT_PEER_PORT: u16 = 25820;

/// Live (non-terminal) inbound states.
pub const LIVE_INBOUND_STATES: [&str; 3] = ["queued", "running", "waiting_for_owner"];
/// Non-terminal outbound states.
pub const LIVE_OUTBOUND_STATES: [&str; 4] = ["pending_delivery", "queued", "running", "waiting_for_owner"];

/// Error codes written into request rows (in addition to `NetworkError::code`).
pub mod codes {
    pub const HOST_RESTARTED: &str = "HOST_RESTARTED";
    pub const AGENT_FAILED: &str = "AGENT_FAILED";
    pub const DEADLINE_EXCEEDED: &str = "DEADLINE_EXCEEDED";
    pub const GRANT_REVOKED: &str = "GRANT_REVOKED";
    pub const CANCELLED_BY_REQUESTER: &str = "CANCELLED_BY_REQUESTER";
    pub const REQUEST_LOST: &str = "REQUEST_LOST";
    pub const NEVER_DELIVERED: &str = "NEVER_DELIVERED";
}

/// The agent mode a share runs in. Only backends whose own advertised mode list
/// has an approval-gated mode are shareable; never a full-access mode.
/// Sources: `agent_metadata.available_modes` written by each agent's handshake
/// on the live host — codex `read-only` ("Approval is required to edit files or
/// access the internet"), claude `default` ("prompts for dangerous operations").
pub fn share_mode_for_backend(backend: &str) -> Option<&'static str> {
    match backend {
        "codex" => Some("read-only"),
        "claude" => Some("default"),
        _ => None,
    }
}

/// How long a responder keeps a pairing exchange waiting for the reveal (ADR-016).
pub const PAIRING_EXCHANGE_TTL_MS: i64 = 5 * 60 * 1000;
/// Pending pairing rows older than this are dropped and cannot be approved (ADR-016).
pub const PENDING_PAIRING_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Drops pending pairing rows not refreshed within [`PENDING_PAIRING_TTL_MS`]
/// (ADR-016), so stale or decoy requests can neither pile up nor be approved.
pub async fn prune_expired_pairings(
    repo: &dyn aionui_db::INetworkRepository,
) -> Result<(), crate::error::NetworkError> {
    let cutoff = aionui_common::now_ms() - PENDING_PAIRING_TTL_MS;
    for peer in repo.list_peers().await? {
        let pending = peer.state == aionui_api_types::PeerState::PendingInbound.as_str()
            || peer.state == aionui_api_types::PeerState::PendingOutbound.as_str();
        if pending && peer.updated_at < cutoff {
            repo.delete_peer(&peer.id).await?;
        }
    }
    Ok(())
}

/// A fresh 32-byte pairing nonce.
pub fn new_pairing_nonce() -> Result<[u8; 32], crate::error::NetworkError> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| crate::error::NetworkError::Internal(format!("entropy source failed: {e}")))?;
    Ok(nonce)
}

/// `hex(SHA-256("aionx-sas-commit-v1" ‖ nonce))`: the responder commits to its
/// nonce before it sees the initiator's, then opens it (ADR-016).
pub fn pairing_commitment(nonce: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"aionx-sas-commit-v1");
    hasher.update(nonce);
    hex::encode(hasher.finalize())
}

/// 6-digit code both owners compare (ADR-016). Bound to both fingerprints and
/// to both nonces of one exchange, with fixed roles: the responder committed to
/// its nonce before seeing the initiator's, so no side can steer the code.
pub fn verification_code(
    initiator: &Fingerprint,
    responder: &Fingerprint,
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"aionx-sas-v1\0");
    hasher.update(initiator.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(responder.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(initiator_nonce);
    hasher.update(responder_nonce);
    let digest = hasher.finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{n:06}")
}

/// Hash that binds a request id to its content (idempotency conflict check).
pub fn content_hash(share_id: &str, thread_id: &str, content: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [share_id, thread_id, content] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Cut `text` to at most `max` bytes on a char boundary.
pub fn truncate_utf8(text: &mut String, max: usize) {
    if text.len() > max {
        let mut cut = max;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
    }
}

/// Request ids are requester-chosen; keep them short and printable.
pub fn valid_request_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(c: char) -> Fingerprint {
        Fingerprint::parse(&c.to_string().repeat(64)).unwrap()
    }

    /// ADR-016: the code is bound to both keys, both nonces and the roles, so
    /// neither side can pick a key or nonce that steers it.
    #[test]
    fn verification_code_is_bound_to_keys_nonces_and_roles() {
        let (a, b, c) = (fp('a'), fp('b'), fp('c'));
        let (na, nb) = ([1u8; 32], [2u8; 32]);
        let code = verification_code(&a, &b, &na, &nb);
        assert_eq!(code.len(), 6);
        assert_eq!(
            code,
            verification_code(&a, &b, &na, &nb),
            "deterministic for one exchange"
        );
        assert_ne!(code, verification_code(&a, &c, &na, &nb), "bound to the responder key");
        assert_ne!(
            code,
            verification_code(&a, &b, &[3u8; 32], &nb),
            "bound to the initiator nonce"
        );
        assert_ne!(
            code,
            verification_code(&a, &b, &na, &[3u8; 32]),
            "bound to the responder nonce"
        );
        assert_ne!(code, verification_code(&b, &a, &na, &nb), "roles are fixed");
    }

    #[test]
    fn commitment_hides_and_binds_the_nonce() {
        assert_eq!(pairing_commitment(&[1u8; 32]), pairing_commitment(&[1u8; 32]));
        assert_ne!(pairing_commitment(&[1u8; 32]), pairing_commitment(&[2u8; 32]));
        assert_eq!(pairing_commitment(&[1u8; 32]).len(), 64);
    }

    #[test]
    fn content_hash_separates_fields() {
        assert_ne!(content_hash("s", "ab", "c"), content_hash("s", "a", "bc"));
        assert_eq!(content_hash("s", "t", "x"), content_hash("s", "t", "x"));
    }

    #[test]
    fn only_approval_gated_modes_are_shareable() {
        assert_eq!(share_mode_for_backend("codex"), Some("read-only"));
        assert_eq!(share_mode_for_backend("claude"), Some("default"));
        assert_eq!(share_mode_for_backend("gemini"), None);
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        let mut s = "aé".to_owned();
        truncate_utf8(&mut s, 2);
        assert_eq!(s, "a");
    }

    #[test]
    fn request_id_shape() {
        assert!(valid_request_id("0192f3a4-aaaa-7bbb-8ccc-123456789abc"));
        assert!(!valid_request_id(""));
        assert!(!valid_request_id("a/b"));
        assert!(!valid_request_id(&"a".repeat(65)));
    }
}
