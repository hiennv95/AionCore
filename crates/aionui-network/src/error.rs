use aionui_db::DbError;

/// Errors of the LAN network domain. Each variant has a stable machine code
/// shared by the owner API and the peer protocol (ADR-009).
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("only the host owner can manage the LAN network")]
    OwnerOnly,
    #[error("LAN collaboration is turned off on this host")]
    Disabled,
    #[error("peer is not trusted by this host")]
    PeerUntrusted,
    #[error("peer has been revoked on this host")]
    PeerRevoked,
    #[error("peer not found")]
    PeerNotFound,
    #[error("too many pending pairing requests")]
    PairingLimit,
    #[error("the fingerprint presented by the peer changed")]
    FingerprintMismatch,
    #[error("share not found or no longer active")]
    ShareNotFound,
    #[error("request not found")]
    RequestNotFound,
    #[error("request id already used with different content")]
    RequestConflict,
    #[error("the owner host's queue is full")]
    QueueFull,
    #[error("unsupported protocol version")]
    VersionUnsupported,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("request is already finished")]
    AlreadyFinished,
    #[error("peer unreachable: {0}")]
    PeerUnreachable(String),
    #[error("peer rejected the call: {code}")]
    PeerRejected { code: String, message: String },
    #[error("network listener failed: {0}")]
    Listener(String),
    #[error("database error: {0}")]
    Db(#[from] DbError),
    #[error("internal error: {0}")]
    Internal(String),
}

impl NetworkError {
    /// Stable machine code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "INVALID_REQUEST",
            Self::OwnerOnly => "NETWORK_OWNER_ONLY",
            Self::Disabled => "NETWORK_DISABLED",
            Self::PeerUntrusted => "PEER_UNTRUSTED",
            Self::PeerRevoked => "PEER_REVOKED",
            Self::PeerNotFound => "PEER_NOT_FOUND",
            Self::PairingLimit => "PAIRING_LIMIT",
            Self::FingerprintMismatch => "FINGERPRINT_MISMATCH",
            Self::ShareNotFound => "SHARE_NOT_FOUND",
            Self::RequestNotFound => "REQUEST_NOT_FOUND",
            Self::RequestConflict => "REQUEST_CONFLICT",
            Self::QueueFull => "QUEUE_FULL",
            Self::VersionUnsupported => "VERSION_UNSUPPORTED",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::AlreadyFinished => "REQUEST_FINISHED",
            Self::PeerUnreachable(_) => "PEER_UNREACHABLE",
            Self::PeerRejected { .. } => "PEER_REJECTED",
            Self::Listener(_) => "NETWORK_LISTENER_FAILED",
            Self::Db(_) | Self::Internal(_) => "NETWORK_INTERNAL",
        }
    }

    /// HTTP status for this error (both APIs).
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidRequest(_) | Self::VersionUnsupported => 400,
            Self::OwnerOnly | Self::PeerUntrusted | Self::PeerRevoked | Self::FingerprintMismatch => 403,
            Self::PeerNotFound | Self::ShareNotFound | Self::RequestNotFound => 404,
            Self::Disabled | Self::RequestConflict | Self::AlreadyFinished => 409,
            Self::PayloadTooLarge => 413,
            Self::PairingLimit | Self::QueueFull => 429,
            Self::PeerUnreachable(_) | Self::PeerRejected { .. } => 502,
            Self::Listener(_) | Self::Db(_) | Self::Internal(_) => 500,
        }
    }

    /// Message safe to return to a caller: internal detail never leaves the host.
    pub fn public_message(&self) -> String {
        match self {
            Self::Db(_) | Self::Internal(_) => "internal error".to_owned(),
            Self::PeerRejected { code, message } => format!("{code}: {message}"),
            other => other.to_string(),
        }
    }

    /// Map a peer's error code back to a typed error (requester side).
    pub fn from_peer_code(code: &str, message: String) -> Self {
        match code {
            "PEER_UNTRUSTED" => Self::PeerUntrusted,
            "PEER_REVOKED" => Self::PeerRevoked,
            "SHARE_NOT_FOUND" => Self::ShareNotFound,
            "REQUEST_NOT_FOUND" => Self::RequestNotFound,
            "REQUEST_CONFLICT" => Self::RequestConflict,
            "QUEUE_FULL" => Self::QueueFull,
            "VERSION_UNSUPPORTED" => Self::VersionUnsupported,
            "PAYLOAD_TOO_LARGE" => Self::PayloadTooLarge,
            "PAIRING_LIMIT" => Self::PairingLimit,
            "NETWORK_DISABLED" => Self::Disabled,
            _ => Self::PeerRejected {
                code: code.to_owned(),
                message,
            },
        }
    }
}
