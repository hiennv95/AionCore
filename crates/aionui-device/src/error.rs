use aionui_db::DbError;

/// Errors of the device domain, each with a stable code (ADR-011).
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("only the host owner can manage devices")]
    OwnerOnly,
    #[error("the bootstrap token is not valid for this host instance")]
    BootstrapInvalid,
    #[error("pairing not found")]
    PairingNotFound,
    #[error("pairing expired")]
    PairingExpired,
    #[error("pairing secret was already used")]
    PairingUsed,
    #[error("the owner rejected this device")]
    PairingRejected,
    #[error("pairing is not waiting for approval")]
    PairingNotRequested,
    #[error("too many open pairings")]
    PairingLimit,
    #[error("device not found")]
    DeviceNotFound,
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("internal error: {0}")]
    Internal(String),
}

impl DeviceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "INVALID_REQUEST",
            Self::OwnerOnly => "DEVICE_OWNER_ONLY",
            Self::BootstrapInvalid => "BOOTSTRAP_INVALID",
            Self::PairingNotFound => "PAIRING_NOT_FOUND",
            Self::PairingExpired => "PAIRING_EXPIRED",
            Self::PairingUsed => "PAIRING_USED",
            Self::PairingRejected => "PAIRING_REJECTED",
            Self::PairingNotRequested => "PAIRING_NOT_REQUESTED",
            Self::PairingLimit => "PAIRING_LIMIT",
            Self::DeviceNotFound => "DEVICE_NOT_FOUND",
            Self::Db(_) | Self::Internal(_) => "DEVICE_INTERNAL",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidRequest(_) => 400,
            Self::OwnerOnly => 403,
            Self::BootstrapInvalid | Self::PairingNotFound | Self::PairingUsed => 401,
            Self::PairingExpired | Self::PairingRejected => 410,
            Self::PairingNotRequested => 409,
            Self::PairingLimit => 429,
            Self::DeviceNotFound => 404,
            Self::Db(_) | Self::Internal(_) => 500,
        }
    }

    /// Message safe to return to clients (no internal details).
    pub fn public_message(&self) -> String {
        match self {
            Self::Db(_) | Self::Internal(_) => "internal error".to_owned(),
            other => other.to_string(),
        }
    }
}
