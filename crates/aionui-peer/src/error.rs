use std::io;

/// Errors raised while loading the host identity or configuring peer TLS.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("peer identity I/O failed at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("peer identity is invalid: {0}")]
    InvalidIdentity(String),
    #[error("peer TLS configuration failed: {0}")]
    Tls(String),
}
