//! Long-lived host identity: a self-signed certificate whose SHA-256 fingerprint names the host.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

use crate::error::PeerError;

const CERT_FILE: &str = "identity.crt";
const KEY_FILE: &str = "identity.key";

/// Lowercase hex SHA-256 of a DER certificate: the stable identity of a host.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub fn of(cert_der: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(cert_der)))
    }

    /// Parse a fingerprint the user typed or stored (64 hex chars, case-insensitive).
    pub fn parse(value: &str) -> Result<Self, PeerError> {
        let normalized = value.trim().to_ascii_lowercase().replace(':', "");
        if normalized.len() == 64 && normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(Self(normalized))
        } else {
            Err(PeerError::InvalidIdentity(
                "fingerprint must be 64 hex characters".into(),
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// First 16 hex chars, for logs and UI labels (not for authorization).
    pub fn short(&self) -> &str {
        &self.0[..16]
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Certificate + private key of this host, loaded from (or created in) `<dir>/`.
pub struct PeerIdentity {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    fingerprint: Fingerprint,
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the private key.
        f.debug_struct("PeerIdentity")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl PeerIdentity {
    /// Load the identity in `dir`, creating a new self-signed one on first use.
    /// `name` only labels the certificate; identity is the fingerprint.
    pub fn load_or_create(dir: &Path, name: &str) -> Result<Self, PeerError> {
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        if !cert_path.exists() || !key_path.exists() {
            Self::create(dir, name, &cert_path, &key_path)?;
        }
        let cert = CertificateDer::from_pem_file(&cert_path)
            .map_err(|e| PeerError::InvalidIdentity(format!("certificate: {e}")))?;
        let key = PrivateKeyDer::from_pem_file(&key_path)
            .map_err(|e| PeerError::InvalidIdentity(format!("private key: {e}")))?;
        let fingerprint = Fingerprint::of(&cert);
        Ok(Self { cert, key, fingerprint })
    }

    fn create(dir: &Path, name: &str, cert_path: &Path, key_path: &Path) -> Result<(), PeerError> {
        fs::create_dir_all(dir).map_err(|source| io_err(dir, source))?;
        let key_pair = rcgen::KeyPair::generate().map_err(|e| PeerError::InvalidIdentity(e.to_string()))?;
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()])
            .map_err(|e| PeerError::InvalidIdentity(e.to_string()))?;
        // Identity is pinned by fingerprint, not by expiry or a CA; keep it valid long-term.
        params.not_after = rcgen::date_time_ymd(2099, 12, 31);
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| PeerError::InvalidIdentity(e.to_string()))?;
        write_private(key_path, key_pair.serialize_pem().as_bytes())?;
        fs::write(cert_path, cert.pem()).map_err(|source| io_err(cert_path, source))?;
        Ok(())
    }

    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    pub fn certificate(&self) -> CertificateDer<'static> {
        self.cert.clone()
    }

    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

/// Write a secret file readable only by the owner (0600 on Unix), created fresh.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), PeerError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|source| io_err(path, source))?;
    file.write_all(bytes).map_err(|source| io_err(path, source))
}

fn io_err(path: &Path, source: std::io::Error) -> PeerError {
    PeerError::Io {
        path: path.display().to_string(),
        source,
    }
}
