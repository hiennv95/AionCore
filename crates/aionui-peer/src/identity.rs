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
    ///
    /// Only an empty start creates one. A certificate without its key (or the
    /// reverse) is refused: replacing it would silently give the host a new identity
    /// that paired devices and peers no longer recognize.
    ///
    /// Peers and devices pin this certificate, so whoever can read or swap the key can
    /// impersonate the host. On Unix the files are therefore loaded only from a real
    /// directory owned by this user that group and others cannot write, without
    /// following links, and only if the key is owner-only (see [`read_owned`]).
    pub fn load_or_create(dir: &Path, name: &str) -> Result<Self, PeerError> {
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        match (present(&cert_path)?, present(&key_path)?) {
            (false, false) => Self::create(dir, name, &cert_path, &key_path)?,
            (true, true) => {}
            (true, false) => {
                return Err(untrusted(
                    &key_path,
                    "missing next to its certificate; restore the key (devices and peers pin this certificate)",
                ));
            }
            (false, true) => {
                return Err(untrusted(
                    &cert_path,
                    "missing next to its key; restore the certificate, or delete the key if no certificate was ever issued",
                ));
            }
        }
        check_private_dir(dir)?;
        // The certificate is public but must not be replaceable; the key must be secret.
        let cert = CertificateDer::from_pem_slice(&read_owned(&cert_path, 0o022)?)
            .map_err(|e| untrusted(&cert_path, &format!("not a PEM certificate: {e}")))?;
        let key = PrivateKeyDer::from_pem_slice(&read_owned(&key_path, 0o077)?)
            .map_err(|e| untrusted(&key_path, &format!("not a PEM private key: {e}")))?;
        let fingerprint = Fingerprint::of(&cert);
        Ok(Self { cert, key, fingerprint })
    }

    fn create(dir: &Path, name: &str, cert_path: &Path, key_path: &Path) -> Result<(), PeerError> {
        // A new identity directory is owner-only; an existing one keeps its mode.
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir).map_err(|source| io_err(dir, source))?;
        // Nothing is written into a directory that is not ours: a planted link to an empty
        // directory, or an existing world-writable one, is refused before the key exists.
        check_private_dir(dir)?;
        let key_pair = rcgen::KeyPair::generate().map_err(|e| PeerError::InvalidIdentity(e.to_string()))?;
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()])
            .map_err(|e| PeerError::InvalidIdentity(e.to_string()))?;
        // Identity is pinned by fingerprint, not by expiry or a CA; keep it valid long-term.
        params.not_after = rcgen::date_time_ymd(2099, 12, 31);
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| PeerError::InvalidIdentity(e.to_string()))?;
        write_private(key_path, key_pair.serialize_pem().as_bytes())?;
        // A key without its certificate was never served, so nobody pinned it: remove it
        // rather than leave a partial identity that every later start refuses.
        if let Err(error) = write_private(cert_path, cert.pem().as_bytes()) {
            let _ = fs::remove_file(key_path);
            return Err(error);
        }
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

/// Whether anything is at `path`, a dangling link included. Only "not found" counts
/// as absent; any other error is reported, never taken as a reason to create.
fn present(path: &Path) -> Result<bool, PeerError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_err(path, source)),
    }
}

fn untrusted(path: &Path, why: &str) -> PeerError {
    PeerError::InvalidIdentity(format!("{}: {why}", path.display()))
}

/// The identity directory: a real directory (not a link) owned by this user that
/// group and others cannot write (mode bits; ACLs are not inspected).
#[cfg(unix)]
fn check_private_dir(dir: &Path) -> Result<(), PeerError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = fs::symlink_metadata(dir).map_err(|source| io_err(dir, source))?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let owner = unsafe { libc::geteuid() };
    if !meta.file_type().is_dir() || meta.uid() != owner || meta.permissions().mode() & 0o022 != 0 {
        return Err(untrusted(
            dir,
            "the identity directory must be a directory owned by this user that group and others cannot write",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_dir(_dir: &Path) -> Result<(), PeerError> {
    Ok(())
}

/// Read an identity file without following a link at `path` (or blocking on a FIFO),
/// then check what was opened: a regular file owned by this user with none of the
/// `forbidden` mode bits.
#[cfg(unix)]
fn read_owned(path: &Path, forbidden: u32) -> Result<Vec<u8>, PeerError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| io_err(path, source))?;
    let meta = file.metadata().map_err(|source| io_err(path, source))?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let owner = unsafe { libc::geteuid() };
    if !meta.is_file() || meta.uid() != owner || meta.permissions().mode() & forbidden != 0 {
        return Err(untrusted(
            path,
            &format!(
                "must be a regular file owned by this user without mode bits {forbidden:03o} (it has {:03o})",
                meta.permissions().mode() & 0o777
            ),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|source| io_err(path, source))?;
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_owned(path: &Path, _forbidden: u32) -> Result<Vec<u8>, PeerError> {
    fs::read(path).map_err(|source| io_err(path, source))
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
    // A half-written file would fail every later load: remove it instead.
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(io_err(path, source));
    }
    Ok(())
}

fn io_err(path: &Path, source: std::io::Error) -> PeerError {
    PeerError::Io {
        path: path.display().to_string(),
        source,
    }
}
