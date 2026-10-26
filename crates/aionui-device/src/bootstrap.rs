//! Per-launch bootstrap secret for the desktop app (ADR-011 §1).
//!
//! Written to `<data-dir>/app-bootstrap.token` with owner-only permissions at
//! every start; the Flutter desktop app (same OS user) reads it and exchanges
//! it for a device session. A new start invalidates the previous value.

use std::io::Write;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::DeviceError;
use crate::secret::{digest, digest_eq, random_secret};

pub const BOOTSTRAP_FILE_NAME: &str = "app-bootstrap.token";

pub struct BootstrapToken {
    digest: [u8; 32],
    path: PathBuf,
}

impl BootstrapToken {
    /// Generate a fresh secret and write it to `data_dir`, replacing any old file.
    pub fn create(data_dir: &Path) -> Result<Self, DeviceError> {
        let secret = random_secret()?;
        let path = data_dir.join(BOOTSTRAP_FILE_NAME);
        write_owner_only(&path, secret.as_bytes())
            .map_err(|e| DeviceError::Internal(format!("cannot write {}: {e}", path.display())))?;
        Ok(Self {
            digest: digest(&secret),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn matches(&self, presented: &str) -> bool {
        digest_eq(&self.digest, &digest(presented.trim()))
    }

    /// Hex HMAC-SHA256 of `"aionx-host-proof:" + nonce`, keyed with the secret's
    /// digest: shows the app this host wrote the file it is about to send.
    pub fn prove(&self, nonce: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.digest).expect("HMAC takes any key length");
        mac.update(HOST_PROOF_LABEL.as_bytes());
        mac.update(nonce.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

const HOST_PROOF_LABEL: &str = "aionx-host-proof:";

/// Write via a temp file + rename so a reader never sees a partial secret.
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_an_owner_only_file_that_matches_only_its_secret() {
        let dir = tempfile::tempdir().unwrap();
        let token = BootstrapToken::create(dir.path()).unwrap();
        let secret = std::fs::read_to_string(token.path()).unwrap();
        assert!(token.matches(&secret));
        assert!(token.matches(&format!("{secret}\n")));
        assert!(!token.matches("nope"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(token.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn host_proof_is_hmac_of_the_nonce_keyed_by_the_secret_digest() {
        let dir = tempfile::tempdir().unwrap();
        let token = BootstrapToken::create(dir.path()).unwrap();
        let secret = std::fs::read_to_string(token.path()).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&digest(&secret)).unwrap();
        mac.update(b"aionx-host-proof:abc");
        assert_eq!(token.prove("abc"), hex::encode(mac.finalize().into_bytes()));
        let other = BootstrapToken::create(dir.path()).unwrap();
        assert_ne!(
            other.prove("abc"),
            token.prove("abc"),
            "a new launch proves with a new secret"
        );
    }

    #[test]
    fn host_proof_known_vector() {
        // Same vector as the desktop app's `host_proof_test.dart`.
        let token = BootstrapToken {
            digest: digest(&"0123456789abcdef".repeat(4)),
            path: PathBuf::new(),
        };
        assert_eq!(
            token.prove("00112233445566778899aabbccddeeff"),
            "225a454315880991068849b056b567718bb9bb1ecc9bd8e08c43a83eab614f40"
        );
    }

    #[test]
    fn a_new_launch_invalidates_the_old_secret() {
        let dir = tempfile::tempdir().unwrap();
        let first = BootstrapToken::create(dir.path()).unwrap();
        let old = std::fs::read_to_string(first.path()).unwrap();
        let second = BootstrapToken::create(dir.path()).unwrap();
        assert!(!second.matches(&old));
        assert!(second.matches(&std::fs::read_to_string(second.path()).unwrap()));
    }
}
