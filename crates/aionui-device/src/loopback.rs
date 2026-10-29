//! Desktop loopback TLS listener (`--loopback-tls`): the same API as the HTTP
//! listener, over TLS with this host's identity, on 127.0.0.1 only. The desktop
//! app finds its port and pins its fingerprint through `<data-dir>/identity.json`.
//!
//! The metadata file is written only after the listener is bound, through an
//! owner-only temp file that is renamed over the old one, so a reader sees the
//! previous file or the new one, never a partial one.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use aionui_peer::{PeerIdentity, device_server_config, serve_loopback_listener};
use axum::Router;
use axum::middleware;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::info;

use crate::error::DeviceError;
use crate::listener::secure_cookies;

pub const IDENTITY_METADATA_FILE: &str = "identity.json";

/// A bound loopback socket, not yet serving.
pub struct LoopbackTlsListener {
    listener: TcpListener,
    addr: SocketAddr,
}

impl LoopbackTlsListener {
    /// Bind 127.0.0.1:`port`; 0 lets the OS pick a free port.
    pub async fn bind(port: u16) -> Result<Self, DeviceError> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| DeviceError::Internal(format!("cannot listen on {addr}: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| DeviceError::Internal(format!("loopback TLS address: {e}")))?;
        debug_assert!(addr.ip().is_loopback());
        Ok(Self { listener, addr })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Serve `router` over TLS with `identity`. Cookies set over it are `Secure`.
    pub fn serve(self, identity: &PeerIdentity, router: Router) -> Result<JoinHandle<()>, DeviceError> {
        let tls = device_server_config(identity).map_err(|e| DeviceError::Internal(e.to_string()))?;
        // The marker the desktop credential policy trusts: only this listener adds it.
        let router = router
            .layer(axum::Extension(aionui_api_types::ViaLoopbackTls))
            .layer(middleware::from_fn(secure_cookies));
        info!(loopback_tls = %self.addr, host_fingerprint = %identity.fingerprint(), "device: loopback TLS listener ready");
        Ok(tokio::spawn(serve_loopback_listener(self.listener, tls, router)))
    }
}

#[derive(Serialize)]
struct IdentityMetadata<'a> {
    version: u32,
    /// The host identity's fingerprint: stable for as long as the identity is.
    host_id: &'a str,
    /// Informational only: a reader must not use it to decide anything.
    pid: u32,
    http_port: u16,
    port: u16,
    tls: TlsMetadata<'a>,
    created_at: i64,
}

#[derive(Serialize)]
struct TlsMetadata<'a> {
    enabled: bool,
    fingerprint_sha256: &'a str,
}

/// Publish `<data_dir>/identity.json` for a loopback TLS listener that is bound
/// on `tls_port`. On any error the previous file, if any, is left as it was.
pub fn publish_identity_metadata(
    data_dir: &Path,
    identity: &PeerIdentity,
    http_port: u16,
    tls_port: u16,
) -> Result<PathBuf, DeviceError> {
    let fingerprint = identity.fingerprint().as_str();
    let metadata = IdentityMetadata {
        version: 1,
        host_id: fingerprint,
        pid: std::process::id(),
        http_port,
        port: tls_port,
        tls: TlsMetadata {
            enabled: true,
            fingerprint_sha256: fingerprint,
        },
        created_at: aionui_common::now_ms(),
    };
    let bytes = serde_json::to_vec_pretty(&metadata).map_err(|e| DeviceError::Internal(e.to_string()))?;
    let path = data_dir.join(IDENTITY_METADATA_FILE);
    replace_private_file(data_dir, IDENTITY_METADATA_FILE, &bytes)
        .map_err(|e| DeviceError::Internal(format!("cannot write {}: {e}", path.display())))?;
    info!(path = %path.display(), port = tls_port, "device: loopback TLS identity published");
    Ok(path)
}

/// A start without the loopback TLS listener removes the metadata an earlier start left,
/// so the desktop app is not sent to a port that no longer serves it. Only the entry
/// itself is removed (a link is not followed); a missing file is fine.
pub fn withdraw_identity_metadata(data_dir: &Path) {
    let path = data_dir.join(IDENTITY_METADATA_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => info!(path = %path.display(), "device: stale loopback TLS identity removed"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(path = %path.display(), %error, "device: stale loopback TLS identity not removed"),
    }
}

/// Replace `dir/name` with `bytes` without following links or trusting what is
/// already there.
///
/// On Unix:
/// - `dir` must be a directory owned by this user that neither group nor others can
///   write (mode bits; ACLs are not inspected), so no other account can swap
///   entries in it;
/// - the temp file gets a unique name and is created with `O_CREAT|O_EXCL|O_NOFOLLOW`
///   and mode 0600, then checked on its descriptor (regular, one link, owned by
///   this user, owner-only) before anything is written;
/// - `rename` replaces the entry `name` itself: a link there is replaced, not
///   followed, and a directory there makes the call fail.
///
/// Elsewhere the directory's inherited ACLs are what keep the file private;
/// nothing is checked.
fn replace_private_file(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    check_private_dir(dir)?;
    let nonce = crate::secret::random_bytes::<8>().map_err(std::io::Error::other)?;
    let tmp = dir.join(format!(".{name}.{}.{}.tmp", std::process::id(), hex::encode(nonce)));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&tmp)?;
    let written = check_fresh_private_file(&file)
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&tmp, dir.join(name)));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return written;
    }
    // Make the rename itself durable (best effort: some filesystems refuse a dir fsync).
    #[cfg(unix)]
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(unix)]
fn check_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::metadata(dir)?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let owner = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != owner || meta.permissions().mode() & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the data directory must be owned by this user and not writable by group or others",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn check_fresh_private_file(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = file.metadata()?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let owner = unsafe { libc::geteuid() };
    if !meta.is_file() || meta.nlink() != 1 || meta.uid() != owner || meta.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the new metadata file is not a private regular file",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_fresh_private_file(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(dir: &Path) -> PeerIdentity {
        PeerIdentity::load_or_create(&dir.join("peer"), "test-host").unwrap()
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn publishes_owner_only_metadata_matching_the_identity() {
        let dir = private_dir();
        let identity = identity(dir.path());
        let path = publish_identity_metadata(dir.path(), &identity, 25808, 50123).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let fingerprint = identity.fingerprint().as_str();
        assert_eq!(value["version"], 1);
        assert_eq!(value["host_id"], fingerprint);
        assert_eq!(value["http_port"], 25808);
        assert_eq!(value["port"], 50123);
        assert_eq!(value["tls"]["enabled"], true);
        assert_eq!(value["tls"]["fingerprint_sha256"], fingerprint);
        assert_eq!(fingerprint.len(), 64);
        assert!(
            fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(leftovers(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_at_the_metadata_path_is_replaced_and_its_target_left_alone() {
        let dir = private_dir();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("victim.json");
        std::fs::write(&target, b"keep me").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(IDENTITY_METADATA_FILE)).unwrap();

        let path = publish_identity_metadata(dir.path(), &identity(dir.path()), 1, 2).unwrap();
        assert!(!std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
    }

    #[cfg(unix)]
    #[test]
    fn a_hard_link_at_the_metadata_path_leaves_the_other_name_alone() {
        use std::os::unix::fs::MetadataExt;
        let dir = private_dir();
        let other = dir.path().join("other.json");
        std::fs::write(&other, b"keep me").unwrap();
        std::fs::hard_link(&other, dir.path().join(IDENTITY_METADATA_FILE)).unwrap();

        let path = publish_identity_metadata(dir.path(), &identity(dir.path()), 1, 2).unwrap();
        assert_eq!(std::fs::read(&other).unwrap(), b"keep me");
        assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 1);
        assert_eq!(std::fs::metadata(&other).unwrap().nlink(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn an_untrusted_directory_is_refused_and_the_previous_file_kept() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let identity = identity(dir.path());
        let path = publish_identity_metadata(dir.path(), &identity, 1, 2).unwrap();
        let before = std::fs::read(&path).unwrap();

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(publish_identity_metadata(dir.path(), &identity, 1, 3).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn a_failed_rename_keeps_the_previous_entry_and_cleans_up() {
        let dir = private_dir();
        // A directory where the file should go: rename cannot replace it.
        std::fs::create_dir(dir.path().join(IDENTITY_METADATA_FILE)).unwrap();
        assert!(publish_identity_metadata(dir.path(), &identity(dir.path()), 1, 2).is_err());
        assert!(dir.path().join(IDENTITY_METADATA_FILE).is_dir());
        assert!(leftovers(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn binds_loopback_only_and_reports_the_actual_port() {
        let listener = LoopbackTlsListener::bind(0).await.unwrap();
        assert_ne!(listener.port(), 0);
        assert!(listener.addr.ip().is_loopback());
    }
}
