//! Owner-only data directory. The database in it holds the JWT signing and
//! storage-encryption secrets, so other local accounts must not read it,
//! whichever launcher created the directory (audit run-2 SEC-D).

use std::path::{Path, PathBuf};

use super::error::{BootstrapError, BootstrapErrorCode};

/// Creates `dir` if needed and restricts it to the current user (0700).
/// Refuses a directory owned by another user rather than taking it over.
/// Returns the resolved path: use it from here on, so a symlink in `dir`
/// cannot be re-pointed after the check.
#[cfg(unix)]
pub(crate) fn secure_data_dir(dir: &Path) -> Result<PathBuf, BootstrapError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fail = |message: &'static str| {
        BootstrapError::new(BootstrapErrorCode::ConfigInvalid, "config.data_dir", message)
            .with_field("dataDir", dir.display().to_string())
    };
    std::fs::create_dir_all(dir).map_err(|e| fail("data directory cannot be created").with_source(e))?;
    let dir = dir
        .canonicalize()
        .map_err(|e| fail("data directory cannot be resolved").with_source(e))?;
    let meta = std::fs::metadata(&dir).map_err(|e| fail("data directory cannot be read").with_source(e))?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(fail("data directory is owned by another user"));
    }
    if meta.permissions().mode() & 0o777 != 0o700 {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| fail("data directory permissions cannot be restricted").with_source(e))?;
    }
    Ok(dir)
}

#[cfg(not(unix))]
pub(crate) fn secure_data_dir(dir: &Path) -> Result<PathBuf, BootstrapError> {
    std::fs::create_dir_all(dir).map_err(|e| {
        BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.data_dir",
            "data directory cannot be created",
        )
        .with_source(e)
    })?;
    Ok(dir.to_path_buf())
}

/// Restricts the SQLite database and its WAL/SHM side files to the owner
/// (0600). Best effort: the 0700 directory already blocks other accounts. A
/// symlink in place of one of them is left alone, and so is its target: the
/// chmod goes through a descriptor opened without following it (audit H2).
#[cfg(unix)]
pub(crate) fn secure_database_files(db_path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut path = db_path.as_os_str().to_owned();
        path.push(suffix);
        let path = std::path::PathBuf::from(path);
        match aionui_db::restrict_to_owner(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "could not restrict database file permissions");
            }
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn secure_database_files(_db_path: &Path) {}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_a_missing_dir_owner_only() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("a/b");
        secure_data_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn tightens_an_existing_open_dir() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        secure_data_dir(root.path()).unwrap();
        assert_eq!(mode(root.path()), 0o700);
    }

    #[test]
    fn restricts_the_database_and_its_side_files() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("aionui-backend.db");
        for name in ["aionui-backend.db", "aionui-backend.db-wal"] {
            std::fs::write(root.path().join(name), b"x").unwrap();
            std::fs::set_permissions(root.path().join(name), std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        secure_database_files(&db);
        assert_eq!(mode(&db), 0o600);
        assert_eq!(mode(&root.path().join("aionui-backend.db-wal")), 0o600);
    }

    /// Audit H2: a symlink planted as a side file never has its target's mode changed.
    #[test]
    fn leaves_a_symlinked_side_file_and_its_target_alone() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("aionui-backend.db");
        std::fs::write(&db, b"x").unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        let outside = root.path().join("outside.txt");
        std::fs::write(&outside, b"not ours").unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&outside, root.path().join("aionui-backend.db-wal")).unwrap();

        secure_database_files(&db);

        assert_eq!(mode(&db), 0o600);
        assert_eq!(mode(&outside), 0o644, "the symlink target keeps its mode");
    }
}
