//! Audit H1: every copy of the database holds the JWT signing and storage-encryption
//! secrets, so the copies the database layer writes are owner-only (0600) whatever the
//! source mode or umask: the legacy-copy staging file and the corrupted-database backup.
//! (The pre-migration backup is covered in `migration_backup.rs`.)
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use aionui_db::{DatabaseInitOptions, init_database_with_options, maybe_copy_legacy_database};

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_world_readable_legacy_database_is_copied_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let legacy = dir.path().join("aionui.db");
    std::fs::write(&legacy, b"legacy data").unwrap();
    std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o644)).unwrap();
    let target = dir.path().join("aionui-backend.db");

    maybe_copy_legacy_database(&target).unwrap();

    assert_eq!(std::fs::read(&target).unwrap(), b"legacy data");
    assert_eq!(mode(&target), 0o600);
    assert!(!target.with_extension("db.tmp").exists(), "no staging file left");
}

#[test]
fn a_legacy_copy_never_writes_through_a_planted_staging_symlink() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("aionui.db"), b"legacy data").unwrap();
    let elsewhere = dir.path().join("elsewhere.db");
    std::fs::write(&elsewhere, b"untouched").unwrap();
    let target = dir.path().join("aionui-backend.db");
    std::os::unix::fs::symlink(&elsewhere, target.with_extension("db.tmp")).unwrap();

    assert!(maybe_copy_legacy_database(&target).is_err(), "fails closed");
    assert_eq!(std::fs::read(&elsewhere).unwrap(), b"untouched");
    assert!(!target.exists());
}

#[tokio::test]
async fn the_corrupted_database_backup_is_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    std::fs::write(&path, b"not a valid sqlite database").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let db = init_database_with_options(
        &path,
        DatabaseInitOptions {
            recover_corrupted_database: true,
        },
    )
    .await
    .unwrap();

    let backups: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".backup."))
        .map(|e| e.path())
        .collect();
    assert_eq!(backups.len(), 1, "{backups:?}");
    assert_eq!(mode(&backups[0]), 0o600);
    db.close().await;
}

#[test]
fn restricting_a_symlink_refuses_and_leaves_the_target_alone() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside.txt");
    std::fs::write(&outside, b"not ours").unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o644)).unwrap();
    let link = dir.path().join("link.db");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    assert!(aionui_db::restrict_to_owner(&link).is_err());
    assert_eq!(mode(&outside), 0o644);

    let regular = dir.path().join("regular.db");
    std::fs::write(&regular, b"x").unwrap();
    std::fs::set_permissions(&regular, std::fs::Permissions::from_mode(0o644)).unwrap();
    aionui_db::restrict_to_owner(&regular).unwrap();
    assert_eq!(mode(&regular), 0o600);
}
