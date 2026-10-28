//! Audit H2: `aioncore doctor` opens (and may create and migrate) the database, so it
//! makes the data dir owner-only (0700) and the database 0600, like the server and the
//! `user`/`secret` commands. Runs in a temp data dir with a temp HOME.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tokio::process::Command;

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn doctor_creates_an_owner_only_data_dir_and_database() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let data = root.path().join("fresh-data");

    let output = Command::new(env!("CARGO_BIN_EXE_aioncore"))
        .arg("--data-dir")
        .arg(&data)
        .arg("doctor")
        .env("HOME", &home)
        .output()
        .await
        .unwrap();

    assert!(
        output.status.success(),
        "doctor failed\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(mode(&data), 0o700, "data dir");
    assert_eq!(mode(&data.join("aionui-backend.db")), 0o600, "database");
}
