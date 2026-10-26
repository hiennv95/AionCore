//! Copy of the database taken before pending migrations run.
//!
//! Migrations are forward-only, so returning to an older binary needs the data
//! as it was before the upgrade. The copy is made with `VACUUM INTO`, which is
//! consistent under WAL, and sits next to the database file.

use std::path::{Path, PathBuf};

use sqlx::SqlitePool;
use tracing::{info, warn};

use crate::error::DbError;

/// Backups kept per database; older ones are deleted after a new one is written.
pub(crate) const KEPT_BACKUPS: usize = 3;

const BACKUP_MARKER: &str = ".pre-migration-v";

/// Highest applied migration version, `None` for a database never migrated.
async fn applied_version(pool: &SqlitePool) -> Result<Option<i64>, DbError> {
    let has_table: Option<(String,)> =
        sqlx::query_as("SELECT name FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'")
            .fetch_optional(pool)
            .await
            .map_err(DbError::Query)?;
    if has_table.is_none() {
        return Ok(None);
    }
    let (version,): (Option<i64>,) = sqlx::query_as("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(version)
}

/// Back up `db_path` when it already holds data and `latest` is newer than what
/// it was migrated to. Returns the backup path, or `None` when nothing is pending.
pub(crate) async fn backup_before_migrations(
    pool: &SqlitePool,
    db_path: &Path,
    latest: Option<i64>,
) -> Result<Option<PathBuf>, DbError> {
    let (Some(applied), Some(latest)) = (applied_version(pool).await?, latest) else {
        return Ok(None);
    };
    if applied >= latest {
        return Ok(None);
    }
    let file_name = db_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "aionui.db".to_owned());
    let backup = db_path.with_file_name(format!(
        "{file_name}{BACKUP_MARKER}{applied}-{}.sqlite",
        aionui_common::now_ms()
    ));
    sqlx::query("VACUUM INTO ?")
        .bind(backup.to_string_lossy().into_owned())
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    info!(
        applied_version = applied,
        target_version = latest,
        backup = %backup.display(),
        "Backed up database before applying migrations"
    );
    prune_old_backups(db_path, &file_name);
    Ok(Some(backup))
}

/// Keep the newest [`KEPT_BACKUPS`] backups of this database. Best effort.
fn prune_old_backups(db_path: &Path, file_name: &str) {
    let Some(dir) = db_path.parent() else { return };
    let prefix = format!("{file_name}{BACKUP_MARKER}");
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut backups: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .filter_map(|entry| Some((entry.metadata().ok()?.modified().ok()?, entry.path())))
        .collect();
    backups.sort_by_key(|backup| std::cmp::Reverse(backup.0));
    for (_, old) in backups.into_iter().skip(KEPT_BACKUPS) {
        if let Err(error) = std::fs::remove_file(&old) {
            warn!(backup = %old.display(), %error, "Could not delete an old pre-migration backup");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqliteConnectOptions;

    async fn file_pool(path: &Path) -> SqlitePool {
        let opts = SqliteConnectOptions::new().filename(path).create_if_missing(true);
        SqlitePool::connect_with(opts).await.unwrap()
    }

    async fn migrated_to(pool: &SqlitePool, version: i64) {
        sqlx::query("CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY)")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO _sqlx_migrations (version) VALUES (?)")
            .bind(version)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE notes (body TEXT); INSERT INTO notes VALUES ('kept')")
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fresh_database_is_not_backed_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aionui.db");
        let pool = file_pool(&path).await;
        assert_eq!(backup_before_migrations(&pool, &path, Some(45)).await.unwrap(), None);
    }

    #[tokio::test]
    async fn up_to_date_database_is_not_backed_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aionui.db");
        let pool = file_pool(&path).await;
        migrated_to(&pool, 45).await;
        assert_eq!(backup_before_migrations(&pool, &path, Some(45)).await.unwrap(), None);
    }

    #[tokio::test]
    async fn pending_migrations_produce_a_readable_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aionui.db");
        let pool = file_pool(&path).await;
        migrated_to(&pool, 44).await;

        let backup = backup_before_migrations(&pool, &path, Some(45)).await.unwrap().unwrap();
        assert!(
            backup
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("aionui.db.pre-migration-v44-")
        );

        let copy = file_pool(&backup).await;
        let (body,): (String,) = sqlx::query_as("SELECT body FROM notes").fetch_one(&copy).await.unwrap();
        assert_eq!(body, "kept");
    }

    #[tokio::test]
    async fn only_the_newest_backups_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aionui.db");
        for i in 0..(KEPT_BACKUPS + 2) {
            let old = dir.path().join(format!("aionui.db{BACKUP_MARKER}40-{i}.sqlite"));
            std::fs::write(&old, b"old").unwrap();
            // Distinct mtimes so the newest-first order is deterministic.
            let time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000 + i as u64);
            std::fs::File::options()
                .write(true)
                .open(&old)
                .unwrap()
                .set_modified(time)
                .unwrap();
        }
        std::fs::write(dir.path().join("unrelated.sqlite"), b"x").unwrap();

        prune_old_backups(&path, "aionui.db");

        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        let expected_newest: Vec<String> = (2..(KEPT_BACKUPS + 2))
            .map(|i| format!("aionui.db{BACKUP_MARKER}40-{i}.sqlite"))
            .collect();
        for name in &expected_newest {
            assert!(left.contains(name), "{name} should be kept; left={left:?}");
        }
        assert!(left.contains(&"unrelated.sqlite".to_owned()));
        assert_eq!(left.len(), KEPT_BACKUPS + 1);
    }
}
