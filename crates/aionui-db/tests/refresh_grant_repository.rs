//! Refresh-token rotation grants (ADR-022): compare-and-swap rotation and revoke.

use aionui_db::{GrantPair, IRefreshGrantRepository, SqliteRefreshGrantRepository, init_database_memory};

fn pair(jti: &str, at: i64) -> GrantPair<'_> {
    GrantPair {
        jti,
        issued_at: at,
        access_expires_at: at + 900,
        refresh_expires_at: at + 30 * 86_400,
    }
}

#[tokio::test]
async fn rotation_is_a_compare_and_swap_on_the_current_jti() {
    let db = init_database_memory().await.unwrap();
    let repo = SqliteRefreshGrantRepository::new(db.pool().clone());
    repo.create("g1", "u1", Some("d1"), pair("j1", 100), 1_000)
        .await
        .unwrap();

    assert!(repo.rotate("g1", "j1", pair("j2", 200), 2_000).await.unwrap());
    // A second rotation from the same jti loses: the grant has moved on.
    assert!(!repo.rotate("g1", "j1", pair("j3", 300), 3_000).await.unwrap());

    let row = repo.find("g1").await.unwrap().unwrap();
    assert_eq!(row.current_jti, "j2");
    assert_eq!(row.previous_jti.as_deref(), Some("j1"));
    assert_eq!((row.issued_at, row.rotated_at), (200, Some(2_000)));
}

#[tokio::test]
async fn a_revoked_grant_no_longer_rotates() {
    let db = init_database_memory().await.unwrap();
    let repo = SqliteRefreshGrantRepository::new(db.pool().clone());
    repo.create("g1", "u1", None, pair("j1", 100), 1_000).await.unwrap();
    assert!(repo.revoke("g1", 1_500).await.unwrap());
    assert!(!repo.revoke("g1", 1_600).await.unwrap(), "revoked once");
    assert!(!repo.rotate("g1", "j1", pair("j2", 200), 2_000).await.unwrap());
    assert_eq!(repo.find("g1").await.unwrap().unwrap().revoked_at, Some(1_500));
}
