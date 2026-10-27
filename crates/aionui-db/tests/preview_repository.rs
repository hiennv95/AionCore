//! Preview v1 storage (ADR-017): file refs per conversation and the owner's device setting.

use aionui_db::{IPreviewRepository, SqlitePreviewRepository, UpsertFileRefParams, init_database_memory};

async fn conversation(pool: &sqlx::SqlitePool, id: &str) {
    sqlx::query(
        "INSERT INTO conversations (id, user_id, name, type, created_at, updated_at) \
         VALUES (?, 'system_default_user', 'c', 'acp', 1, 1)",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
}

fn params<'a>(conversation_id: &'a str, rel_path: &'a str, call_id: &'a str, mtime_ms: i64) -> UpsertFileRefParams<'a> {
    UpsertFileRefParams {
        conversation_id,
        rel_path,
        workspace_canonical: "/ws",
        call_id: Some(call_id),
        size: 3,
        mtime_ms,
    }
}

#[tokio::test]
async fn a_later_report_of_the_same_path_refreshes_the_ref_and_keeps_its_id() {
    let db = init_database_memory().await.unwrap();
    conversation(db.pool(), "c1").await;
    let repo = SqlitePreviewRepository::new(db.pool().clone());

    let first = repo
        .upsert_file_ref(params("c1", "src/a.rs", "call-1", 10))
        .await
        .unwrap();
    let again = repo
        .upsert_file_ref(params("c1", "src/a.rs", "call-2", 20))
        .await
        .unwrap();
    assert_eq!(again.id, first.id);
    assert_eq!(again.call_id.as_deref(), Some("call-2"));
    assert_eq!(again.mtime_ms, 20);

    repo.upsert_file_ref(params("c1", "README.md", "call-3", 30))
        .await
        .unwrap();
    let listed = repo.list_file_refs("c1").await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(repo.find_file_ref("c1", &first.id).await.unwrap().is_some());
}

#[tokio::test]
async fn refs_are_scoped_to_their_conversation_and_go_with_it() {
    let db = init_database_memory().await.unwrap();
    conversation(db.pool(), "c1").await;
    conversation(db.pool(), "c2").await;
    let repo = SqlitePreviewRepository::new(db.pool().clone());
    let r = repo.upsert_file_ref(params("c1", "a.txt", "call-1", 1)).await.unwrap();

    assert!(repo.find_file_ref("c2", &r.id).await.unwrap().is_none());
    assert!(repo.list_file_refs("c2").await.unwrap().is_empty());

    sqlx::query("DELETE FROM conversations WHERE id = 'c1'")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(repo.list_file_refs("c1").await.unwrap().is_empty());
}

#[tokio::test]
async fn device_preview_is_off_until_the_owner_turns_it_on() {
    let db = init_database_memory().await.unwrap();
    let repo = SqlitePreviewRepository::new(db.pool().clone());
    assert!(!repo.devices_allowed("system_default_user").await.unwrap());
    repo.set_devices_allowed("system_default_user", true).await.unwrap();
    assert!(repo.devices_allowed("system_default_user").await.unwrap());
    repo.set_devices_allowed("system_default_user", false).await.unwrap();
    assert!(!repo.devices_allowed("system_default_user").await.unwrap());
}
