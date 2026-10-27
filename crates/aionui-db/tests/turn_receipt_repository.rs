//! Result receipts (B05.R1): observations stored once, acceptance kept apart, and the
//! turn's messages read by time window.

use aionui_db::{
    ITurnOutcomeRepository, ITurnReceiptRepository, RecordTurnOutcomeParams, RecordTurnReceiptParams,
    SqliteTurnOutcomeRepository, SqliteTurnReceiptRepository, init_database_memory,
};

async fn setup() -> (aionui_db::Database, SqliteTurnReceiptRepository) {
    let db = init_database_memory().await.unwrap();
    sqlx::query(
        "INSERT INTO conversations (id, user_id, name, type, created_at, updated_at) \
         VALUES ('c1', 'system_default_user', 'c', 'acp', 1, 1)",
    )
    .execute(db.pool())
    .await
    .unwrap();
    SqliteTurnOutcomeRepository::new(db.pool().clone())
        .record(RecordTurnOutcomeParams {
            turn_id: "t1",
            user_id: "system_default_user",
            conversation_id: "c1",
            outcome: "finished",
            source: "relay_finish",
            error_code: None,
            ended_at: 200,
        })
        .await
        .unwrap();
    let repo = SqliteTurnReceiptRepository::new(db.pool().clone());
    (db, repo)
}

fn receipt<'a>(fingerprint: &'a str) -> RecordTurnReceiptParams<'a> {
    RecordTurnReceiptParams {
        turn_id: "t1",
        conversation_id: "c1",
        started_at: 100,
        workspace_state: "git",
        workspace_head: Some("abc"),
        workspace_fingerprint: Some(fingerprint),
    }
}

async fn message(pool: &sqlx::SqlitePool, id: &str, kind: &str, position: &str, content: &str, at: i64) {
    sqlx::query(
        "INSERT INTO messages (id, conversation_id, msg_id, type, content, position, status, hidden, created_at) \
         VALUES (?, 'c1', ?, ?, ?, ?, 'finish', 0, ?)",
    )
    .bind(id)
    .bind(id)
    .bind(kind)
    .bind(content)
    .bind(position)
    .bind(at)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn observations_are_stored_once_and_acceptance_survives_a_repeat() {
    let (_db, repo) = setup().await;
    repo.record(receipt("first")).await.unwrap();
    repo.record(receipt("second")).await.unwrap();
    let row = repo.get("c1", "t1").await.unwrap().unwrap();
    assert_eq!(row.workspace_fingerprint.as_deref(), Some("first"));
    assert_eq!(row.accepted_at, None);

    assert!(repo.accept("c1", "t1", 300).await.unwrap());
    assert!(repo.accept("c1", "t1", 400).await.unwrap());
    repo.record(receipt("third")).await.unwrap();
    assert_eq!(repo.get("c1", "t1").await.unwrap().unwrap().accepted_at, Some(300));

    assert!(!repo.accept("c1", "missing", 1).await.unwrap());
    assert!(repo.get("other", "t1").await.unwrap().is_none());
}

#[tokio::test]
async fn the_turn_window_bounds_tools_and_the_claim() {
    let (db, repo) = setup().await;
    let pool = db.pool();
    message(pool, "before", "tool_call", "left", "{}", 50).await;
    message(pool, "exec-1", "tool_call", "left", r#"{"name":"a"}"#, 120).await;
    message(pool, "exec-2", "acp_tool_call", "left", r#"{"name":"b"}"#, 150).await;
    message(pool, "after", "tool_call", "left", "{}", 250).await;
    message(pool, "user", "text", "right", r#"{"content":"do it"}"#, 100).await;
    message(pool, "early", "text", "left", r#"{"content":"working"}"#, 130).await;
    message(pool, "last", "text", "left", r#"{"content":"done"}"#, 190).await;
    message(pool, "later", "text", "left", r#"{"content":"next turn"}"#, 260).await;

    let tools = repo.tool_messages_between("c1", 100, 200).await.unwrap();
    assert_eq!(
        tools.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(),
        ["exec-1", "exec-2"]
    );
    let claim = repo.last_assistant_text_between("c1", 100, 200).await.unwrap().unwrap();
    assert_eq!(claim.content, r#"{"content":"done"}"#);
    assert!(repo.last_assistant_text_between("c1", 0, 99).await.unwrap().is_none());
}

#[tokio::test]
async fn receipts_go_with_their_turn() {
    let (db, repo) = setup().await;
    repo.record(receipt("f")).await.unwrap();
    sqlx::query("DELETE FROM conversations WHERE id = 'c1'")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(repo.get("c1", "t1").await.unwrap().is_none());
}
