//! Turn outcomes for the attention inbox (B05): one row per turn, a user stop wins,
//! only unseen finished/failed turns are listed, and rows go with their conversation.

use aionui_db::{
    ITurnOutcomeRepository, IUserRepository, RecordTurnOutcomeParams, SqliteTurnOutcomeRepository,
    SqliteUserRepository, init_database_memory,
};

async fn conversation(pool: &sqlx::SqlitePool, id: &str, user_id: &str) {
    sqlx::query(
        "INSERT INTO conversations (id, user_id, name, type, created_at, updated_at) VALUES (?, ?, 'c', 'acp', 1, 1)",
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();
}

fn outcome<'a>(
    turn_id: &'a str,
    conversation_id: &'a str,
    outcome: &'a str,
    source: &'a str,
) -> RecordTurnOutcomeParams<'a> {
    RecordTurnOutcomeParams {
        turn_id,
        user_id: "system_default_user",
        conversation_id,
        outcome,
        source,
        error_code: None,
        ended_at: 100,
    }
}

async fn setup() -> (aionui_db::Database, SqliteTurnOutcomeRepository) {
    let db = init_database_memory().await.unwrap();
    conversation(db.pool(), "c1", "system_default_user").await;
    conversation(db.pool(), "c2", "system_default_user").await;
    let repo = SqliteTurnOutcomeRepository::new(db.pool().clone());
    (db, repo)
}

#[tokio::test]
async fn a_turn_is_recorded_once_and_a_repeat_changes_nothing() {
    let (_db, repo) = setup().await;
    assert!(
        repo.record(outcome("t1", "c1", "finished", "relay_finish"))
            .await
            .unwrap()
    );
    assert!(
        !repo
            .record(outcome("t1", "c1", "finished", "relay_finish"))
            .await
            .unwrap()
    );
    let listed = repo.list_unseen("system_default_user", 50).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].outcome.as_str(), listed[0].source.as_str()),
        ("finished", "relay_finish")
    );
}

#[tokio::test]
async fn a_user_stop_wins_over_a_later_finish_and_is_not_listed() {
    let (_db, repo) = setup().await;
    assert!(
        repo.record(outcome("t1", "c1", "stopped", "user_cancel"))
            .await
            .unwrap()
    );
    assert!(
        !repo
            .record(outcome("t1", "c1", "finished", "relay_finish"))
            .await
            .unwrap()
    );
    assert!(!repo.record(outcome("t1", "c1", "failed", "relay_error")).await.unwrap());
    assert!(repo.list_unseen("system_default_user", 50).await.unwrap().is_empty());

    // A stop that arrives after the finish row still replaces it.
    repo.record(outcome("t2", "c1", "finished", "relay_finish"))
        .await
        .unwrap();
    assert!(
        repo.record(outcome("t2", "c1", "stopped", "user_cancel"))
            .await
            .unwrap()
    );
    assert!(repo.list_unseen("system_default_user", 50).await.unwrap().is_empty());
}

#[tokio::test]
async fn failures_keep_their_code_and_are_listed_newest_first() {
    let (_db, repo) = setup().await;
    repo.record(outcome("t1", "c1", "finished", "relay_finish"))
        .await
        .unwrap();
    repo.record(RecordTurnOutcomeParams {
        error_code: Some("RATE_LIMITED"),
        ended_at: 200,
        ..outcome("t2", "c2", "failed", "relay_error")
    })
    .await
    .unwrap();
    let listed = repo.list_unseen("system_default_user", 50).await.unwrap();
    assert_eq!(
        listed.iter().map(|r| r.turn_id.as_str()).collect::<Vec<_>>(),
        ["t2", "t1"]
    );
    assert_eq!(listed[0].error_code.as_deref(), Some("RATE_LIMITED"));
    assert_eq!(repo.list_unseen("system_default_user", 1).await.unwrap().len(), 1);
}

#[tokio::test]
async fn seen_is_per_conversation_and_survives_a_repeat_record() {
    let (_db, repo) = setup().await;
    repo.record(outcome("t1", "c1", "finished", "relay_finish"))
        .await
        .unwrap();
    repo.record(outcome("t2", "c2", "failed", "relay_error")).await.unwrap();
    assert_eq!(repo.mark_seen("system_default_user", "c1", 300).await.unwrap(), 1);
    assert_eq!(repo.mark_seen("system_default_user", "c1", 301).await.unwrap(), 0);
    repo.record(RecordTurnOutcomeParams {
        error_code: Some("X"),
        ..outcome("t1", "c1", "failed", "relay_error")
    })
    .await
    .unwrap();
    let listed = repo.list_unseen("system_default_user", 50).await.unwrap();
    assert_eq!(listed.iter().map(|r| r.turn_id.as_str()).collect::<Vec<_>>(), ["t2"]);
}

#[tokio::test]
async fn outcomes_are_isolated_per_user() {
    let (db, repo) = setup().await;
    let bob = SqliteUserRepository::new(db.pool().clone())
        .create_user("bob", "hash")
        .await
        .unwrap()
        .id;
    let bob = bob.as_str();
    conversation(db.pool(), "bob-c", bob).await;
    repo.record(RecordTurnOutcomeParams {
        user_id: bob,
        ..outcome("tb", "bob-c", "failed", "relay_error")
    })
    .await
    .unwrap();
    assert!(repo.list_unseen("system_default_user", 50).await.unwrap().is_empty());
    assert_eq!(repo.mark_seen("system_default_user", "bob-c", 1).await.unwrap(), 0);
    assert_eq!(repo.list_unseen(bob, 50).await.unwrap().len(), 1);
    // Another user cannot take over a turn id.
    assert!(
        !repo
            .record(outcome("tb", "c1", "finished", "relay_finish"))
            .await
            .unwrap()
    );
    assert_eq!(repo.list_unseen(bob, 50).await.unwrap()[0].outcome, "failed");
}

#[tokio::test]
async fn outcomes_go_with_their_conversation() {
    let (db, repo) = setup().await;
    repo.record(outcome("t1", "c1", "finished", "relay_finish"))
        .await
        .unwrap();
    sqlx::query("DELETE FROM conversations WHERE id = 'c1'")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(repo.list_unseen("system_default_user", 50).await.unwrap().is_empty());
}
