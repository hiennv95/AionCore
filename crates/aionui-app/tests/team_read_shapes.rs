//! Shapes of a non-empty Team task board and mailbox through the real in-memory router.
//!
//! SEEDED data, not a native agent turn and not `team.*` events: the team row is created
//! through `ITeamRepository`, tasks through `TaskBoard`, and the message through `Mailbox`,
//! all on the app's own database. No team session starts and no agent runs.
//!
//! Optional fixture writer for the aionx contract (`contracts/fixtures/team/`): set
//! `AIONX_TEAM_SEEDED_OUT` to a NEW file under the temp dir; existing files are never
//! overwritten. The output is reviewed and copied by hand.

mod common;

use std::sync::Arc;

use aionui_db::models::TeamRow;
use aionui_db::{ITeamRepository, SqliteTeamRepository};
use aionui_team::{Mailbox, MailboxMessageType, TaskBoard};
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use common::{body_json, build_app, get_with_token, setup_and_login};

const TEAM_ID: &str = "team-seeded-read";
const LEAD_SLOT: &str = "slot-seeded-lead";
const SEEDED_FILE: &str = "/tmp/aionx-seeded/report.md";

/// Public contract keys (aionx `contracts/openapi.yaml` TeamTask / TeamMailboxMessage).
const TASK_KEYS: &[&str] = &[
    "blocked_by",
    "blocks",
    "created_at",
    "description",
    "id",
    "owner",
    "status",
    "subject",
    "team_id",
    "updated_at",
];
const MAILBOX_KEYS: &[&str] = &[
    "content",
    "created_at",
    "files",
    "from_agent_id",
    "id",
    "msg_type",
    "read",
    "summary",
    "team_id",
    "to_agent_id",
];

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().expect("object").keys().cloned().collect();
    keys.sort();
    keys
}

async fn seed(services: &aionui_app::AppServices) {
    let repo: Arc<dyn ITeamRepository> = Arc::new(SqliteTeamRepository::new(services.database.pool().clone()));
    repo.create_team(&TeamRow {
        id: TEAM_ID.into(),
        user_id: "system_default_user".into(),
        name: "Seeded".into(),
        workspace: String::new(),
        workspace_mode: "shared".into(),
        agents: "[]".into(),
        lead_agent_id: Some(LEAD_SLOT.into()),
        session_mode: None,
        agents_version: "1.0.1".into(),
        created_at: 1,
        updated_at: 1,
        project_id: None,
        folder_id: None,
    })
    .await
    .expect("seed team row");

    let board = TaskBoard::new_for_user(repo.clone(), "system_default_user");
    let first = board
        .create_task(TEAM_ID, "Draft the report", Some("First pass"), Some(LEAD_SLOT), &[])
        .await
        .expect("seed task 1");
    board
        .create_task(
            TEAM_ID,
            "Review the report",
            None,
            None,
            std::slice::from_ref(&first.id),
        )
        .await
        .expect("seed task 2");

    Mailbox::new_for_user(repo, "system_default_user")
        .write_with_files(
            TEAM_ID,
            LEAD_SLOT,
            "user",
            MailboxMessageType::Message,
            "Please review the attached report.",
            Some("review request"),
            Some(&[SEEDED_FILE.to_owned()]),
        )
        .await
        .expect("seed mailbox message");
}

/// Writes the fixture only to a new file whose parent canonically sits under the temp dir.
fn maybe_write_fixture(tasks: &Value, mailbox: &Value) {
    let Ok(out) = std::env::var("AIONX_TEAM_SEEDED_OUT") else {
        return;
    };
    let out = std::path::PathBuf::from(out);
    assert!(out.is_absolute(), "AIONX_TEAM_SEEDED_OUT must be absolute");
    let parent = out.parent().expect("parent").canonicalize().expect("parent must exist");
    let temp_roots = [std::env::temp_dir(), std::path::PathBuf::from("/tmp")]
        .into_iter()
        .filter_map(|p| p.canonicalize().ok())
        .collect::<Vec<_>>();
    assert!(
        temp_roots.iter().any(|root| parent.starts_with(root)),
        "AIONX_TEAM_SEEDED_OUT must be under the temp dir"
    );
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&out)
        .expect("AIONX_TEAM_SEEDED_OUT must be a new file");
    serde_json::to_writer_pretty(
        file,
        &json!({ "seeded": true, "list_team_tasks": tasks, "list_team_mailbox": mailbox }),
    )
    .expect("write fixture");
}

#[tokio::test]
async fn seeded_tasks_and_mailbox_have_the_contract_shape() {
    let (mut app, services) = build_app().await;
    let (token, _csrf) = setup_and_login(&mut app, &services, "admin", "StrongP@ss1").await;
    seed(&services).await;

    let resp = app
        .clone()
        .oneshot(get_with_token(&format!("/api/teams/{TEAM_ID}/tasks?limit=50"), &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tasks = body_json(resp).await;
    let items = tasks["data"].as_array().expect("tasks array");
    assert_eq!(items.len(), 2);
    for task in items {
        assert_eq!(sorted_keys(task), TASK_KEYS);
    }
    let first = items.iter().find(|t| t["subject"] == "Draft the report").unwrap();
    let second = items.iter().find(|t| t["subject"] == "Review the report").unwrap();
    assert_eq!(first["owner"], LEAD_SLOT);
    assert_eq!(first["description"], "First pass");
    assert!(second["owner"].is_null() && second["description"].is_null());
    assert_eq!(second["blocked_by"], json!([first["id"]]));
    assert_eq!(first["blocks"], json!([second["id"]]));

    let resp = app
        .clone()
        .oneshot(get_with_token(
            &format!("/api/teams/{TEAM_ID}/mailbox?limit=50"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mailbox = body_json(resp).await;
    let messages = mailbox["data"].as_array().expect("mailbox array");
    assert_eq!(messages.len(), 1);
    assert_eq!(sorted_keys(&messages[0]), MAILBOX_KEYS);
    assert_eq!(messages[0]["summary"], "review request");
    assert_eq!(messages[0]["read"], false);
    // Audit §8: the stored path comes back verbatim to every reader of the team.
    assert_eq!(messages[0]["files"], json!([SEEDED_FILE]));

    maybe_write_fixture(&tasks, &mailbox);
}

#[tokio::test]
async fn another_user_cannot_read_the_seeded_tasks_or_mailbox() {
    let (mut app, services) = build_app().await;
    let (_admin, _) = setup_and_login(&mut app, &services, "admin", "StrongP@ss1").await;
    let (bob, _) = setup_and_login(&mut app, &services, "bob", "StrongP@ss2").await;
    seed(&services).await;

    for path in ["tasks", "mailbox"] {
        let resp = app
            .clone()
            .oneshot(get_with_token(&format!("/api/teams/{TEAM_ID}/{path}"), &bob))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
        let body = body_json(resp).await;
        let text = body.to_string();
        assert!(
            !text.contains(SEEDED_FILE) && !text.contains("Draft the report"),
            "{path}: {text}"
        );
    }
}
