//! Preview refs minted from an agent's report (ADR-017), through the real app: a mock agent's turn
//! reports files the way the session pump translates a successful codex `fileChange` / claude
//! `Write` result (`AgentStreamEvent::FilesReported`), and the conversation lists only the ones that
//! are regular files inside its folder.

mod common;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use aionui_ai_agent::agent_task::{AgentInstance, IAgentTask, IMockAgent};
use aionui_ai_agent::protocol::events::{FilesReportedData, FinishEventData};
use aionui_ai_agent::types::{BuildTaskOptions, SendMessageData};
use aionui_ai_agent::{AgentError, AgentStreamEvent, IWorkerTaskManager};
use aionui_common::{AgentKillReason, AgentType, ConversationStatus, TimestampMs, now_ms};
use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tower::ServiceExt;

use common::{body_json, get_with_token, json_with_token, setup_and_login};

/// Reports `paths` from one finished tool call, then ends the turn.
struct ReportingAgent {
    conversation_id: String,
    paths: Vec<String>,
    event_tx: broadcast::Sender<AgentStreamEvent>,
    last_activity: AtomicI64,
}

#[async_trait]
impl IAgentTask for ReportingAgent {
    fn agent_type(&self) -> AgentType {
        AgentType::Acp
    }
    fn conversation_id(&self) -> &str {
        &self.conversation_id
    }
    fn workspace(&self) -> &str {
        ""
    }
    fn status(&self) -> Option<ConversationStatus> {
        Some(ConversationStatus::Running)
    }
    fn last_activity_at(&self) -> TimestampMs {
        self.last_activity.load(Ordering::Relaxed)
    }
    fn subscribe(&self) -> broadcast::Receiver<AgentStreamEvent> {
        self.event_tx.subscribe()
    }
    async fn send_message(&self, _data: SendMessageData) -> Result<(), aionui_ai_agent::AgentSendError> {
        self.last_activity.store(now_ms(), Ordering::Relaxed);
        let _ = self.event_tx.send(AgentStreamEvent::FilesReported(FilesReportedData {
            call_id: "call-1".into(),
            paths: self.paths.clone(),
        }));
        let _ = self.event_tx.send(AgentStreamEvent::Finish(FinishEventData::default()));
        Ok(())
    }
    async fn cancel(&self) -> Result<(), AgentError> {
        Ok(())
    }
    fn kill(&self, _reason: Option<AgentKillReason>) -> Result<(), AgentError> {
        Ok(())
    }
}

impl IMockAgent for ReportingAgent {}

struct Tasks {
    paths: Vec<String>,
    agents: Mutex<std::collections::HashMap<String, AgentInstance>>,
}

#[async_trait]
impl IWorkerTaskManager for Tasks {
    fn get_task(&self, conversation_id: &str) -> Option<AgentInstance> {
        self.agents.lock().unwrap().get(conversation_id).cloned()
    }
    async fn get_or_build_task(&self, conversation_id: &str, _: BuildTaskOptions) -> Result<AgentInstance, AgentError> {
        let mut agents = self.agents.lock().unwrap();
        let agent = agents.entry(conversation_id.to_owned()).or_insert_with(|| {
            AgentInstance::Mock(Arc::new(ReportingAgent {
                conversation_id: conversation_id.to_owned(),
                paths: self.paths.clone(),
                event_tx: broadcast::channel(64).0,
                last_activity: AtomicI64::new(now_ms()),
            }))
        });
        Ok(agent.clone())
    }
    fn kill(&self, conversation_id: &str, _: Option<AgentKillReason>) -> Result<(), AgentError> {
        self.agents.lock().unwrap().remove(conversation_id);
        Ok(())
    }
    fn kill_and_wait(
        &self,
        conversation_id: &str,
        reason: Option<AgentKillReason>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        let _ = self.kill(conversation_id, reason);
        Box::pin(std::future::ready(()))
    }
    async fn clear(&self) {
        self.agents.lock().unwrap().clear();
    }
    fn active_count(&self) -> usize {
        self.agents.lock().unwrap().len()
    }
    fn collect_idle(&self, _: TimestampMs) -> Vec<String> {
        vec![]
    }
}

#[tokio::test]
async fn a_turn_reporting_files_mints_refs_only_for_files_inside_the_folder() {
    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(workspace.path().join("notes.md"), "# notes").unwrap();
    std::fs::create_dir(workspace.path().join("src")).unwrap();
    std::fs::write(workspace.path().join("src/a.rs"), "fn main() {}").unwrap();
    std::fs::write(outside.path().join("secret.txt"), "outside").unwrap();
    let paths = vec![
        // codex reports absolute paths (capture), claude too; relative is accepted as well.
        workspace.path().join("notes.md").to_string_lossy().into_owned(),
        "src/a.rs".to_owned(),
        outside.path().join("secret.txt").to_string_lossy().into_owned(),
        "../secret.txt".to_owned(),
        workspace.path().join("missing.md").to_string_lossy().into_owned(),
    ];

    let db = aionui_db::init_database_memory().await.unwrap();
    let services = aionui_app::AppServices::from_config(db, &aionui_app::AppConfig::default())
        .await
        .unwrap()
        .with_worker_task_manager(Arc::new(Tasks {
            paths,
            agents: Mutex::default(),
        }));
    let mut app = aionui_app::create_router(&services).await.expect("router");
    let (token, csrf) = setup_and_login(&mut app, &services, "admin", "Pass123!").await;

    let created = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            "/api/conversations",
            json!({"type": "acp", "name": "preview", "extra": {"workspace": workspace.path()}}),
            &token,
            &csrf,
        ))
        .await
        .unwrap();
    let created = body_json(created).await;
    let id = created["data"]["id"].as_str().expect("conversation created").to_owned();

    let sent = app
        .clone()
        .oneshot(json_with_token(
            "POST",
            &format!("/api/conversations/{id}/messages"),
            json!({"content": "write files"}),
            &token,
            &csrf,
        ))
        .await
        .unwrap();
    assert!(sent.status().is_success(), "send: {}", sent.status());

    let mut files = Value::Null;
    for _ in 0..100 {
        let resp = app
            .clone()
            .oneshot(get_with_token(&format!("/api/conversations/{id}/files"), &token))
            .await
            .unwrap();
        files = body_json(resp).await["data"].clone();
        if files.as_array().is_some_and(|f| f.len() >= 2) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut rel: Vec<&str> = files
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rel_path"].as_str().unwrap())
        .collect();
    rel.sort();
    assert_eq!(rel, vec!["notes.md", "src/a.rs"], "{files}");
    assert!(files.as_array().unwrap().iter().all(|f| f["call_id"] == "call-1"));
    assert!(!files.to_string().contains(outside.path().to_str().unwrap()));
    assert!(!files.to_string().contains(workspace.path().to_str().unwrap()));
}
