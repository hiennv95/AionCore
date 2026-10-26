//! [`RemoteTurnRunner`] over the host's own conversation runtime: a remote turn
//! is an ordinary owner-host conversation, so the owner sees it in the sidebar
//! and approves tools / answers questions in the normal conversation UI.

use std::sync::Arc;

use aionui_ai_agent::{AgentStreamEvent, IWorkerTaskManager};
use aionui_api_types::{CreateConversationRequest, SendMessageRequest, WaitingKind};
use aionui_common::{AgentType, ConversationSource};
use aionui_conversation::ConversationService;
use aionui_network::{NetworkError, RemoteConversationSpec, RemoteTurnRunner, TurnEvent};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, warn};

pub(crate) struct ConversationTurnRunner {
    conversations: ConversationService,
    task_manager: Arc<dyn IWorkerTaskManager>,
}

impl ConversationTurnRunner {
    pub(crate) fn new(conversations: ConversationService, task_manager: Arc<dyn IWorkerTaskManager>) -> Self {
        Self {
            conversations,
            task_manager,
        }
    }
}

fn runtime_error(error: impl std::fmt::Display) -> NetworkError {
    NetworkError::Internal(error.to_string())
}

/// Project one runtime event for the requester. Tool payloads, thinking text
/// and internal frames never leave the owner host.
fn project(event: &AgentStreamEvent) -> Option<TurnEvent> {
    match event {
        AgentStreamEvent::Text(data) => Some(TurnEvent::Text(data.content.clone())),
        AgentStreamEvent::Permission(_) | AgentStreamEvent::AcpPermission(_) => {
            Some(TurnEvent::WaitingForOwner(WaitingKind::Approval))
        }
        AgentStreamEvent::Ask(_) => Some(TurnEvent::WaitingForOwner(WaitingKind::Question)),
        AgentStreamEvent::ToolCall(_) | AgentStreamEvent::AcpToolCall(_) | AgentStreamEvent::Thinking(_) => {
            Some(TurnEvent::Activity)
        }
        AgentStreamEvent::Finish(_) => Some(TurnEvent::Finished),
        AgentStreamEvent::Error(_) => Some(TurnEvent::Failed),
        _ => None,
    }
}

async fn pump(mut rx: broadcast::Receiver<AgentStreamEvent>, tx: mpsc::Sender<TurnEvent>, conversation_id: String) {
    loop {
        match rx.recv().await {
            Ok(event) => {
                let Some(projected) = project(&event) else { continue };
                let last = matches!(projected, TurnEvent::Finished | TurnEvent::Failed);
                if tx.send(projected).await.is_err() || last {
                    return;
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                // Text may be incomplete; the full reply stays in the owner's conversation.
                warn!(%conversation_id, skipped, "network: remote turn relay lagged");
            }
            Err(broadcast::error::RecvError::Closed) => {
                debug!(%conversation_id, "network: agent stream closed");
                return;
            }
        }
    }
}

#[async_trait::async_trait]
impl RemoteTurnRunner for ConversationTurnRunner {
    async fn create_conversation(
        &self,
        owner_user_id: &str,
        spec: &RemoteConversationSpec,
    ) -> Result<String, NetworkError> {
        let request = CreateConversationRequest {
            r#type: Some(AgentType::Acp),
            name: Some(spec.name.clone()),
            model: None,
            assistant: None,
            source: Some(ConversationSource::Aionui),
            channel_chat_id: None,
            extra: serde_json::json!({
                "backend": spec.backend,
                "workspace": spec.workspace,
                "session_mode": spec.mode,
                "current_mode_id": spec.mode,
                "lan_remote": true,
            }),
        };
        let created = self
            .conversations
            .create(owner_user_id, request)
            .await
            .map_err(runtime_error)?;
        Ok(created.id)
    }

    async fn start_turn(
        &self,
        owner_user_id: &str,
        conversation_id: &str,
        content: &str,
    ) -> Result<mpsc::Receiver<TurnEvent>, NetworkError> {
        // Same order as channel relays: warm the runtime, subscribe, then send,
        // so no event of this turn is emitted before the subscription exists.
        self.conversations
            .warmup(owner_user_id, conversation_id, &self.task_manager)
            .await
            .map_err(runtime_error)?;
        // The peer's prompt runs only in the share's fixed mode (audit run-2 SEC-F).
        self.conversations
            .ensure_lan_share_mode(owner_user_id, conversation_id)
            .await
            .map_err(runtime_error)?;
        let stream = self
            .task_manager
            .get_task(conversation_id)
            .map(|handle| handle.subscribe())
            .ok_or_else(|| NetworkError::Internal("agent task missing after warmup".into()))?;
        let request = SendMessageRequest {
            content: content.to_owned(),
            files: vec![],
            sessions: vec![],
            inject_skills: vec![],
            hidden: false,
        };
        self.conversations
            .send_message(owner_user_id, conversation_id, request, &self.task_manager)
            .await
            .map_err(runtime_error)?;
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(pump(stream, tx, conversation_id.to_owned()));
        Ok(rx)
    }

    async fn cancel_turn(&self, owner_user_id: &str, conversation_id: &str) -> Result<(), NetworkError> {
        let Some(turn_id) = self.conversations.runtime_state().active_turn_id_for(conversation_id) else {
            return Ok(()); // nothing running
        };
        self.conversations
            .cancel(owner_user_id, conversation_id, &turn_id, &self.task_manager)
            .await
            .map_err(runtime_error)?;
        Ok(())
    }
}
