use std::sync::Arc;

use aionui_ai_agent::IWorkerTaskManager;
use aionui_api_types::{
    INBOX_OUTCOME_LIMIT, InboxApproval, InboxChangedPayload, InboxOutcome, InboxResponse, WebSocketMessage,
};
use aionui_common::{OnConversationTurnCancelled, OnConversationTurnEnded, TurnCancelCause, TurnEnd, now_ms};
use aionui_db::{IConversationRepository, ITurnOutcomeRepository, RecordTurnOutcomeParams};
use aionui_realtime::EventBroadcaster;
use tracing::{debug, error, info};

use crate::error::InboxError;
use crate::receipt::ReceiptService;

/// Builds the inbox from live agent state and recorded turn outcomes.
///
/// Reading never starts or wakes an agent: approvals come only from tasks that are
/// already running, so a host restart (which ends them) leaves no stale approval.
pub struct InboxService {
    outcomes: Arc<dyn ITurnOutcomeRepository>,
    conversations: Arc<dyn IConversationRepository>,
    task_manager: Arc<dyn IWorkerTaskManager>,
    broadcaster: Arc<dyn EventBroadcaster>,
    receipts: Arc<ReceiptService>,
}

impl InboxService {
    pub fn new(
        outcomes: Arc<dyn ITurnOutcomeRepository>,
        conversations: Arc<dyn IConversationRepository>,
        task_manager: Arc<dyn IWorkerTaskManager>,
        broadcaster: Arc<dyn EventBroadcaster>,
        receipts: Arc<ReceiptService>,
    ) -> Self {
        Self {
            outcomes,
            conversations,
            task_manager,
            broadcaster,
            receipts,
        }
    }

    /// Result receipts (B05.R1).
    pub fn receipts(&self) -> &ReceiptService {
        &self.receipts
    }

    pub async fn inbox(&self, user_id: &str) -> Result<InboxResponse, InboxError> {
        let mut approvals = Vec::new();
        let mut owned = Vec::new();
        for conversation_id in self.task_manager.active_conversation_ids() {
            // Ownership first: another user's running chat is not visible here.
            let Some(conversation) = self.conversations.get(user_id, &conversation_id).await? else {
                continue;
            };
            let Some(agent) = self.task_manager.get_task(&conversation_id) else {
                continue;
            };
            let pending = agent.get_confirmations();
            if !pending.is_empty() {
                owned.push((conversation, pending));
            }
        }
        owned.sort_by(|(a, _), (b, _)| b.updated_at.cmp(&a.updated_at).then_with(|| b.id.cmp(&a.id)));
        for (conversation, pending) in owned {
            for confirmation in pending {
                approvals.push(InboxApproval {
                    conversation_id: conversation.id.clone(),
                    conversation_name: conversation.name.clone(),
                    confirmation,
                });
            }
        }

        let mut outcomes = Vec::new();
        for row in self.outcomes.list_unseen(user_id, INBOX_OUTCOME_LIMIT).await? {
            let Some(conversation) = self.conversations.get(user_id, &row.conversation_id).await? else {
                continue;
            };
            outcomes.push(InboxOutcome {
                turn_id: row.turn_id,
                conversation_id: row.conversation_id,
                conversation_name: conversation.name,
                outcome: row.outcome,
                source: row.source,
                error_code: row.error_code,
                ended_at: row.ended_at,
            });
        }
        Ok(InboxResponse { approvals, outcomes })
    }

    /// The owner opened this chat: its outcomes leave the inbox.
    pub async fn mark_seen(&self, user_id: &str, conversation_id: &str) -> Result<(), InboxError> {
        if self.conversations.get(user_id, conversation_id).await?.is_none() {
            return Err(InboxError::ConversationNotFound);
        }
        if self.outcomes.mark_seen(user_id, conversation_id, now_ms()).await? > 0 {
            self.changed(user_id, conversation_id);
        }
        Ok(())
    }

    async fn record(
        &self,
        user_id: &str,
        conversation_id: &str,
        turn_id: &str,
        outcome: &str,
        source: &str,
        error_code: Option<&str>,
    ) {
        let params = RecordTurnOutcomeParams {
            turn_id,
            user_id,
            conversation_id,
            outcome,
            source,
            error_code,
            ended_at: now_ms(),
        };
        match self.outcomes.record(params).await {
            Ok(true) => {
                info!(
                    conversation_id,
                    turn_id, outcome, source, "inbox: turn outcome recorded"
                );
                self.changed(user_id, conversation_id);
            }
            Ok(false) => debug!(conversation_id, turn_id, outcome, "inbox: turn outcome unchanged"),
            Err(error) => error!(conversation_id, turn_id, %error, "inbox: failed to record turn outcome"),
        }
    }

    fn changed(&self, user_id: &str, conversation_id: &str) {
        let payload = InboxChangedPayload {
            user_id: user_id.to_owned(),
            conversation_id: conversation_id.to_owned(),
        };
        match serde_json::to_value(payload) {
            Ok(data) => self.broadcaster.broadcast(WebSocketMessage::new("inbox.changed", data)),
            Err(error) => error!(%error, "inbox: failed to encode inbox.changed"),
        }
    }
}

#[async_trait::async_trait]
impl OnConversationTurnEnded for InboxService {
    async fn on_turn_ended(&self, user_id: &str, conversation_id: &str, turn_id: &str, end: &TurnEnd) {
        let outcome = if end.failed { "failed" } else { "finished" };
        self.record(
            user_id,
            conversation_id,
            turn_id,
            outcome,
            end.source,
            end.error_code.as_deref(),
        )
        .await;
        // After the outcome row: the receipt references it.
        self.receipts
            .record(user_id, conversation_id, turn_id, end.started_at)
            .await;
    }
}

#[async_trait::async_trait]
impl OnConversationTurnCancelled for InboxService {
    async fn on_turn_cancelled(&self, user_id: &str, conversation_id: &str, turn_id: &str, cause: TurnCancelCause) {
        // A restart is not the owner's stop: the turn's own end is recorded as usual.
        if cause == TurnCancelCause::UserRequested {
            self.record(user_id, conversation_id, turn_id, "stopped", "user_cancel", None)
                .await;
        }
    }
}
