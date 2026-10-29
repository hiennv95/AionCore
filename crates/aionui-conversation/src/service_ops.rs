//! Agent-session operations on ConversationService.
//!
//! These forward to the active AgentInstance (via `self.task(id)`) for
//! config-options/usage/slash-commands/side-question queries, plus workspace
//! browsing that needs the conversations.extra.workspace field.
//!
//! Kept in a separate file from service.rs to avoid pushing that file
//! over 2000 lines.

use std::collections::HashMap;
use std::path::Component;

use aionui_ai_agent::{AcpError, AgentError};
use aionui_api_types::{
    ConfigOptionConfirmation, GetConfigOptionsResponse, SetConfigOptionRequest, SetConfigOptionResponse,
    SideQuestionRequest, SideQuestionResponse, SlashCommandItem, WorkspaceBrowseQuery, WorkspaceEntry,
};
use aionui_common::{AgentKillReason, ErrorChain};
use aionui_db::SaveRuntimeStateParams;
use tracing::warn;

use crate::ConversationError;
use crate::service::{AssistantRuntimePreferenceUpdate, ConversationService};

const MAX_DIR_DEPTH: usize = 10;

/// Mode a LAN remote conversation is locked to. A LAN conversation whose extra
/// lost its mode is locked to an impossible value, so every mode change fails.
pub fn lan_locked_mode_from_extra(extra: &str) -> Option<String> {
    let extra: serde_json::Value = serde_json::from_str(extra).ok()?;
    if extra.get("lan_remote").and_then(serde_json::Value::as_bool) != Some(true) {
        return None;
    }
    Some(
        extra
            .get("session_mode")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    )
}

/// A LAN share fixes the permission mode; other options (model, effort) stay free.
fn violates_lan_mode_lock(locked: &str, category: &str, value: &str) -> bool {
    category == "mode" && value != locked
}

impl ConversationService {
    // ── Config Options ──────────────────────────────────────────────

    pub async fn get_config_options(
        &self,
        user_id: &str,
        conversation_id: &str,
    ) -> Result<GetConfigOptionsResponse, ConversationError> {
        self.ensure_owned_conversation(user_id, conversation_id).await?;
        if self.runtime_state().is_restarting(conversation_id) {
            return Err(ConversationError::RuntimeRestarting {
                conversation_id: conversation_id.to_owned(),
            });
        }
        self.task(conversation_id)?
            .get_config_options()
            .await
            .map_err(ConversationError::from)
    }

    /// Return the last model selection that was confirmed by the runtime.
    ///
    /// Generic config selections and the assistant snapshot are checked before
    /// the legacy ACP current-model field. Older Team builds could persist the
    /// first two after an observed switch while leaving that field stale.
    pub async fn confirmed_model_id(
        &self,
        user_id: &str,
        conversation_id: &str,
    ) -> Result<Option<String>, ConversationError> {
        self.ensure_owned_conversation(user_id, conversation_id).await?;
        let runtime_state = self
            .acp_session_repo()
            .load_runtime_state_for_user(user_id, conversation_id)
            .await
            .map_err(|e| ConversationError::internal(format!("Failed to load runtime model state: {e}")))?;
        let config_selection = runtime_state
            .as_ref()
            .and_then(|state| state.config_selections_json.as_deref())
            .and_then(|raw| serde_json::from_str::<HashMap<String, String>>(raw).ok())
            .and_then(|selections| selections.get("model").cloned())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if config_selection.is_some() {
            return Ok(config_selection);
        }

        let snapshot_model = self
            .conversation_repo()
            .get_assistant_snapshot(user_id, conversation_id)
            .await
            .map_err(|e| ConversationError::internal(format!("Failed to load assistant model snapshot: {e}")))?
            .and_then(|snapshot| snapshot.resolved_model_id)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if snapshot_model.is_some() {
            return Ok(snapshot_model);
        }

        Ok(runtime_state
            .and_then(|state| state.current_model_id)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()))
    }

    /// Persist an already-observed model selection into every conversation
    /// source used when a Team member runtime is rebuilt.
    pub async fn persist_confirmed_model(
        &self,
        user_id: &str,
        conversation_id: &str,
        model: &str,
    ) -> Result<(), ConversationError> {
        let model = model.trim();
        if model.is_empty() {
            return Err(ConversationError::BadRequest {
                reason: "model must not be empty".into(),
            });
        }
        self.update_extra(
            user_id,
            conversation_id,
            serde_json::json!({ "current_model_id": model }),
        )
        .await?;

        let runtime_state = self
            .acp_session_repo()
            .load_runtime_state_for_user(user_id, conversation_id)
            .await
            .map_err(|e| ConversationError::internal(format!("Failed to load runtime model state: {e}")))?;
        let mut selections = runtime_state
            .and_then(|state| state.config_selections_json)
            .and_then(|raw| serde_json::from_str::<HashMap<String, String>>(&raw).ok())
            .unwrap_or_default();
        selections.insert("model".to_owned(), model.to_owned());
        let selections_json = serde_json::to_string(&selections)
            .map_err(|e| ConversationError::internal(format!("Failed to serialize runtime model selection: {e}")))?;
        self.acp_session_repo()
            .save_runtime_state_for_user(
                user_id,
                conversation_id,
                &SaveRuntimeStateParams {
                    current_model_id: Some(Some(model)),
                    config_selections_json: Some(Some(&selections_json)),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| ConversationError::internal(format!("Failed to persist runtime model: {e}")))?;
        self.persist_runtime_assistant_snapshot(
            user_id,
            conversation_id,
            AssistantRuntimePreferenceUpdate {
                model: Some(model),
                permission: None,
                thought_level: None,
            },
        )
        .await?;
        Ok(())
    }

    pub async fn set_config_option(
        &self,
        user_id: &str,
        conversation_id: &str,
        option_id: &str,
        req: SetConfigOptionRequest,
    ) -> Result<SetConfigOptionResponse, ConversationError> {
        if option_id.trim().is_empty() {
            return Err(ConversationError::BadRequest {
                reason: "option_id must not be empty".into(),
            });
        }
        if req.value.trim().is_empty() {
            return Err(ConversationError::BadRequest {
                reason: "value must not be empty".into(),
            });
        }
        let locked_mode = self.lan_locked_mode(user_id, conversation_id).await?;
        if self.runtime_state().is_restarting(conversation_id) {
            return Err(ConversationError::RuntimeRestarting {
                conversation_id: conversation_id.to_owned(),
            });
        }
        let agent = self.task(conversation_id)?;
        if let Some(locked) = locked_mode.as_deref() {
            // Resolve the option's category from the live catalog; ids differ per
            // backend, so an unknown option is judged by its id (fail closed).
            let options = agent.get_config_options().await.map_err(ConversationError::from)?;
            let category = options
                .config_options
                .iter()
                .find(|option| option.id == option_id)
                .and_then(|option| option.category.as_deref())
                .unwrap_or(option_id);
            if violates_lan_mode_lock(locked, category, &req.value) {
                warn!(
                    conversation_id,
                    option_id, "rejected mode change on a LAN remote conversation; the shared mode is fixed"
                );
                return Err(ConversationError::Forbidden {
                    reason: "this conversation runs a LAN share and keeps the shared mode".into(),
                });
            }
        }
        let response = match agent.set_config_option(option_id, &req.value).await {
            Ok(response) => response,
            Err(err @ AgentError::Acp(AcpError::NotConnected)) => {
                warn!(
                    conversation_id,
                    option_id,
                    reason = ?AgentKillReason::AgentErrorRecovery,
                    error = %ErrorChain(&err),
                    "ACP config option failed because protocol is disconnected; evicting task"
                );
                self.task_manager()
                    .kill_and_wait(conversation_id, Some(AgentKillReason::AgentErrorRecovery))
                    .await;
                return Err(ConversationError::from(err));
            }
            Err(err) => return Err(ConversationError::from(err)),
        };

        // Mirror runtime model/mode/thought-level switches into the persisted assistant
        // snapshot + preference so the next conversation seeded from this
        // assistant in `auto` mode reflects the latest pick.
        //
        // `PendingNextTurn` counts: it means the agent WILL apply the value from the next
        // turn, so it is the user's settled choice, merely not in force yet. codex reports
        // every mode switch that way (its schema documents `permissions` as "for
        // subsequent turns"), so excluding it would strip preference memory from every
        // codex conversation. `CommandAck` still does NOT count — it means nothing could
        // be established either way. Persistence failures are logged but do not roll back
        // the user-facing config switch.
        if matches!(
            response.confirmation,
            ConfigOptionConfirmation::Observed | ConfigOptionConfirmation::PendingNextTurn
        ) {
            let category = response
                .config_options
                .as_ref()
                .and_then(|options| options.iter().find(|option| option.id == option_id))
                .and_then(|option| option.category.as_deref())
                .unwrap_or(option_id);
            let updates = match category {
                "model" => Some(AssistantRuntimePreferenceUpdate {
                    model: Some(req.value.as_str()),
                    permission: None,
                    thought_level: None,
                }),
                "mode" => Some(AssistantRuntimePreferenceUpdate {
                    model: None,
                    permission: Some(req.value.as_str()),
                    thought_level: None,
                }),
                "thought_level" | "reasoning_effort" => Some(AssistantRuntimePreferenceUpdate {
                    model: None,
                    permission: None,
                    thought_level: Some(req.value.as_str()),
                }),
                _ => None,
            };
            if let Some(updates) = updates {
                if let Err(err) = self
                    .persist_runtime_assistant_snapshot(user_id, conversation_id, updates)
                    .await
                {
                    warn!(
                        conversation_id,
                        option_id,
                        error = %ErrorChain(&err),
                        "Failed to persist runtime assistant snapshot after set_config_option",
                    );
                }
                if let Err(err) = self
                    .persist_runtime_assistant_preferences(user_id, conversation_id, updates)
                    .await
                {
                    warn!(
                        conversation_id,
                        option_id,
                        error = %ErrorChain(&err),
                        "Failed to persist runtime assistant preferences after set_config_option",
                    );
                }
            }
        }

        Ok(response)
    }

    // ── Usage / Slash commands ──────────────────────────────────────

    pub async fn get_usage(
        &self,
        user_id: &str,
        conversation_id: &str,
    ) -> Result<Option<serde_json::Value>, ConversationError> {
        self.ensure_owned_conversation(user_id, conversation_id).await?;
        // A reaped task must NOT mean "no usage". The indicator's whole point is
        // to survive switching away and back, and the snapshot it needs is
        // already durable in `acp_session.session_config.runtime.context_usage`
        // — `SessionAgentTask::get_usage` reads it from there too. Requiring a
        // live task here made the figure vanish exactly when the user returned
        // to an idle conversation.
        if let Ok(task) = self.task(conversation_id) {
            return task.get_usage().await.map_err(ConversationError::from);
        }
        let state = self
            .acp_session_repo()
            .load_runtime_state_for_user(user_id, conversation_id)
            .await
            .map_err(|e| ConversationError::internal(format!("Failed to load usage state: {e}")))?;
        Ok(state
            .and_then(|s| s.context_usage_json)
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok()))
    }

    pub async fn get_slash_commands(
        &self,
        user_id: &str,
        conversation_id: &str,
    ) -> Result<Vec<SlashCommandItem>, ConversationError> {
        self.ensure_owned_conversation(user_id, conversation_id).await?;
        self.task(conversation_id)?
            .get_slash_commands()
            .await
            .map_err(ConversationError::from)
    }

    // ── Side question ───────────────────────────────────────────────

    pub async fn handle_side_question(
        &self,
        user_id: &str,
        conversation_id: &str,
        req: SideQuestionRequest,
    ) -> Result<SideQuestionResponse, ConversationError> {
        self.ensure_owned_conversation(user_id, conversation_id).await?;
        // `AgentInstance::handle_side_question` already validates that the
        // question is non-empty; no need to duplicate the check here.
        self.task(conversation_id)?
            .handle_side_question(req)
            .await
            .map_err(ConversationError::from)
    }

    /// Before a peer's turn on a LAN share: the live agent must run in the
    /// share's mode, whatever changed it since (audit run-2 SEC-F, Jev 031).
    /// A conversation that is not a LAN share, or an agent that reports no mode
    /// option, passes.
    pub async fn ensure_lan_share_mode(&self, user_id: &str, conversation_id: &str) -> Result<(), ConversationError> {
        let Some(locked) = self.lan_locked_mode(user_id, conversation_id).await? else {
            return Ok(());
        };
        let options = self
            .task(conversation_id)?
            .get_config_options()
            .await
            .map_err(ConversationError::from)?;
        let live = options
            .config_options
            .iter()
            .find(|option| option.category.as_deref() == Some("mode"))
            .and_then(|option| option.current_value.as_deref());
        match live {
            Some(mode) if mode != locked => {
                warn!(
                    conversation_id,
                    "LAN share agent is not in the shared mode; refusing the peer turn"
                );
                Err(ConversationError::Forbidden {
                    reason: "this LAN share's agent is not in the shared mode".into(),
                })
            }
            Some(_) => Ok(()),
            None => {
                warn!(
                    conversation_id,
                    "LAN share agent did not report a mode; refusing the peer turn"
                );
                Err(ConversationError::Forbidden {
                    reason: "this LAN share's agent did not report a mode".into(),
                })
            }
        }
    }

    /// Ownership check that also returns the fixed mode of a LAN remote
    /// conversation (`extra.lan_remote`), whose mode must stay what the share set.
    async fn lan_locked_mode(&self, user_id: &str, conversation_id: &str) -> Result<Option<String>, ConversationError> {
        let row = self
            .conversation_repo()
            .get(user_id, conversation_id)
            .await
            .map_err(|e| ConversationError::internal(format!("Failed to load conversation: {e}")))?
            .ok_or_else(|| ConversationError::NotFound {
                id: conversation_id.to_owned(),
            })?;
        Ok(lan_locked_mode_from_extra(&row.extra))
    }

    async fn ensure_owned_conversation(&self, user_id: &str, conversation_id: &str) -> Result<(), ConversationError> {
        let exists = self
            .conversation_repo()
            .get(user_id, conversation_id)
            .await
            .map_err(|e| ConversationError::internal(format!("Failed to load conversation: {e}")))?
            .is_some();
        if exists {
            Ok(())
        } else {
            Err(ConversationError::NotFound {
                id: conversation_id.to_owned(),
            })
        }
    }

    // ── Workspace browsing ──────────────────────────────────────────

    /// Enumerate entries under `query.path` inside the conversation's
    /// workspace root. Enforces workspace isolation (no traversal outside
    /// the root, with an allowance for symlinked sub-directories) and a
    /// depth cap of [`MAX_DIR_DEPTH`].
    pub async fn browse_workspace(
        &self,
        user_id: &str,
        conversation_id: &str,
        query: WorkspaceBrowseQuery,
    ) -> Result<Vec<WorkspaceEntry>, ConversationError> {
        if query.path.trim().is_empty() {
            return Err(ConversationError::BadRequest {
                reason: "path must not be empty".into(),
            });
        }

        let row = self
            .conversation_repo()
            .get(user_id, conversation_id)
            .await
            .map_err(|e| ConversationError::internal(format!("Failed to load conversation: {e}")))?
            .ok_or_else(|| ConversationError::NotFound {
                id: conversation_id.to_owned(),
            })?;

        let extra: serde_json::Value = serde_json::from_str(&row.extra)
            .map_err(|e| ConversationError::internal(format!("Invalid extra JSON: {e}")))?;
        let workspace = extra
            .get("workspace")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_owned();
        if workspace.is_empty() {
            return Err(ConversationError::BadRequest {
                reason: "Conversation has no workspace assigned".into(),
            });
        }

        let relative_path = query.path.trim_start_matches('/');
        let relative_path_obj = std::path::Path::new(relative_path);
        if relative_path_obj
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(ConversationError::BadRequest {
                reason: "Path traversal outside workspace is not allowed".into(),
            });
        }

        // Resolve the browsed path relative to the workspace root
        let base = std::path::Path::new(&workspace);
        let browse_path = if relative_path.is_empty() {
            base.to_path_buf()
        } else {
            base.join(relative_path_obj)
        };

        // Security: reject direct traversal outside the workspace root, but allow
        // symlinked directories mounted inside the workspace (e.g. native skill
        // dirs that point at the builtin skills corpus under data-dir).
        let canonical_base = base
            .canonicalize()
            .map_err(|e| ConversationError::internal(format!("Failed to resolve workspace path: {e}")))?;
        let canonical_browse = browse_path
            .canonicalize()
            .map_err(|_| ConversationError::not_found_reason("Directory not found"))?;
        if !browse_path.starts_with(base) && !canonical_browse.starts_with(&canonical_base) {
            return Err(ConversationError::BadRequest {
                reason: "Path traversal outside workspace is not allowed".into(),
            });
        }

        // Check depth limit
        let depth = relative_path_obj.components().count();
        if depth > MAX_DIR_DEPTH {
            return Err(ConversationError::BadRequest {
                reason: format!("Directory depth exceeds maximum of {MAX_DIR_DEPTH}"),
            });
        }

        let mut entries = Vec::new();
        let mut dir_reader = tokio::fs::read_dir(&canonical_browse)
            .await
            .map_err(|e| ConversationError::internal(format!("Failed to read directory: {e}")))?;

        while let Ok(Some(entry)) = dir_reader.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();

            // Apply search filter if provided
            if let Some(ref search) = query.search
                && !search.is_empty()
                && !name.to_lowercase().contains(&search.to_lowercase())
            {
                continue;
            }

            let entry_path = entry.path();
            let metadata = tokio::fs::metadata(&entry_path)
                .await
                .map_err(|e| ConversationError::internal(format!("Failed to read entry metadata: {e}")))?;

            let entry_type = if metadata.is_dir() { "directory" } else { "file" };

            entries.push(WorkspaceEntry {
                name,
                entry_type: entry_type.into(),
            });
        }

        // Sort: directories first, then alphabetically
        entries.sort_by(|a, b| {
            let type_cmp = a.entry_type.cmp(&b.entry_type);
            if type_cmp == std::cmp::Ordering::Equal {
                a.name.to_lowercase().cmp(&b.name.to_lowercase())
            } else {
                type_cmp
            }
        });

        Ok(entries)
    }
}

#[cfg(test)]
mod lan_mode_lock_tests {
    use super::{lan_locked_mode_from_extra, violates_lan_mode_lock};

    #[test]
    fn only_lan_remote_conversations_are_locked() {
        assert_eq!(
            lan_locked_mode_from_extra(r#"{"lan_remote":true,"session_mode":"read-only"}"#),
            Some("read-only".to_owned())
        );
        assert_eq!(lan_locked_mode_from_extra(r#"{"session_mode":"read-only"}"#), None);
        assert_eq!(lan_locked_mode_from_extra(r#"{"lan_remote":false}"#), None);
        assert_eq!(lan_locked_mode_from_extra("not json"), None);
    }

    #[test]
    fn lan_conversation_without_mode_rejects_every_mode_change() {
        let locked = lan_locked_mode_from_extra(r#"{"lan_remote":true}"#).unwrap();
        assert!(violates_lan_mode_lock(&locked, "mode", "read-only"));
        assert!(violates_lan_mode_lock(&locked, "mode", "full-access"));
    }

    #[test]
    fn mode_change_away_from_share_mode_is_rejected_but_other_options_pass() {
        assert!(violates_lan_mode_lock("read-only", "mode", "full-access"));
        assert!(!violates_lan_mode_lock("read-only", "mode", "read-only"));
        assert!(!violates_lan_mode_lock("read-only", "model", "gpt-x"));
        assert!(!violates_lan_mode_lock("read-only", "thought_level", "high"));
    }
}
