//! Who may use a conversation-helper credential, checked on every request.
//!
//! Every conversation's agent, LAN shares included, receives a helper token. A LAN
//! share grants a peer chat with one agent (ADR-009), not the owner's host, so the
//! helper of a LAN-share conversation may only read skills (owner decision on Jev
//! 051). The bound conversation is looked up per request, so tokens issued before
//! a conversation became (or stopped being) a share follow its current state.

use std::sync::Arc;

use aionui_db::IConversationRepository;

use crate::runtime_token::{
    RuntimeTokenClaims, RuntimeTokenScope, RuntimeTokenService, TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
};

/// What a helper request is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperUse {
    /// The three read-only runtime skill routes (list, show, file).
    ReadSkills,
    /// Everything else the helper can reach.
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperDenied {
    /// No valid token for this (user, conversation).
    Unauthenticated,
    /// The token is live but its conversation no longer exists for this user.
    ConversationGone,
    /// The bound conversation is a LAN share and the use is not [`HelperUse::ReadSkills`].
    LanShare,
    /// The conversation could not be looked up; refused rather than guessed.
    Unavailable,
}

/// The single check every helper-authenticated route goes through.
pub struct HelperAccess {
    tokens: Arc<RuntimeTokenService>,
    conversations: Arc<dyn IConversationRepository>,
}

impl HelperAccess {
    pub fn new(tokens: Arc<RuntimeTokenService>, conversations: Arc<dyn IConversationRepository>) -> Self {
        Self { tokens, conversations }
    }

    /// Validate the token for exactly this (user, conversation), then apply the
    /// LAN-share rule. `user_id` and `conversation_id` come from request headers;
    /// they only count once the token is bound to both.
    pub async fn authorize(
        &self,
        token: Option<&str>,
        user_id: &str,
        conversation_id: &str,
        purpose: HelperUse,
    ) -> Result<RuntimeTokenClaims, HelperDenied> {
        let claims = self
            .tokens
            .validate(
                token,
                user_id,
                conversation_id,
                RuntimeTokenScope::ConversationHelper,
                // Every conversation's helper token is issued with this constant.
                TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
            )
            .map_err(|_| HelperDenied::Unauthenticated)?;
        // Skill reads are open to every helper; the skill routes scope them to the
        // conversation's own enabled skills.
        if purpose == HelperUse::ReadSkills {
            return Ok(claims);
        }
        let row = self
            .conversations
            .get(user_id, conversation_id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "helper access: conversation lookup failed");
                HelperDenied::Unavailable
            })?
            .ok_or(HelperDenied::ConversationGone)?;
        if is_lan_share(&row.extra) {
            tracing::info!(conversation_id, "helper access: refused for a LAN share conversation");
            return Err(HelperDenied::LanShare);
        }
        Ok(claims)
    }
}

/// `extra.lan_remote == true`, as the network runner creates a share. An extra that
/// does not parse counts as a share: the helper is refused rather than granted.
fn is_lan_share(extra: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(extra) {
        Ok(extra) => extra.get("lan_remote").and_then(serde_json::Value::as_bool) == Some(true),
        Err(_) => {
            tracing::warn!("helper access: conversation extra is not JSON; treated as a LAN share");
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aionui_db::models::ConversationRow;
    use aionui_db::{SqliteConversationRepository, init_database_memory};

    const USER: &str = "user-1";

    async fn setup() -> (HelperAccess, Arc<RuntimeTokenService>, sqlx::SqlitePool) {
        let db = init_database_memory().await.unwrap();
        let pool = db.pool().clone();
        std::mem::forget(db);
        sqlx::query(
            "INSERT INTO users (id, user_type, username, password_hash, status, session_generation, created_at, updated_at) \
             VALUES (?, 'local', ?, 'hash', 'active', 0, 1, 1)",
        )
        .bind(USER)
        .bind(USER)
        .execute(&pool)
        .await
        .unwrap();
        let repo = Arc::new(SqliteConversationRepository::new(pool.clone()));
        for (id, extra) in [
            ("owner", r#"{"backend":"gemini"}"#),
            ("share", r#"{"lan_remote":true}"#),
        ] {
            repo.create(&ConversationRow {
                id: id.into(),
                user_id: USER.into(),
                name: id.into(),
                r#type: "acp".into(),
                extra: extra.into(),
                model: None,
                status: Some("finished".into()),
                source: None,
                channel_chat_id: None,
                pinned: false,
                pinned_at: None,
                created_at: 1,
                updated_at: 1,
                project_id: None,
                folder_id: None,
                name_source: None,
            })
            .await
            .unwrap();
        }
        let tokens = Arc::new(RuntimeTokenService::new());
        (HelperAccess::new(tokens.clone(), repo), tokens, pool)
    }

    fn issue(tokens: &RuntimeTokenService, conversation: &str) -> String {
        tokens
            .issue(
                USER,
                conversation,
                TEAM_RUNTIME_TOKEN_SESSION_GENERATION,
                [RuntimeTokenScope::ConversationHelper],
            )
            .token
    }

    #[tokio::test]
    async fn a_share_only_reads_skills_and_an_owner_conversation_keeps_its_helper() {
        let (access, tokens, _pool) = setup().await;
        let share = issue(&tokens, "share");
        let owner = issue(&tokens, "owner");
        let check = |token: &str, conversation: &str, purpose| {
            let token = token.to_owned();
            let conversation = conversation.to_owned();
            let access = &access;
            async move {
                access
                    .authorize(Some(&token), USER, &conversation, purpose)
                    .await
                    .map(|_| ())
            }
        };
        assert_eq!(
            check(&share, "share", HelperUse::Other).await,
            Err(HelperDenied::LanShare)
        );
        assert_eq!(check(&share, "share", HelperUse::ReadSkills).await, Ok(()));
        assert_eq!(check(&owner, "owner", HelperUse::Other).await, Ok(()));
        assert_eq!(check(&owner, "owner", HelperUse::ReadSkills).await, Ok(()));
        // The headers cannot rebind a token to another conversation or user.
        assert_eq!(
            check(&share, "owner", HelperUse::Other).await,
            Err(HelperDenied::Unauthenticated)
        );
        assert_eq!(
            access
                .authorize(Some(&owner), "user-2", "owner", HelperUse::Other)
                .await
                .map(|_| ()),
            Err(HelperDenied::Unauthenticated)
        );
        assert_eq!(
            check("not-a-token", "owner", HelperUse::Other).await,
            Err(HelperDenied::Unauthenticated)
        );
        assert_eq!(
            access
                .authorize(None, USER, "owner", HelperUse::ReadSkills)
                .await
                .map(|_| ()),
            Err(HelperDenied::Unauthenticated)
        );
    }

    #[tokio::test]
    async fn a_live_token_follows_the_conversation_as_it_is_now() {
        let (access, tokens, pool) = setup().await;
        let owner = issue(&tokens, "owner");
        assert!(
            access
                .authorize(Some(&owner), USER, "owner", HelperUse::Other)
                .await
                .is_ok()
        );

        sqlx::query("UPDATE conversations SET extra = '{\"lan_remote\":true}' WHERE id = 'owner'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            access
                .authorize(Some(&owner), USER, "owner", HelperUse::Other)
                .await
                .map(|_| ()),
            Err(HelperDenied::LanShare),
            "a token issued before the conversation became a share is refused"
        );

        sqlx::query("DELETE FROM conversations WHERE id = 'owner'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            access
                .authorize(Some(&owner), USER, "owner", HelperUse::Other)
                .await
                .map(|_| ()),
            Err(HelperDenied::ConversationGone),
            "a token whose conversation is gone is refused"
        );
    }

    #[tokio::test]
    async fn a_failed_lookup_is_refused() {
        let (access, tokens, pool) = setup().await;
        let owner = issue(&tokens, "owner");
        pool.close().await;
        assert_eq!(
            access
                .authorize(Some(&owner), USER, "owner", HelperUse::Other)
                .await
                .map(|_| ()),
            Err(HelperDenied::Unavailable)
        );
    }

    #[test]
    fn only_lan_remote_true_is_a_share() {
        assert!(is_lan_share(r#"{"lan_remote":true}"#));
        assert!(!is_lan_share(r#"{"lan_remote":false}"#));
        assert!(!is_lan_share(r#"{"lan_remote":"true"}"#));
        assert!(!is_lan_share(r#"{}"#));
        assert!(is_lan_share("not json"), "an unreadable extra fails closed");
    }
}
