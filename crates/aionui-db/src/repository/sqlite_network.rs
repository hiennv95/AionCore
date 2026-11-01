use aionui_common::{TimestampMs, generate_prefixed_id, now_ms};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use crate::error::{DbError, message_indicates_unique_violation};
use crate::models::{NetworkInboundRequestRow, NetworkOutboundRequestRow, NetworkPeerRow, NetworkShareRow};
use crate::repository::network::{
    ActiveLanTeamMember, INetworkRepository, InsertInboundParams, InsertOutboundParams, InsertPeerParams, InsertShareParams, LanMessageEnqueue, LanTeamOutboxRow, OutboundUpdate,
    PendingLanInvitation, RequestUpdate, UpdatePeerParams,
};

/// Terminal request states; rows in these states never change again.
const TERMINAL_STATES_SQL: &str = "('succeeded', 'failed', 'cancelled', 'expired')";

/// SQLite-backed implementation of [`INetworkRepository`].
#[derive(Clone, Debug)]
pub struct SqliteNetworkRepository {
    pool: SqlitePool,
}

impl SqliteNetworkRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn map_unique(error: sqlx::Error, what: &str) -> DbError {
    if message_indicates_unique_violation(&error.to_string()) {
        DbError::Conflict(what.to_owned())
    } else {
        DbError::Query(error)
    }
}

/// Append `SET ...` assignments of a [`RequestUpdate`] (always bumps `version`).
fn push_request_update(builder: &mut QueryBuilder<'_, Sqlite>, update: &RequestUpdate<'_>) {
    builder.push("version = version + 1, updated_at = ");
    builder.push_bind(update.updated_at);
    if let Some(state) = update.state {
        builder.push(", state = ").push_bind(state.to_owned());
    }
    if let Some(code) = update.error_code {
        builder.push(", error_code = ").push_bind(code.map(str::to_owned));
    }
    if let Some(kind) = update.waiting_kind {
        builder.push(", waiting_kind = ").push_bind(kind.map(str::to_owned));
    }
    if let Some(conversation_id) = update.conversation_id {
        builder
            .push(", conversation_id = ")
            .push_bind(conversation_id.to_owned());
    }
    if let Some(text) = update.result_text {
        builder.push(", result_text = ").push_bind(text.to_owned());
    }
    if let Some(finished_at) = update.finished_at {
        builder.push(", finished_at = ").push_bind(finished_at);
    }
}

fn push_state_list(builder: &mut QueryBuilder<'_, Sqlite>, states: &[&str]) {
    builder.push("(");
    let mut separated = builder.separated(", ");
    for state in states {
        separated.push_bind(state.to_string());
    }
    builder.push(")");
}

#[async_trait::async_trait]
impl INetworkRepository for SqliteNetworkRepository {
    async fn enqueue_lan_team_outbound_with_mailbox(
        &self, user_id: &str, peer_id: &str, remote_team_id: &str, message: &crate::models::MailboxMessageRow,
    ) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query("INSERT INTO lan_team_outbox (id, user_id, team_id, peer_id, remote_team_id, content, state, created_at) SELECT ?, teams.user_id, teams.id, peer.id, member.remote_team_id, ?, 'pending', ? FROM teams JOIN lan_shared_teams shared ON shared.team_id = teams.id JOIN lan_team_members member ON member.team_id = teams.id AND member.state = 'active' JOIN network_peers peer ON peer.fingerprint = member.fingerprint AND peer.state = 'trusted' WHERE teams.user_id = ? AND teams.id = ? AND peer.id = ? AND member.remote_team_id = ?")
            .bind(&message.id).bind(&message.content).bind(message.created_at).bind(user_id).bind(&message.team_id).bind(peer_id).bind(remote_team_id)
            .execute(&mut *tx).await?;
        if inserted.rows_affected() != 1 { return Ok(false); }
        sqlx::query("INSERT INTO mailbox (id, team_id, to_agent_id, from_agent_id, type, content, summary, files, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&message.id).bind(&message.team_id).bind(&message.to_agent_id).bind(&message.from_agent_id).bind(&message.msg_type)
            .bind(&message.content).bind(&message.summary).bind(&message.files).bind(message.read).bind(message.created_at)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }
    async fn enqueue_lan_team_outbound(
        &self, id: &str, user_id: &str, team_id: &str, peer_id: &str, remote_team_id: &str, content: &str,
    ) -> Result<bool, DbError> {
        let result = sqlx::query("INSERT INTO lan_team_outbox (id, user_id, team_id, peer_id, remote_team_id, content, state, created_at) SELECT ?, teams.user_id, teams.id, peer.id, member.remote_team_id, ?, 'pending', ? FROM teams JOIN lan_shared_teams shared ON shared.team_id = teams.id JOIN lan_team_members member ON member.team_id = teams.id AND member.state = 'active' JOIN network_peers peer ON peer.fingerprint = member.fingerprint AND peer.state = 'trusted' WHERE teams.user_id = ? AND teams.id = ? AND peer.id = ? AND member.remote_team_id = ?")
            .bind(id).bind(content).bind(now_ms()).bind(user_id).bind(team_id).bind(peer_id).bind(remote_team_id)
            .execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }
    async fn pending_lan_team_outbound(&self, now: i64, limit: i64) -> Result<Vec<LanTeamOutboxRow>, DbError> {
        Ok(sqlx::query_as("SELECT item.id, item.user_id, item.team_id, item.peer_id, item.remote_team_id, item.content FROM lan_team_outbox item WHERE item.state = 'pending' AND item.next_attempt_at <= ? AND NOT EXISTS (SELECT 1 FROM lan_team_outbox earlier WHERE earlier.state = 'pending' AND earlier.team_id = item.team_id AND earlier.peer_id = item.peer_id AND earlier.remote_team_id = item.remote_team_id AND earlier.rowid < item.rowid) ORDER BY item.next_attempt_at, item.rowid LIMIT ?")
            .bind(now).bind(limit).fetch_all(&self.pool).await?)
    }
    async fn defer_lan_team_outbound(&self, id: &str, until: i64) -> Result<bool, DbError> {
        Ok(sqlx::query("UPDATE lan_team_outbox SET next_attempt_at = ? WHERE id = ? AND state = 'pending'")
            .bind(until).bind(id).execute(&self.pool).await?.rows_affected() == 1)
    }
    async fn finish_lan_team_outbound(&self, id: &str, state: &str) -> Result<bool, DbError> {
        if state != "delivered" && state != "revoked" { return Ok(false); }
        Ok(sqlx::query("UPDATE lan_team_outbox SET state = ? WHERE id = ? AND state = 'pending'")
            .bind(state).bind(id).execute(&self.pool).await?.rows_affected() == 1)
    }
    async fn lan_team_delivery_statuses(&self, user_id: &str, team_id: &str) -> Result<Vec<(String, String)>, DbError> {
        Ok(sqlx::query_as("SELECT outbox.id, outbox.state FROM lan_team_outbox outbox JOIN teams ON teams.id = outbox.team_id WHERE teams.user_id = ? AND outbox.user_id = ? AND outbox.team_id = ? ORDER BY outbox.rowid")
            .bind(user_id).bind(user_id).bind(team_id).fetch_all(&self.pool).await?)
    }
    async fn teams_with_unread_lan_messages(&self, user_id: &str) -> Result<Vec<String>, DbError> {
        Ok(sqlx::query_scalar("SELECT DISTINCT teams.id FROM lan_team_message_receipts receipt JOIN mailbox ON mailbox.id = receipt.mailbox_id AND mailbox.team_id = receipt.team_id JOIN teams ON teams.id = receipt.team_id WHERE teams.user_id = ? AND mailbox.read = 0")
            .bind(user_id).fetch_all(&self.pool).await?)
    }
    async fn enqueue_lan_team_message(
        &self, user_id: &str, fingerprint: &str, remote_team_id: &str, request_id: &str,
        message: &crate::models::MailboxMessageRow,
    ) -> Result<LanMessageEnqueue, DbError> {
        let mut tx = self.pool.begin().await?;
        let locked = sqlx::query("UPDATE network_peers SET state = state WHERE fingerprint = ? AND state = 'trusted' AND EXISTS (SELECT 1 FROM lan_team_members member JOIN teams ON teams.id = member.team_id JOIN lan_shared_teams shared ON shared.team_id = teams.id WHERE member.team_id = ? AND teams.user_id = ? AND member.fingerprint = network_peers.fingerprint AND member.remote_team_id = ? AND member.state = 'active')")
            .bind(fingerprint).bind(&message.team_id).bind(user_id).bind(remote_team_id).execute(&mut *tx).await?;
        if locked.rows_affected() != 1 { return Ok(LanMessageEnqueue::Unauthorized); }
        let peer_id: String = sqlx::query_scalar("SELECT id FROM network_peers WHERE fingerprint = ?")
            .bind(fingerprint).fetch_one(&mut *tx).await?;
        let existing: Option<(String, String, String)> = sqlx::query_as("SELECT team_id, remote_team_id, mailbox_id FROM lan_team_message_receipts WHERE peer_id = ? AND request_id = ?")
            .bind(&peer_id).bind(request_id).fetch_optional(&mut *tx).await?;
        if let Some((team, remote, mailbox_id)) = existing {
            let same: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mailbox WHERE id = ? AND team_id = ? AND to_agent_id = ? AND from_agent_id = ? AND type = ? AND content = ? AND summary IS ? AND files IS ?)")
                .bind(mailbox_id).bind(&message.team_id).bind(&message.to_agent_id).bind(&message.from_agent_id)
                .bind(&message.msg_type).bind(&message.content).bind(&message.summary).bind(&message.files)
                .fetch_one(&mut *tx).await?;
            return Ok(if same && team == message.team_id && remote == remote_team_id { LanMessageEnqueue::Duplicate } else { LanMessageEnqueue::Conflict });
        }
        sqlx::query("INSERT INTO mailbox (id, team_id, to_agent_id, from_agent_id, type, content, summary, files, read, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&message.id).bind(&message.team_id).bind(&message.to_agent_id).bind(&message.from_agent_id)
            .bind(&message.msg_type).bind(&message.content).bind(&message.summary).bind(&message.files).bind(message.read).bind(message.created_at)
            .execute(&mut *tx).await?;
        sqlx::query("INSERT INTO lan_team_message_receipts (peer_id, request_id, team_id, remote_team_id, mailbox_id) VALUES (?, ?, ?, ?, ?)")
            .bind(peer_id).bind(request_id).bind(&message.team_id).bind(remote_team_id).bind(&message.id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(LanMessageEnqueue::Inserted)
    }
    async fn record_team_pair_attestation(
        &self, user_id: &str, invitation_id: &str, fingerprint: &str, participants: &str, local: bool, now: i64,
    ) -> Result<bool, DbError> {
        let result = sqlx::query("INSERT INTO lan_team_pair_attestations (invitation_id, fingerprint, attested_at) SELECT invitation.id, ?, ? FROM lan_team_invitations invitation JOIN teams ON teams.id = invitation.team_id JOIN lan_team_invitation_votes voter ON voter.invitation_id = invitation.id AND voter.fingerprint = ? WHERE invitation.id = ? AND teams.user_id = ? AND invitation.state = 'pending' AND voter.decision = 'approved' AND (? = 1 OR EXISTS (SELECT 1 FROM network_peers WHERE fingerprint = ? AND state = 'trusted')) AND NOT EXISTS (SELECT 1 FROM lan_team_invitation_votes vote WHERE vote.invitation_id = invitation.id AND (vote.decision <> 'approved' OR NOT EXISTS (SELECT 1 FROM json_each(?) item WHERE item.value = vote.fingerprint))) AND (SELECT COUNT(*) FROM lan_team_invitation_votes vote WHERE vote.invitation_id = invitation.id) = (SELECT COUNT(DISTINCT value) FROM json_each(?)) ON CONFLICT (invitation_id, fingerprint) DO UPDATE SET attested_at = excluded.attested_at")
            .bind(fingerprint).bind(now).bind(fingerprint).bind(invitation_id).bind(user_id).bind(local).bind(fingerprint).bind(participants).bind(participants)
            .execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }

    async fn team_pair_attestations_complete(&self, user_id: &str, invitation_id: &str, since: i64) -> Result<bool, DbError> {
        Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM lan_team_invitations invitation JOIN teams ON teams.id = invitation.team_id WHERE invitation.id = ? AND teams.user_id = ? AND invitation.state = 'pending' AND EXISTS (SELECT 1 FROM lan_team_invitation_votes WHERE invitation_id = invitation.id) AND NOT EXISTS (SELECT 1 FROM lan_team_invitation_votes vote WHERE vote.invitation_id = invitation.id AND (vote.decision <> 'approved' OR NOT EXISTS (SELECT 1 FROM lan_team_pair_attestations attestation WHERE attestation.invitation_id = vote.invitation_id AND attestation.fingerprint = vote.fingerprint AND attestation.attested_at >= ?))))")
            .bind(invitation_id).bind(user_id).bind(since).fetch_one(&self.pool).await?)
    }
    async fn complete_team_invitation(
        &self, user_id: &str, invitation_id: &str, local_fingerprint: &str, since: i64,
    ) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query("UPDATE lan_team_invitations AS invitation SET state = 'completed' WHERE invitation.id = ? AND invitation.state = 'pending' AND EXISTS (SELECT 1 FROM teams JOIN lan_shared_teams shared ON shared.team_id = teams.id WHERE teams.id = invitation.team_id AND teams.user_id = ?) AND EXISTS (SELECT 1 FROM lan_team_invitation_votes vote WHERE vote.invitation_id = invitation.id AND vote.fingerprint = ? AND vote.remote_team_id = invitation.team_id) AND EXISTS (SELECT 1 FROM lan_team_invitation_votes vote WHERE vote.invitation_id = invitation.id AND vote.fingerprint = invitation.candidate_fingerprint) AND NOT EXISTS (SELECT 1 FROM lan_team_invitation_votes vote WHERE vote.invitation_id = invitation.id AND (vote.decision <> 'approved' OR vote.remote_team_id IS NULL OR length(trim(vote.remote_team_id)) = 0 OR (vote.fingerprint <> ? AND NOT EXISTS (SELECT 1 FROM network_peers peer WHERE peer.fingerprint = vote.fingerprint AND peer.state = 'trusted')) OR NOT EXISTS (SELECT 1 FROM lan_team_pair_attestations attestation WHERE attestation.invitation_id = vote.invitation_id AND attestation.fingerprint = vote.fingerprint AND attestation.attested_at >= ?))) AND NOT EXISTS (SELECT 1 FROM lan_team_members member WHERE member.team_id = invitation.team_id AND member.state = 'active' AND NOT EXISTS (SELECT 1 FROM lan_team_invitation_votes vote WHERE vote.invitation_id = invitation.id AND vote.fingerprint = member.fingerprint AND vote.remote_team_id = member.remote_team_id))")
            .bind(invitation_id).bind(user_id).bind(local_fingerprint).bind(local_fingerprint).bind(since)
            .execute(&mut *tx).await?;
        if updated.rows_affected() != 1 {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) SELECT invitation.team_id, vote.fingerprint, vote.remote_team_id, 'active' FROM lan_team_invitations invitation JOIN lan_team_invitation_votes vote ON vote.invitation_id = invitation.id WHERE invitation.id = ? AND vote.fingerprint <> ? ON CONFLICT (team_id, fingerprint) DO UPDATE SET remote_team_id = excluded.remote_team_id, state = excluded.state")
            .bind(invitation_id).bind(local_fingerprint).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }
    async fn record_team_poll_consent(
        &self, user_id: &str, team_id: &str, coordinator: &str, invitation_id: &str, participants: &str,
    ) -> Result<bool, DbError> {
        let result = sqlx::query("INSERT INTO lan_team_poll_consents (coordinator_fingerprint, invitation_id, team_id, participants) SELECT ?, ?, teams.id, ? FROM teams JOIN lan_shared_teams ON lan_shared_teams.team_id = teams.id JOIN network_peers ON network_peers.fingerprint = ? AND network_peers.state = 'trusted' WHERE teams.user_id = ? AND teams.id = ? AND NOT EXISTS (SELECT 1 FROM lan_team_members member WHERE member.team_id = teams.id AND member.state = 'active' AND NOT EXISTS (SELECT 1 FROM json_each(?) participant WHERE participant.value = member.fingerprint)) AND NOT EXISTS (SELECT 1 FROM lan_team_invitations invitation WHERE invitation.team_id = teams.id AND invitation.state = 'pending') AND NOT EXISTS (SELECT 1 FROM lan_team_poll_consents consent WHERE consent.team_id = teams.id AND (consent.coordinator_fingerprint <> ? OR consent.invitation_id <> ?)) ON CONFLICT (coordinator_fingerprint, invitation_id) DO UPDATE SET participants = excluded.participants WHERE lan_team_poll_consents.team_id = excluded.team_id AND lan_team_poll_consents.participants = excluded.participants")
            .bind(coordinator).bind(invitation_id).bind(participants).bind(coordinator).bind(user_id).bind(team_id).bind(participants).bind(coordinator).bind(invitation_id)
            .execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }

    async fn remove_team_poll_consent(&self, user_id: &str, coordinator: &str, invitation_id: &str) -> Result<bool, DbError> {
        Ok(sqlx::query("DELETE FROM lan_team_poll_consents WHERE coordinator_fingerprint = ? AND invitation_id = ? AND EXISTS (SELECT 1 FROM teams WHERE teams.id = lan_team_poll_consents.team_id AND teams.user_id = ?)")
            .bind(coordinator).bind(invitation_id).bind(user_id).execute(&self.pool).await?.rows_affected() == 1)
    }
    async fn team_poll_consent(
        &self, user_id: &str, coordinator: &str, invitation_id: &str,
    ) -> Result<Option<(String, String)>, DbError> {
        Ok(sqlx::query_as("SELECT consent.team_id, consent.participants FROM lan_team_poll_consents consent JOIN teams ON teams.id = consent.team_id JOIN lan_shared_teams ON lan_shared_teams.team_id = teams.id JOIN network_peers peer ON peer.fingerprint = consent.coordinator_fingerprint AND peer.state = 'trusted' WHERE teams.user_id = ? AND consent.coordinator_fingerprint = ? AND consent.invitation_id = ?")
            .bind(user_id).bind(coordinator).bind(invitation_id).fetch_optional(&self.pool).await?)
    }
    async fn apply_team_poll_membership(
        &self, user_id: &str, coordinator: &str, invitation_id: &str, local_fingerprint: &str,
        members: &[(String, String)],
    ) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        // Acquire the write lock before reading consent and trust so revoke cannot race the roster update.
        let locked = sqlx::query("UPDATE lan_team_poll_consents SET participants = participants WHERE coordinator_fingerprint = ? AND invitation_id = ? AND EXISTS (SELECT 1 FROM teams JOIN lan_shared_teams shared ON shared.team_id = teams.id WHERE teams.id = lan_team_poll_consents.team_id AND teams.user_id = ?) AND EXISTS (SELECT 1 FROM network_peers WHERE fingerprint = ? AND state = 'trusted')")
            .bind(coordinator).bind(invitation_id).bind(user_id).bind(coordinator).execute(&mut *tx).await?;
        if locked.rows_affected() != 1 {
            return Ok(false);
        }
        let (team_id, participants): (String, String) = sqlx::query_as("SELECT team_id, participants FROM lan_team_poll_consents WHERE coordinator_fingerprint = ? AND invitation_id = ?")
            .bind(coordinator).bind(invitation_id).fetch_one(&mut *tx).await?;
        let Ok(expected) = serde_json::from_str::<Vec<String>>(&participants) else { return Ok(false) };
        let mut actual = members.iter().map(|(fingerprint, _)| fingerprint.clone()).collect::<Vec<_>>();
        actual.sort_unstable();
        let mut expected_sorted = expected.clone();
        expected_sorted.sort_unstable();
        if actual != expected_sorted || actual.windows(2).any(|pair| pair[0] == pair[1])
            || !actual.iter().any(|fingerprint| fingerprint == coordinator)
            || members.iter().any(|(fingerprint, team)| fingerprint.is_empty() || team.trim().is_empty())
            || !members.iter().any(|(fingerprint, team)| fingerprint == local_fingerprint && team == &team_id)
        {
            return Ok(false);
        }
        for (fingerprint, _) in members.iter().filter(|(fingerprint, _)| fingerprint != local_fingerprint) {
            let trusted: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM network_peers WHERE fingerprint = ? AND state = 'trusted')")
                .bind(fingerprint).fetch_one(&mut *tx).await?;
            if !trusted { return Ok(false); }
        }
        let active: Vec<(String, String)> = sqlx::query_as("SELECT fingerprint, remote_team_id FROM lan_team_members WHERE team_id = ? AND state = 'active'")
            .bind(&team_id).fetch_all(&mut *tx).await?;
        if active.iter().any(|member| !members.contains(member)) {
            return Ok(false);
        }
        for (fingerprint, remote_team) in members.iter().filter(|(fingerprint, _)| fingerprint != local_fingerprint) {
            sqlx::query("INSERT INTO lan_team_members (team_id, fingerprint, remote_team_id, state) VALUES (?, ?, ?, 'active') ON CONFLICT (team_id, fingerprint) DO UPDATE SET remote_team_id = excluded.remote_team_id, state = excluded.state")
                .bind(&team_id).bind(fingerprint).bind(remote_team).execute(&mut *tx).await?;
        }
        sqlx::query("DELETE FROM lan_team_poll_consents WHERE coordinator_fingerprint = ? AND invitation_id = ?")
            .bind(coordinator).bind(invitation_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }
    async fn list_team_poll_consents(&self, user_id: &str) -> Result<Vec<(String, String)>, DbError> {
        Ok(sqlx::query_as("SELECT peer.id, consent.invitation_id FROM lan_team_poll_consents consent JOIN teams ON teams.id = consent.team_id JOIN lan_shared_teams ON lan_shared_teams.team_id = teams.id JOIN network_peers peer ON peer.fingerprint = consent.coordinator_fingerprint AND peer.state = 'trusted' WHERE teams.user_id = ? ORDER BY consent.invitation_id")
            .bind(user_id).fetch_all(&self.pool).await?)
    }
    async fn authorized_lan_team_member(
        &self, user_id: &str, team_id: &str, fingerprint: &str, remote_team_id: &str,
    ) -> Result<Option<String>, DbError> {
        Ok(sqlx::query_scalar("SELECT peer.id FROM lan_team_members member JOIN teams ON teams.id = member.team_id JOIN lan_shared_teams shared ON shared.team_id = teams.id JOIN network_peers peer ON peer.fingerprint = member.fingerprint WHERE teams.user_id = ? AND teams.id = ? AND member.fingerprint = ? AND member.remote_team_id = ? AND member.state = 'active' AND peer.state = 'trusted'")
            .bind(user_id).bind(team_id).bind(fingerprint).bind(remote_team_id).fetch_optional(&self.pool).await?)
    }
    async fn active_lan_team_members(&self, user_id: &str) -> Result<Vec<ActiveLanTeamMember>, DbError> {
        Ok(sqlx::query_as("SELECT member.team_id, peer.id AS peer_id, peer.display_name AS peer_name, peer.fingerprint, member.remote_team_id FROM lan_team_members member JOIN teams ON teams.id = member.team_id JOIN lan_shared_teams shared ON shared.team_id = teams.id JOIN network_peers peer ON peer.fingerprint = member.fingerprint WHERE teams.user_id = ? AND member.state = 'active' AND peer.state = 'trusted' ORDER BY member.team_id, peer.id")
            .bind(user_id).fetch_all(&self.pool).await?)
    }
    async fn create_team_invitation(
        &self,
        user_id: &str,
        team_id: &str,
        invitation_id: &str,
        local_fingerprint: &str,
        candidate_peer_id: &str,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("INSERT INTO lan_team_invitations (id, team_id, candidate_fingerprint, state, created_at) SELECT ?, teams.id, peer.fingerprint, 'pending', ? FROM teams JOIN lan_shared_teams ON lan_shared_teams.team_id = teams.id JOIN network_peers peer ON peer.id = ? AND peer.state = 'trusted' WHERE teams.id = ? AND teams.user_id = ? AND peer.fingerprint <> ? AND NOT EXISTS (SELECT 1 FROM lan_team_members WHERE team_id = teams.id AND fingerprint = peer.fingerprint AND state = 'active') AND NOT EXISTS (SELECT 1 FROM lan_team_poll_consents WHERE team_id = teams.id)")
            .bind(invitation_id)
            .bind(now_ms())
            .bind(candidate_peer_id)
            .bind(team_id)
            .bind(user_id)
            .bind(local_fingerprint)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_unique(error, "pending invitation already exists"))?;
        if result.rows_affected() != 1 {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM lan_team_poll_consents consent JOIN teams ON teams.id = consent.team_id WHERE teams.id = ? AND teams.user_id = ?)")
                .bind(team_id).bind(user_id).fetch_one(&mut *tx).await?;
            if blocked { return Err(DbError::Conflict("conversation has an active invitation".into())); }
            return Err(DbError::NotFound("shared team or eligible trusted peer not found".into()));
        }
        sqlx::query("INSERT INTO lan_team_invitation_votes (invitation_id, fingerprint, decision) SELECT ?, fingerprint, 'pending' FROM (SELECT ? AS fingerprint UNION SELECT candidate_fingerprint FROM lan_team_invitations WHERE id = ? UNION SELECT fingerprint FROM lan_team_members WHERE team_id = ? AND state = 'active')")
            .bind(invitation_id)
            .bind(local_fingerprint)
            .bind(invitation_id)
            .bind(team_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn team_invitation_votes(
        &self,
        user_id: &str,
        invitation_id: &str,
    ) -> Result<Vec<(String, String)>, DbError> {
        Ok(sqlx::query_as("SELECT votes.fingerprint, votes.decision FROM lan_team_invitation_votes votes JOIN lan_team_invitations invitations ON invitations.id = votes.invitation_id JOIN teams ON teams.id = invitations.team_id WHERE invitations.id = ? AND teams.user_id = ? ORDER BY votes.fingerprint")
            .bind(invitation_id)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?)
    }

    async fn team_invitation_conversations(
        &self,
        user_id: &str,
        invitation_id: &str,
    ) -> Result<Vec<(String, String)>, DbError> {
        Ok(sqlx::query_as("SELECT votes.fingerprint, votes.remote_team_id FROM lan_team_invitation_votes votes JOIN lan_team_invitations invitations ON invitations.id = votes.invitation_id JOIN teams ON teams.id = invitations.team_id WHERE invitations.id = ? AND teams.user_id = ? AND votes.decision = 'approved' AND votes.remote_team_id IS NOT NULL ORDER BY votes.fingerprint")
            .bind(invitation_id)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?)
    }

    async fn decide_team_invitation(
        &self,
        user_id: &str,
        invitation_id: &str,
        fingerprint: &str,
        approve: bool,
        remote_team_id: Option<&str>,
    ) -> Result<bool, DbError> {
        if approve && remote_team_id.is_none_or(|id| id.trim().is_empty()) {
            return Ok(false);
        }
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("UPDATE lan_team_invitation_votes SET decision = ?, remote_team_id = ? WHERE invitation_id = ? AND fingerprint = ? AND (decision = 'pending' OR (? = 0 AND decision = 'approved')) AND EXISTS (SELECT 1 FROM lan_team_invitations JOIN teams ON teams.id = lan_team_invitations.team_id WHERE lan_team_invitations.id = ? AND lan_team_invitations.state = 'pending' AND teams.user_id = ? AND (? = 0 OR NOT EXISTS (SELECT 1 FROM lan_team_members member WHERE member.team_id = teams.id AND member.fingerprint = lan_team_invitation_votes.fingerprint AND member.state = 'active' AND member.remote_team_id <> ?)))")
            .bind(if approve { "approved" } else { "rejected" })
            .bind(remote_team_id)
            .bind(invitation_id)
            .bind(fingerprint)
            .bind(approve)
            .bind(invitation_id)
            .bind(user_id)
            .bind(approve)
            .bind(remote_team_id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 1 && !approve {
            sqlx::query("UPDATE lan_team_invitations SET state = 'rejected' WHERE id = ? AND state = 'pending'")
                .bind(invitation_id)
                .execute(&mut *tx)
                .await?;
        }
        let recorded = if result.rows_affected() == 1 {
            true
        } else if !approve {
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM lan_team_invitation_votes vote JOIN lan_team_invitations invitation ON invitation.id = vote.invitation_id JOIN teams ON teams.id = invitation.team_id WHERE vote.invitation_id = ? AND vote.fingerprint = ? AND vote.decision = 'rejected' AND invitation.state = 'rejected' AND teams.user_id = ?)")
                .bind(invitation_id).bind(fingerprint).bind(user_id).fetch_one(&mut *tx).await?
        } else {
            false
        };
        tx.commit().await?;
        Ok(recorded)
    }

    async fn pending_local_team_invitation(&self, user_id: &str, team_id: &str) -> Result<Option<(String, String, String)>, DbError> {
        Ok(sqlx::query_as("SELECT invitation.id, invitation.candidate_fingerprint, invitation.state FROM lan_team_invitations invitation JOIN teams ON teams.id = invitation.team_id WHERE teams.user_id = ? AND teams.id = ? AND invitation.id = (SELECT id FROM lan_team_invitations WHERE team_id = teams.id ORDER BY rowid DESC LIMIT 1) AND invitation.state IN ('pending', 'rejected', 'cancelled')")
            .bind(user_id).bind(team_id).fetch_optional(&self.pool).await?)
    }
    async fn cancel_team_invitation(&self, user_id: &str, team_id: &str, invitation_id: &str) -> Result<bool, DbError> {
        Ok(sqlx::query("UPDATE lan_team_invitations SET state = 'cancelled' WHERE id = ? AND team_id = ? AND state = 'pending' AND EXISTS (SELECT 1 FROM teams WHERE teams.id = lan_team_invitations.team_id AND teams.user_id = ?)")
            .bind(invitation_id).bind(team_id).bind(user_id).execute(&self.pool).await?.rows_affected() == 1)
    }
    async fn team_invitation_team_id(&self, user_id: &str, invitation_id: &str) -> Result<Option<String>, DbError> {
        Ok(sqlx::query_scalar("SELECT invitations.team_id FROM lan_team_invitations invitations JOIN teams ON teams.id = invitations.team_id WHERE invitations.id = ? AND teams.user_id = ? AND invitations.state = 'pending'")
            .bind(invitation_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    async fn pending_team_invitations(
        &self,
        user_id: &str,
        fingerprint: &str,
    ) -> Result<Vec<PendingLanInvitation>, DbError> {
        Ok(sqlx::query_as::<_, PendingLanInvitation>(
            "SELECT invitations.id, invitations.state, teams.name AS team_name, invitations.candidate_fingerprint, candidate.display_name AS candidate_name, votes.decision FROM lan_team_invitations invitations JOIN teams ON teams.id = invitations.team_id JOIN lan_shared_teams shared ON shared.team_id = teams.id JOIN lan_team_invitation_votes votes ON votes.invitation_id = invitations.id LEFT JOIN network_peers candidate ON candidate.fingerprint = invitations.candidate_fingerprint WHERE teams.user_id = ? AND votes.fingerprint = ? AND (invitations.state = 'pending' OR (invitations.state = 'completed' AND EXISTS (SELECT 1 FROM lan_team_members member WHERE member.team_id = invitations.team_id AND member.fingerprint = votes.fingerprint AND member.state = 'active'))) ORDER BY invitations.created_at, invitations.id",
        )
        .bind(user_id)
        .bind(fingerprint)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn compare_and_set_peer_state(&self, id: &str, expected: &str, next: &str) -> Result<bool, DbError> {
        let result = sqlx::query("UPDATE network_peers SET state = ?, updated_at = ? WHERE id = ? AND state = ?")
            .bind(next)
            .bind(now_ms())
            .bind(id)
            .bind(expected)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn revoke_peer_and_memberships(&self, id: &str, expected: Option<&str>) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("UPDATE network_peers SET state = 'revoked', updated_at = ? WHERE id = ? AND (? IS NULL OR state = ?)")
            .bind(now_ms())
            .bind(id)
            .bind(expected)
            .bind(expected)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query("UPDATE lan_team_invitations SET state = 'cancelled' WHERE state = 'pending' AND id IN (SELECT votes.invitation_id FROM lan_team_invitation_votes votes JOIN network_peers peer ON peer.fingerprint = votes.fingerprint WHERE peer.id = ?)")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE lan_team_members SET state = 'revoked' WHERE fingerprint = (SELECT fingerprint FROM network_peers WHERE id = ?) AND state = 'active'")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM lan_team_poll_consents WHERE coordinator_fingerprint = (SELECT fingerprint FROM network_peers WHERE id = ?) OR EXISTS (SELECT 1 FROM json_each(lan_team_poll_consents.participants) WHERE value = (SELECT fingerprint FROM network_peers WHERE id = ?))")
            .bind(id).bind(id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }
    async fn set_team_shared(&self, user_id: &str, team_id: &str, enabled: bool) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM teams WHERE id = ? AND user_id = ?)")
            .bind(team_id)
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
        if !exists {
            return Err(DbError::NotFound("team not found".into()));
        }
        if enabled {
            sqlx::query("INSERT OR IGNORE INTO lan_shared_teams (team_id) VALUES (?)")
                .bind(team_id)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query("DELETE FROM lan_team_poll_consents WHERE team_id = ?")
                .bind(team_id).execute(&mut *tx).await?;
            sqlx::query("UPDATE lan_team_invitations SET state = 'cancelled' WHERE team_id = ? AND state = 'pending'")
                .bind(team_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM lan_shared_teams WHERE team_id = ?")
                .bind(team_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn list_shared_teams(&self, user_id: &str) -> Result<Vec<(String, String)>, DbError> {
        Ok(sqlx::query_as("SELECT teams.id, teams.name FROM teams JOIN lan_shared_teams ON teams.id = lan_shared_teams.team_id WHERE teams.user_id = ? ORDER BY teams.name, teams.id")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?)
    }

    async fn list_peers(&self) -> Result<Vec<NetworkPeerRow>, DbError> {
        Ok(
            sqlx::query_as::<_, NetworkPeerRow>("SELECT * FROM network_peers ORDER BY created_at ASC")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    async fn find_peer(&self, id: &str) -> Result<Option<NetworkPeerRow>, DbError> {
        Ok(
            sqlx::query_as::<_, NetworkPeerRow>("SELECT * FROM network_peers WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn find_peer_by_fingerprint(&self, fingerprint: &str) -> Result<Option<NetworkPeerRow>, DbError> {
        Ok(
            sqlx::query_as::<_, NetworkPeerRow>("SELECT * FROM network_peers WHERE fingerprint = ?")
                .bind(fingerprint)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn insert_peer(&self, params: InsertPeerParams<'_>) -> Result<NetworkPeerRow, DbError> {
        let row = NetworkPeerRow {
            id: generate_prefixed_id("peer"),
            fingerprint: params.fingerprint.to_owned(),
            display_name: params.display_name.to_owned(),
            peer_url: params.peer_url.map(str::to_owned),
            state: params.state.to_owned(),
            verification_code: params.verification_code.to_owned(),
            created_at: now_ms(),
            updated_at: now_ms(),
        };
        sqlx::query(
            "INSERT INTO network_peers (id, fingerprint, display_name, peer_url, state, verification_code, \
             created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&row.id)
        .bind(&row.fingerprint)
        .bind(&row.display_name)
        .bind(&row.peer_url)
        .bind(&row.state)
        .bind(&row.verification_code)
        .bind(row.created_at)
        .bind(row.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| map_unique(e, "peer fingerprint already known"))?;
        Ok(row)
    }

    async fn update_peer(&self, id: &str, params: UpdatePeerParams<'_>) -> Result<(), DbError> {
        let mut builder = QueryBuilder::<Sqlite>::new("UPDATE network_peers SET updated_at = ");
        builder.push_bind(now_ms());
        if let Some(state) = params.state {
            builder.push(", state = ").push_bind(state.to_owned());
        }
        if let Some(name) = params.display_name {
            builder.push(", display_name = ").push_bind(name.to_owned());
        }
        if let Some(url) = params.peer_url {
            builder.push(", peer_url = ").push_bind(url.to_owned());
        }
        if let Some(code) = params.verification_code {
            builder.push(", verification_code = ").push_bind(code.to_owned());
        }
        builder.push(" WHERE id = ").push_bind(id.to_owned());
        let result = builder.build().execute(&self.pool).await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("peer '{id}'")));
        }
        Ok(())
    }

    async fn delete_peer(&self, id: &str) -> Result<(), DbError> {
        let result = sqlx::query("DELETE FROM network_peers WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("peer '{id}'")));
        }
        Ok(())
    }

    async fn count_peers_in_state(&self, state: &str) -> Result<i64, DbError> {
        Ok(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM network_peers WHERE state = ?")
                .bind(state)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    async fn list_shares(&self, peer_id: Option<&str>) -> Result<Vec<NetworkShareRow>, DbError> {
        let rows = match peer_id {
            Some(peer_id) => {
                sqlx::query_as::<_, NetworkShareRow>(
                    "SELECT * FROM network_shares WHERE peer_id = ? ORDER BY created_at ASC",
                )
                .bind(peer_id)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, NetworkShareRow>("SELECT * FROM network_shares ORDER BY created_at ASC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    async fn find_share(&self, id: &str) -> Result<Option<NetworkShareRow>, DbError> {
        Ok(
            sqlx::query_as::<_, NetworkShareRow>("SELECT * FROM network_shares WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn insert_share(&self, params: InsertShareParams<'_>) -> Result<NetworkShareRow, DbError> {
        let now = now_ms();
        let row = NetworkShareRow {
            id: generate_prefixed_id("share"),
            peer_id: params.peer_id.to_owned(),
            label: params.label.to_owned(),
            backend: params.backend.to_owned(),
            mode: params.mode.to_owned(),
            workspace: params.workspace.to_owned(),
            scope: "chat".to_owned(),
            expires_at: params.expires_at,
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        sqlx::query(
            "INSERT INTO network_shares (id, peer_id, label, backend, mode, workspace, scope, expires_at, \
             revoked_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
        )
        .bind(&row.id)
        .bind(&row.peer_id)
        .bind(&row.label)
        .bind(&row.backend)
        .bind(&row.mode)
        .bind(&row.workspace)
        .bind(&row.scope)
        .bind(row.expires_at)
        .bind(row.created_at)
        .bind(row.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(row)
    }

    async fn revoke_share(&self, id: &str, now: TimestampMs) -> Result<bool, DbError> {
        let result =
            sqlx::query("UPDATE network_shares SET revoked_at = ?, updated_at = ? WHERE id = ? AND revoked_at IS NULL")
                .bind(now)
                .bind(now)
                .bind(id)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn insert_inbound(&self, params: InsertInboundParams<'_>) -> Result<NetworkInboundRequestRow, DbError> {
        let id = generate_prefixed_id("inreq");
        let now = now_ms();
        sqlx::query(
            "INSERT INTO network_inbound_requests (id, peer_id, share_id, request_id, thread_id, content, \
             content_hash, state, deadline_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(params.peer_id)
        .bind(params.share_id)
        .bind(params.request_id)
        .bind(params.thread_id)
        .bind(params.content)
        .bind(params.content_hash)
        .bind(params.state)
        .bind(params.deadline_at)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| map_unique(e, "request id already used by this peer"))?;
        self.find_inbound(&id)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("inbound request '{id}'")))
    }

    async fn find_inbound(&self, id: &str) -> Result<Option<NetworkInboundRequestRow>, DbError> {
        Ok(
            sqlx::query_as::<_, NetworkInboundRequestRow>("SELECT * FROM network_inbound_requests WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn find_inbound_by_request(
        &self,
        peer_id: &str,
        request_id: &str,
    ) -> Result<Option<NetworkInboundRequestRow>, DbError> {
        Ok(sqlx::query_as::<_, NetworkInboundRequestRow>(
            "SELECT * FROM network_inbound_requests WHERE peer_id = ? AND request_id = ?",
        )
        .bind(peer_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn list_inbound(&self, limit: i64) -> Result<Vec<NetworkInboundRequestRow>, DbError> {
        Ok(sqlx::query_as::<_, NetworkInboundRequestRow>(
            "SELECT * FROM network_inbound_requests ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn list_inbound_in_states(&self, states: &[&str]) -> Result<Vec<NetworkInboundRequestRow>, DbError> {
        let mut builder = QueryBuilder::<Sqlite>::new("SELECT * FROM network_inbound_requests WHERE state IN ");
        push_state_list(&mut builder, states);
        builder.push(" ORDER BY created_at ASC");
        Ok(builder
            .build_query_as::<NetworkInboundRequestRow>()
            .fetch_all(&self.pool)
            .await?)
    }

    async fn count_inbound_in_states(&self, peer_id: Option<&str>, states: &[&str]) -> Result<i64, DbError> {
        let mut builder = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM network_inbound_requests WHERE state IN ");
        push_state_list(&mut builder, states);
        if let Some(peer_id) = peer_id {
            builder.push(" AND peer_id = ").push_bind(peer_id.to_owned());
        }
        Ok(builder.build_query_scalar::<i64>().fetch_one(&self.pool).await?)
    }

    async fn find_thread_conversation(
        &self,
        peer_id: &str,
        share_id: &str,
        thread_id: &str,
    ) -> Result<Option<String>, DbError> {
        Ok(sqlx::query_scalar::<_, String>(
            "SELECT conversation_id FROM network_inbound_requests \
             WHERE peer_id = ? AND share_id = ? AND thread_id = ? AND conversation_id IS NOT NULL \
             ORDER BY created_at ASC LIMIT 1",
        )
        .bind(peer_id)
        .bind(share_id)
        .bind(thread_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn claim_inbound(&self, id: &str, claim_token: &str, now: TimestampMs) -> Result<bool, DbError> {
        let result = sqlx::query(
            "UPDATE network_inbound_requests SET state = 'running', claim_token = ?, version = version + 1, \
             updated_at = ? WHERE id = ? AND state = 'queued'",
        )
        .bind(claim_token)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn update_inbound_fenced(
        &self,
        id: &str,
        claim_token: &str,
        update: &RequestUpdate<'_>,
    ) -> Result<bool, DbError> {
        let mut builder = QueryBuilder::<Sqlite>::new("UPDATE network_inbound_requests SET ");
        push_request_update(&mut builder, update);
        builder.push(" WHERE id = ").push_bind(id.to_owned());
        builder.push(" AND claim_token = ").push_bind(claim_token.to_owned());
        builder.push(format!(" AND state NOT IN {TERMINAL_STATES_SQL}"));
        Ok(builder.build().execute(&self.pool).await?.rows_affected() == 1)
    }

    async fn update_inbound_if_state(
        &self,
        id: &str,
        expected_state: &str,
        update: &RequestUpdate<'_>,
    ) -> Result<bool, DbError> {
        let mut builder = QueryBuilder::<Sqlite>::new("UPDATE network_inbound_requests SET ");
        push_request_update(&mut builder, update);
        builder.push(" WHERE id = ").push_bind(id.to_owned());
        builder.push(" AND state = ").push_bind(expected_state.to_owned());
        Ok(builder.build().execute(&self.pool).await?.rows_affected() == 1)
    }

    async fn request_inbound_cancel(&self, id: &str, now: TimestampMs) -> Result<bool, DbError> {
        let result = sqlx::query(&format!(
            "UPDATE network_inbound_requests SET cancel_requested = 1, version = version + 1, updated_at = ? \
             WHERE id = ? AND state NOT IN {TERMINAL_STATES_SQL}"
        ))
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn insert_outbound(&self, params: InsertOutboundParams<'_>) -> Result<NetworkOutboundRequestRow, DbError> {
        let id = generate_prefixed_id("outreq");
        let now = now_ms();
        sqlx::query(
            "INSERT INTO network_outbound_requests (id, user_id, peer_id, share_id, share_label, request_id, \
             thread_id, content, state, deadline_at, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_delivery', ?, ?, ?)",
        )
        .bind(&id)
        .bind(params.user_id)
        .bind(params.peer_id)
        .bind(params.share_id)
        .bind(params.share_label)
        .bind(params.request_id)
        .bind(params.thread_id)
        .bind(params.content)
        .bind(params.deadline_at)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| map_unique(e, "request id already used"))?;
        self.find_outbound(&id)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("outbound request '{id}'")))
    }

    async fn find_outbound(&self, id: &str) -> Result<Option<NetworkOutboundRequestRow>, DbError> {
        Ok(
            sqlx::query_as::<_, NetworkOutboundRequestRow>("SELECT * FROM network_outbound_requests WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn list_outbound(&self, user_id: &str, limit: i64) -> Result<Vec<NetworkOutboundRequestRow>, DbError> {
        Ok(sqlx::query_as::<_, NetworkOutboundRequestRow>(
            "SELECT * FROM network_outbound_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    async fn list_outbound_in_states(&self, states: &[&str]) -> Result<Vec<NetworkOutboundRequestRow>, DbError> {
        let mut builder = QueryBuilder::<Sqlite>::new("SELECT * FROM network_outbound_requests WHERE state IN ");
        push_state_list(&mut builder, states);
        builder.push(" ORDER BY created_at ASC");
        Ok(builder
            .build_query_as::<NetworkOutboundRequestRow>()
            .fetch_all(&self.pool)
            .await?)
    }

    async fn update_outbound(&self, id: &str, update: &OutboundUpdate<'_>) -> Result<(), DbError> {
        let mut builder = QueryBuilder::<Sqlite>::new("UPDATE network_outbound_requests SET ");
        // Outbound rows have no version column; reuse the shared assignments minus `version`.
        builder.push("updated_at = ").push_bind(update.request.updated_at);
        let request = &update.request;
        if let Some(state) = request.state {
            builder.push(", state = ").push_bind(state.to_owned());
        }
        if let Some(code) = request.error_code {
            builder.push(", error_code = ").push_bind(code.map(str::to_owned));
        }
        if let Some(kind) = request.waiting_kind {
            builder.push(", waiting_kind = ").push_bind(kind.map(str::to_owned));
        }
        if let Some(text) = request.result_text {
            builder.push(", result_text = ").push_bind(text.to_owned());
        }
        if let Some(finished_at) = request.finished_at {
            builder.push(", finished_at = ").push_bind(finished_at);
        }
        if let Some(version) = update.remote_version {
            builder.push(", remote_version = ").push_bind(version);
        }
        if let Some(reachable) = update.peer_reachable {
            builder.push(", peer_reachable = ").push_bind(reachable);
        }
        if let Some(cancel) = update.cancel_requested {
            builder.push(", cancel_requested = ").push_bind(cancel);
        }
        builder.push(" WHERE id = ").push_bind(id.to_owned());
        // A terminal outbound row is final: later polls must not reopen it.
        builder.push(format!(" AND state NOT IN {TERMINAL_STATES_SQL}"));
        builder.build().execute(&self.pool).await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "sqlite_network_test.rs"]
mod tests;
