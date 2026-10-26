use aionui_common::{TimestampMs, generate_prefixed_id, now_ms};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use crate::error::{DbError, message_indicates_unique_violation};
use crate::models::{NetworkInboundRequestRow, NetworkOutboundRequestRow, NetworkPeerRow, NetworkShareRow};
use crate::repository::network::{
    INetworkRepository, InsertInboundParams, InsertOutboundParams, InsertPeerParams, InsertShareParams, OutboundUpdate,
    RequestUpdate, UpdatePeerParams,
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
