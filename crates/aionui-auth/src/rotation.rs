//! Refresh-token rotation (ADR-022). Every issued session is a grant: the database
//! keeps the current refresh token's id and times, never the token. A refresh with
//! the current token rotates the grant (compare-and-swap, so concurrent refreshes
//! advance it once). The previous token still works for [`REFRESH_GRACE`] and gets
//! the same successor, re-signed byte-for-byte from the stored ids and times. Any
//! other token of the grant is a replay: the grant, and only that grant, is revoked.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aionui_common::{generate_prefixed_id, now_ms};
use aionui_db::{DbError, GrantPair, IRefreshGrantRepository, RefreshGrantRow};

use crate::error::AuthError;
use crate::jwt::{JwtService, TokenPayload, TokenType, now_secs};

/// How long the previous refresh token of a grant still returns its successor:
/// covers a lost response, a client retry and a second browser tab.
pub const REFRESH_GRACE: Duration = Duration::from_secs(120);

/// Why a grant-bound refresh was refused.
#[derive(Debug)]
pub enum RotateError {
    /// An older token of the grant was presented; the grant is now revoked.
    Replayed,
    /// Unknown, revoked or foreign grant.
    Invalid,
    Internal(String),
}

impl From<DbError> for RotateError {
    fn from(e: DbError) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<AuthError> for RotateError {
    fn from(e: AuthError) -> Self {
        Self::Internal(e.to_string())
    }
}

impl JwtService {
    /// Keep rotation grants in this store (the host's database). Call once at startup.
    pub fn set_grant_repository(&self, repo: Arc<dyn IRefreshGrantRepository>) {
        if let Ok(mut grants) = self.grants.write() {
            *grants = repo;
        }
    }

    /// Override [`REFRESH_GRACE`]. Call once at startup (tests use zero).
    pub fn set_refresh_grace(&self, grace: Duration) {
        self.refresh_grace_ms
            .store(grace.as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    fn grants(&self) -> Result<Arc<dyn IRefreshGrantRepository>, AuthError> {
        self.grants
            .read()
            .map(|g| g.clone())
            .map_err(|e| AuthError::TokenInvalid(format!("grant store lock poisoned: {e}")))
    }

    /// Sign an access + refresh pair for a new session, starting its rotation grant.
    pub async fn issue_session_pair(
        &self,
        user_id: &str,
        username: &str,
        session_generation: i64,
        device_id: Option<&str>,
    ) -> Result<(String, String), AuthError> {
        let jti = generate_prefixed_id("rt");
        let row = self
            .grants()?
            .create(
                &generate_prefixed_id("rg"),
                user_id,
                device_id,
                self.next_pair(&jti)?,
                now_ms(),
            )
            .await
            .map_err(|e| AuthError::TokenInvalid(format!("grant store: {e}")))?;
        self.sign_grant_pair(&row, username, session_generation)
    }

    /// Rotate the grant of a verified refresh token that carries `jti` and `gid`.
    /// The caller has already checked the user, session generation and device.
    pub async fn rotate_refresh(
        &self,
        payload: &TokenPayload,
        username: &str,
        session_generation: i64,
    ) -> Result<(String, String), RotateError> {
        let (Some(jti), Some(gid)) = (payload.jti.as_deref(), payload.grant_id.as_deref()) else {
            return Err(RotateError::Invalid);
        };
        let grants = self.grants()?;
        // A lost compare-and-swap means another refresh rotated first: read again,
        // and this token is then the previous one, inside the grace.
        for _ in 0..2 {
            let row = grants.find(gid).await?.ok_or(RotateError::Invalid)?;
            if row.user_id != payload.user_id || row.device_id != payload.device_id || row.revoked_at.is_some() {
                return Err(RotateError::Invalid);
            }
            let now = now_ms();
            if row.current_jti == jti {
                let next_jti = generate_prefixed_id("rt");
                let next = self.next_pair(&next_jti)?;
                if grants.rotate(gid, jti, next, now).await? {
                    let rotated = RefreshGrantRow {
                        current_jti: next_jti.clone(),
                        issued_at: next.issued_at,
                        access_expires_at: next.access_expires_at,
                        refresh_expires_at: next.refresh_expires_at,
                        ..row
                    };
                    return Ok(self.sign_grant_pair(&rotated, username, session_generation)?);
                }
                continue;
            }
            let grace = self.refresh_grace_ms.load(std::sync::atomic::Ordering::Relaxed) as i64;
            if row.previous_jti.as_deref() == Some(jti) && row.rotated_at.is_some_and(|at| now - at < grace) {
                return Ok(self.sign_grant_pair(&row, username, session_generation)?);
            }
            if grants.revoke(gid, now).await? {
                tracing::warn!(grant_id = gid, "auth: refresh token reused; grant revoked");
            }
            return Err(RotateError::Replayed);
        }
        Err(RotateError::Internal("grant rotation contended".into()))
    }

    fn next_pair<'a>(&self, jti: &'a str) -> Result<GrantPair<'a>, AuthError> {
        let now = now_secs()? as i64;
        Ok(GrantPair {
            jti,
            issued_at: now,
            access_expires_at: now + self.access_ttl().as_secs() as i64,
            refresh_expires_at: now + crate::jwt::REFRESH_TOKEN_EXPIRY.as_secs() as i64,
        })
    }

    /// The grant's current pair, exactly as first signed (stored ids and times only).
    fn sign_grant_pair(
        &self,
        row: &RefreshGrantRow,
        username: &str,
        session_generation: i64,
    ) -> Result<(String, String), AuthError> {
        let claims = |token_type, exp: i64, jti: Option<&str>, gid: Option<&str>| TokenPayload {
            user_id: row.user_id.clone(),
            username: username.to_owned(),
            iat: row.issued_at as u64,
            exp: exp as u64,
            iss: crate::jwt::JWT_ISSUER.to_owned(),
            aud: crate::jwt::JWT_AUDIENCE.to_owned(),
            session_generation,
            token_type,
            device_id: row.device_id.clone(),
            jti: jti.map(str::to_owned),
            grant_id: gid.map(str::to_owned),
        };
        let access = self.sign_payload(&claims(TokenType::Access, row.access_expires_at, None, None))?;
        let refresh = self.sign_payload(&claims(
            TokenType::Refresh,
            row.refresh_expires_at,
            Some(&row.current_jti),
            Some(&row.id),
        ))?;
        Ok((access, refresh))
    }
}

/// Default grant store until the host installs its database one (unit tests, tools).
#[derive(Default)]
pub(crate) struct MemoryGrants(Mutex<HashMap<String, RefreshGrantRow>>);

impl MemoryGrants {
    fn rows(&self) -> std::sync::MutexGuard<'_, HashMap<String, RefreshGrantRow>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl IRefreshGrantRepository for MemoryGrants {
    async fn create(
        &self,
        id: &str,
        user_id: &str,
        device_id: Option<&str>,
        pair: GrantPair<'_>,
        now_ms: i64,
    ) -> Result<RefreshGrantRow, DbError> {
        let row = RefreshGrantRow {
            id: id.to_owned(),
            user_id: user_id.to_owned(),
            device_id: device_id.map(str::to_owned),
            current_jti: pair.jti.to_owned(),
            issued_at: pair.issued_at,
            access_expires_at: pair.access_expires_at,
            refresh_expires_at: pair.refresh_expires_at,
            previous_jti: None,
            rotated_at: None,
            revoked_at: None,
            created_at: now_ms,
        };
        self.rows().insert(id.to_owned(), row.clone());
        Ok(row)
    }

    async fn find(&self, id: &str) -> Result<Option<RefreshGrantRow>, DbError> {
        Ok(self.rows().get(id).cloned())
    }

    async fn rotate(&self, id: &str, expected_jti: &str, next: GrantPair<'_>, now_ms: i64) -> Result<bool, DbError> {
        let mut rows = self.rows();
        let Some(row) = rows
            .get_mut(id)
            .filter(|r| r.current_jti == expected_jti && r.revoked_at.is_none())
        else {
            return Ok(false);
        };
        row.previous_jti = Some(std::mem::replace(&mut row.current_jti, next.jti.to_owned()));
        row.rotated_at = Some(now_ms);
        row.issued_at = next.issued_at;
        row.access_expires_at = next.access_expires_at;
        row.refresh_expires_at = next.refresh_expires_at;
        Ok(true)
    }

    async fn revoke(&self, id: &str, now_ms: i64) -> Result<bool, DbError> {
        Ok(self
            .rows()
            .get_mut(id)
            .filter(|r| r.revoked_at.is_none())
            .map(|r| r.revoked_at = Some(now_ms))
            .is_some())
    }
}
