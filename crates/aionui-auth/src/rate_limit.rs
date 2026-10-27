#![allow(clippy::disallowed_types)]

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use dashmap::DashMap;

use aionui_common::ApiError;

use crate::error::AuthError;
use crate::extract::extract_client_ip;
use crate::middleware::CurrentUser;

/// Rate limit entry tracking request count within a fixed time window.
struct RateLimitEntry {
    count: u32,
    reset_time_ms: u64,
}

/// Fixed-window rate limiter backed by a concurrent `DashMap`.
///
/// Thread-safe for use across multiple request handlers.
pub struct RateLimiter {
    entries: DashMap<String, RateLimitEntry>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    /// Create a rate limiter with the given capacity and window duration.
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            max_requests,
            window,
        }
    }

    /// Auth rate limiter: 5 failed attempts per 15-minute window.
    pub fn auth() -> Self {
        Self::new(5, Duration::from_secs(15 * 60))
    }

    /// API rate limiter: 60 requests per 1-minute window.
    pub fn api() -> Self {
        Self::new(60, Duration::from_secs(60))
    }

    /// Authenticated action limiter: 20 requests per 1-minute window.
    pub fn authenticated_action() -> Self {
        Self::new(20, Duration::from_secs(60))
    }

    /// Check if the key is rate limited without modifying state.
    ///
    /// For the auth rate limiter: check first, record failure later
    /// via [`record_attempt`](Self::record_attempt).
    pub fn check(&self, key: &str) -> Result<(), AuthError> {
        let now = now_ms();
        if let Some(entry) = self.entries.get(key)
            && now < entry.reset_time_ms
            && entry.count >= self.max_requests
        {
            return Err(AuthError::RateLimited);
        }
        Ok(())
    }

    /// Check rate limit and increment the counter atomically.
    ///
    /// For API and authenticated-action rate limiters.
    pub fn check_and_increment(&self, key: &str) -> Result<(), AuthError> {
        let now = now_ms();
        let window_ms = self.window.as_millis() as u64;

        let mut entry = self.entries.entry(key.to_owned()).or_insert(RateLimitEntry {
            count: 0,
            reset_time_ms: now + window_ms,
        });

        if now >= entry.reset_time_ms {
            entry.count = 0;
            entry.reset_time_ms = now + window_ms;
        }

        if entry.count >= self.max_requests {
            return Err(AuthError::RateLimited);
        }

        entry.count += 1;
        Ok(())
    }

    /// Record a single failed attempt without checking the limit.
    ///
    /// Used by the auth rate limiter after a failed login response.
    pub fn record_attempt(&self, key: &str) {
        let now = now_ms();
        let window_ms = self.window.as_millis() as u64;

        let mut entry = self.entries.entry(key.to_owned()).or_insert(RateLimitEntry {
            count: 0,
            reset_time_ms: now + window_ms,
        });

        if now >= entry.reset_time_ms {
            entry.count = 0;
            entry.reset_time_ms = now + window_ms;
        }

        entry.count += 1;
    }

    /// Remove expired entries to prevent unbounded memory growth.
    pub fn cleanup(&self) {
        let now = now_ms();
        self.entries.retain(|_, entry| now < entry.reset_time_ms);
    }

    /// Start a background task that cleans up expired entries periodically.
    pub fn start_cleanup_task(self: &Arc<Self>, interval: Duration) {
        let limiter = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                limiter.cleanup();
            }
        });
    }

    /// Number of tracked keys (for monitoring/testing).
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Auth rate limit middleware: 5 failed attempts per 15 minutes per IP.
///
/// Pre-checks the limit; records only rejected credentials (401/403). Malformed
/// requests do not count: a cross-site page can send those to loopback without
/// a preflight and would otherwise lock the desktop app out of its own host.
pub async fn auth_rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let ip = extract_client_ip(&request);
    limiter.check(&ip).map_err(ApiError::from)?;

    let response = next.run(request).await;

    if matches!(response.status(), StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        limiter.record_attempt(&ip);
    }

    Ok(response)
}

/// API rate limit middleware: 60 requests per minute per IP.
pub async fn api_rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let ip = extract_client_ip(&request);
    limiter.check_and_increment(&ip).map_err(ApiError::from)?;
    Ok(next.run(request).await)
}

/// API rate limit for the public `/api/auth/status` probe, except from this
/// machine. Every loopback socket shares one key, so another local process
/// could otherwise fill it and make the desktop launcher read the host as down
/// (C7, Jev 048). The probe is cheap and public; remote callers stay limited.
pub async fn status_rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if !crate::extract::is_loopback_client(&request) {
        let ip = extract_client_ip(&request);
        limiter.check_and_increment(&ip).map_err(ApiError::from)?;
    }
    Ok(next.run(request).await)
}

/// Limits for `/api/auth/refresh` (C7, Jev 048).
///
/// A request whose token verifies is counted against its own grant (or user,
/// for legacy tokens without one), so other callers on the same IP cannot use
/// up the owner's refreshes. Only requests whose token does not verify are
/// counted per client IP.
pub struct RefreshLimiter {
    by_grant: RateLimiter,
    invalid_by_ip: RateLimiter,
}

impl RefreshLimiter {
    /// 20 refreshes per minute per grant, 20 invalid tokens per minute per IP.
    pub fn new() -> Self {
        Self {
            by_grant: RateLimiter::authenticated_action(),
            invalid_by_ip: RateLimiter::authenticated_action(),
        }
    }

    /// Count a refresh by a token that verified.
    pub fn check_verified(&self, user_id: &str, grant_id: Option<&str>) -> Result<(), AuthError> {
        let key = match grant_id {
            Some(grant) => format!("grant:{grant}"),
            None => format!("user:{user_id}"),
        };
        self.by_grant.check_and_increment(&key)
    }

    /// Count a refresh by a token that did not verify.
    pub fn check_invalid(&self, client_ip: &str) -> Result<(), AuthError> {
        self.invalid_by_ip.check_and_increment(&format!("ip:{client_ip}"))
    }

    /// Start periodic cleanup of both buckets.
    pub fn start_cleanup_task(self: &Arc<Self>, interval: Duration) {
        let limiter = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                limiter.by_grant.cleanup();
                limiter.invalid_by_ip.cleanup();
            }
        });
    }
}

impl Default for RefreshLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Authenticated action rate limit middleware: 20 requests per minute.
///
/// Prefers user ID from [`CurrentUser`] extension (set by auth middleware),
/// falls back to client IP.
pub async fn authenticated_action_rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let key = request
        .extensions()
        .get::<CurrentUser>()
        .map(|u| format!("user:{}", u.id))
        .unwrap_or_else(|| format!("ip:{}", extract_client_ip(&request)));
    limiter.check_and_increment(&key).map_err(ApiError::from)?;
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn statuses_after(failures: StatusCode) -> StatusCode {
        use axum::Router;
        use axum::body::Body;
        use axum::middleware::from_fn_with_state;
        use axum::routing::post;
        use tower::ServiceExt;

        let limiter = Arc::new(RateLimiter::new(2, Duration::from_secs(60)));
        let app = Router::new()
            .route("/fail", post(move || async move { failures }))
            .route("/ok", post(|| async { StatusCode::OK }))
            .route_layer(from_fn_with_state(limiter, auth_rate_limit_middleware));
        let send = |path: &'static str| {
            let app = app.clone();
            async move {
                let request = axum::http::Request::post(path).body(Body::empty()).unwrap();
                app.oneshot(request).await.unwrap().status()
            }
        };
        send("/fail").await;
        send("/fail").await;
        send("/ok").await
    }

    #[tokio::test]
    async fn only_rejected_credentials_count_toward_the_auth_limit() {
        assert_eq!(
            statuses_after(StatusCode::UNAUTHORIZED).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            statuses_after(StatusCode::FORBIDDEN).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(statuses_after(StatusCode::UNSUPPORTED_MEDIA_TYPE).await, StatusCode::OK);
        assert_eq!(statuses_after(StatusCode::BAD_REQUEST).await, StatusCode::OK);
    }

    #[test]
    fn new_limiter_allows_requests() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.check("key").is_ok());
    }

    #[test]
    fn check_and_increment_enforces_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check_and_increment("key").is_ok());
        assert!(limiter.check_and_increment("key").is_ok());
        assert!(limiter.check_and_increment("key").is_err());
    }

    #[test]
    fn different_keys_have_independent_limits() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check_and_increment("key_a").is_ok());
        assert!(limiter.check_and_increment("key_b").is_ok());
        assert!(limiter.check_and_increment("key_a").is_err());
    }

    #[test]
    fn check_does_not_increment() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        // check() alone never increments
        assert!(limiter.check("key").is_ok());
        assert!(limiter.check("key").is_ok());
        // One recorded attempt fills the quota
        limiter.record_attempt("key");
        assert!(limiter.check("key").is_err());
    }

    #[test]
    fn record_attempt_increments_counter() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        limiter.record_attempt("key");
        limiter.record_attempt("key");
        assert!(limiter.check("key").is_err());
    }

    #[test]
    fn expired_window_resets_count() {
        let limiter = RateLimiter::new(1, Duration::from_millis(50));
        assert!(limiter.check_and_increment("key").is_ok());
        std::thread::sleep(Duration::from_millis(100));
        // Window expired → counter reset
        assert!(limiter.check_and_increment("key").is_ok());
    }

    #[test]
    fn expired_window_allows_check() {
        let limiter = RateLimiter::new(1, Duration::from_millis(50));
        limiter.record_attempt("key");
        assert!(limiter.check("key").is_err());
        std::thread::sleep(Duration::from_millis(100));
        // Window expired → check passes
        assert!(limiter.check("key").is_ok());
    }

    #[test]
    fn cleanup_removes_expired_entries() {
        let limiter = RateLimiter::new(10, Duration::from_millis(50));
        limiter.check_and_increment("key").unwrap();
        assert_eq!(limiter.entry_count(), 1);
        std::thread::sleep(Duration::from_millis(100));
        limiter.cleanup();
        assert_eq!(limiter.entry_count(), 0);
    }

    #[test]
    fn cleanup_keeps_active_entries() {
        let limiter = RateLimiter::new(10, Duration::from_secs(60));
        limiter.check_and_increment("key").unwrap();
        limiter.cleanup();
        assert_eq!(limiter.entry_count(), 1);
    }

    #[test]
    fn factory_auth_limit_is_five() {
        let limiter = RateLimiter::auth();
        for _ in 0..5 {
            assert!(limiter.check_and_increment("ip").is_ok());
        }
        assert!(limiter.check_and_increment("ip").is_err());
    }

    #[test]
    fn factory_api_limit_is_sixty() {
        let limiter = RateLimiter::api();
        for _ in 0..60 {
            assert!(limiter.check_and_increment("ip").is_ok());
        }
        assert!(limiter.check_and_increment("ip").is_err());
    }

    #[test]
    fn factory_authenticated_action_limit_is_twenty() {
        let limiter = RateLimiter::authenticated_action();
        for _ in 0..20 {
            assert!(limiter.check_and_increment("user:1").is_ok());
        }
        assert!(limiter.check_and_increment("user:1").is_err());
    }
}
