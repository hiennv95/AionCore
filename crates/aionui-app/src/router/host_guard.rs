//! `Host` allowlist for the loopback listener (C5, ADR-010).
//!
//! A DNS-rebinding page (`http://evil.example:<port>` resolved to 127.0.0.1)
//! is same-origin with itself, so its GETs carry no `Origin` and pass the
//! origin guard. Its `Host` header still names the attacker's hostname. When
//! the listener is bound to loopback, only this machine's loopback names on
//! the bound port (and the hosts of `--allowed-origin`) are served; anything
//! else is rejected before routing, auth, CORS or static files run.
//! Requests without a `Host` (HTTP/1.0 tools) pass: browsers always send one.

// HTTP middleware boundary: building the ApiError response here is the allowed use.
#![allow(clippy::disallowed_types)]

use std::collections::HashSet;
use std::sync::Arc;

use aionui_common::ApiError;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::header::HOST;
use axum::http::uri::Authority;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};

use super::origin_guard::AllowedOrigins;

/// Normalized `host[:port]` values this listener answers to.
#[derive(Debug, Clone)]
pub struct AllowedHosts {
    hosts: Arc<HashSet<String>>,
}

impl AllowedHosts {
    /// `127.0.0.1`, `localhost` and `[::1]` on `port`, plus the host of every
    /// allowlisted browser origin.
    pub fn loopback(port: u16, origins: Option<&AllowedOrigins>) -> Self {
        let mut hosts: HashSet<String> = ["127.0.0.1", "localhost", "[::1]"]
            .iter()
            .filter_map(|host| normalize_host(&format!("{host}:{port}")))
            .collect();
        if let Some(origins) = origins {
            hosts.extend(origins.authorities().filter_map(|a| normalize_host(&a)));
        }
        Self { hosts: Arc::new(hosts) }
    }

    /// Whether the raw `Host` header value is served.
    pub fn allows(&self, host: &str) -> bool {
        normalize_host(host).is_some_and(|host| self.hosts.contains(&host))
    }

    /// Normalized hosts, sorted, for startup logging.
    pub fn sorted(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.hosts.iter().cloned().collect();
        hosts.sort();
        hosts
    }
}

/// `host[:port]` lowercased; ports 80 and 443 dropped, since a browser omits
/// the default port of the scheme it used. `None` for userinfo or garbage.
fn normalize_host(value: &str) -> Option<String> {
    let authority: Authority = value.parse().ok()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host().to_ascii_lowercase();
    Some(match authority.port_u16() {
        Some(port) if port != 80 && port != 443 => format!("{host}:{port}"),
        _ => host,
    })
}

async fn host_guard(State(allowed): State<AllowedHosts>, request: Request, next: Next) -> Response {
    if let Some(host) = request.headers().get(HOST) {
        let permitted = host.to_str().is_ok_and(|host| allowed.allows(host));
        if !permitted {
            tracing::warn!(
                host = %String::from_utf8_lossy(host.as_bytes()),
                method = %request.method(),
                path = request.uri().path(),
                "rejected request for a Host this listener does not serve"
            );
            return ApiError::Forbidden("host not allowed".into()).into_response();
        }
    }
    next.run(request).await
}

/// Wrap the whole loopback router with the `Host` allowlist.
pub fn with_host_guard(router: Router, allowed: AllowedHosts) -> Router {
    router.layer(middleware::from_fn_with_state(allowed, host_guard))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::StatusCode;
    use axum::routing::get;
    use tower::ServiceExt;

    fn app() -> Router {
        let origins = AllowedOrigins::parse(&["https://aionx.example".to_owned()]).unwrap();
        let inner = Router::new().route("/api/providers", get(|| async { "dummy-key" }));
        with_host_guard(inner, AllowedHosts::loopback(25808, Some(&origins)))
    }

    async fn get_with_host(host: Option<&str>) -> (StatusCode, String) {
        let mut builder = Request::builder().uri("/api/providers");
        if let Some(host) = host {
            builder = builder.header(HOST, host);
        }
        let response = app().oneshot(builder.body(Body::empty()).unwrap()).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn a_rebound_hostname_cannot_read_owner_data() {
        for host in [
            "rebind.test:25808",
            "evil.example",
            "127.0.0.1.nip.io:25808",
            "localhost.evil.example:25808",
            "user@127.0.0.1:25808",
        ] {
            let (status, body) = get_with_host(Some(host)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{host}");
            assert!(body.contains("\"code\":\"FORBIDDEN\""), "{host}: {body}");
            assert!(!body.contains("dummy-key"), "{host}");
        }
    }

    #[tokio::test]
    async fn loopback_names_on_the_bound_port_are_served() {
        for host in ["127.0.0.1:25808", "localhost:25808", "LOCALHOST:25808", "[::1]:25808"] {
            assert_eq!(
                get_with_host(Some(host)).await,
                (StatusCode::OK, "dummy-key".into()),
                "{host}"
            );
        }
    }

    #[tokio::test]
    async fn other_ports_are_rejected() {
        for host in ["127.0.0.1:9", "localhost", "127.0.0.1"] {
            assert_eq!(get_with_host(Some(host)).await.0, StatusCode::FORBIDDEN, "{host}");
        }
    }

    #[tokio::test]
    async fn allowed_origin_hosts_and_hostless_requests_are_served() {
        assert_eq!(get_with_host(Some("aionx.example")).await.0, StatusCode::OK);
        assert_eq!(get_with_host(Some("aionx.example:443")).await.0, StatusCode::OK);
        assert_eq!(get_with_host(None).await.0, StatusCode::OK);
    }

    #[test]
    fn startup_log_lists_the_served_hosts() {
        assert_eq!(
            AllowedHosts::loopback(25808, None).sorted(),
            vec!["127.0.0.1:25808", "[::1]:25808", "localhost:25808"]
        );
    }
}
