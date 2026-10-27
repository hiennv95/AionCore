//! Optional browser-origin allowlist (`--allowed-origin`).
//!
//! When configured, any request that carries an `Origin` header outside the
//! allowlist is rejected before routing, CORS, auth or static files run. This
//! closes cross-origin reads and cross-site WebSocket hijacking from pages that
//! share the host's cookies (e.g. another port of the same loopback host).
//! Requests without `Origin` (native clients, same-origin navigations) pass.

// HTTP middleware boundary: building the ApiError response here is the allowed use.
#![allow(clippy::disallowed_types)]

use std::collections::HashSet;
use std::sync::Arc;

use aionui_common::ApiError;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::Uri;
use axum::http::header::ORIGIN;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};

/// Error returned when an `--allowed-origin` value is not a bare http(s) origin.
#[derive(Debug)]
pub struct InvalidOriginError {
    pub value: String,
}

impl std::fmt::Display for InvalidOriginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid allowed origin {:?}: expected scheme://host[:port]",
            self.value
        )
    }
}

impl std::error::Error for InvalidOriginError {}

/// Normalized set of browser origins allowed to talk to this server.
#[derive(Debug, Clone)]
pub struct AllowedOrigins {
    origins: Arc<HashSet<String>>,
    /// Also allow `http(s)://localhost|127.0.0.1|[::1]` on any port.
    any_loopback: bool,
}

impl AllowedOrigins {
    /// Parse and normalize `values`; any malformed value fails the whole set.
    pub fn parse(values: &[String]) -> Result<Self, InvalidOriginError> {
        let origins = values
            .iter()
            .map(|value| normalize_origin(value).ok_or_else(|| InvalidOriginError { value: value.clone() }))
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Self {
            origins: Arc::new(origins),
            any_loopback: false,
        })
    }

    /// Pages served from this machine's loopback only (any port). `null`
    /// (sandboxed iframes, `data:` and `file:` pages) is not loopback.
    pub fn loopback() -> Self {
        Self {
            origins: Arc::new(HashSet::new()),
            any_loopback: true,
        }
    }

    /// The default for a non-local host started without `--allowed-origin` (C4, Jev 045):
    /// only this machine's loopback origins on the bound port, as the AionX launchers pass.
    pub fn bound_loopback(port: u16) -> Self {
        let origins = ["127.0.0.1", "localhost", "[::1]"]
            .iter()
            .filter_map(|host| normalize_origin(&format!("http://{host}:{port}")))
            .collect();
        Self {
            origins: Arc::new(origins),
            any_loopback: false,
        }
    }

    /// Whether the raw `Origin` header value is allowlisted.
    pub fn allows(&self, origin: &str) -> bool {
        normalize_origin(origin)
            .is_some_and(|origin| self.origins.contains(&origin) || (self.any_loopback && is_loopback_origin(&origin)))
    }

    /// `host[:port]` of each listed origin (default port dropped), for the Host guard.
    pub fn authorities(&self) -> impl Iterator<Item = String> + '_ {
        self.origins
            .iter()
            .filter_map(|origin| origin.split_once("://").map(|(_, authority)| authority.to_owned()))
    }

    /// Normalized origins, sorted, for startup logging.
    pub fn sorted(&self) -> Vec<String> {
        let mut origins: Vec<String> = self.origins.iter().cloned().collect();
        origins.sort();
        origins
    }
}

/// `scheme://host[:port]` lowercased, default port dropped; `None` for anything
/// else (path, query, userinfo, non-http scheme, `null`).
fn normalize_origin(value: &str) -> Option<String> {
    let uri: Uri = value.trim_end_matches('/').parse().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = uri.authority()?;
    if authority.as_str().contains('@') || uri.query().is_some() || !matches!(uri.path(), "" | "/") {
        return None;
    }
    let host = authority.host().to_ascii_lowercase();
    Some(match authority.port_u16() {
        Some(port) if port != default_port => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    })
}

fn is_loopback_origin(normalized: &str) -> bool {
    let host = normalized.split_once("://").map_or("", |(_, rest)| rest);
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host.split(':').next().unwrap_or(""),
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

async fn origin_guard(State(allowed): State<AllowedOrigins>, request: Request, next: Next) -> Response {
    if let Some(origin) = request.headers().get(ORIGIN) {
        let permitted = origin.to_str().is_ok_and(|origin| allowed.allows(origin));
        if !permitted {
            tracing::warn!(
                origin = %String::from_utf8_lossy(origin.as_bytes()),
                method = %request.method(),
                path = request.uri().path(),
                "rejected request from a browser origin that is not allowed"
            );
            return ApiError::Forbidden("origin not allowed".into()).into_response();
        }
    }
    next.run(request).await
}

/// Wrap the whole router (routes, CORS, WebSocket upgrades, static files) with the allowlist.
pub fn with_origin_guard(router: Router, allowed: AllowedOrigins) -> Router {
    router.layer(middleware::from_fn_with_state(allowed, origin_guard))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, StatusCode, header};
    use axum::routing::get;
    use tower::ServiceExt;
    use tower_http::cors::{AllowOrigin, CorsLayer};

    const HOST: &str = "http://127.0.0.1:25818";

    /// C4 (Jev 045): the default for a non-local host without `--allowed-origin`.
    #[test]
    fn bound_loopback_policy_allows_only_this_port() {
        let allowed = AllowedOrigins::bound_loopback(25818);
        for ok in ["http://127.0.0.1:25818", "http://localhost:25818", "http://[::1]:25818"] {
            assert!(allowed.allows(ok), "{ok}");
        }
        for bad in [
            "http://127.0.0.1:9",
            "http://localhost:5173",
            "https://127.0.0.1:25818",
            "https://evil.example",
            "null",
        ] {
            assert!(!allowed.allows(bad), "{bad}");
        }
    }

    #[test]
    fn loopback_policy_allows_this_machine_on_any_port_only() {
        let loopback = AllowedOrigins::loopback();
        for ok in [
            "http://localhost:5173",
            "http://127.0.0.1:25818",
            "https://[::1]:8443",
            "http://LOCALHOST",
        ] {
            assert!(loopback.allows(ok), "{ok}");
        }
        for bad in [
            "null",
            "https://evil.example",
            "http://localhost.evil.example",
            "http://127.0.0.1.nip.io",
            "file://",
        ] {
            assert!(!loopback.allows(bad), "{bad}");
        }
    }

    /// Mirrors the webui-mode CORS layer so tests show the guard runs before it.
    fn app() -> Router {
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::mirror_request())
            .allow_credentials(true)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::CONTENT_TYPE]);
        let inner = Router::new()
            .route("/api/ping", get(|| async { "pong" }).post(|| async { "posted" }))
            .route("/ws", get(|| async { "upgrade" }))
            .layer(cors);
        with_origin_guard(inner, AllowedOrigins::parse(&[HOST.to_owned()]).unwrap())
    }

    async fn send(request: Request<Body>) -> (StatusCode, Response, String) {
        let response = app().oneshot(request).await.unwrap();
        let status = response.status();
        let (parts, body) = response.into_parts();
        let body = String::from_utf8_lossy(&to_bytes(body, usize::MAX).await.unwrap()).into_owned();
        (status, Response::from_parts(parts, Body::empty()), body)
    }

    fn request(method: Method, path: &str, origin: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(origin) = origin {
            builder = builder.header(ORIGIN, origin);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn requests_without_origin_pass() {
        let (status, _, body) = send(request(Method::GET, "/api/ping", None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "pong");
    }

    #[tokio::test]
    async fn allowed_origin_passes_and_keeps_cors() {
        let (status, response, _) = send(request(Method::POST, "/api/ping", Some(HOST))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], HOST);
    }

    #[tokio::test]
    async fn disallowed_origins_get_403_without_cors_headers() {
        for origin in [
            "http://127.0.0.1:9999",
            "https://evil.example",
            "null",
            "http://localhost:25818",
        ] {
            for method in [Method::GET, Method::POST] {
                let (status, response, body) = send(request(method.clone(), "/api/ping", Some(origin))).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{method} {origin}");
                assert!(body.contains("\"code\":\"FORBIDDEN\""), "{method} {origin}: {body}");
                assert!(!body.contains("pong") && !body.contains("posted"), "{method} {origin}");
                assert!(
                    !response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
                    "{method} {origin}"
                );
            }
        }
    }

    #[tokio::test]
    async fn disallowed_preflight_is_rejected() {
        let preflight = Request::builder()
            .method(Method::OPTIONS)
            .uri("/api/ping")
            .header(ORIGIN, "https://evil.example")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(Body::empty())
            .unwrap();
        let (status, response, _) = send(preflight).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            !response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
        );
    }

    #[tokio::test]
    async fn disallowed_websocket_upgrade_is_rejected() {
        let upgrade = Request::builder()
            .uri("/ws")
            .header(ORIGIN, "http://127.0.0.1:9999")
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(upgrade).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!body.contains("upgrade"));
    }

    #[test]
    fn origins_are_normalized() {
        let allowed =
            AllowedOrigins::parse(&["HTTP://LocalHost:80/".to_owned(), "https://h.ts.net:443".to_owned()]).unwrap();
        assert_eq!(allowed.sorted(), ["http://localhost", "https://h.ts.net"]);
        assert!(allowed.allows("http://localhost"));
        assert!(allowed.allows("https://H.ts.net"));
        assert!(!allowed.allows("https://h.ts.net:8443"));
        assert!(!allowed.allows("http://h.ts.net"));
    }

    #[test]
    fn malformed_origins_are_rejected_at_parse() {
        for value in [
            "127.0.0.1:25818",
            "ftp://host",
            "http://host/path",
            "http://host?x=1",
            "http://user@host",
            "null",
            "",
        ] {
            assert!(AllowedOrigins::parse(&[value.to_owned()]).is_err(), "{value:?}");
        }
    }
}
