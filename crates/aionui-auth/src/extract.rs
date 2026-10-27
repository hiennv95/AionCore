use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, header};

use aionui_common::constants::COOKIE_NAME;

/// Whether a loopback peer is a reverse proxy whose forwarding headers name
/// the real client (`--trusted-proxy`). Off by default: any local process can
/// set those headers, so honouring them lets it dodge or aim rate limits (C7).
static TRUST_FORWARDED_HEADERS: AtomicBool = AtomicBool::new(false);

/// Honour `X-Forwarded-For` / `X-Real-IP` from loopback peers. Intended to be
/// called once at startup, before serving requests.
pub fn set_trust_forwarded_headers(trust: bool) {
    TRUST_FORWARDED_HEADERS.store(trust, Ordering::Relaxed);
}

/// Whether forwarding headers from loopback peers are honoured.
pub fn trust_forwarded_headers() -> bool {
    TRUST_FORWARDED_HEADERS.load(Ordering::Relaxed)
}

/// The client IP used to key rate limits.
///
/// The socket peer address (`ConnectInfo`, attached by every listener) is the
/// truth: `X-Forwarded-For` / `X-Real-IP` are client-supplied and would let any
/// caller rotate them to dodge a limit. They are honoured only when the host
/// trusts a local reverse proxy (`--trusted-proxy`) and the connection itself
/// comes from loopback. Without a peer address (in-process tests), the headers
/// are used under the same flag, else the key is `unknown`.
pub fn extract_client_ip<B>(request: &Request<B>) -> String {
    let trust = trust_forwarded_headers();
    match request.extensions().get::<ConnectInfo<SocketAddr>>() {
        Some(ConnectInfo(peer)) if !trust || !peer.ip().is_loopback() => peer.ip().to_string(),
        Some(ConnectInfo(peer)) => {
            let forwarded = extract_client_ip_from_headers(request.headers());
            if forwarded == "unknown" {
                peer.ip().to_string()
            } else {
                forwarded
            }
        }
        None if trust => extract_client_ip_from_headers(request.headers()),
        None => "unknown".to_owned(),
    }
}

/// Whether the request's effective client (see [`extract_client_ip`]) is this
/// machine. A proxied remote client is not, even though its socket is loopback.
pub fn is_loopback_client<B>(request: &Request<B>) -> bool {
    extract_client_ip(request)
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Extract client IP from a `HeaderMap` directly.
pub fn extract_client_ip_from_headers(headers: &HeaderMap) -> String {
    // X-Forwarded-For: client, proxy1, proxy2
    if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(first_ip) = forwarded.split(',').next()
    {
        let ip = first_ip.trim();
        if !ip.is_empty() {
            return ip.to_owned();
        }
    }

    // X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = real_ip.trim();
        if !ip.is_empty() {
            return ip.to_owned();
        }
    }

    "unknown".to_owned()
}

/// Extract bearer token from HTTP request headers.
///
/// Priority: `Authorization: Bearer <token>` > `aionui-session` cookie.
pub fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = extract_bearer_token(headers) {
        return Some(token);
    }
    extract_cookie_value(headers, COOKIE_NAME)
}

/// Extract bearer token from WebSocket upgrade request headers.
///
/// Priority: `Authorization` > `Cookie` > `Sec-WebSocket-Protocol` (first value).
pub fn extract_token_from_ws_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = extract_bearer_token(headers) {
        return Some(token);
    }

    if let Some(token) = extract_cookie_value(headers, COOKIE_NAME) {
        return Some(token);
    }

    // Sec-WebSocket-Protocol: <token>, ...
    headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .and_then(|protocols| {
            let first = protocols.split(',').next()?.trim();
            if first.is_empty() { None } else { Some(first.to_owned()) }
        })
}

/// Extract a named cookie value from the `Cookie` header.
pub fn extract_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        if key.trim() == name {
            let v = value.trim();
            if !v.is_empty() {
                return Some(v.to_owned());
            }
        }
    }
    None
}

/// Extract the bearer token from the `Authorization` header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    if token.is_empty() { None } else { Some(token.to_owned()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for &(name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    // --- extract_client_ip ---

    #[test]
    fn ip_from_x_forwarded_for() {
        let headers = headers_with(&[("x-forwarded-for", "1.2.3.4, 5.6.7.8")]);
        assert_eq!(extract_client_ip_from_headers(&headers), "1.2.3.4");
    }

    #[test]
    fn ip_from_x_real_ip() {
        let headers = headers_with(&[("x-real-ip", "10.0.0.1")]);
        assert_eq!(extract_client_ip_from_headers(&headers), "10.0.0.1");
    }

    #[test]
    fn ip_forwarded_for_takes_priority() {
        let headers = headers_with(&[("x-forwarded-for", "1.2.3.4"), ("x-real-ip", "10.0.0.1")]);
        assert_eq!(extract_client_ip_from_headers(&headers), "1.2.3.4");
    }

    #[test]
    fn ip_fallback_to_unknown() {
        let headers = HeaderMap::new();
        assert_eq!(extract_client_ip_from_headers(&headers), "unknown");
    }

    fn request_from(peer: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut request = Request::new(());
        *request.headers_mut() = headers_with(headers);
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        request
    }

    #[test]
    fn a_lan_caller_cannot_choose_its_rate_limit_key() {
        let _guard = TRUST_FLAG.lock().unwrap();
        let spoofed = request_from(
            "192.168.1.50:40000",
            &[("x-forwarded-for", "9.9.9.9"), ("x-real-ip", "8.8.8.8")],
        );
        assert_eq!(extract_client_ip(&spoofed), "192.168.1.50");
    }

    /// The trust flag is process-wide; serialise the tests that read or flip it.
    static TRUST_FLAG: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn a_local_caller_cannot_choose_its_rate_limit_key_by_default() {
        let _guard = TRUST_FLAG.lock().unwrap();
        set_trust_forwarded_headers(false);
        let spoofed = request_from(
            "127.0.0.1:40000",
            &[("x-forwarded-for", "192.168.1.20"), ("x-real-ip", "8.8.8.8")],
        );
        assert_eq!(extract_client_ip(&spoofed), "127.0.0.1");
        assert!(is_loopback_client(&spoofed));
        let mut no_peer = Request::new(());
        *no_peer.headers_mut() = headers_with(&[("x-forwarded-for", "9.9.9.9")]);
        assert_eq!(extract_client_ip(&no_peer), "unknown");
    }

    #[test]
    fn a_trusted_local_reverse_proxy_may_forward_the_client_address() {
        let _guard = TRUST_FLAG.lock().unwrap();
        set_trust_forwarded_headers(true);
        let proxied = request_from("127.0.0.1:40000", &[("x-forwarded-for", "203.0.113.7")]);
        let direct = request_from("127.0.0.1:40000", &[]);
        let lan = request_from("192.168.1.50:40000", &[("x-forwarded-for", "9.9.9.9")]);
        let results = (
            extract_client_ip(&proxied),
            is_loopback_client(&proxied),
            extract_client_ip(&direct),
            extract_client_ip(&lan),
        );
        set_trust_forwarded_headers(false);
        assert_eq!(
            results,
            ("203.0.113.7".into(), false, "127.0.0.1".into(), "192.168.1.50".into())
        );
    }

    // --- extract_token_from_headers ---

    #[test]
    fn token_from_authorization_header() {
        let headers = headers_with(&[("authorization", "Bearer my_jwt_token")]);
        assert_eq!(extract_token_from_headers(&headers), Some("my_jwt_token".into()));
    }

    #[test]
    fn token_from_cookie() {
        let headers = headers_with(&[("cookie", "aionui-session=cookie_token; other=val")]);
        assert_eq!(extract_token_from_headers(&headers), Some("cookie_token".into()));
    }

    #[test]
    fn token_header_takes_priority_over_cookie() {
        let headers = headers_with(&[
            ("authorization", "Bearer header_token"),
            ("cookie", "aionui-session=cookie_token"),
        ]);
        assert_eq!(extract_token_from_headers(&headers), Some("header_token".into()));
    }

    #[test]
    fn token_none_when_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_token_from_headers(&headers), None);
    }

    #[test]
    fn token_none_for_empty_bearer() {
        let headers = headers_with(&[("authorization", "Bearer ")]);
        assert_eq!(extract_token_from_headers(&headers), None);
    }

    #[test]
    fn token_none_for_non_bearer_auth() {
        let headers = headers_with(&[("authorization", "Basic dXNlcjpwYXNz")]);
        assert_eq!(extract_token_from_headers(&headers), None);
    }

    // --- extract_token_from_ws_headers ---

    #[test]
    fn ws_token_from_authorization() {
        let headers = headers_with(&[("authorization", "Bearer ws_token")]);
        assert_eq!(extract_token_from_ws_headers(&headers), Some("ws_token".into()));
    }

    #[test]
    fn ws_token_from_cookie() {
        let headers = headers_with(&[("cookie", "aionui-session=ws_cookie")]);
        assert_eq!(extract_token_from_ws_headers(&headers), Some("ws_cookie".into()));
    }

    #[test]
    fn ws_token_from_sec_websocket_protocol() {
        let headers = headers_with(&[("sec-websocket-protocol", "my_ws_token, graphql-ws")]);
        assert_eq!(extract_token_from_ws_headers(&headers), Some("my_ws_token".into()));
    }

    #[test]
    fn ws_token_priority_order() {
        let headers = headers_with(&[
            ("authorization", "Bearer auth_token"),
            ("cookie", "aionui-session=cookie_token"),
            ("sec-websocket-protocol", "proto_token"),
        ]);
        assert_eq!(extract_token_from_ws_headers(&headers), Some("auth_token".into()));
    }

    #[test]
    fn ws_token_fallback_through_sources() {
        // Only cookie and protocol, no authorization
        let headers = headers_with(&[
            ("cookie", "aionui-session=cookie_token"),
            ("sec-websocket-protocol", "proto_token"),
        ]);
        assert_eq!(extract_token_from_ws_headers(&headers), Some("cookie_token".into()));
    }

    // --- extract_cookie_value ---

    #[test]
    fn cookie_value_extracted() {
        let headers = headers_with(&[("cookie", "a=1; target=hello; b=2")]);
        assert_eq!(extract_cookie_value(&headers, "target"), Some("hello".into()));
    }

    #[test]
    fn cookie_value_not_found() {
        let headers = headers_with(&[("cookie", "a=1; b=2")]);
        assert_eq!(extract_cookie_value(&headers, "missing"), None);
    }

    #[test]
    fn cookie_value_no_cookie_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_cookie_value(&headers, "any"), None);
    }

    #[test]
    fn cookie_value_skips_malformed_entries() {
        // Entry without '=' should be skipped, not abort the entire search
        let headers = headers_with(&[("cookie", "malformed; target=found; also_bad")]);
        assert_eq!(extract_cookie_value(&headers, "target"), Some("found".into()));
    }

    #[test]
    fn cookie_value_all_malformed_returns_none() {
        let headers = headers_with(&[("cookie", "no_equals; also_none")]);
        assert_eq!(extract_cookie_value(&headers, "target"), None);
    }

    #[test]
    fn cookie_value_malformed_before_target() {
        // Malformed entry appears before the target cookie
        let headers = headers_with(&[("cookie", "bad_entry; aionui-session=tok123")]);
        assert_eq!(extract_cookie_value(&headers, "aionui-session"), Some("tok123".into()));
    }

    #[test]
    fn token_from_cookie_with_malformed_entries() {
        // End-to-end: extract_token_from_headers should still find the
        // session cookie even when other entries lack '='
        let headers = headers_with(&[("cookie", "garbage; aionui-session=abc; nope")]);
        assert_eq!(extract_token_from_headers(&headers), Some("abc".into()));
    }
}
