//! [`PeerTransport`] over HTTPS with mutual TLS (reqwest + rustls). Every call
//! presents this host's identity and pins the server's fingerprint; only the
//! first-contact `observe` accepts an unknown certificate, and it carries no work.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aionui_api_types::{
    PeerErrorBody, PeerHelloResponse, PeerPairingRequest, PeerPairingResponse, PeerPairingReveal,
    PeerPairingRevealResponse, PeerRequestStatus, PeerSharesResponse, PeerSubmitRequest,
};
use aionui_peer::{Fingerprint, PeerIdentity, ServerPin, client_config};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::NetworkError;
use crate::ports::PeerTransport;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CALL_TIMEOUT: Duration = Duration::from_secs(15);
/// Long-polls get their wait plus this margin.
const POLL_MARGIN: Duration = Duration::from_secs(10);
/// Largest peer reply read: a full result after JSON escaping (a control
/// character becomes six bytes) plus its envelope. A peer is untrusted data
/// (ADR-009), so a bigger body is refused, not buffered.
const MAX_REPLY_BYTES: usize = 6 * crate::policy::MAX_RESULT_BYTES + 64 * 1024;

/// Reads `response` up to `max` bytes, failing as soon as it is exceeded.
async fn read_capped(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>, NetworkError> {
    let too_large = || NetworkError::PeerUnreachable("peer reply too large".into());
    if response.content_length().is_some_and(|len| len > max as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| NetworkError::PeerUnreachable(describe(&e)))?
    {
        if body.len() + chunk.len() > max {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub struct HttpsPeerTransport {
    identity: Arc<PeerIdentity>,
    /// One pinned client per peer fingerprint (keeps connections alive).
    clients: Mutex<HashMap<Fingerprint, reqwest::Client>>,
}

impl HttpsPeerTransport {
    pub fn new(identity: Arc<PeerIdentity>) -> Self {
        Self {
            identity,
            clients: Mutex::new(HashMap::new()),
        }
    }

    fn build(&self, pin: ServerPin) -> Result<reqwest::Client, NetworkError> {
        let tls = client_config(&self.identity, pin).map_err(|e| NetworkError::Internal(e.to_string()))?;
        reqwest::Client::builder()
            .use_preconfigured_tls((*tls).clone())
            .connect_timeout(CONNECT_TIMEOUT)
            // Peer calls go straight to the LAN address; never through a proxy.
            .no_proxy()
            // Nor anywhere a peer redirects to: a 3xx could send the request, body
            // included, to a plain-HTTP or unpinned URL (audit H22).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| NetworkError::Internal(format!("peer client: {e}")))
    }

    fn pinned(&self, expected: &Fingerprint) -> Result<reqwest::Client, NetworkError> {
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(client) = clients.get(expected) {
            return Ok(client.clone());
        }
        let client = self.build(ServerPin::Expect(expected.clone()))?;
        clients.insert(expected.clone(), client.clone());
        Ok(client)
    }

    async fn call<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        timeout: Duration,
    ) -> Result<T, NetworkError> {
        let response = request
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| NetworkError::PeerUnreachable(describe(&e)))?;
        let status = response.status();
        let body = read_capped(response, MAX_REPLY_BYTES).await?;
        if status.is_success() {
            return serde_json::from_slice::<T>(&body)
                .map_err(|e| NetworkError::PeerUnreachable(format!("bad response: {e}")));
        }
        match serde_json::from_slice::<PeerErrorBody>(&body) {
            Ok(body) => Err(NetworkError::from_peer_code(&body.code, body.message)),
            Err(_) => Err(NetworkError::PeerRejected {
                code: format!("HTTP_{}", status.as_u16()),
                message: "peer answered without an error body".into(),
            }),
        }
    }

    async fn post<B: Serialize + Sync, T: DeserializeOwned>(
        &self,
        expected: &Fingerprint,
        url: &str,
        path: &str,
        body: &B,
    ) -> Result<T, NetworkError> {
        let client = self.pinned(expected)?;
        self.call(client.post(join(url, path)).json(body), CALL_TIMEOUT).await
    }
}

fn join(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// Transport error text without URLs' query strings or bodies.
fn describe(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "timed out".into()
    } else if error.is_connect() {
        "connection failed (TLS identity mismatch or host offline)".into()
    } else {
        "request failed".into()
    }
}

#[async_trait::async_trait]
impl PeerTransport for HttpsPeerTransport {
    async fn observe(&self, url: &str) -> Result<(Fingerprint, PeerHelloResponse), NetworkError> {
        let slot = Arc::new(Mutex::new(None));
        let client = self.build(ServerPin::Observe(slot.clone()))?;
        let hello: PeerHelloResponse = self.call(client.get(join(url, "/peer/v1/hello")), CALL_TIMEOUT).await?;
        let observed = slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| NetworkError::PeerUnreachable("no server certificate observed".into()))?;
        // The body must describe the certificate we actually saw.
        if hello.host_fingerprint != observed.as_str() {
            return Err(NetworkError::FingerprintMismatch);
        }
        Ok((observed, hello))
    }

    async fn pair(
        &self,
        url: &str,
        expected: &Fingerprint,
        body: &PeerPairingRequest,
    ) -> Result<PeerPairingResponse, NetworkError> {
        self.post(expected, url, "/peer/v1/pairing", body).await
    }

    async fn reveal(
        &self,
        url: &str,
        expected: &Fingerprint,
        body: &PeerPairingReveal,
    ) -> Result<PeerPairingRevealResponse, NetworkError> {
        self.post(expected, url, "/peer/v1/pairing/reveal", body).await
    }

    async fn list_shares(&self, url: &str, expected: &Fingerprint) -> Result<PeerSharesResponse, NetworkError> {
        let client = self.pinned(expected)?;
        self.call(client.get(join(url, "/peer/v1/shares")), CALL_TIMEOUT).await
    }

    async fn submit(
        &self,
        url: &str,
        expected: &Fingerprint,
        body: &PeerSubmitRequest,
    ) -> Result<PeerRequestStatus, NetworkError> {
        self.post(expected, url, "/peer/v1/requests", body).await
    }

    async fn status(
        &self,
        url: &str,
        expected: &Fingerprint,
        request_id: &str,
        after_version: i64,
        wait_ms: u64,
    ) -> Result<PeerRequestStatus, NetworkError> {
        let client = self.pinned(expected)?;
        let path = format!("/peer/v1/requests/{request_id}?after_version={after_version}&wait_ms={wait_ms}");
        self.call(
            client.get(join(url, &path)),
            Duration::from_millis(wait_ms) + POLL_MARGIN,
        )
        .await
    }

    async fn cancel(
        &self,
        url: &str,
        expected: &Fingerprint,
        request_id: &str,
    ) -> Result<PeerRequestStatus, NetworkError> {
        self.post(
            expected,
            url,
            &format!("/peer/v1/requests/{request_id}/cancel"),
            &serde_json::json!({}),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer reply larger than the cap is refused while reading, never
    /// buffered whole (audit run-2 SEC-F).
    #[tokio::test]
    async fn an_oversized_peer_reply_is_refused_while_reading() {
        let big = format!("{{\"text\":\"{}\"}}", "a".repeat(2 * 1024 * 1024));
        let app = axum::Router::new().route("/", axum::routing::get(move || async move { big }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
        let err = read_capped(response, MAX_REPLY_BYTES).await.unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

    #[tokio::test]
    async fn a_normal_peer_reply_is_read_whole() {
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "{\"ok\":true}" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
        assert_eq!(read_capped(response, MAX_REPLY_BYTES).await.unwrap(), b"{\"ok\":true}");
    }
}
