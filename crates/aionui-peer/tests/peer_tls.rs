//! Real mutual TLS between two host identities on a loopback port (ADR-009 M2.1).

use std::sync::{Arc, Mutex};

use aionui_peer::{
    Fingerprint, InMemoryTrustStore, PeerCaller, PeerIdentity, ServerPin, TrustStore, client_config,
    serve_peer_listener, server_config,
};
use axum::routing::get;
use axum::{Extension, Json, Router};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

struct Host {
    _dir: tempfile::TempDir,
    identity: PeerIdentity,
}

fn host(name: &str) -> Host {
    let dir = tempfile::tempdir().unwrap();
    let identity = PeerIdentity::load_or_create(&dir.path().join("peer"), name).unwrap();
    Host { _dir: dir, identity }
}

/// Start a peer listener for `server` whose /peer/v1/hello reports the caller and its trust.
async fn start_listener(server: &PeerIdentity, trust: Arc<InMemoryTrustStore>) -> std::net::SocketAddr {
    let router = Router::new().route(
        "/peer/v1/hello",
        get(
            move |Extension(caller): Extension<PeerCaller>,
                  axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>| {
                let trust = trust.clone();
                async move {
                    Json(json!({
                        "caller": caller.fingerprint.as_str(),
                        "trusted": trust.is_trusted(&caller.fingerprint),
                        // Rate limits key on the socket address; the listener must provide it.
                        "peer_ip": peer.ip().to_string(),
                    }))
                }
            },
        ),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_peer_listener(listener, server_config(server).unwrap(), router));
    addr
}

/// One HTTP/1.1 GET over TLS; returns (status, JSON body).
async fn get_json(addr: std::net::SocketAddr, config: Arc<ClientConfig>, path: &str) -> std::io::Result<(u16, Value)> {
    let tcp = TcpStream::connect(addr).await?;
    let mut tls = TlsConnector::from(config)
        .connect(ServerName::try_from("peer.invalid").unwrap(), tcp)
        .await?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: peer\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await?;
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await?;
    let text = String::from_utf8_lossy(&raw);
    let status = text[9..12].parse().unwrap();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or_default();
    // Chunked or plain: the JSON object sits between the first '{' and the last '}'.
    let json = &body[body.find('{').unwrap_or(0)..=body.rfind('}').unwrap_or(0)];
    Ok((status, serde_json::from_str(json).unwrap_or(Value::Null)))
}

#[test]
fn identity_is_created_once_then_reloaded_with_a_private_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("peer");
    let first = PeerIdentity::load_or_create(&path, "host-a").unwrap();
    let again = PeerIdentity::load_or_create(&path, "host-a").unwrap();
    assert_eq!(first.fingerprint(), again.fingerprint());
    assert_eq!(first.fingerprint().as_str().len(), 64);
    assert!(!format!("{first:?}").contains("PRIVATE"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path.join("identity.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn fingerprint_parse_normalizes_and_rejects_garbage() {
    let fp = host("a").identity.fingerprint().clone();
    let colons = fp
        .as_str()
        .to_uppercase()
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":");
    assert_eq!(Fingerprint::parse(&colons).unwrap(), fp);
    assert!(Fingerprint::parse("abc").is_err());
    assert!(Fingerprint::parse(&"g".repeat(64)).is_err());
}

#[tokio::test]
async fn pinned_client_is_identified_and_trust_is_decided_by_the_application() {
    let (server, client) = (host("b"), host("a"));
    let trust = Arc::new(InMemoryTrustStore::default());
    let addr = start_listener(&server.identity, trust.clone()).await;
    let config = client_config(
        &client.identity,
        ServerPin::Expect(server.identity.fingerprint().clone()),
    )
    .unwrap();

    let (status, body) = get_json(addr, config.clone(), "/peer/v1/hello").await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["caller"], client.identity.fingerprint().as_str());
    assert_eq!(body["trusted"], false);
    assert_eq!(
        body["peer_ip"], "127.0.0.1",
        "the connection's own address reaches the handlers"
    );

    trust.trust(client.identity.fingerprint().clone());
    assert_eq!(
        get_json(addr, config.clone(), "/peer/v1/hello").await.unwrap().1["trusted"],
        true
    );

    trust.revoke(client.identity.fingerprint());
    assert_eq!(
        get_json(addr, config, "/peer/v1/hello").await.unwrap().1["trusted"],
        false
    );
}

#[tokio::test]
async fn client_pinning_the_wrong_server_fingerprint_is_refused() {
    let (server, client, impostor) = (host("b"), host("a"), host("x"));
    let addr = start_listener(&server.identity, Arc::new(InMemoryTrustStore::default())).await;
    let config = client_config(
        &client.identity,
        ServerPin::Expect(impostor.identity.fingerprint().clone()),
    )
    .unwrap();
    let error = get_json(addr, config, "/peer/v1/hello").await.unwrap_err();
    assert!(error.to_string().contains("invalid peer certificate"), "{error}");
}

#[tokio::test]
async fn observe_pin_records_the_server_fingerprint_for_owner_confirmation() {
    let (server, client) = (host("b"), host("a"));
    let addr = start_listener(&server.identity, Arc::new(InMemoryTrustStore::default())).await;
    let seen = Arc::new(Mutex::new(None));
    let config = client_config(&client.identity, ServerPin::Observe(seen.clone())).unwrap();
    assert_eq!(get_json(addr, config, "/peer/v1/hello").await.unwrap().0, 200);
    assert_eq!(seen.lock().unwrap().as_ref(), Some(server.identity.fingerprint()));
}

/// Test-only verifier for a client that has no identity: accepts the server so the
/// rejection observed below can only come from the missing client certificate.
#[derive(Debug)]
struct AcceptAnyServer(rustls::crypto::WebPkiSupportedAlgorithms);

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[tokio::test]
async fn client_without_a_certificate_is_rejected() {
    let server = host("b");
    let addr = start_listener(&server.identity, Arc::new(InMemoryTrustStore::default())).await;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let algorithms = provider.signature_verification_algorithms;
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer(algorithms)))
        .with_no_client_auth();
    let result = get_json(addr, Arc::new(config), "/peer/v1/hello").await;
    assert!(result.is_err(), "anonymous client must not get a response: {result:?}");
}

/// A LAN host can neither hold the listener forever after the handshake nor
/// pile up unbounded connections (audit run-2 SEC-F).
#[tokio::test]
async fn a_silent_connection_is_closed_after_the_header_timeout() {
    let (server, client) = (host("b"), host("a"));
    let addr = start_listener(&server.identity, Arc::new(InMemoryTrustStore::default())).await;
    let config = client_config(
        &client.identity,
        ServerPin::Expect(server.identity.fingerprint().clone()),
    )
    .unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = TlsConnector::from(config)
        .connect(ServerName::try_from("peer.invalid").unwrap(), tcp)
        .await
        .unwrap();
    // Send nothing; the server must close the connection on its own.
    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(
        aionui_peer::HEADER_READ_TIMEOUT + std::time::Duration::from_secs(5),
        tls.read(&mut byte),
    )
    .await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "connection still open: {closed:?}"
    );
}

#[tokio::test]
async fn connections_beyond_the_cap_are_closed_at_once() {
    let server = host("b");
    let addr = start_listener(&server.identity, Arc::new(InMemoryTrustStore::default())).await;
    let mut idle = Vec::new();
    for _ in 0..aionui_peer::MAX_TLS_CONNECTIONS {
        idle.push(TcpStream::connect(addr).await.unwrap());
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let mut extra = TcpStream::connect(addr).await.unwrap();
    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(std::time::Duration::from_secs(2), extra.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "connection over the cap still open: {closed:?}"
    );
    drop(idle);
}
