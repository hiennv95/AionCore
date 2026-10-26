//! rustls configuration for the peer listener (server) and outgoing peer calls (client).
//!
//! Peers have no CA. Identity is the pinned SHA-256 fingerprint of a self-signed certificate;
//! the TLS handshake still proves possession of that certificate's key (rustls verifies the
//! handshake signature with the provider's algorithms). Authorization by fingerprint happens
//! in the application, see `server.rs`.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme,
};

use crate::error::PeerError;
use crate::identity::{Fingerprint, PeerIdentity};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Server side: every client must present a certificate and prove its key; which
/// fingerprints may do what is decided per endpoint by the application.
#[derive(Debug)]
struct RequireClientCertificate {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for RequireClientCertificate {
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// How an outgoing peer call checks the server's certificate.
#[derive(Debug, Clone)]
pub enum ServerPin {
    /// Paired peer: the server certificate must have exactly this fingerprint.
    Expect(Fingerprint),
    /// First contact while pairing: accept any certificate but record its fingerprint so
    /// the owner can confirm it out of band before anything is trusted.
    Observe(Arc<Mutex<Option<Fingerprint>>>),
}

#[derive(Debug)]
struct PinnedServerCertificate {
    pin: ServerPin,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let presented = Fingerprint::of(end_entity);
        match &self.pin {
            ServerPin::Expect(expected) if *expected == presented => Ok(ServerCertVerified::assertion()),
            ServerPin::Expect(_) => Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
            ServerPin::Observe(slot) => {
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(presented);
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// TLS config for the peer listener: this host's identity, client certificates mandatory.
pub fn server_config(identity: &PeerIdentity) -> Result<Arc<ServerConfig>, PeerError> {
    let provider = provider();
    let verifier = Arc::new(RequireClientCertificate {
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| PeerError::Tls(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![identity.certificate()], identity.private_key())
        .map_err(|e| PeerError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

/// TLS config for the device listener: this host's identity, no client certificate. Devices
/// pin the fingerprint they got from the pairing QR code.
pub fn device_server_config(identity: &PeerIdentity) -> Result<Arc<ServerConfig>, PeerError> {
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| PeerError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![identity.certificate()], identity.private_key())
        .map_err(|e| PeerError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

/// TLS config for calling a peer: presents this host's identity, checks the server by `pin`.
pub fn client_config(identity: &PeerIdentity, pin: ServerPin) -> Result<Arc<ClientConfig>, PeerError> {
    let provider = provider();
    let verifier = Arc::new(PinnedServerCertificate {
        pin,
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| PeerError::Tls(e.to_string()))?
        // `dangerous()` is rustls's gate for any custom verifier. This one pins the peer's
        // fingerprint; it never skips verification.
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![identity.certificate()], identity.private_key())
        .map_err(|e| PeerError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}
