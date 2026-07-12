//! Shared rustls plumbing for the slow-connection and HTTP/2 rapid-reset engines.
//!
//! Both connect over TLS to a target that has already passed the datum
//! authorization gate and been pinned to a single connect address. Because the
//! safety boundary is *which host we reach* — not the peer's certificate identity
//! — and neither primitive sends secrets or trusts a response, the client config
//! **accepts any server certificate**. This keeps the tooling usable against the
//! self-signed / internal-CA certs typical of lab targets. The relaxed verifier
//! lives only here (used by [`crate::slow`] and [`crate::rapid_reset`]); the fast
//! [`crate::L7Engine`] keeps reqwest's normal verification.

use std::sync::Arc;

use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, SignatureScheme};

use crate::{Datum, L7Error};

/// Build an accept-any-certificate rustls (ring) client config, advertising the
/// given ALPN protocols (empty for none). See the module docs for why accepting
/// any certificate is the correct, scoped choice here.
pub(crate) fn client_config(alpn: Vec<Vec<u8>>) -> Result<Arc<ClientConfig>, L7Error> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let verifier = Arc::new(AcceptAnyServerCert::new(&provider));
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| L7Error::Client(format!("TLS config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    // Disable client-side session resumption: every connection must complete a
    // FULL handshake. This is a no-op for the single-connection slow / rapid-reset
    // engines, but it is what makes the tls-handshake flood meaningful — a resumed
    // handshake is cheap for the server, defeating the CPU-asymmetry self-test.
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// The SNI server name for a datum: an IP-based name for an IP-literal target, a
/// DNS name otherwise. Owned (`'static`) so it can move into per-connection tasks.
pub(crate) fn server_name(datum: &Datum) -> Result<ServerName<'static>, L7Error> {
    match datum.ip {
        Some(ip) => Ok(ServerName::IpAddress(ip.into())),
        None => ServerName::try_from(datum.host.clone())
            .map_err(|e| L7Error::Client(format!("bad TLS server name: {e}"))),
    }
}

/// A rustls certificate verifier that accepts everything. Deliberate and scoped —
/// see the module docs.
#[derive(Debug)]
struct AcceptAnyServerCert {
    schemes: Vec<SignatureScheme>,
}

impl AcceptAnyServerCert {
    fn new(provider: &tokio_rustls::rustls::crypto::CryptoProvider) -> Self {
        Self { schemes: provider.signature_verification_algorithms.supported_schemes() }
    }
}

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builds_with_and_without_alpn() {
        assert!(client_config(vec![]).is_ok());
        let cfg = client_config(vec![b"h2".to_vec()]).expect("alpn config builds");
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
    }
}
