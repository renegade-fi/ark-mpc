//! Implements a dummy certificate verifier that simply passes through the request
//! We do not care about the authenticity of certificates during the course of a
//! p2p MPC

use rustls::client::{ServerCertVerified, ServerCertVerifier};

/// Responds Ok() to any certificate verification request
pub(crate) struct PassThroughCertVerifier;

impl PassThroughCertVerifier {
    /// Create a new dummy verifier
    pub fn new() -> Self {
        Self
    }
}

impl ServerCertVerifier for PassThroughCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}
