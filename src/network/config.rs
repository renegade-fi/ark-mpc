//! Groups network config related helpers

use std::{sync::Arc, time::Duration};

use quinn::{ClientConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use rcgen::RcgenError;
use rustls::{Certificate, ClientConfig as CryptoClientConfig};

use crate::error::SetupError;
use crate::network::cert_verifier::PassThroughCertVerifier;

#[cfg(not(test))]
const MAX_IDLE_TIMEOUT: u32 = 10_000; // milliseconds
#[cfg(test)]
const MAX_IDLE_TIMEOUT: u32 = 0; // No timeout
const KEEP_ALIVE_INTERVAL: u64 = 3_000; // milliseconds
pub(crate) const SERVER_NAME: &str = "otter.cash"; // dummy value

/// Builds the configs for quinn p2p communication
pub fn build_configs() -> Result<(ClientConfig, ServerConfig), SetupError> {
    // 1. Transport config
    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(MAX_IDLE_TIMEOUT))));

    transport_config.keep_alive_interval(Some(Duration::from_millis(KEEP_ALIVE_INTERVAL)));

    let transport: Arc<TransportConfig> = Arc::new(transport_config);

    // 2. Cryptography setup
    // Generate a self-signed server certificate for the QUIC connection
    let (cert, key) = generate_cert().map_err(|_| SetupError::KeygenError)?;

    // Setup the certificate root
    let mut roots = rustls::RootCertStore::empty();
    roots.add(&cert).map_err(|_| SetupError::ServerSetupError)?;

    // Pass the self-signed cert to the client, and disable auth; p2p auth should happen at a higher layer
    let mut client_crypto_config = CryptoClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto_config
        .dangerous()
        .set_certificate_verifier(Arc::new(PassThroughCertVerifier::new()));

    // 3. Client and server setup
    let mut client_config = ClientConfig::new(Arc::new(client_crypto_config));
    client_config.transport_config(transport.clone());

    let mut server_config = ServerConfig::with_single_cert(vec![cert], key)
        .map_err(|_| SetupError::ServerSetupError)?;
    server_config.transport = transport;

    Ok((client_config, server_config))
}

/// Generates a self-signed certificate to construct TLS 1.3 connections with
/// borrowed from https://github.com/maidsafe/qp2p/blob/main/src/config.rs#L317
fn generate_cert() -> Result<(Certificate, rustls::PrivateKey), RcgenError> {
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;

    let key = cert.serialize_private_key_der();
    let cert = cert.serialize_der().unwrap();

    let key = rustls::PrivateKey(key);
    let cert = Certificate(cert);
    Ok((cert, key))
}
