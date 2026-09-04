use std::io;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info};

use crate::conn::ProxyConn;
use crate::handler::Handler;

/// TLS server: terminates TLS and hands the decrypted stream to a handler.
///
/// This is the `+tls` half of a `-L http+tls://` listener. It mirrors
/// [`Server`](crate::server::Server) — same accept backoff, cancellation token
/// and task tracker — but wraps each accepted socket in a TLS session first.
///
/// Backed by rustls rather than native-tls so the server identity is built
/// identically on every platform; native-tls delegates to schannel on Windows,
/// which cannot construct an identity from a PEM key pair.
pub struct TlsServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handler: Arc<dyn Handler>,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

impl TlsServer {
    /// Create a new TLS server from a prepared rustls configuration.
    pub async fn new(
        addr: &str,
        config: ServerConfig,
        handler: impl Handler + 'static,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(addr).await?;

        info!("TLS listening on {}", listener.local_addr()?);

        Ok(Self {
            listener,
            acceptor,
            handler: Arc::new(handler),
            cancel: CancellationToken::new(),
            tracker: TaskTracker::new(),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Accepts TLS connections and dispatches them to the handler.
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut temp_delay = Duration::ZERO;

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    info!("[tls] shutdown signal received, draining connections...");
                    break;
                }
                result = self.listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            temp_delay = Duration::ZERO;
                            let acceptor = self.acceptor.clone();
                            let handler = self.handler.clone();
                            let cancel = self.cancel.clone();
                            // Captured before the socket is consumed by the TLS
                            // session, so the handler still sees the real client
                            // and listener addresses.
                            let local_addr = stream.local_addr().ok();

                            self.tracker.spawn(async move {
                                let tls_stream = match acceptor.accept(stream).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        // A failed handshake is routine: port
                                        // scanners and plaintext clients cause it.
                                        debug!("[tls] handshake failed from {}: {}", peer_addr, e);
                                        return;
                                    }
                                };

                                let conn = ProxyConn::layered(
                                    Box::new(tls_stream),
                                    Some(peer_addr),
                                    local_addr,
                                );

                                tokio::select! {
                                    result = handler.handle(conn) => {
                                        if let Err(e) = result {
                                            debug!("[tls] {} : {}", peer_addr, e);
                                        }
                                    }
                                    _ = cancel.cancelled() => {
                                        debug!("[tls] {} : cancelled", peer_addr);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            if temp_delay.is_zero() {
                                temp_delay = Duration::from_millis(5);
                            } else {
                                temp_delay *= 2;
                            }
                            if temp_delay > Duration::from_secs(1) {
                                temp_delay = Duration::from_secs(1);
                            }
                            error!("[tls] accept error: {}; retrying in {:?}", e, temp_delay);
                            tokio::time::sleep(temp_delay).await;
                        }
                    }
                }
            }
        }

        self.tracker.close();
        self.tracker.wait().await;
        Ok(())
    }
}

/// Builds a rustls server configuration from PEM certificate and key bytes.
pub fn server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut io::BufReader::new(cert_pem)).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err("no certificates found in the PEM data".into());
    }

    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut io::BufReader::new(key_pem))?
            .ok_or("no private key found in the PEM data")?;

    // The provider is named explicitly: several crates in this dependency graph
    // pull in both ring and aws-lc-rs, which leaves no unambiguous default.
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

    Ok(config)
}

/// Loads a rustls server configuration from certificate and key files.
pub fn server_config_from_files(
    cert_path: &str,
    key_path: &str,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;
    server_config_from_pem(&cert_pem, &key_pem)
}

/// Generates a self-signed certificate, as gost does when a listener has no
/// key pair configured. Returns the rustls configuration plus the certificate
/// PEM, which callers may want to publish to clients.
pub fn self_signed_config(
    hostname: &str,
) -> Result<(ServerConfig, String), Box<dyn std::error::Error + Send + Sync>> {
    let generated = rcgen::generate_simple_self_signed(vec![hostname.to_string()])?;
    let cert_pem = generated.cert.pem();
    let key_pem = generated.key_pair.serialize_pem();
    let config = server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
    Ok((config, cert_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_from_missing_files() {
        assert!(server_config_from_files("nonexistent.pem", "nonexistent.key").is_err());
    }

    #[test]
    fn test_server_config_rejects_garbage_pem() {
        assert!(server_config_from_pem(b"not a certificate", b"not a key").is_err());
    }

    #[test]
    fn test_self_signed_config_builds_on_every_platform() {
        // The point of using rustls: this must succeed on Windows too, where
        // native_tls::Identity::from_pkcs8 does not.
        let (_config, cert_pem) = self_signed_config("localhost").unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
    }
}
