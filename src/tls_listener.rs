use std::sync::Arc;
use std::time::Duration;

use native_tls::{Identity, TlsAcceptor as NativeTlsAcceptor};
use tokio::net::TcpListener;
use tokio_native_tls::TlsAcceptor;
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
pub struct TlsServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    handler: Arc<dyn Handler>,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

impl TlsServer {
    /// Create a new TLS server with the given identity (cert+key).
    pub async fn new(
        addr: &str,
        identity: Identity,
        handler: impl Handler + 'static,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let native_acceptor = NativeTlsAcceptor::new(identity)?;
        let acceptor = TlsAcceptor::from(native_acceptor);
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
                            // Captured before the socket is consumed by the
                            // TLS session, so the handler still sees the real
                            // client and listener addresses.
                            let local_addr = stream.local_addr().ok();

                            self.tracker.spawn(async move {
                                let tls_stream = match acceptor.accept(stream).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        // A failed handshake is routine — port
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

/// Loads a TLS identity.
///
/// Accepts either a PEM certificate/key pair, or — when `cert_path` points at
/// a `.p12`/`.pfx` archive and `key_path` is its password — a PKCS#12 bundle.
/// The PKCS#12 form matters on Windows, whose schannel backend cannot build an
/// identity from PEM.
pub fn load_identity(
    cert_path: &str,
    key_path: &str,
) -> Result<Identity, Box<dyn std::error::Error>> {
    let lower = cert_path.to_ascii_lowercase();
    if lower.ends_with(".p12") || lower.ends_with(".pfx") {
        let der = std::fs::read(cert_path)?;
        return Ok(Identity::from_pkcs12(&der, key_path)?);
    }

    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;
    Ok(Identity::from_pkcs8(&cert_pem, &key_pem)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_identity_missing_files() {
        let result = load_identity("nonexistent.pem", "nonexistent.key");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_identity_missing_pkcs12() {
        let result = load_identity("nonexistent.p12", "password");
        assert!(result.is_err());
    }
}
