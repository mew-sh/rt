use native_tls::{Identity, TlsConnector as NativeTlsConnector};
use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector, TlsStream};

/// Generate a self-signed TLS certificate.
///
/// The listener side uses [`crate::tls_listener::self_signed_config`] instead;
/// this exists for the client paths that still want a native-tls `Identity`.
pub fn gen_self_signed_cert() -> Result<Identity, Box<dyn std::error::Error>> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_pem = generated.cert.pem();
    let key_pem = generated.key_pair.serialize_pem();
    Ok(Identity::from_pkcs8(
        cert_pem.as_bytes(),
        key_pem.as_bytes(),
    )?)
}

/// Wrap any stream in TLS, not just a TCP socket.
///
/// This is what lets a chain hop layer TLS over whatever the previous hop
/// produced, rather than only over a freshly dialled socket.
pub async fn tls_connect_stream<S>(
    stream: S,
    domain: &str,
    insecure: bool,
) -> Result<TlsStream<S>, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let connector = if insecure {
        insecure_tls_connector()?
    } else {
        default_tls_connector()?
    };
    Ok(connector.connect(domain, stream).await?)
}

/// Create a TLS connector that skips verification (insecure).
///
/// This is gost's default for a chain node: `InsecureSkipVerify` is set unless
/// `?secure=true` is given (route.go:135). That skips the hostname check as
/// well as the chain check, so both are disabled here.
pub fn insecure_tls_connector() -> Result<TlsConnector, native_tls::Error> {
    let connector = NativeTlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;
    Ok(TlsConnector::from(connector))
}

/// Create a default TLS connector.
pub fn default_tls_connector() -> Result<TlsConnector, native_tls::Error> {
    let connector = NativeTlsConnector::new()?;
    Ok(TlsConnector::from(connector))
}

/// Wrap a TCP stream in TLS.
pub async fn tls_connect(
    stream: TcpStream,
    domain: &str,
    insecure: bool,
) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    let connector = if insecure {
        insecure_tls_connector()?
    } else {
        default_tls_connector()?
    };
    let tls_stream = connector.connect(domain, stream).await?;
    Ok(tls_stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insecure_connector() {
        let connector = insecure_tls_connector();
        assert!(connector.is_ok());
    }

    #[test]
    fn test_default_connector() {
        let connector = default_tls_connector();
        assert!(connector.is_ok());
    }
}
