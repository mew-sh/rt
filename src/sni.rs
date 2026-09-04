use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::permissions::Can;
use crate::transport::transport;

// TLS record type for Handshake
const TLS_HANDSHAKE: u8 = 0x16;

/// Bytes of the TLS record header: type(1) + version(2) + length(2).
const TLS_RECORD_HEADER_LEN: usize = 5;

/// Upper bound on the ClientHello we buffer before giving up on finding a
/// server name, matching the fixed 4096-byte peek this used to do.
const MAX_CLIENT_HELLO: usize = 4096;

/// SNI proxy handler - routes based on TLS SNI or HTTP Host header.
pub struct SniHandler {
    options: HandlerOptions,
}

impl SniHandler {
    pub fn new(options: HandlerOptions) -> Self {
        Self { options }
    }
}

#[async_trait]
impl Handler for SniHandler {
    async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();

        // Peek the first byte to detect the protocol. `ProxyConn::peek` fills
        // the whole buffer before returning, so ask for exactly the one byte
        // the check below reads rather than a speculative block that may never
        // arrive.
        let mut peek_buf = [0u8; 1];
        let n = conn.peek(&mut peek_buf).await?;
        if n == 0 {
            return Err(HandlerError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "empty connection",
            )));
        }

        if peek_buf[0] == TLS_HANDSHAKE {
            // TLS - extract SNI from ClientHello. The record header carries the
            // exact ClientHello length, so peek that first and then ask for
            // precisely the record: peeking a fixed 4096 bytes would block on a
            // client that has nothing more to send until the server replies.
            let mut record_head = [0u8; TLS_RECORD_HEADER_LEN];
            if conn.peek(&mut record_head).await? < TLS_RECORD_HEADER_LEN {
                return Err(HandlerError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated TLS record header",
                )));
            }
            let record_len = u16::from_be_bytes([record_head[3], record_head[4]]) as usize;
            let want = TLS_RECORD_HEADER_LEN + record_len;
            if want > MAX_CLIENT_HELLO {
                // `extract_sni` needs the whole record, so a record this large
                // could never yield a server name; fail now rather than wait
                // for bytes that would be useless anyway.
                return Err(HandlerError::Proxy("SNI: ClientHello too large".into()));
            }

            let mut buf = vec![0u8; want];
            let n = conn.peek(&mut buf).await?;
            let buf = &buf[..n];

            let host = extract_sni(buf).unwrap_or_default();
            if host.is_empty() {
                return Err(HandlerError::Proxy("SNI: no server name found".into()));
            }

            // Determine target port
            let sport = self
                .options
                .host
                .rsplit_once(':')
                .map(|(_, p)| p.to_string())
                .unwrap_or_else(|| "443".to_string());
            let target = format!("{}:{}", host, sport);

            info!("[sni] {} -> {}", peer_addr, target);

            if !Can(
                "tcp",
                &target,
                self.options.whitelist.as_ref(),
                self.options.blacklist.as_ref(),
            ) {
                warn!(
                    "[sni] {} : unauthorized to connect to {}",
                    peer_addr, target
                );
                return Err(HandlerError::Forbidden);
            }

            if let Some(ref bypass) = self.options.bypass {
                if bypass.contains(&target) {
                    info!("[sni] {} bypass {}", peer_addr, target);
                    return Ok(());
                }
            }

            let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

            match chain.dial(&target).await {
                Ok(mut cc) => {
                    // Read the actual data (not just peek) and forward it
                    let mut initial = vec![0u8; n];
                    conn.read_exact(&mut initial).await?;
                    cc.write_all(&initial).await?;

                    info!("[sni] {} <-> {}", peer_addr, target);
                    transport(conn, cc).await.ok();
                    info!("[sni] {} >-< {}", peer_addr, target);
                }
                Err(e) => {
                    debug!("[sni] {} -> {} : {}", peer_addr, target, e);
                    return Err(HandlerError::Chain(e));
                }
            }
        } else {
            // Not TLS - assume HTTP and delegate to HTTP handler
            let handler = crate::http_proxy::HttpHandler::new(self.options.clone());
            return handler.handle(conn).await;
        }

        Ok(())
    }
}

/// Extract SNI (Server Name Indication) from a TLS ClientHello message.
fn extract_sni(data: &[u8]) -> Option<String> {
    // Minimum TLS record header: 5 bytes
    if data.len() < 5 || data[0] != TLS_HANDSHAKE {
        return None;
    }

    // TLS record: type(1) + version(2) + length(2) + payload
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None; // incomplete, try with what we have
    }

    let payload = &data[5..];
    if payload.is_empty() || payload[0] != 0x01 {
        // Not a ClientHello
        return None;
    }

    // ClientHello: type(1) + length(3) + version(2) + random(32) + session_id_len(1) + ...
    if payload.len() < 38 {
        return None;
    }

    let mut pos = 4; // skip type + length
    pos += 2; // skip client version
    pos += 32; // skip random

    if pos >= payload.len() {
        return None;
    }

    // Skip session ID
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > payload.len() {
        return None;
    }

    // Skip cipher suites
    let cipher_suites_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if pos >= payload.len() {
        return None;
    }

    // Skip compression methods
    let comp_methods_len = payload[pos] as usize;
    pos += 1 + comp_methods_len;

    if pos + 2 > payload.len() {
        return None;
    }

    // Extensions
    let extensions_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + extensions_len;
    while pos + 4 <= ext_end && pos + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // Server Name extension
            if pos + 2 > payload.len() {
                return None;
            }
            let _sni_list_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
            pos += 2;

            if pos >= payload.len() {
                return None;
            }
            let name_type = payload[pos];
            pos += 1;

            if name_type == 0x00 {
                // host_name
                if pos + 2 > payload.len() {
                    return None;
                }
                let name_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
                pos += 2;

                if pos + name_len > payload.len() {
                    return None;
                }
                return Some(String::from_utf8_lossy(&payload[pos..pos + name_len]).to_string());
            }
        }

        pos += ext_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sni_empty() {
        assert_eq!(extract_sni(&[]), None);
        assert_eq!(extract_sni(&[0x00, 0x00, 0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn test_extract_sni_from_client_hello() {
        // Minimal synthetic TLS ClientHello with SNI extension
        let mut data = Vec::new();

        // TLS record header
        data.push(0x16); // handshake
        data.push(0x03);
        data.push(0x01); // TLS 1.0
                         // Record length placeholder - we'll fix at end
        let record_len_pos = data.len();
        data.push(0x00);
        data.push(0x00);

        let handshake_start = data.len();

        // Handshake header
        data.push(0x01); // ClientHello
                         // Length placeholder
        let hs_len_pos = data.len();
        data.push(0x00);
        data.push(0x00);
        data.push(0x00);

        let hello_start = data.len();

        // Client version
        data.push(0x03);
        data.push(0x03); // TLS 1.2

        // Random (32 bytes)
        data.extend_from_slice(&[0u8; 32]);

        // Session ID length
        data.push(0x00);

        // Cipher suites (2 bytes length + 2 bytes one suite)
        data.push(0x00);
        data.push(0x02);
        data.push(0x00);
        data.push(0x2F); // TLS_RSA_WITH_AES_128_CBC_SHA

        // Compression methods
        data.push(0x01);
        data.push(0x00); // null compression

        // Extensions
        let host = b"example.com";
        let sni_ext_len = 5 + host.len(); // list_len(2) + type(1) + name_len(2) + name
        let ext_total = 4 + sni_ext_len; // ext_type(2) + ext_len(2) + sni_ext_data

        data.extend_from_slice(&(ext_total as u16).to_be_bytes()); // extensions length

        // SNI extension
        data.push(0x00);
        data.push(0x00); // ext type = server_name
        data.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // ext data length

        // SNI list
        data.extend_from_slice(&((3 + host.len()) as u16).to_be_bytes()); // list length
        data.push(0x00); // host_name type
        data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        data.extend_from_slice(host);

        // Fix lengths
        let hello_len = data.len() - hello_start;
        data[hs_len_pos] = 0;
        data[hs_len_pos + 1] = ((hello_len >> 8) & 0xFF) as u8;
        data[hs_len_pos + 2] = (hello_len & 0xFF) as u8;

        let record_len = data.len() - handshake_start;
        data[record_len_pos] = ((record_len >> 8) & 0xFF) as u8;
        data[record_len_pos + 1] = (record_len & 0xFF) as u8;

        let result = extract_sni(&data);
        assert_eq!(result, Some("example.com".to_string()));
    }
}
