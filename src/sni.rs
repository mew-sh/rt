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

            // A gost client hides the real destination in extension 0xFFFE and
            // leaves a decoy in the SNI, so the visible name is not necessarily
            // where this connection is going. The rewrite strips that extension
            // and restores the SNI, giving both the destination and the record
            // to forward. A client that knows nothing about it still routes by
            // its own SNI.
            let (rewritten, host) = match rewrite_client_hello(buf, "", false) {
                Some((record, host)) => (Some(record), host),
                None => (None, extract_sni(buf).unwrap_or_default()),
            };
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
                    // Consume the peeked record, then forward the rewritten
                    // one so the origin sees a ClientHello naming itself and
                    // without gost's private extension.
                    let mut initial = vec![0u8; n];
                    conn.read_exact(&mut initial).await?;
                    cc.write_all(rewritten.as_deref().unwrap_or(&initial))
                        .await?;

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
/// gost's private ClientHello extension carrying the real destination
/// (sni.go:287, 305).
const EXT_GOST_HOST: u16 = 0xFFFE;
const EXT_SERVER_NAME: u16 = 0x0000;

/// CRC32 (IEEE), which gost prefixes the encoded name with as an integrity
/// check (sni.go:329).
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// gost's `encodeServerName` (sni.go:327-332).
///
/// `base64url(crc32(name) || base64url(name))`, unpadded at both levels.
pub fn encode_server_name(name: &str) -> String {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mut buf = crc32_ieee(name.as_bytes()).to_be_bytes().to_vec();
    buf.extend_from_slice(engine.encode(name.as_bytes()).as_bytes());
    engine.encode(&buf)
}

/// gost's `decodeServerName` (sni.go:334-350).
///
/// Returns `None` when the checksum does not match, so a corrupted or forged
/// extension falls back to the ordinary SNI rather than redirecting the
/// connection somewhere else.
pub fn decode_server_name(s: &str) -> Option<String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let outer = engine.decode(s).ok()?;
    if outer.len() < 4 {
        return None;
    }
    let inner = engine.decode(&outer[4..]).ok()?;
    let want = u32::from_be_bytes([outer[0], outer[1], outer[2], outer[3]]);
    if crc32_ieee(&inner) != want {
        return None;
    }
    String::from_utf8(inner).ok()
}

/// Where the extensions block sits inside a ClientHello handshake body.
///
/// Returns `(start, end)` as offsets into `hello`, which is the handshake
/// message including its 4-byte header.
fn extensions_span(hello: &[u8]) -> Option<(usize, usize)> {
    let mut i = 4 + 2 + 32;
    let session_len = *hello.get(i)? as usize;
    i += 1 + session_len;

    let suites_len = u16::from_be_bytes([*hello.get(i)?, *hello.get(i + 1)?]) as usize;
    i += 2 + suites_len;

    let comp_len = *hello.get(i)? as usize;
    i += 1 + comp_len;

    let exts_len = u16::from_be_bytes([*hello.get(i)?, *hello.get(i + 1)?]) as usize;
    let start = i + 2;
    let end = start.checked_add(exts_len)?;
    if end > hello.len() {
        return None;
    }
    Some((start, end))
}

/// Splits an extensions block into `(type, body)` pairs.
fn parse_extensions(block: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= block.len() {
        let ext_type = u16::from_be_bytes([block[i], block[i + 1]]);
        let len = u16::from_be_bytes([block[i + 2], block[i + 3]]) as usize;
        i += 4;
        if i + len > block.len() {
            return None;
        }
        out.push((ext_type, block[i..i + len].to_vec()));
        i += len;
    }
    Some(out)
}

/// Builds an SNI extension body for `name`.
fn sni_body(name: &str) -> Vec<u8> {
    let n = name.as_bytes();
    let mut body = Vec::with_capacity(5 + n.len());
    body.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
    body.push(0x00);
    body.extend_from_slice(&(n.len() as u16).to_be_bytes());
    body.extend_from_slice(n);
    body
}

/// The host named by an SNI extension body.
fn sni_name(body: &[u8]) -> Option<String> {
    if body.len() < 5 {
        return None;
    }
    let len = u16::from_be_bytes([body[3], body[4]]) as usize;
    let name = body.get(5..5 + len)?;
    String::from_utf8(name.to_vec()).ok()
}

/// Rewrites a ClientHello record the way gost's `readClientHelloRecord` does
/// (sni.go:273-325), returning the new record and the destination host.
///
/// As the client, the real SNI is copied into the private extension and the
/// visible SNI is replaced by the decoy `host`. As the server, the private
/// extension is removed and its contents become the destination, overwriting
/// the SNI so the origin sees the name it expects.
pub fn rewrite_client_hello(
    record: &[u8],
    host: &str,
    is_client: bool,
) -> Option<(Vec<u8>, String)> {
    if record.len() < 5 || record[0] != 0x16 {
        return None;
    }
    let body_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let hello = record.get(5..5 + body_len)?;

    let (start, end) = extensions_span(hello)?;
    let mut exts = parse_extensions(&hello[start..end])?;

    let mut host = host.to_string();

    if !is_client {
        // Take the private extension out; whatever it names is the target.
        let mut kept = Vec::with_capacity(exts.len());
        for (ext_type, body) in exts {
            if ext_type == EXT_GOST_HOST {
                if let Some(decoded) = decode_server_name(&String::from_utf8_lossy(&body)) {
                    host = decoded;
                    continue;
                }
            }
            kept.push((ext_type, body));
        }
        exts = kept;
    }

    let mut appended = None;
    for (ext_type, body) in exts.iter_mut() {
        if *ext_type != EXT_SERVER_NAME {
            continue;
        }
        let name = sni_name(body).unwrap_or_default();
        if host.is_empty() {
            host = name.clone();
        }
        if is_client {
            appended = Some((EXT_GOST_HOST, encode_server_name(&name).into_bytes()));
        }
        if !host.is_empty() {
            *body = sni_body(&host);
        }
        break;
    }
    if let Some(ext) = appended {
        exts.push(ext);
    }

    // Re-encode: the extension block and both enclosing lengths all move.
    let mut block = Vec::new();
    for (ext_type, body) in &exts {
        block.extend_from_slice(&ext_type.to_be_bytes());
        block.extend_from_slice(&(body.len() as u16).to_be_bytes());
        block.extend_from_slice(body);
    }

    let mut new_hello = Vec::with_capacity(hello.len() + block.len());
    new_hello.extend_from_slice(&hello[..start - 2]);
    new_hello.extend_from_slice(&(block.len() as u16).to_be_bytes());
    new_hello.extend_from_slice(&block);
    new_hello.extend_from_slice(&hello[end..]);

    // Handshake length is a 3-byte field covering everything after it.
    let hs_len = new_hello.len() - 4;
    new_hello[1..4].copy_from_slice(&(hs_len as u32).to_be_bytes()[1..]);

    let mut out = Vec::with_capacity(5 + new_hello.len());
    out.extend_from_slice(&record[..3]);
    out.extend_from_slice(&(new_hello.len() as u16).to_be_bytes());
    out.extend_from_slice(&new_hello);

    Some((out, host))
}

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

    // ---- gost's private host extension (0xFFFE) ----

    #[test]
    fn test_crc32_ieee_known_vectors() {
        // The standard check values; gost uses Go's crc32.ChecksumIEEE.
        assert_eq!(crc32_ieee(b""), 0x0000_0000);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_ieee(b"example.com"), crc32_ieee(b"example.com"));
    }

    #[test]
    fn test_server_name_encoding_roundtrip() {
        for name in ["example.com", "a", "very.long.sub.domain.example.org"] {
            let encoded = encode_server_name(name);
            assert_ne!(encoded, name, "the name must not travel in clear");
            assert_eq!(decode_server_name(&encoded).as_deref(), Some(name));
        }
    }

    #[test]
    fn test_decode_server_name_rejects_a_bad_checksum() {
        let mut encoded = encode_server_name("example.com");
        // Corrupt a byte of the inner payload; the CRC must catch it.
        let bad = if encoded.ends_with('A') { 'B' } else { 'A' };
        encoded.pop();
        encoded.push(bad);
        assert_eq!(
            decode_server_name(&encoded),
            None,
            "a corrupted name must be refused, not followed"
        );
    }

    #[test]
    fn test_decode_server_name_rejects_short_input() {
        assert_eq!(decode_server_name(""), None);
        assert_eq!(decode_server_name("AAA"), None);
    }

    /// Builds a ClientHello record naming `host` in its SNI extension.
    fn client_hello_for(host: &str) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0x00); // no session id
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x00, 0x2f]);
        hello.push(0x01);
        hello.push(0x00);

        let body = sni_body(host);
        let mut exts = Vec::new();
        exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&(body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&body);
        hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hello.extend_from_slice(&exts);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn test_client_rewrite_hides_the_real_name_behind_the_decoy() {
        let record = client_hello_for("secret.example");
        let (rewritten, host) = rewrite_client_hello(&record, "decoy.example", true).unwrap();

        assert_eq!(host, "decoy.example");
        // The visible SNI is now the decoy, and the real name is not on the
        // wire in clear anywhere in the record.
        assert_eq!(extract_sni(&rewritten).as_deref(), Some("decoy.example"));
        assert!(
            !rewritten
                .windows(b"secret.example".len())
                .any(|w| w == b"secret.example"),
            "the real name must not appear in plaintext"
        );
    }

    #[test]
    fn test_server_rewrite_recovers_the_real_name() {
        let record = client_hello_for("secret.example");
        let (from_client, _) = rewrite_client_hello(&record, "decoy.example", true).unwrap();

        // The server side strips the private extension and restores the SNI.
        let (to_origin, host) = rewrite_client_hello(&from_client, "", false).unwrap();
        assert_eq!(host, "secret.example");
        assert_eq!(extract_sni(&to_origin).as_deref(), Some("secret.example"));

        // The private extension must not be forwarded to the origin.
        let hello = &to_origin[5..];
        let (start, end) = extensions_span(hello).unwrap();
        let exts = parse_extensions(&hello[start..end]).unwrap();
        assert!(
            !exts.iter().any(|(t, _)| *t == EXT_GOST_HOST),
            "the private extension must be removed before the origin sees it"
        );
    }

    #[test]
    fn test_server_rewrite_without_the_extension_uses_the_sni() {
        // A plain client that knows nothing about gost still routes.
        let record = client_hello_for("plain.example");
        let (_, host) = rewrite_client_hello(&record, "", false).unwrap();
        assert_eq!(host, "plain.example");
    }
}
