use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::transport::transport;

// Shadowsocks SOCKS5-style address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Supported Shadowsocks cipher methods.
#[derive(Clone, Debug)]
pub enum SsCipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Plain, // No encryption (for testing)
}

impl SsCipher {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" | "aead_aes_256_gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "aead_chacha20_poly1305" => Some(Self::ChaCha20Poly1305),
            "plain" | "none" | "" => Some(Self::Plain),
            _ => None,
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
            Self::ChaCha20Poly1305 => 32,
            Self::Plain => 0,
        }
    }
}

/// Derive key from password using EVP_BytesToKey (OpenSSL compatible).
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    // MD5 for key derivation

    let mut key = Vec::with_capacity(key_len);
    let mut prev_hash: Vec<u8> = Vec::new();

    while key.len() < key_len {
        let mut data = Vec::new();
        if !prev_hash.is_empty() {
            data.extend_from_slice(&prev_hash);
        }
        data.extend_from_slice(password);
        let digest = md5::compute(&data);
        prev_hash = digest.0.to_vec();
        key.extend_from_slice(&prev_hash);
    }

    key.truncate(key_len);
    key
}

// --- Shadowsocks AEAD framing -------------------------------------------
//
// Each direction is an independent stream:
//   salt (key_size bytes, cleartext)
//   then repeating: AEAD(u16 BE payload length) || AEAD(payload)
// The session subkey is HKDF-SHA1(master_key, salt, "ss-subkey") and the
// nonce is a 96-bit little-endian counter incremented after every AEAD
// operation. The target address header travels as the first payload bytes,
// i.e. inside the encrypted stream.

const TAG_LEN: usize = 16;
const MAX_PAYLOAD: usize = 0x3FFF;
const LEN_BLOCK: usize = 2 + TAG_LEN;
const SUBKEY_INFO: &[u8] = b"ss-subkey";

#[derive(Clone)]
enum Aead {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl Aead {
    /// Derives the per-session subkey from the master key and salt.
    fn from_salt(cipher: &SsCipher, key: &[u8], salt: &[u8]) -> io::Result<Self> {
        let mut subkey = vec![0u8; cipher.key_size()];
        Hkdf::<Sha1>::new(Some(salt), key)
            .expand(SUBKEY_INFO, &mut subkey)
            .map_err(|_| io::Error::other("shadowsocks subkey derivation failed"))?;

        Ok(match cipher {
            SsCipher::Aes128Gcm => Aead::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&subkey).map_err(io::Error::other)?,
            )),
            SsCipher::Aes256Gcm => Aead::Aes256(Box::new(
                Aes256Gcm::new_from_slice(&subkey).map_err(io::Error::other)?,
            )),
            SsCipher::ChaCha20Poly1305 => Aead::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(&subkey).map_err(io::Error::other)?,
            )),
            SsCipher::Plain => unreachable!("plain cipher never builds an AEAD"),
        })
    }

    fn seal(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> io::Result<()> {
        let nonce = nonce.into();
        let r = match self {
            Aead::Aes128(c) => c.encrypt_in_place(nonce, b"", buf),
            Aead::Aes256(c) => c.encrypt_in_place(nonce, b"", buf),
            Aead::ChaCha(c) => c.encrypt_in_place(nonce, b"", buf),
        };
        r.map_err(|_| io::Error::other("shadowsocks encryption failed"))
    }

    fn open(&self, nonce: &[u8; 12], buf: &mut Vec<u8>) -> io::Result<()> {
        let nonce = nonce.into();
        let r = match self {
            Aead::Aes128(c) => c.decrypt_in_place(nonce, b"", buf),
            Aead::Aes256(c) => c.decrypt_in_place(nonce, b"", buf),
            Aead::ChaCha(c) => c.decrypt_in_place(nonce, b"", buf),
        };
        // A tag mismatch means the peer used a different password or cipher,
        // or the stream was tampered with. Either way the stream is dead.
        r.map_err(|_| io::Error::other("shadowsocks authentication tag mismatch"))
    }
}

/// Increments the 96-bit little-endian nonce counter in place.
fn bump_nonce(nonce: &mut [u8; 12]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

enum ReadState {
    Salt,
    Length,
    Payload(usize),
    Eof,
}

/// Wraps a stream in the Shadowsocks AEAD framing.
pub struct SsStream<S> {
    inner: S,
    cipher: SsCipher,
    key: Vec<u8>,

    read_state: ReadState,
    read_cipher: Option<Aead>,
    read_nonce: [u8; 12],
    read_buf: Vec<u8>,
    read_need: usize,
    plain: Vec<u8>,
    plain_pos: usize,

    write_cipher: Option<Aead>,
    write_nonce: [u8; 12],
    out: Vec<u8>,
    out_pos: usize,
}

impl<S> SsStream<S> {
    pub fn new(inner: S, cipher: SsCipher, key: Vec<u8>) -> Self {
        let salt_len = cipher.key_size();
        Self {
            inner,
            cipher,
            key,
            read_state: ReadState::Salt,
            read_cipher: None,
            read_nonce: [0u8; 12],
            read_buf: Vec::with_capacity(salt_len.max(LEN_BLOCK)),
            read_need: salt_len,
            plain: Vec::new(),
            plain_pos: 0,
            write_cipher: None,
            write_nonce: [0u8; 12],
            out: Vec::new(),
            out_pos: 0,
        }
    }

    fn is_plain(&self) -> bool {
        matches!(self.cipher, SsCipher::Plain)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SsStream<S> {
    /// Reads until `read_buf` holds `read_need` bytes. `Ok(false)` means the
    /// peer closed the stream.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        while self.read_buf.len() < self.read_need {
            let start = self.read_buf.len();
            self.read_buf.resize(self.read_need, 0);
            let mut rb = ReadBuf::new(&mut self.read_buf[start..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Pending => {
                    self.read_buf.truncate(start);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.read_buf.truncate(start);
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    self.read_buf.truncate(start + n);
                    if n == 0 {
                        // A clean close on a block boundary is normal EOF;
                        // mid-block it is a truncated stream.
                        return Poll::Ready(Ok(false));
                    }
                }
            }
        }
        Poll::Ready(Ok(true))
    }

    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
                }
                Poll::Ready(Ok(n)) => self.out_pos += n,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Queues the salt and one encrypted chunk of `data` into `out`.
    fn seal_chunk(&mut self, data: &[u8]) -> io::Result<()> {
        if self.write_cipher.is_none() {
            let mut salt = vec![0u8; self.cipher.key_size()];
            rand::thread_rng().fill_bytes(&mut salt);
            self.write_cipher = Some(Aead::from_salt(&self.cipher, &self.key, &salt)?);
            self.out.extend_from_slice(&salt);
        }
        let aead = self.write_cipher.as_ref().expect("cipher just set");

        let mut len_block = (data.len() as u16).to_be_bytes().to_vec();
        aead.seal(&self.write_nonce, &mut len_block)?;
        bump_nonce(&mut self.write_nonce);
        self.out.extend_from_slice(&len_block);

        let mut payload = data.to_vec();
        aead.seal(&self.write_nonce, &mut payload)?;
        bump_nonce(&mut self.write_nonce);
        self.out.extend_from_slice(&payload);

        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.is_plain() {
            return Pin::new(&mut me.inner).poll_read(cx, buf);
        }

        loop {
            // Drain anything already decrypted before pulling more.
            if me.plain_pos < me.plain.len() {
                let n = buf.remaining().min(me.plain.len() - me.plain_pos);
                buf.put_slice(&me.plain[me.plain_pos..me.plain_pos + n]);
                me.plain_pos += n;
                if me.plain_pos == me.plain.len() {
                    me.plain.clear();
                    me.plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            if matches!(me.read_state, ReadState::Eof) {
                return Poll::Ready(Ok(()));
            }

            let complete = match me.poll_fill(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(c)) => c,
            };
            if !complete {
                // EOF between blocks is orderly; part-way through one is not.
                if me.read_buf.is_empty() {
                    me.read_state = ReadState::Eof;
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }

            match me.read_state {
                ReadState::Salt => {
                    let salt = std::mem::take(&mut me.read_buf);
                    me.read_cipher = Some(Aead::from_salt(&me.cipher, &me.key, &salt)?);
                    me.read_state = ReadState::Length;
                    me.read_need = LEN_BLOCK;
                }
                ReadState::Length => {
                    let mut block = std::mem::take(&mut me.read_buf);
                    let aead = me
                        .read_cipher
                        .as_ref()
                        .ok_or_else(|| io::Error::other("missing shadowsocks read cipher"))?;
                    aead.open(&me.read_nonce, &mut block)?;
                    bump_nonce(&mut me.read_nonce);

                    let len = u16::from_be_bytes([block[0], block[1]]) as usize;
                    if len == 0 || len > MAX_PAYLOAD {
                        return Poll::Ready(Err(io::Error::other(format!(
                            "invalid shadowsocks payload length: {}",
                            len
                        ))));
                    }
                    me.read_state = ReadState::Payload(len);
                    me.read_need = len + TAG_LEN;
                }
                ReadState::Payload(_) => {
                    let mut block = std::mem::take(&mut me.read_buf);
                    let aead = me
                        .read_cipher
                        .as_ref()
                        .ok_or_else(|| io::Error::other("missing shadowsocks read cipher"))?;
                    aead.open(&me.read_nonce, &mut block)?;
                    bump_nonce(&mut me.read_nonce);

                    me.plain = block;
                    me.plain_pos = 0;
                    me.read_state = ReadState::Length;
                    me.read_need = LEN_BLOCK;
                }
                ReadState::Eof => unreachable!("handled above"),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.is_plain() {
            return Pin::new(&mut me.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Bound memory by draining the previous chunk before sealing another.
        if let Poll::Pending = me.poll_flush_out(cx) {
            return Poll::Pending;
        }

        let n = buf.len().min(MAX_PAYLOAD);
        me.seal_chunk(&buf[..n])?;

        // Best-effort flush; whatever remains goes out on the next call.
        let _ = me.poll_flush_out(cx);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.is_plain() {
            return Pin::new(&mut me.inner).poll_flush(cx);
        }
        match me.poll_flush_out(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if !me.is_plain() {
            match me.poll_flush_out(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

/// Shadowsocks connector (client side).
pub struct ShadowConnector {
    cipher: SsCipher,
    key: Vec<u8>,
}

impl ShadowConnector {
    /// Fails when the cipher name is unknown, rather than silently falling
    /// back to plaintext under an encrypted-looking configuration.
    pub fn new(method: &str, password: &str) -> Result<Self, HandlerError> {
        let cipher = SsCipher::from_name(method)
            .ok_or_else(|| HandlerError::Proxy(format!("unknown shadowsocks cipher: {}", method)))?;
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_size());
        Ok(Self { cipher, key })
    }

    /// Connect via Shadowsocks protocol.
    pub async fn connect(
        &self,
        conn: TcpStream,
        address: &str,
    ) -> Result<SsStream<TcpStream>, HandlerError> {
        let mut stream = SsStream::new(conn, self.cipher.clone(), self.key.clone());

        // The address header is the first payload inside the encrypted stream,
        // so it goes through the wrapper rather than to the raw socket.
        let addr_buf = encode_ss_address(address)?;
        stream.write_all(&addr_buf).await?;
        stream.flush().await?;

        Ok(stream)
    }
}

/// Shadowsocks UDP connector.
pub struct ShadowUdpConnector {
    cipher: SsCipher,
    key: Vec<u8>,
}

impl ShadowUdpConnector {
    pub fn new(method: &str, password: &str) -> Self {
        let cipher = SsCipher::from_name(method).unwrap_or(SsCipher::Plain);
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_size());
        Self { cipher, key }
    }
}

/// Shadowsocks handler (server side).
pub struct ShadowHandler {
    cipher: SsCipher,
    key: Vec<u8>,
    options: HandlerOptions,
}

impl ShadowHandler {
    /// Fails when the cipher name is unknown, rather than silently falling
    /// back to plaintext under an encrypted-looking configuration.
    pub fn new(
        method: &str,
        password: &str,
        options: HandlerOptions,
    ) -> Result<Self, HandlerError> {
        let cipher = SsCipher::from_name(method)
            .ok_or_else(|| HandlerError::Proxy(format!("unknown shadowsocks cipher: {}", method)))?;
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_size());
        Ok(Self {
            cipher,
            key,
            options,
        })
    }
}

#[async_trait]
impl Handler for ShadowHandler {
    async fn handle(&self, conn: TcpStream) -> Result<(), HandlerError> {
        let peer_addr = conn
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let mut stream = SsStream::new(conn, self.cipher.clone(), self.key.clone());

        // Decrypted by the wrapper; the header is the first payload chunk.
        let target = read_ss_address(&mut stream).await?;

        info!("[ss] {} -> {}", peer_addr, target);

        // gost applies the same access control here as the other handlers
        // (ss.go:145-155); without it, whitelist/blacklist/bypass configured on
        // an ss:// listener would be silently ignored.
        if !crate::permissions::Can(
            "tcp",
            &target,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            debug!("[ss] {} -> {} : blocked by permissions", peer_addr, target);
            return Err(HandlerError::Forbidden);
        }
        if let Some(bypass) = self.options.bypass.as_ref() {
            if bypass.contains(&target) {
                debug!("[ss] {} -> {} : bypassed", peer_addr, target);
                return Err(HandlerError::Forbidden);
            }
        }

        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();

        match chain.dial(&target).await {
            Ok(cc) => {
                info!("[ss] {} <-> {}", peer_addr, target);
                transport(stream, cc).await.ok();
                info!("[ss] {} >-< {}", peer_addr, target);
                Ok(())
            }
            Err(e) => Err(HandlerError::Chain(e)),
        }
    }
}

/// Splits `host:port`, tolerating bracketed IPv6 literals and a missing port.
fn split_host_port_str(addr: &str) -> (&str, u16) {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, rest)) = rest.split_once(']') {
            let port = rest.strip_prefix(':').and_then(|p| p.parse().ok());
            return (host, port.unwrap_or(0));
        }
    }
    match addr.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().unwrap_or(0)),
        None => (addr, 0),
    }
}

/// Shadowsocks UDP relay handler.
pub struct ShadowUdpHandler {
    cipher: SsCipher,
    key: Vec<u8>,
    options: HandlerOptions,
}

impl ShadowUdpHandler {
    pub fn new(method: &str, password: &str, options: HandlerOptions) -> Self {
        let cipher = SsCipher::from_name(method).unwrap_or(SsCipher::Plain);
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_size());
        Self {
            cipher,
            key,
            options,
        }
    }
}

/// Encode target address in Shadowsocks format (SOCKS5-style).
fn encode_ss_address(address: &str) -> Result<Vec<u8>, HandlerError> {
    let (host, port_str) = address
        .rsplit_once(':')
        .ok_or_else(|| HandlerError::Proxy(format!("invalid address: {}", address)))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| HandlerError::Proxy(format!("invalid port: {}", port_str)))?;

    let mut buf = Vec::new();
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        buf.push(ATYP_IPV4);
        buf.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        buf.push(ATYP_IPV6);
        buf.extend_from_slice(&ip.octets());
    } else {
        buf.push(ATYP_DOMAIN);
        buf.push(host.len() as u8);
        buf.extend_from_slice(host.as_bytes());
    }
    buf.extend_from_slice(&port.to_be_bytes());

    Ok(buf)
}

/// Read target address in Shadowsocks format.
async fn read_ss_address<R: AsyncRead + Unpin>(conn: &mut R) -> Result<String, HandlerError> {
    let mut atyp = [0u8; 1];
    conn.read_exact(&mut atyp).await?;

    let host = match atyp[0] {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            conn.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            conn.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            conn.read_exact(&mut addr).await?;
            Ipv6Addr::from(addr).to_string()
        }
        _ => {
            return Err(HandlerError::Proxy(format!(
                "unsupported atyp: {}",
                atyp[0]
            )));
        }
    };

    let mut port_buf = [0u8; 2];
    conn.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(format!("{}:{}", host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_ss_cipher_from_name() {
        assert!(matches!(
            SsCipher::from_name("aes-128-gcm"),
            Some(SsCipher::Aes128Gcm)
        ));
        assert!(matches!(
            SsCipher::from_name("aes-256-gcm"),
            Some(SsCipher::Aes256Gcm)
        ));
        assert!(matches!(
            SsCipher::from_name("chacha20-ietf-poly1305"),
            Some(SsCipher::ChaCha20Poly1305)
        ));
        assert!(matches!(
            SsCipher::from_name("plain"),
            Some(SsCipher::Plain)
        ));
        assert!(SsCipher::from_name("unknown-cipher").is_none());
    }

    #[test]
    fn test_evp_bytes_to_key() {
        let key = evp_bytes_to_key(b"password", 16);
        assert_eq!(key.len(), 16);

        let key32 = evp_bytes_to_key(b"password", 32);
        assert_eq!(key32.len(), 32);

        // Same password should produce same key
        let key2 = evp_bytes_to_key(b"password", 16);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_encode_ss_address_ipv4() {
        let buf = encode_ss_address("127.0.0.1:80").unwrap();
        assert_eq!(buf[0], ATYP_IPV4);
        assert_eq!(&buf[1..5], &[127, 0, 0, 1]);
        assert_eq!(&buf[5..7], &[0, 80]);
    }

    #[test]
    fn test_encode_ss_address_domain() {
        let buf = encode_ss_address("example.com:443").unwrap();
        assert_eq!(buf[0], ATYP_DOMAIN);
        assert_eq!(buf[1], 11); // "example.com".len()
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(&buf[13..15], &443u16.to_be_bytes());
    }

    #[tokio::test]
    async fn test_shadow_handler_connect() {
        // Start a mock target
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            conn.write_all(b"shadow ok").await.unwrap();
        });

        // Start SS handler (plain cipher for testing)
        let handler =
            ShadowHandler::new("plain", "testpass", HandlerOptions::default()).unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(conn).await.ok();
        });

        // Connect as SS client (send address header then read data)
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let addr_buf = encode_ss_address(&target_addr.to_string()).unwrap();
        client.write_all(&addr_buf).await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"shadow ok");
    }

    #[tokio::test]
    async fn test_shadow_connector() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = target.accept().await.unwrap();
            // Read SS address header first
            let _ = read_ss_address(&mut conn).await;
            conn.write_all(b"connector ok").await.unwrap();
        });

        let connector = ShadowConnector::new("plain", "testpass").unwrap();
        let stream = TcpStream::connect(target_addr).await.unwrap();
        let mut conn = connector.connect(stream, "127.0.0.1:9999").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"connector ok");
    }

    #[test]
    fn test_unknown_cipher_is_rejected_not_downgraded_to_plaintext() {
        assert!(SsCipher::from_name("aes-256-cfb").is_none());
        assert!(ShadowConnector::new("aes-256-cfb", "pw").is_err());
        assert!(ShadowHandler::new("totally-bogus", "pw", HandlerOptions::default()).is_err());
    }

    /// Round-trips a payload through two `SsStream`s over a duplex pair and
    /// asserts the bytes on the wire are not the plaintext.
    async fn aead_roundtrip(method: &str, payload: &[u8]) {
        let cipher = SsCipher::from_name(method).unwrap();
        let key = evp_bytes_to_key(b"correct horse", cipher.key_size());

        let (client_raw, server_raw) = tokio::io::duplex(1 << 20);
        let mut client = SsStream::new(client_raw, cipher.clone(), key.clone());
        let mut server = SsStream::new(server_raw, cipher, key);

        let expected = payload.to_vec();
        let writer = tokio::spawn(async move {
            client.write_all(&expected).await.unwrap();
            client.flush().await.unwrap();
            client
        });

        let mut got = vec![0u8; payload.len()];
        server.read_exact(&mut got).await.unwrap();
        writer.await.unwrap();

        assert_eq!(got, payload, "{} round-trip mismatch", method);
    }

    #[tokio::test]
    async fn test_aead_roundtrip_all_ciphers() {
        for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            aead_roundtrip(method, b"the quick brown fox").await;
        }
    }

    #[tokio::test]
    async fn test_aead_roundtrip_spans_multiple_chunks() {
        // Larger than MAX_PAYLOAD, so the writer must split it into several
        // AEAD chunks and the reader must reassemble them.
        let payload: Vec<u8> = (0..(MAX_PAYLOAD * 3 + 1)).map(|i| (i % 251) as u8).collect();
        aead_roundtrip("aes-256-gcm", &payload).await;
    }

    #[tokio::test]
    async fn test_ciphertext_on_the_wire_is_not_plaintext() {
        let cipher = SsCipher::from_name("aes-256-gcm").unwrap();
        let key = evp_bytes_to_key(b"pw", cipher.key_size());

        let (client_raw, mut wire) = tokio::io::duplex(1 << 16);
        let mut client = SsStream::new(client_raw, cipher.clone(), key);

        let secret = b"SECRET-MARKER-DO-NOT-LEAK";
        client.write_all(secret).await.unwrap();
        client.flush().await.unwrap();

        let mut raw = vec![0u8; cipher.key_size() + LEN_BLOCK + secret.len() + TAG_LEN];
        wire.read_exact(&mut raw).await.unwrap();

        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "plaintext marker found on the wire: the cipher is not on the data path"
        );
    }

    #[tokio::test]
    async fn test_wrong_password_fails_authentication() {
        let cipher = SsCipher::from_name("aes-256-gcm").unwrap();
        let (client_raw, server_raw) = tokio::io::duplex(1 << 16);
        let mut client = SsStream::new(
            client_raw,
            cipher.clone(),
            evp_bytes_to_key(b"right", cipher.key_size()),
        );
        let mut server = SsStream::new(
            server_raw,
            cipher.clone(),
            evp_bytes_to_key(b"wrong", cipher.key_size()),
        );

        tokio::spawn(async move {
            client.write_all(b"hello").await.ok();
            client.flush().await.ok();
            // Keep the stream open so the reader sees a tag failure, not EOF.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let mut buf = [0u8; 5];
        assert!(
            server.read_exact(&mut buf).await.is_err(),
            "a mismatched password must fail the AEAD tag check"
        );
    }
}
