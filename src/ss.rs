use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info};

use crate::conn::ProxyConn;
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
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
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
        let cipher = SsCipher::from_name(method).ok_or_else(|| {
            HandlerError::Proxy(format!("unknown shadowsocks cipher: {}", method))
        })?;
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_size());
        Ok(Self { cipher, key })
    }

    /// Connect via Shadowsocks protocol.
    pub async fn connect<S>(&self, conn: S, address: &str) -> Result<SsStream<S>, HandlerError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let mut stream = SsStream::new(conn, self.cipher.clone(), self.key.clone());

        // The address header is the first payload inside the encrypted stream,
        // so it goes through the wrapper rather than to the raw socket.
        let addr_buf = encode_ss_address(address)?;
        stream.write_all(&addr_buf).await?;
        stream.flush().await?;

        Ok(stream)
    }
}

// --- Shadowsocks UDP datagram framing ------------------------------------
//
// UDP does NOT reuse the TCP framing. Every datagram stands entirely alone:
//
//     salt (key_size bytes, cleartext) || AEAD(subkey, socks5_address || payload)
//
// The subkey is derived exactly as for TCP -- HKDF-SHA1(master_key, salt,
// "ss-subkey") -- but the nonce is ALL ZEROES for every datagram. There is no
// counter, because each datagram carries its own fresh random salt, and there
// is no 2-byte length block either: the datagram boundary *is* the frame.
//
// Verified against the implementation gost actually links: gost builds its
// cipher with `core.PickCipher` (ss.go:603) and wraps the socket with
// `cipher.PacketConn` (ss.go:583, ss.go:317), which is go-shadowsocks2's
// `shadowaead.NewPacketConn`. Its `Pack`/`Unpack` (shadowaead/packet.go, v0.1.5
// -- the version pinned in gost's go.mod:23) seal and open with
// `_zerononce[:aead.NonceSize()]`, where `var _zerononce [128]byte` is a
// read-only all-zero array, over `pkt[saltSize:]` with no length prefix.
// `SaltSize()` is `max(KeySize, 16)`, which equals the key size for all three
// AEAD ciphers supported here (16 / 32 / 32).

/// The nonce for every shadowsocks UDP datagram: all zeroes.
const UDP_NONCE: [u8; 12] = [0u8; 12];

/// Working buffer for one datagram. A UDP payload cannot exceed 65507 bytes,
/// and `udp.rs` reads with the same bound, so a whole datagram always fits in
/// a single read and is never split across two.
const UDP_MAX_DATAGRAM: usize = 64 * 1024;

/// Encrypts one shadowsocks UDP datagram with a fresh random salt.
///
/// `plain` is the full inner frame, i.e. the SOCKS5-style address followed by
/// the payload.
fn seal_udp_datagram(cipher: &SsCipher, key: &[u8], plain: &[u8]) -> io::Result<Vec<u8>> {
    if matches!(cipher, SsCipher::Plain) {
        return Ok(plain.to_vec());
    }

    let salt_len = cipher.key_size();
    let mut salt = vec![0u8; salt_len];
    rand::thread_rng().fill_bytes(&mut salt);
    let aead = Aead::from_salt(cipher, key, &salt)?;

    let mut body = plain.to_vec();
    aead.seal(&UDP_NONCE, &mut body)?;

    let mut out = Vec::with_capacity(salt_len + body.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decrypts one shadowsocks UDP datagram.
///
/// Fails closed: a datagram shorter than `salt || tag`, a tampered salt, a
/// tampered body and a wrong password all produce an error. Nothing is ever
/// returned unauthenticated.
fn open_udp_datagram(cipher: &SsCipher, key: &[u8], packet: &[u8]) -> io::Result<Vec<u8>> {
    if matches!(cipher, SsCipher::Plain) {
        return Ok(packet.to_vec());
    }

    let salt_len = cipher.key_size();
    // go-shadowsocks2's ErrShortPacket: anything below salt + tag cannot even
    // hold an empty authenticated payload.
    if packet.len() < salt_len + TAG_LEN {
        return Err(io::Error::other(format!(
            "short shadowsocks UDP datagram: {} bytes, minimum {}",
            packet.len(),
            salt_len + TAG_LEN
        )));
    }

    let (salt, body) = packet.split_at(salt_len);
    let aead = Aead::from_salt(cipher, key, salt)?;
    let mut buf = body.to_vec();
    aead.open(&UDP_NONCE, &mut buf)?;
    Ok(buf)
}

/// Appends a `SocketAddr` in the SOCKS5 address encoding.
///
/// Going through the `SocketAddr` rather than its string form matters for IPv6:
/// `Display` brackets the host (`[::1]:53`), and a bracketed literal does not
/// parse as an `Ipv6Addr`, so a string round-trip would encode it as a *domain*
/// that no upstream can resolve.
fn encode_ss_socket_addr(addr: &SocketAddr, buf: &mut Vec<u8>) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

/// Encodes a target address, accepting both literal endpoints (including the
/// bracketed IPv6 form) and `domain:port`.
fn encode_ss_target(address: &str) -> Result<Vec<u8>, HandlerError> {
    if let Ok(sa) = address.parse::<SocketAddr>() {
        let mut buf = Vec::with_capacity(19);
        encode_ss_socket_addr(&sa, &mut buf);
        return Ok(buf);
    }
    encode_ss_address(address)
}

/// Parses the SOCKS5-style address at the head of a decrypted datagram,
/// returning it as `host:port` together with the offset of the payload that
/// follows it.
///
/// Fails closed on every malformed input: an empty frame, an unknown address
/// type, a truncated address or port, an empty or non-UTF-8 domain. The caller
/// must never fall back to treating the bytes as payload.
fn parse_ss_address(buf: &[u8]) -> Result<(String, usize), HandlerError> {
    fn bad(what: &str) -> HandlerError {
        HandlerError::Proxy(format!("malformed shadowsocks address: {}", what))
    }

    enum Host {
        Ip(IpAddr),
        Domain(String),
    }

    let atyp = *buf.first().ok_or_else(|| bad("empty datagram"))?;
    let (host, off) = match atyp {
        ATYP_IPV4 => {
            let raw: [u8; 4] = buf
                .get(1..5)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| bad("truncated IPv4 address"))?;
            (Host::Ip(IpAddr::V4(Ipv4Addr::from(raw))), 5)
        }
        ATYP_IPV6 => {
            let raw: [u8; 16] = buf
                .get(1..17)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| bad("truncated IPv6 address"))?;
            (Host::Ip(IpAddr::V6(Ipv6Addr::from(raw))), 17)
        }
        ATYP_DOMAIN => {
            let len = *buf.get(1).ok_or_else(|| bad("truncated domain length"))? as usize;
            if len == 0 {
                return Err(bad("empty domain"));
            }
            let raw = buf.get(2..2 + len).ok_or_else(|| bad("truncated domain"))?;
            let name = std::str::from_utf8(raw).map_err(|_| bad("non-UTF-8 domain"))?;
            // A peer may send an IP literal under the domain type. Normalising
            // it here keeps IP and CIDR rules effective whichever type was
            // used, and produces the bracketed form for IPv6 that
            // `split_host_port` and the bypass matchers expect.
            match name.parse::<IpAddr>() {
                Ok(ip) => (Host::Ip(ip), 2 + len),
                Err(_) => (Host::Domain(name.to_string()), 2 + len),
            }
        }
        other => return Err(bad(&format!("unsupported atyp {}", other))),
    };

    let port_raw: [u8; 2] = buf
        .get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| bad("truncated port"))?;
    let port = u16::from_be_bytes(port_raw);

    let address = match host {
        Host::Ip(ip) => SocketAddr::new(ip, port).to_string(),
        Host::Domain(name) => format!("{}:{}", name, port),
    };
    Ok((address, off + 2))
}

/// Resolves a target address for the UDP relay, accepting literal endpoints
/// (including `[::1]:53`) without touching the resolver.
async fn resolve_udp_addr(address: &str) -> Option<SocketAddr> {
    if let Ok(sa) = address.parse::<SocketAddr>() {
        return Some(sa);
    }
    let (host, port) = crate::permissions::split_host_port(address).ok()?;
    let port: u16 = port.parse().ok()?;
    tokio::net::lookup_host((host, port)).await.ok()?.next()
}

/// Shadowsocks UDP connector (client side).
///
/// gost's `shadowUDPConnector` (ss.go:206-269) wraps a packet connection with
/// the cipher and hands back a `shadowUDPPacketConn` (ss.go:510-572) that
/// prefixes every outgoing datagram with the target address and strips the
/// origin address off every incoming one. This is the same thing, split into a
/// transport-agnostic codec plus a wrapper for stream-shaped connections.
pub struct ShadowUdpConnector {
    cipher: SsCipher,
    key: Vec<u8>,
}

impl ShadowUdpConnector {
    /// Fails when the cipher name is unknown, rather than silently falling back
    /// to plaintext under an encrypted-looking configuration -- the same
    /// fail-closed rule the TCP `ShadowConnector` follows.
    pub fn new(method: &str, password: &str) -> Result<Self, HandlerError> {
        let cipher = SsCipher::from_name(method).ok_or_else(|| {
            HandlerError::Proxy(format!("unknown shadowsocks cipher: {}", method))
        })?;
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_size());
        Ok(Self { cipher, key })
    }

    /// Builds the wire form of one datagram addressed to `target`.
    pub fn encode_to(&self, target: &str, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
        let mut plain = encode_ss_target(target)?;
        plain.extend_from_slice(payload);
        Ok(seal_udp_datagram(&self.cipher, &self.key, &plain)?)
    }

    /// Splits a received datagram into the origin address and the payload.
    pub fn decode_from(&self, packet: &[u8]) -> Result<(String, Vec<u8>), HandlerError> {
        let plain = open_udp_datagram(&self.cipher, &self.key, packet)?;
        let (address, off) = parse_ss_address(&plain)?;
        Ok((address, plain[off..].to_vec()))
    }

    /// Wraps a datagram-shaped connection to the shadowsocks server, defaulting
    /// every `send` to `address`.
    pub fn connect<S>(
        &self,
        conn: S,
        address: &str,
    ) -> Result<ShadowUdpPacketConn<S>, HandlerError> {
        // Reject a bad target now instead of on the first datagram.
        encode_ss_target(address)?;
        Ok(ShadowUdpPacketConn {
            conn,
            cipher: self.cipher.clone(),
            key: self.key.clone(),
            target: address.to_string(),
        })
    }
}

/// A shadowsocks UDP association seen from the client, gost's
/// `shadowUDPPacketConn` (ss.go:510-572).
pub struct ShadowUdpPacketConn<S> {
    conn: S,
    cipher: SsCipher,
    key: Vec<u8>,
    target: String,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> ShadowUdpPacketConn<S> {
    /// Sends one datagram to the association's default target.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), HandlerError> {
        let target = self.target.clone();
        self.send_to(&target, payload).await
    }

    /// Sends one datagram to an arbitrary target, gost's `WriteTo`.
    pub async fn send_to(&mut self, target: &str, payload: &[u8]) -> Result<(), HandlerError> {
        let mut plain = encode_ss_target(target)?;
        plain.extend_from_slice(payload);
        let packet = seal_udp_datagram(&self.cipher, &self.key, &plain)?;
        self.conn.write_all(&packet).await?;
        self.conn.flush().await?;
        Ok(())
    }

    /// Receives one datagram, returning the origin address and the payload,
    /// gost's `ReadFrom`.
    pub async fn recv(&mut self) -> Result<(String, Vec<u8>), HandlerError> {
        let mut buf = vec![0u8; UDP_MAX_DATAGRAM];
        let n = self.conn.read(&mut buf).await?;
        if n == 0 {
            return Err(HandlerError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        let plain = open_udp_datagram(&self.cipher, &self.key, &buf[..n])?;
        let (address, off) = parse_ss_address(&plain)?;
        Ok((address, plain[off..].to_vec()))
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
        let cipher = SsCipher::from_name(method).ok_or_else(|| {
            HandlerError::Proxy(format!("unknown shadowsocks cipher: {}", method))
        })?;
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
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();

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

/// Shadowsocks UDP relay handler, gost's `shadowUDPHandler` (ss.go:271-489).
///
/// One instance of [`handle`](Handler::handle) serves one association. The
/// [`ProxyConn`] it is given comes from [`UdpServer`](crate::udp::UdpServer),
/// so its reads and writes are datagram-shaped: one read yields at most one
/// datagram, one write sends exactly one. The association therefore lives
/// exactly as long as that connection -- when the client goes idle, the
/// listener shuts down, or the peer is closed, the read reports EOF, this
/// function returns, and the target-facing socket is dropped with it.
pub struct ShadowUdpHandler {
    cipher: SsCipher,
    key: Vec<u8>,
    options: HandlerOptions,
}

impl ShadowUdpHandler {
    /// Fails when the cipher name is unknown, rather than silently falling back
    /// to plaintext under an encrypted-looking configuration -- matching
    /// [`ShadowHandler::new`].
    pub fn new(
        method: &str,
        password: &str,
        options: HandlerOptions,
    ) -> Result<Self, HandlerError> {
        let cipher = SsCipher::from_name(method).ok_or_else(|| {
            HandlerError::Proxy(format!("unknown shadowsocks cipher: {}", method))
        })?;
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_size());
        Ok(Self {
            cipher,
            key,
            options,
        })
    }

    /// Whether one datagram may be forwarded to `dst` ("host:port").
    ///
    /// gost's `transportPacket` -- the branch an `ssu://` listener actually
    /// takes, because its `udpServerConn` is a `net.PacketConn` (udp.go:195) --
    /// applies no filtering at all; only the `transportUDP` fallback checks the
    /// bypass, at ss.go:437 outbound and ss.go:465 inbound, and neither branch
    /// ever calls `Can`. Leaving it that way would mean `?whitelist=`,
    /// `?blacklist=` and `?bypass=` on an `ssu://` listener were silently
    /// ignored, so the check the TCP handler performs once per connection
    /// (ss.go:145-155) is performed here once per datagram instead -- a
    /// datagram relay has no other point at which to enforce it.
    fn udp_dst_allowed(&self, dst: &str) -> bool {
        if !crate::permissions::Can(
            "udp",
            dst,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            debug!("[ssu] unauthorized to send to {}", dst);
            return false;
        }
        if let Some(bypass) = self.options.bypass.as_ref() {
            if bypass.contains(dst) {
                debug!("[ssu] [bypass] write to {}", dst);
                return false;
            }
        }
        true
    }

    /// Pumps datagrams both ways until the association ends.
    ///
    /// `conn` faces the client and speaks the encrypted shadowsocks datagram
    /// format; `target_sock` faces the world and speaks plain UDP.
    async fn relay(
        &self,
        conn: &mut ProxyConn,
        out: &crate::chain::UdpChannel,
        peer_addr: &str,
    ) -> Result<(), HandlerError> {
        // A datagram whose length exceeds this cannot exist on the wire, so a
        // full frame is always delivered by a single read.
        let mut cbuf = vec![0u8; UDP_MAX_DATAGRAM];
        let mut consecutive_recv_errors = 0u32;

        enum Ev {
            FromClient(io::Result<usize>),
            FromTarget(io::Result<(Vec<u8>, String, u16)>),
        }

        loop {
            // The results are hoisted out of `select!` so both futures -- and
            // the borrows they hold on `conn` and the buffers -- are dropped
            // before the datagram is inspected and relayed.
            let ev = tokio::select! {
                r = conn.read(&mut cbuf) => Ev::FromClient(r),
                r = out.recv_from() => Ev::FromTarget(r),
            };

            match ev {
                Ev::FromClient(Err(e)) => return Err(HandlerError::Io(e)),
                // EOF: the virtual connection is over (idle TTL, an explicit
                // close, or listener shutdown), and so is the association.
                Ev::FromClient(Ok(0)) => return Ok(()),
                Ev::FromClient(Ok(n)) => {
                    // Fail closed on anything that does not authenticate: an
                    // undecryptable or malformed datagram is dropped, never
                    // forwarded as-is. Only this datagram is discarded, so one
                    // spoofed or corrupted frame cannot end a working
                    // association (gost tears the whole thing down instead).
                    let plain = match open_udp_datagram(&self.cipher, &self.key, &cbuf[..n]) {
                        Ok(p) => p,
                        Err(e) => {
                            debug!("[ssu] {} : dropping datagram: {}", peer_addr, e);
                            continue;
                        }
                    };
                    let (target, off) = match parse_ss_address(&plain) {
                        Ok(v) => v,
                        Err(e) => {
                            debug!("[ssu] {} : dropping datagram: {}", peer_addr, e);
                            continue;
                        }
                    };

                    // Filtered twice, as in socks5.rs: once as written by the
                    // client so domain rules apply, and once after resolution
                    // so IP and CIDR rules apply. Checking only the name would
                    // let any domain reach a blacklisted address.
                    if !self.udp_dst_allowed(&target) {
                        continue;
                    }
                    let Some(raddr) = resolve_udp_addr(&target).await else {
                        debug!("[ssu] {} : cannot resolve {}", peer_addr, target);
                        continue;
                    };
                    let resolved = raddr.to_string();
                    if resolved != target && !self.udp_dst_allowed(&resolved) {
                        continue;
                    }

                    debug!(
                        "[ssu] {} >>> {} length: {}",
                        peer_addr,
                        target,
                        plain.len() - off
                    );
                    // One unreachable target must not end the association.
                    if let Err(e) = out
                        .send_to(&plain[off..], &raddr.ip().to_string(), raddr.port())
                        .await
                    {
                        debug!("[ssu] {} >>> {} : {}", peer_addr, target, e);
                    }
                }
                Ev::FromTarget(Err(e)) => {
                    // A UDP socket reports errors for *earlier* sends here: on
                    // Windows an ICMP port-unreachable from a dead target comes
                    // back as ConnectionReset on the next recv (see udp.rs).
                    // Killing the association for that would let any target
                    // hang up on every other one, so carry on -- but not
                    // forever, in case the socket itself has gone bad.
                    consecutive_recv_errors += 1;
                    debug!("[ssu] {} <<< recv error: {}", peer_addr, e);
                    if consecutive_recv_errors > MAX_CONSECUTIVE_RECV_ERRORS {
                        return Err(HandlerError::Io(e));
                    }
                }
                Ev::FromTarget(Ok((data, host, port))) => {
                    consecutive_recv_errors = 0;
                    let n = data.len();
                    let origin = if host.contains(':') {
                        format!("[{}]:{}", host, port)
                    } else {
                        format!("{}:{}", host, port)
                    };
                    // gost applies the bypass to the reply's source too
                    // (ss.go:465).
                    if let Some(bypass) = self.options.bypass.as_ref() {
                        if bypass.contains(&origin) {
                            debug!("[ssu] [bypass] read from {}", origin);
                            continue;
                        }
                    }

                    debug!("[ssu] {} <<< {} length: {}", peer_addr, origin, n);
                    let mut plain = encode_ss_target(&origin)?;
                    plain.extend_from_slice(&data);
                    let packet = seal_udp_datagram(&self.cipher, &self.key, &plain)?;
                    conn.write_all(&packet).await?;
                }
            }
        }
    }
}

/// How many consecutive failed receives on the target socket are tolerated
/// before the association is considered dead.
const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 64;

#[async_trait]
impl Handler for ShadowUdpHandler {
    async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();
        let local_addr = conn.local_addr_str();

        // The outbound side comes from the chain, as in gost (ss.go:300): with
        // no chain it is a plain socket, and behind a SOCKS5 hop it is a
        // CmdUDPTun tunnel, so datagrams do not bypass the configured proxy.
        // The bind address follows the listener's family, so an IPv6 listener
        // can reach IPv6 targets.
        let bind: SocketAddr = match conn.local_addr().map(|a| a.ip()) {
            Some(IpAddr::V6(_)) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        };
        let chain = self.options.chain.as_ref().cloned().unwrap_or_default();
        let out = chain.dial_udp(bind).await?;

        info!("[ssu] {} <-> {}", peer_addr, local_addr);
        let result = self.relay(&mut conn, &out, &peer_addr).await;
        info!("[ssu] {} >-< {}", peer_addr, local_addr);

        // `out` is dropped here, closing the association's outbound socket
        // or tunnel the moment the client's virtual connection ends.
        result
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
        let handler = ShadowHandler::new("plain", "testpass", HandlerOptions::default()).unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = proxy.accept().await.unwrap();
            handler.handle(ProxyConn::from_tcp(conn)).await.ok();
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
        let payload: Vec<u8> = (0..(MAX_PAYLOAD * 3 + 1))
            .map(|i| (i % 251) as u8)
            .collect();
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

    // -----------------------------------------------------------------------
    // UDP: datagram framing
    // -----------------------------------------------------------------------

    const AEAD_METHODS: [&str; 3] = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"];

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn cipher_and_key(method: &str, password: &[u8]) -> (SsCipher, Vec<u8>) {
        let cipher = SsCipher::from_name(method).unwrap();
        let key = evp_bytes_to_key(password, cipher.key_size());
        (cipher, key)
    }

    #[test]
    fn test_udp_datagram_roundtrip_all_ciphers() {
        for method in AEAD_METHODS {
            let (cipher, key) = cipher_and_key(method, b"correct horse");

            for target in ["127.0.0.1:53", "[2001:db8::1]:443", "example.com:8080"] {
                let mut plain = encode_ss_target(target).unwrap();
                plain.extend_from_slice(b"the quick brown fox");

                let packet = seal_udp_datagram(&cipher, &key, &plain).unwrap();
                // salt || AEAD(plain): no length framing, one tag.
                assert_eq!(
                    packet.len(),
                    cipher.key_size() + plain.len() + TAG_LEN,
                    "{} datagram layout",
                    method
                );

                let opened = open_udp_datagram(&cipher, &key, &packet).unwrap();
                assert_eq!(opened, plain, "{} round-trip mismatch", method);

                let (addr, off) = parse_ss_address(&opened).unwrap();
                assert_eq!(addr, target);
                assert_eq!(&opened[off..], b"the quick brown fox");
            }
        }
    }

    #[test]
    fn test_udp_datagrams_use_a_fresh_salt_each_time() {
        // The zero nonce is only safe because the salt is fresh per datagram;
        // if two datagrams ever shared one, the keystream would repeat.
        let (cipher, key) = cipher_and_key("aes-256-gcm", b"pw");
        let plain = encode_ss_target("127.0.0.1:53").unwrap();
        let a = seal_udp_datagram(&cipher, &key, &plain).unwrap();
        let b = seal_udp_datagram(&cipher, &key, &plain).unwrap();
        assert_ne!(&a[..cipher.key_size()], &b[..cipher.key_size()]);
        assert_ne!(
            a, b,
            "identical plaintext must not produce identical wire bytes"
        );
    }

    #[test]
    fn test_udp_ciphertext_on_the_wire_is_not_plaintext() {
        // The equivalent of `test_ciphertext_on_the_wire_is_not_plaintext` for
        // the datagram path: it is what catches an implementation that is a
        // plaintext no-op.
        for method in AEAD_METHODS {
            let (cipher, key) = cipher_and_key(method, b"pw");
            let secret = b"SECRET-MARKER-DO-NOT-LEAK";

            for target in ["203.0.113.7:4433", "secret.example.com:443"] {
                let address = encode_ss_target(target).unwrap();
                let mut plain = address.clone();
                plain.extend_from_slice(secret);

                let packet = seal_udp_datagram(&cipher, &key, &plain).unwrap();

                assert!(
                    !contains(&packet, &address),
                    "{}: the encoded target address appears in clear on the wire",
                    method
                );
                assert!(
                    !contains(&packet, target.as_bytes()),
                    "{}: the target address text appears in clear on the wire",
                    method
                );
                assert!(
                    !contains(&packet, secret),
                    "{}: the payload appears in clear on the wire",
                    method
                );
            }
        }
    }

    #[test]
    fn test_udp_wrong_password_fails_the_tag_check() {
        for method in AEAD_METHODS {
            let (cipher, right) = cipher_and_key(method, b"right");
            let (_, wrong) = cipher_and_key(method, b"wrong");

            let mut plain = encode_ss_target("127.0.0.1:9").unwrap();
            plain.extend_from_slice(b"payload");
            let packet = seal_udp_datagram(&cipher, &right, &plain).unwrap();

            let err = open_udp_datagram(&cipher, &wrong, &packet)
                .expect_err("a mismatched password must fail the AEAD tag check");
            assert!(
                err.to_string().contains("authentication tag mismatch"),
                "{}: unexpected error {}",
                method,
                err
            );
            // ...and must not have yielded anything usable.
            assert!(open_udp_datagram(&cipher, &wrong, &packet).is_err());
        }
    }

    #[test]
    fn test_udp_truncated_or_corrupted_datagram_is_rejected() {
        for method in AEAD_METHODS {
            let (cipher, key) = cipher_and_key(method, b"pw");
            let salt_len = cipher.key_size();

            let mut plain = encode_ss_target("127.0.0.1:9").unwrap();
            plain.extend_from_slice(b"payload");
            let packet = seal_udp_datagram(&cipher, &key, &plain).unwrap();
            assert!(open_udp_datagram(&cipher, &key, &packet).is_ok());

            // Nothing at all.
            assert!(open_udp_datagram(&cipher, &key, &[]).is_err());
            // Salt only: no room for a tag.
            assert!(open_udp_datagram(&cipher, &key, &packet[..salt_len]).is_err());
            // One byte short of the salt + tag minimum.
            assert!(open_udp_datagram(&cipher, &key, &packet[..salt_len + TAG_LEN - 1]).is_err());
            // Body truncated by one byte: the tag no longer covers it.
            assert!(open_udp_datagram(&cipher, &key, &packet[..packet.len() - 1]).is_err());

            // A flipped ciphertext byte.
            let mut corrupt = packet.clone();
            corrupt[salt_len] ^= 0xff;
            assert!(open_udp_datagram(&cipher, &key, &corrupt).is_err());

            // A flipped salt byte derives a different subkey.
            let mut corrupt = packet.clone();
            corrupt[0] ^= 0xff;
            assert!(open_udp_datagram(&cipher, &key, &corrupt).is_err());

            // A flipped tag byte.
            let mut corrupt = packet.clone();
            let last = corrupt.len() - 1;
            corrupt[last] ^= 0xff;
            assert!(open_udp_datagram(&cipher, &key, &corrupt).is_err());
        }
    }

    #[test]
    fn test_parse_ss_address_fails_closed_on_malformed_input() {
        // Empty frame.
        assert!(parse_ss_address(&[]).is_err());
        // Unknown address type.
        assert!(parse_ss_address(&[0x02, 1, 2, 3, 4, 0, 80]).is_err());
        assert!(parse_ss_address(&[0x00]).is_err());
        // Truncated addresses.
        assert!(parse_ss_address(&[ATYP_IPV4, 127, 0, 0]).is_err());
        assert!(parse_ss_address(&[ATYP_IPV6, 0, 0, 0]).is_err());
        // Truncated port.
        assert!(parse_ss_address(&[ATYP_IPV4, 127, 0, 0, 1]).is_err());
        assert!(parse_ss_address(&[ATYP_IPV4, 127, 0, 0, 1, 0]).is_err());
        // Domain length overruns the buffer.
        assert!(parse_ss_address(&[ATYP_DOMAIN, 9, b'a', b'b']).is_err());
        // Empty domain.
        assert!(parse_ss_address(&[ATYP_DOMAIN, 0, 0, 80]).is_err());
        // Non-UTF-8 domain.
        assert!(parse_ss_address(&[ATYP_DOMAIN, 2, 0xff, 0xfe, 0, 80]).is_err());
        // Missing domain length byte.
        assert!(parse_ss_address(&[ATYP_DOMAIN]).is_err());

        // A well-formed frame reports where the payload starts.
        let (addr, off) = parse_ss_address(&[ATYP_IPV4, 127, 0, 0, 1, 0, 80, b'h', b'i']).unwrap();
        assert_eq!(addr, "127.0.0.1:80");
        assert_eq!(off, 7);
    }

    #[test]
    fn test_ss_address_ipv6_survives_a_round_trip() {
        // The bracketed form must not be mistaken for a domain, or the relay
        // would try to resolve the literal text "[::1]".
        let encoded = encode_ss_target("[::1]:53").unwrap();
        assert_eq!(encoded[0], ATYP_IPV6);
        let (addr, off) = parse_ss_address(&encoded).unwrap();
        assert_eq!(addr, "[::1]:53");
        assert_eq!(off, encoded.len());

        // An IP literal sent under the domain type is normalised, so IP rules
        // still apply to it.
        let mut domain_form = vec![ATYP_DOMAIN, 3];
        domain_form.extend_from_slice(b"::1");
        domain_form.extend_from_slice(&53u16.to_be_bytes());
        assert_eq!(parse_ss_address(&domain_form).unwrap().0, "[::1]:53");
    }

    #[test]
    fn test_udp_unknown_cipher_is_rejected_not_downgraded_to_plaintext() {
        assert!(ShadowUdpConnector::new("aes-256-cfb", "pw").is_err());
        assert!(ShadowUdpConnector::new("totally-bogus", "pw").is_err());
        assert!(ShadowUdpHandler::new("rc4-md5", "pw", HandlerOptions::default()).is_err());
        assert!(ShadowUdpHandler::new("aes-256-cfb", "pw", HandlerOptions::default()).is_err());
        // The supported set still builds.
        for method in AEAD_METHODS {
            assert!(ShadowUdpConnector::new(method, "pw").is_ok());
            assert!(ShadowUdpHandler::new(method, "pw", HandlerOptions::default()).is_ok());
        }
    }

    // -----------------------------------------------------------------------
    // UDP: end-to-end relay through the handler
    // -----------------------------------------------------------------------

    use crate::udp::{UdpListenConfig, UdpListener, UdpServer};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    /// A UDP echo server on 127.0.0.1, bound to port 0.
    async fn spawn_udp_echo() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                if sock.send_to(&buf[..n], from).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    /// Serves `handler` on a real UDP listener bound to port 0.
    async fn spawn_ssu_server(handler: ShadowUdpHandler) -> (SocketAddr, CancellationToken) {
        let listener = UdpListener::bind(
            "127.0.0.1:0",
            UdpListenConfig {
                ttl: Duration::from_secs(10),
                backlog: 8,
                queue_size: 32,
            },
        )
        .await
        .unwrap();
        let addr = listener.local_addr();
        let server = UdpServer::from_listener(listener, handler);
        let cancel = server.cancel_token();
        tokio::spawn(async move { server.serve().await.ok() });
        (addr, cancel)
    }

    /// Waits `ms` for one datagram on `sock`.
    async fn recv_within(sock: &UdpSocket, ms: u64) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; UDP_MAX_DATAGRAM];
        tokio::time::timeout(Duration::from_millis(ms), sock.recv_from(&mut buf))
            .await
            .ok()
            .map(|r| {
                let (n, _) = r.unwrap();
                buf[..n].to_vec()
            })
    }

    #[tokio::test]
    async fn test_ssu_handler_relays_to_a_local_echo_server() {
        for method in AEAD_METHODS {
            let echo = spawn_udp_echo().await;
            let handler =
                ShadowUdpHandler::new(method, "s3cret", HandlerOptions::default()).unwrap();
            let (server_addr, cancel) = spawn_ssu_server(handler).await;

            let connector = ShadowUdpConnector::new(method, "s3cret").unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let packet = connector
                .encode_to(&echo.to_string(), b"ping over shadowsocks")
                .unwrap();
            client.send_to(&packet, server_addr).await.unwrap();

            let reply = recv_within(&client, 2_000)
                .await
                .unwrap_or_else(|| panic!("{}: no reply from the relay", method));

            // The reply must be encrypted too, not the echo in the clear.
            assert!(
                !contains(&reply, b"ping over shadowsocks"),
                "{}: the reply payload is on the wire in clear",
                method
            );

            let (origin, payload) = connector.decode_from(&reply).unwrap();
            assert_eq!(origin, echo.to_string(), "{}: wrong reply origin", method);
            assert_eq!(
                payload, b"ping over shadowsocks",
                "{}: wrong payload",
                method
            );

            // The association keeps serving further datagrams.
            let packet = connector.encode_to(&echo.to_string(), b"second").unwrap();
            client.send_to(&packet, server_addr).await.unwrap();
            let reply = recv_within(&client, 2_000).await.expect("second reply");
            assert_eq!(connector.decode_from(&reply).unwrap().1, b"second");

            cancel.cancel();
        }
    }

    #[tokio::test]
    async fn test_ssu_handler_relays_a_domain_target() {
        let echo = spawn_udp_echo().await;
        let handler =
            ShadowUdpHandler::new("aes-256-gcm", "pw", HandlerOptions::default()).unwrap();
        let (server_addr, cancel) = spawn_ssu_server(handler).await;

        let connector = ShadowUdpConnector::new("aes-256-gcm", "pw").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // ATYP_DOMAIN rather than ATYP_IPV4, so the resolver path is exercised.
        let target = format!("localhost:{}", echo.port());
        let packet = connector.encode_to(&target, b"by name").unwrap();
        assert_eq!(
            open_udp_datagram(&connector.cipher, &connector.key, &packet).unwrap()[0],
            ATYP_DOMAIN
        );
        client.send_to(&packet, server_addr).await.unwrap();

        // "localhost" resolves to ::1 first on some hosts, which an IPv4 echo
        // server cannot answer. Resolve it the same way the relay does and only
        // demand a reply when the name really does point at the echo server, so
        // the assertion is firm rather than conditional on the relay's own
        // behaviour.
        let resolved = tokio::net::lookup_host(("localhost", echo.port()))
            .await
            .ok()
            .and_then(|mut it| it.next());
        let reply = recv_within(&client, 2_000).await;
        if resolved == Some(echo) {
            let reply = reply.expect("a domain target must be resolved and relayed");
            let (origin, payload) = connector.decode_from(&reply).unwrap();
            assert_eq!(origin, echo.to_string());
            assert_eq!(payload, b"by name");
        } else {
            assert!(
                reply.is_none(),
                "localhost resolves to {:?}, not the echo server, so nothing may come back",
                resolved
            );
        }

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_ssu_handler_drops_datagrams_from_a_wrong_password_client() {
        let echo = spawn_udp_echo().await;
        let handler =
            ShadowUdpHandler::new("aes-256-gcm", "server-pw", HandlerOptions::default()).unwrap();
        let (server_addr, cancel) = spawn_ssu_server(handler).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Wrong password: the tag check must fail and nothing may be relayed.
        let bad = ShadowUdpConnector::new("aes-256-gcm", "client-pw").unwrap();
        client
            .send_to(
                &bad.encode_to(&echo.to_string(), b"leak me").unwrap(),
                server_addr,
            )
            .await
            .unwrap();
        assert!(
            recv_within(&client, 400).await.is_none(),
            "a datagram that fails authentication must not be relayed"
        );

        // Plain garbage is dropped just as quietly.
        client
            .send_to(b"not a shadowsocks datagram", server_addr)
            .await
            .unwrap();
        assert!(recv_within(&client, 300).await.is_none());

        // ...and the association still works for the right password, so a bad
        // datagram does not tear it down.
        let good = ShadowUdpConnector::new("aes-256-gcm", "server-pw").unwrap();
        client
            .send_to(
                &good.encode_to(&echo.to_string(), b"ok").unwrap(),
                server_addr,
            )
            .await
            .unwrap();
        let reply = recv_within(&client, 2_000)
            .await
            .expect("the association must survive a rejected datagram");
        assert_eq!(good.decode_from(&reply).unwrap().1, b"ok");

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_ssu_handler_blacklist_blocks_per_datagram() {
        let blocked = spawn_udp_echo().await;
        let allowed = spawn_udp_echo().await;

        let options = HandlerOptions {
            blacklist: Some(
                crate::permissions::Permissions::parse(&format!(
                    "udp:127.0.0.1:{}",
                    blocked.port()
                ))
                .unwrap(),
            ),
            ..HandlerOptions::default()
        };
        let handler = ShadowUdpHandler::new("aes-256-gcm", "pw", options).unwrap();
        let (server_addr, cancel) = spawn_ssu_server(handler).await;

        let connector = ShadowUdpConnector::new("aes-256-gcm", "pw").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Blacklisted destination: dropped.
        client
            .send_to(
                &connector
                    .encode_to(&blocked.to_string(), b"blocked")
                    .unwrap(),
                server_addr,
            )
            .await
            .unwrap();
        assert!(
            recv_within(&client, 500).await.is_none(),
            "a blacklisted destination must not be relayed"
        );

        // The very next datagram on the SAME association, to a destination that
        // is not blacklisted, still goes through: the check is per datagram and
        // a block does not end the association.
        client
            .send_to(
                &connector
                    .encode_to(&allowed.to_string(), b"allowed")
                    .unwrap(),
                server_addr,
            )
            .await
            .unwrap();
        let reply = recv_within(&client, 2_000)
            .await
            .expect("an allowed destination must still be relayed");
        let (origin, payload) = connector.decode_from(&reply).unwrap();
        assert_eq!(origin, allowed.to_string());
        assert_eq!(payload, b"allowed");

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_ssu_handler_whitelist_blocks_per_datagram() {
        let echo = spawn_udp_echo().await;

        // A whitelist that names a different port than the echo server's.
        let options = HandlerOptions {
            whitelist: Some(
                crate::permissions::Permissions::parse(&format!(
                    "udp:127.0.0.1:{}",
                    echo.port().wrapping_add(1).max(1)
                ))
                .unwrap(),
            ),
            ..HandlerOptions::default()
        };
        let handler = ShadowUdpHandler::new("aes-256-gcm", "pw", options).unwrap();
        let (server_addr, cancel) = spawn_ssu_server(handler).await;

        let connector = ShadowUdpConnector::new("aes-256-gcm", "pw").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(
                &connector.encode_to(&echo.to_string(), b"nope").unwrap(),
                server_addr,
            )
            .await
            .unwrap();
        assert!(
            recv_within(&client, 500).await.is_none(),
            "a destination outside the whitelist must not be relayed"
        );

        cancel.cancel();
    }

    #[tokio::test]
    async fn test_ssu_handler_bypass_blocks_per_datagram() {
        let echo = spawn_udp_echo().await;

        // Control: with no bypass the datagram is relayed, so the negative
        // assertion below cannot pass for an unrelated reason.
        let plain_handler =
            ShadowUdpHandler::new("aes-256-gcm", "pw", HandlerOptions::default()).unwrap();
        let (open_addr, open_cancel) = spawn_ssu_server(plain_handler).await;

        let connector = ShadowUdpConnector::new("aes-256-gcm", "pw").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(
                &connector.encode_to(&echo.to_string(), b"control").unwrap(),
                open_addr,
            )
            .await
            .unwrap();
        let reply = recv_within(&client, 2_000)
            .await
            .expect("the control relay must reach the echo server");
        assert_eq!(connector.decode_from(&reply).unwrap().1, b"control");
        open_cancel.cancel();

        // Same target, same client, but 127.0.0.1 is bypassed.
        let options = HandlerOptions {
            bypass: Some(std::sync::Arc::new(crate::bypass::Bypass::from_patterns(
                false,
                &["127.0.0.1"],
            ))),
            ..HandlerOptions::default()
        };
        let handler = ShadowUdpHandler::new("aes-256-gcm", "pw", options).unwrap();
        let (bypass_addr, bypass_cancel) = spawn_ssu_server(handler).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(
                &connector.encode_to(&echo.to_string(), b"bypassed").unwrap(),
                bypass_addr,
            )
            .await
            .unwrap();
        assert!(
            recv_within(&client, 500).await.is_none(),
            "a bypassed destination must not be relayed"
        );

        bypass_cancel.cancel();
    }

    #[tokio::test]
    async fn test_ssu_packet_conn_round_trips_over_a_stream() {
        // `ShadowUdpConnector::connect` is the gost `shadowUDPPacketConn`
        // shape: writes carry the target address, reads yield the origin.
        let (client_raw, mut wire) = tokio::io::duplex(1 << 16);
        let connector = ShadowUdpConnector::new("chacha20-ietf-poly1305", "pw").unwrap();
        let mut pc = connector.connect(client_raw, "198.51.100.9:5353").unwrap();

        pc.send(b"hello").await.unwrap();

        let mut raw = vec![0u8; 4096];
        let n = wire.read(&mut raw).await.unwrap();
        assert!(
            !contains(&raw[..n], b"hello"),
            "the payload must be encrypted"
        );
        let (target, payload) = connector.decode_from(&raw[..n]).unwrap();
        assert_eq!(target, "198.51.100.9:5353");
        assert_eq!(payload, b"hello");

        // A reply flows back the other way.
        let reply = connector.encode_to("198.51.100.9:5353", b"world").unwrap();
        wire.write_all(&reply).await.unwrap();
        let (origin, payload) = pc.recv().await.unwrap();
        assert_eq!(origin, "198.51.100.9:5353");
        assert_eq!(payload, b"world");

        // An unparseable target is rejected at connect time.
        let (other, _keep) = tokio::io::duplex(64);
        assert!(connector.connect(other, "no-port-here").is_err());
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
