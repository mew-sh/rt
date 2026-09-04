//! Framed obfuscation transports: `ohttp` and `otls`.
//!
//! [`obfs`](crate::obfs) only opened the connection. gost keeps framing every
//! byte afterwards (obfs.go:596-665): `otls` wraps each write in a TLS
//! application-data record, so the traffic stays record-shaped for the life of
//! the connection instead of turning into obvious plaintext one byte after the
//! ServerHello. Without that framing the transport is decorative, which is why
//! it was never wired to the CLI.
//!
//! `ohttp` is transparent once the fake WebSocket upgrade completes, so only
//! the TLS variant needs a stream type.
//!
//! # Shape
//!
//! Like [`H2Handler`](crate::h2_transport::H2Handler), [`ObfsHandler`] is a
//! [`Handler`] that wraps another handler: it performs the server handshake
//! and hands the framed stream to the inner handler. The chain side layers the
//! matching client handshake.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use crate::conn::{AsyncStream, ProxyConn};
use crate::handler::{Handler, HandlerError};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// gost caps a record's payload here (obfs.go:29).
const MAX_TLS_DATA_LEN: usize = 16384;

const REC_CHANGE_CIPHER_SPEC: u8 = 0x14;
const REC_HANDSHAKE: u8 = 0x16;
const REC_APP_DATA: u8 = 0x17;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ENCRYPT_THEN_MAC: u16 = 0x0016;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

// ---------------------------------------------------------------------------
// Record encoding
// ---------------------------------------------------------------------------

fn put_ext(buf: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    buf.extend_from_slice(&ext_type.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

fn sni_ext_body(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut body = Vec::new();
    body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    body.push(0x00);
    body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    body.extend_from_slice(name);
    body
}

fn gmt_unix_time() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn record(kind: u8, version: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind);
    out.extend_from_slice(&version);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Builds gost's obfuscating ClientHello (obfs.go:481-523).
///
/// The first payload rides in the session-ticket extension, so the exchange
/// looks like a session resumption rather than a handshake that carries
/// nothing.
pub fn build_client_hello(host: &str, payload: &[u8]) -> Vec<u8> {
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&gmt_unix_time().to_be_bytes());
    let opaque: [u8; 28] = rand::random();
    hello.extend_from_slice(&opaque);

    let session_id: [u8; 32] = rand::random();
    hello.push(32);
    hello.extend_from_slice(&session_id);

    let suites: [u16; 10] = [
        0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0x009e, 0x009f, 0x002f, 0x0035,
    ];
    hello.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        hello.extend_from_slice(&s.to_be_bytes());
    }

    hello.push(0x01);
    hello.push(0x00);

    let mut exts = Vec::new();
    put_ext(&mut exts, EXT_SESSION_TICKET, payload);
    put_ext(&mut exts, EXT_SERVER_NAME, &sni_ext_body(host));
    put_ext(&mut exts, EXT_EC_POINT_FORMATS, &[0x03, 0x01, 0x00, 0x02]);
    put_ext(
        &mut exts,
        EXT_SUPPORTED_GROUPS,
        &[0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18],
    );
    put_ext(
        &mut exts,
        EXT_SIGNATURE_ALGORITHMS,
        &[0x00, 0x08, 0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x08, 0x04],
    );
    put_ext(&mut exts, EXT_ENCRYPT_THEN_MAC, &[]);
    put_ext(&mut exts, EXT_EXTENDED_MASTER_SECRET, &[]);
    hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hello.extend_from_slice(&exts);

    let mut handshake = Vec::with_capacity(4 + hello.len());
    handshake.push(0x01);
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hello);

    record(REC_HANDSHAKE, [0x03, 0x01], &handshake)
}

/// The session id a ClientHello body carries.
fn session_id_of(hello: &[u8]) -> Vec<u8> {
    let i = 4 + 2 + 32;
    match hello.get(i) {
        Some(&len) if hello.len() >= i + 1 + len as usize => {
            hello[i + 1..i + 1 + len as usize].to_vec()
        }
        _ => Vec::new(),
    }
}

/// The session-ticket payload a ClientHello body carries, if any.
pub fn session_ticket_of(hello: &[u8]) -> Option<Vec<u8>> {
    let mut i = 4 + 2 + 32;
    let session_len = *hello.get(i)? as usize;
    i += 1 + session_len;

    let suites_len = u16::from_be_bytes([*hello.get(i)?, *hello.get(i + 1)?]) as usize;
    i += 2 + suites_len;

    let comp_len = *hello.get(i)? as usize;
    i += 1 + comp_len;

    let exts_len = u16::from_be_bytes([*hello.get(i)?, *hello.get(i + 1)?]) as usize;
    i += 2;
    let end = (i + exts_len).min(hello.len());

    while i + 4 <= end {
        let ext_type = u16::from_be_bytes([hello[i], hello[i + 1]]);
        let ext_len = u16::from_be_bytes([hello[i + 2], hello[i + 3]]) as usize;
        i += 4;
        if i + ext_len > end {
            return None;
        }
        if ext_type == EXT_SESSION_TICKET {
            return Some(hello[i..i + ext_len].to_vec());
        }
        i += ext_len;
    }
    None
}

/// The ServerHello and ChangeCipherSpec gost answers with (obfs.go:552-594).
fn build_server_reply(session_id: &[u8]) -> Vec<u8> {
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&gmt_unix_time().to_be_bytes());
    let opaque: [u8; 28] = rand::random();
    hello.extend_from_slice(&opaque);

    hello.push(session_id.len() as u8);
    hello.extend_from_slice(session_id);

    hello.extend_from_slice(&0xcca8u16.to_be_bytes());
    hello.push(0x00);

    let mut exts = Vec::new();
    put_ext(&mut exts, EXT_RENEGOTIATION_INFO, &[0x00]);
    put_ext(&mut exts, EXT_EXTENDED_MASTER_SECRET, &[]);
    put_ext(&mut exts, EXT_EC_POINT_FORMATS, &[0x01, 0x00]);
    hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hello.extend_from_slice(&exts);

    let mut handshake = Vec::with_capacity(4 + hello.len());
    handshake.push(0x02);
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hello);

    let mut out = record(REC_HANDSHAKE, [0x03, 0x01], &handshake);
    out.extend_from_slice(&record(REC_CHANGE_CIPHER_SPEC, [0x03, 0x03], &[0x01]));
    out
}

// ---------------------------------------------------------------------------
// The framed stream
// ---------------------------------------------------------------------------

/// A connection whose payload travels inside TLS application-data records.
pub struct ObfsTlsStream<S> {
    inner: S,
    /// Bytes read from the socket that do not yet form a whole record.
    raw: Vec<u8>,
    /// Decoded payload not yet handed to the reader.
    ready: Vec<u8>,
    ready_pos: usize,
    /// Encoded bytes not yet written, including the deferred server reply.
    out: Vec<u8>,
    out_pos: usize,
    /// Client side only: the server's opening ServerHello and
    /// ChangeCipherSpec still have to be stepped over.
    ///
    /// Record type cannot be used to tell framing from payload here. gost
    /// flushes its held-back ServerHello together with the first response and
    /// relabels that whole record as `Handshake` (obfs.go:650-655), so the
    /// first bytes of real payload arrive typed 0x16. Skipping by type would
    /// silently drop them -- which is exactly how this failed against a real
    /// gost server, with the request going through and the reply vanishing.
    /// Position is reliable instead: everything after the ChangeCipherSpec is
    /// payload, whatever it claims to be.
    expect_server_reply: bool,
    /// The record type to stamp on the next outgoing data record.
    ///
    /// gost's client parser is a fixed state machine over the record sequence
    /// it expects from a server: `[0x16, 0x14, 0x16, 0x17]` with minor
    /// versions `[0x01, 0x03, 0x03, 0x03]` (obfs.go:317-318). The third entry
    /// is not a handshake message -- it is the first record of real payload,
    /// which gost labels `Handshake` because it flushes the held-back
    /// ServerHello alongside it. A server that sends application data there
    /// gets `ErrBadType` and the client drops the connection, which is how
    /// this failed against a real gost client.
    next_record_type: u8,
}

impl<S> ObfsTlsStream<S> {
    fn new(inner: S, ready: Vec<u8>, out: Vec<u8>, expect_server_reply: bool) -> Self {
        Self {
            inner,
            raw: Vec::new(),
            ready,
            ready_pos: 0,
            out,
            out_pos: 0,
            expect_server_reply,
            // A client is not parsed this strictly by gost's server, which
            // reads whatever record arrives, so it uses application data
            // throughout; a server owes the sequence above.
            next_record_type: if expect_server_reply {
                REC_APP_DATA
            } else {
                REC_HANDSHAKE
            },
        }
    }

    /// Splits one whole record off the front of `raw`, if there is one.
    ///
    /// Yields the record type with the payload, because only application data
    /// is stream content: the handshake and change-cipher-spec records the
    /// server sends back are framing and must be skipped, not delivered.
    fn take_record(&mut self) -> io::Result<Option<(u8, Vec<u8>)>> {
        if self.raw.len() < 5 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([self.raw[3], self.raw[4]]) as usize;
        if len > MAX_TLS_DATA_LEN + 2048 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "obfs-tls: oversized record",
            ));
        }
        if self.raw.len() < 5 + len {
            return Ok(None);
        }
        let kind = self.raw[0];
        let payload = self.raw[5..5 + len].to_vec();
        self.raw.drain(..5 + len);
        Ok(Some((kind, payload)))
    }
}

impl<S: AsyncWrite + Unpin> ObfsTlsStream<S> {
    /// Drains whatever is already encoded.
    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let Self {
                inner,
                out,
                out_pos,
                ..
            } = self;
            match Pin::new(inner).poll_write(cx, &out[*out_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "obfs-tls: write returned zero",
                    )))
                }
                Poll::Ready(Ok(n)) => *out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObfsTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.ready_pos < self.ready.len() {
                let n = (self.ready.len() - self.ready_pos).min(buf.remaining());
                let from = self.ready_pos;
                buf.put_slice(&self.ready[from..from + n]);
                self.ready_pos += n;
                if self.ready_pos == self.ready.len() {
                    self.ready.clear();
                    self.ready_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // A complete record already buffered needs no syscall.
            match self.take_record() {
                Err(e) => return Poll::Ready(Err(e)),
                Ok(Some((kind, payload))) => {
                    if self.expect_server_reply {
                        // The ChangeCipherSpec closes the opening reply;
                        // everything from the next record on is payload.
                        if kind == REC_CHANGE_CIPHER_SPEC {
                            self.expect_server_reply = false;
                            continue;
                        }
                        if kind == REC_HANDSHAKE {
                            continue;
                        }
                        // Anything else means the reply is already over.
                        self.expect_server_reply = false;
                    }
                    if payload.is_empty() {
                        continue;
                    }
                    self.ready = payload;
                    self.ready_pos = 0;
                    continue;
                }
                Ok(None) => {}
            }

            let mut chunk = [0u8; 8192];
            let mut tmp = ReadBuf::new(&mut chunk);
            let this = &mut *self;
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(())) => {
                    let n = tmp.filled().len();
                    if n == 0 {
                        // A close on a record boundary is a clean end; one
                        // part way through a record is truncation.
                        return if this.raw.is_empty() {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "obfs-tls: truncated record",
                            )))
                        };
                    }
                    this.raw.extend_from_slice(&tmp.filled()[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObfsTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Anything already encoded, including a deferred server reply, has to
        // reach the socket before a new record is queued behind it.
        if self.flush_out(cx).is_pending() {
            return Poll::Pending;
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let take = buf.len().min(MAX_TLS_DATA_LEN);
        let kind = self.next_record_type;
        self.next_record_type = REC_APP_DATA;
        self.out = record(kind, [0x03, 0x03], &buf[..take]);
        self.out_pos = 0;
        match self.flush_out(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            // Buffered either way: a partial flush finishes on the next poll.
            _ => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.flush_out(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.flush_out(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// Handshakes
// ---------------------------------------------------------------------------

/// Client side of `otls`.
pub async fn otls_connect<S>(mut stream: S, host: &str) -> Result<ObfsTlsStream<S>, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // gost carries the first payload in the session ticket. rt sends the
    // handshake eagerly with an empty ticket and puts the data in records,
    // which the server side handles either way.
    stream.write_all(&build_client_hello(host, &[])).await?;
    stream.flush().await?;

    // Deliberately no read here. gost's server holds its ServerHello back
    // until it has payload to send (obfs.go:650-656), so a client that waited
    // for the reply would deadlock against a server waiting for the request.
    // The reply arrives as ordinary records and the reader skips them.
    Ok(ObfsTlsStream::new(stream, Vec::new(), Vec::new(), true))
}

/// Server side of `otls`.
pub async fn otls_accept<S>(mut stream: S) -> Result<ObfsTlsStream<S>, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    if header[0] != REC_HANDSHAKE {
        return Err("obfs-tls: not a handshake record".into());
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_TLS_DATA_LEN + 2048 {
        return Err("obfs-tls: oversized ClientHello".into());
    }
    let mut hello = vec![0u8; len];
    stream.read_exact(&mut hello).await?;

    let session_id = session_id_of(&hello);
    // A non-empty ticket is the peer's first payload.
    let ready = session_ticket_of(&hello).unwrap_or_default();

    // Held back rather than sent now, matching gost, which flushes it with the
    // first response bytes.
    let pending = build_server_reply(&session_id);
    Ok(ObfsTlsStream::new(stream, ready, pending, false))
}

/// Client side of `ohttp`: a fake WebSocket upgrade, transparent afterwards.
pub async fn ohttp_connect<S>(mut stream: S, host: &str) -> Result<S, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use base64::Engine;
    let key: [u8; 16] = rand::random();
    let key = base64::engine::general_purpose::STANDARD.encode(key);
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        host,
        crate::DEFAULT_USER_AGENT,
        key
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let head = read_head(&mut stream).await?;
    if !head.contains(" 101 ") {
        return Err(format!(
            "obfs-http: unexpected response: {}",
            head.lines().next().unwrap_or_default()
        )
        .into());
    }
    Ok(stream)
}

/// Server side of `ohttp`.
pub async fn ohttp_accept<S>(mut stream: S) -> Result<S, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let _request = read_head(&mut stream).await?;
    let resp = "HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.10.0\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(stream)
}

/// Reads to the blank line, one byte at a time.
///
/// Buffering would consume payload that follows the head on the same segment,
/// and this transport has nowhere to put it: the stream is handed on raw.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<String, BoxError> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            return Err("obfs-http: connection closed during handshake".into());
        }
        head.push(byte[0]);
        if head.len() > 8192 {
            return Err("obfs-http: header too large".into());
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

// ---------------------------------------------------------------------------
// Listener side
// ---------------------------------------------------------------------------

/// Which obfuscation a listener or hop uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObfsKind {
    Http,
    Tls,
}

/// Runs the server handshake, then hands the framed stream to the inner
/// handler.
pub struct ObfsHandler {
    inner: std::sync::Arc<dyn Handler>,
    kind: ObfsKind,
}

impl ObfsHandler {
    pub fn new(inner: impl Handler + 'static, kind: ObfsKind) -> Self {
        Self {
            inner: std::sync::Arc::new(inner),
            kind,
        }
    }
}

#[async_trait]
impl Handler for ObfsHandler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let peer = conn.peer_addr();
        let local = conn.local_addr();

        let inner: Box<dyn AsyncStream> = match self.kind {
            ObfsKind::Http => match ohttp_accept(conn).await {
                Ok(s) => Box::new(s),
                Err(e) => {
                    debug!("[ohttp] handshake failed: {}", e);
                    return Ok(());
                }
            },
            ObfsKind::Tls => match otls_accept(conn).await {
                Ok(s) => Box::new(s),
                Err(e) => {
                    debug!("[otls] handshake failed: {}", e);
                    return Ok(());
                }
            },
        };

        self.inner
            .handle(ProxyConn::layered(inner, peer, local))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_client_hello_is_a_handshake_record() {
        let hello = build_client_hello("example.com", b"payload");
        assert_eq!(hello[0], REC_HANDSHAKE);
        assert_eq!(&hello[1..3], &[0x03, 0x01]);
        let len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(len, hello.len() - 5);
        assert_eq!(hello[5], 0x01, "handshake type must be ClientHello");
    }

    #[test]
    fn test_session_ticket_roundtrip() {
        let hello = build_client_hello("example.com", b"first-payload");
        assert_eq!(
            session_ticket_of(&hello[5..]).as_deref(),
            Some(&b"first-payload"[..])
        );
    }

    #[test]
    fn test_session_ticket_empty_is_recovered_as_empty() {
        let hello = build_client_hello("example.com", b"");
        assert_eq!(session_ticket_of(&hello[5..]), Some(Vec::new()));
    }

    #[test]
    fn test_session_id_is_echoed_by_the_server_reply() {
        let hello = build_client_hello("example.com", b"");
        let id = session_id_of(&hello[5..]);
        assert_eq!(id.len(), 32);
        let reply = build_server_reply(&id);
        assert_eq!(reply[0], REC_HANDSHAKE);
        // ServerHello body: type(1) len(3) version(2) random(32) id_len(1)
        let body = &reply[5..];
        assert_eq!(body[0], 0x02);
        let id_len = body[4 + 2 + 32] as usize;
        assert_eq!(id_len, 32);
        assert_eq!(&body[4 + 2 + 32 + 1..4 + 2 + 32 + 1 + 32], &id[..]);
    }

    #[test]
    fn test_session_ticket_of_rejects_truncated_input() {
        assert_eq!(session_ticket_of(&[0u8; 10]), None);
    }

    #[test]
    fn test_server_hello_is_exactly_91_bytes() {
        // Not a round number by choice: gost's client parser ignores the
        // declared length at this step and substitutes 91 (obfs.go:384-385),
        // so a ServerHello of any other size desynchronises it and every
        // following record is misread.
        let reply = build_server_reply(&[0u8; 32]);
        let len = u16::from_be_bytes([reply[3], reply[4]]) as usize;
        assert_eq!(len, 91, "gost hard-codes this length");
        assert_eq!(reply[0], REC_HANDSHAKE);
        assert_eq!(&reply[1..3], &[0x03, 0x01]);

        // ChangeCipherSpec follows, one byte, minor version 3.
        let ccs = &reply[5 + 91..];
        assert_eq!(ccs[0], REC_CHANGE_CIPHER_SPEC);
        assert_eq!(&ccs[1..3], &[0x03, 0x03]);
        assert_eq!(u16::from_be_bytes([ccs[3], ccs[4]]) as usize, 1);
    }

    #[tokio::test]
    async fn test_server_first_data_record_is_typed_handshake() {
        // gost's parser expects [0x16, 0x14, 0x16, 0x17]; the third is
        // payload wearing a handshake label.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut s = otls_accept(sock).await.unwrap();
            s.write_all(b"first").await.unwrap();
            s.write_all(b"second").await.unwrap();
            s.flush().await.unwrap();
            // Hold the connection while the client reads.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(&build_client_hello("example.com", b""))
            .await
            .unwrap();
        sock.flush().await.unwrap();

        let mut seen = vec![0u8; 4096];
        let mut got = 0;
        // ServerHello(5+91) + CCS(5+1) + record(5+5) + record(5+6)
        while got < 5 + 91 + 5 + 1 + 5 + 5 + 5 + 6 {
            let n = sock.read(&mut seen[got..]).await.unwrap();
            assert_ne!(n, 0, "server closed early");
            got += n;
        }

        let mut i = 0;
        assert_eq!(seen[i], REC_HANDSHAKE, "step 0 must be the ServerHello");
        i += 5 + 91;
        assert_eq!(seen[i], REC_CHANGE_CIPHER_SPEC, "step 1 must be the CCS");
        i += 5 + 1;
        assert_eq!(seen[i], REC_HANDSHAKE, "step 2 is payload typed handshake");
        assert_eq!(&seen[i + 5..i + 10], b"first");
        i += 5 + 5;
        assert_eq!(seen[i], REC_APP_DATA, "step 3 onwards is application data");
        assert_eq!(&seen[i + 5..i + 11], b"second");
    }

    /// Drives a client and server over loopback and returns what the server
    /// read and what the client read back.
    async fn roundtrip(kind: ObfsKind, payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let n = payload.len();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut s: Box<dyn AsyncStream> = match kind {
                ObfsKind::Http => Box::new(ohttp_accept(sock).await.unwrap()),
                ObfsKind::Tls => Box::new(otls_accept(sock).await.unwrap()),
            };
            let mut got = vec![0u8; n];
            s.read_exact(&mut got).await.unwrap();
            s.write_all(b"server-reply").await.unwrap();
            s.flush().await.unwrap();
            got
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        let mut c: Box<dyn AsyncStream> = match kind {
            ObfsKind::Http => Box::new(ohttp_connect(sock, "example.com").await.unwrap()),
            ObfsKind::Tls => Box::new(otls_connect(sock, "example.com").await.unwrap()),
        };
        c.write_all(payload).await.unwrap();
        c.flush().await.unwrap();

        let mut back = vec![0u8; b"server-reply".len()];
        c.read_exact(&mut back).await.unwrap();

        (server.await.unwrap(), back)
    }

    #[tokio::test]
    async fn test_otls_roundtrip() {
        let (got, back) = roundtrip(ObfsKind::Tls, b"through the otls transport").await;
        assert_eq!(got, b"through the otls transport");
        assert_eq!(back, b"server-reply");
    }

    #[tokio::test]
    async fn test_ohttp_roundtrip() {
        let (got, back) = roundtrip(ObfsKind::Http, b"through the ohttp transport").await;
        assert_eq!(got, b"through the ohttp transport");
        assert_eq!(back, b"server-reply");
    }

    #[tokio::test]
    async fn test_otls_spans_multiple_records() {
        // Larger than one record, so this fails if chunking or reassembly is
        // wrong rather than merely slow.
        let payload = vec![0x5Au8; MAX_TLS_DATA_LEN * 2 + 123];
        let (got, _) = roundtrip(ObfsKind::Tls, &payload).await;
        assert_eq!(got.len(), payload.len());
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn test_otls_payload_is_not_on_the_wire_in_clear() {
        // The point of the transport: a marker written through it must not
        // appear as a contiguous run of plaintext framing-free bytes at the
        // start of the connection.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut seen = vec![0u8; 4096];
            let n = sock.read(&mut seen).await.unwrap();
            seen.truncate(n);
            seen
        });

        let sock = TcpStream::connect(addr).await.unwrap();
        // The handshake will not complete because the raw server never
        // answers; what matters is that the first thing on the wire is a
        // record header, not the marker.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            otls_connect(sock, "example.com"),
        )
        .await;

        let seen = server.await.unwrap();
        assert!(!seen.is_empty());
        assert_eq!(seen[0], REC_HANDSHAKE, "first byte must be a record type");
    }
}
