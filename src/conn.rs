//! A transport-agnostic connection type.
//!
//! Handlers used to take a concrete `TcpStream`, which is why none of the
//! transports in this crate (TLS, WebSocket, KCP, QUIC, ...) could ever be
//! wired to them: a `TlsStream` is not a `TcpStream`, so `-L http+tls://`
//! had nowhere to deliver its accepted connection and silently served
//! plaintext instead.
//!
//! `ProxyConn` erases the underlying stream behind a trait object while
//! carrying the two things handlers actually needed the concrete type for:
//! the peer and local addresses. Transports that wrap a TCP socket pass those
//! addresses through, so a handler behaves identically whether it is reading
//! from a raw socket or from a TLS session on top of one.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Any bidirectional byte stream a handler can serve.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// A connection handed to a [`Handler`](crate::handler::Handler).
pub struct ProxyConn {
    inner: Box<dyn AsyncStream>,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    /// The pre-NAT destination, captured at accept time on a transparent
    /// proxy listener. Reading it needs the raw socket, which is no longer
    /// reachable once the stream is boxed, so the listener records it.
    original_dst: Option<SocketAddr>,
    /// Bytes read ahead of the handler, replayed before the inner stream.
    prefix: Vec<u8>,
    prefix_pos: usize,
}

impl ProxyConn {
    pub fn new(
        inner: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            inner,
            peer_addr,
            local_addr,
            original_dst: None,
            prefix: Vec::new(),
            prefix_pos: 0,
        }
    }

    /// Wraps a TCP socket, recording its addresses.
    pub fn from_tcp(stream: TcpStream) -> Self {
        let peer_addr = stream.peer_addr().ok();
        let local_addr = stream.local_addr().ok();
        Self::new(Box::new(stream), peer_addr, local_addr)
    }

    /// Wraps a stream layered on top of an accepted TCP socket, keeping the
    /// underlying socket's addresses so handlers still see the real client.
    pub fn layered(
        inner: Box<dyn AsyncStream>,
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
    ) -> Self {
        Self::new(inner, peer_addr, local_addr)
    }

    pub fn with_original_dst(mut self, addr: Option<SocketAddr>) -> Self {
        self.original_dst = addr;
        self
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn original_dst(&self) -> Option<SocketAddr> {
        self.original_dst
    }

    /// The peer address for logging, or `"unknown"` when the transport has none.
    pub fn peer_addr_str(&self) -> String {
        self.peer_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn local_addr_str(&self) -> String {
        self.local_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Reads ahead without consuming, so protocol detection works on any
    /// transport. `TcpStream::peek` only exists on TCP sockets; this buffers
    /// the bytes and replays them on the next read instead.
    pub async fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use tokio::io::AsyncReadExt;

        while self.buffered().len() < buf.len() {
            let mut chunk = vec![0u8; buf.len() - self.buffered().len()];
            let n = self.inner.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            self.prefix.extend_from_slice(&chunk[..n]);
        }

        let available = self.buffered();
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }

    /// Pushes bytes back so the next read returns them first.
    pub fn unread(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut merged = Vec::with_capacity(bytes.len() + self.buffered().len());
        merged.extend_from_slice(bytes);
        merged.extend_from_slice(self.buffered());
        self.prefix = merged;
        self.prefix_pos = 0;
    }

    fn buffered(&self) -> &[u8] {
        &self.prefix[self.prefix_pos..]
    }
}

impl AsyncRead for ProxyConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // Anything peeked or pushed back is delivered before the inner stream.
        if me.prefix_pos < me.prefix.len() {
            let available = &me.prefix[me.prefix_pos..];
            let n = buf.remaining().min(available.len());
            buf.put_slice(&available[..n]);
            me.prefix_pos += n;
            if me.prefix_pos == me.prefix.len() {
                me.prefix.clear();
                me.prefix_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn conn_from(bytes: &[u8]) -> ProxyConn {
        let (mut a, b) = tokio::io::duplex(1024);
        let owned = bytes.to_vec();
        tokio::spawn(async move {
            a.write_all(&owned).await.ok();
        });
        ProxyConn::new(Box::new(b), None, None)
    }

    #[tokio::test]
    async fn test_peek_does_not_consume() {
        let mut conn = conn_from(b"hello world");

        let mut peeked = [0u8; 5];
        let n = conn.peek(&mut peeked).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&peeked, b"hello");

        // The peeked bytes must still be readable.
        let mut all = Vec::new();
        conn.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"hello world");
    }

    #[tokio::test]
    async fn test_peek_twice_is_stable() {
        let mut conn = conn_from(b"\x05\x01\x00");
        let mut first = [0u8; 1];
        let mut second = [0u8; 1];
        conn.peek(&mut first).await.unwrap();
        conn.peek(&mut second).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(first[0], 0x05);
    }

    #[tokio::test]
    async fn test_peek_past_eof_returns_short_count() {
        let mut conn = conn_from(b"ab");
        let mut buf = [0u8; 8];
        let n = conn.peek(&mut buf).await.unwrap();
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn test_unread_replays_before_stream() {
        let mut conn = conn_from(b"world");
        conn.unread(b"hello ");

        let mut all = Vec::new();
        conn.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"hello world");
    }

    #[tokio::test]
    async fn test_addresses_survive_layering() {
        let peer: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let local: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let (_a, b) = tokio::io::duplex(64);

        let conn = ProxyConn::layered(Box::new(b), Some(peer), Some(local));
        assert_eq!(conn.peer_addr(), Some(peer));
        assert_eq!(conn.local_addr(), Some(local));
        assert_eq!(conn.peer_addr_str(), "1.2.3.4:5678");
    }

    #[tokio::test]
    async fn test_missing_addresses_render_as_unknown() {
        let (_a, b) = tokio::io::duplex(64);
        let conn = ProxyConn::new(Box::new(b), None, None);
        assert_eq!(conn.peer_addr_str(), "unknown");
        assert_eq!(conn.local_addr_str(), "unknown");
    }

    #[tokio::test]
    async fn test_write_reaches_the_inner_stream() {
        let (a, b) = tokio::io::duplex(64);
        let mut conn = ProxyConn::new(Box::new(b), None, None);
        conn.write_all(b"ping").await.unwrap();
        conn.flush().await.unwrap();

        let mut a = a;
        let mut got = [0u8; 4];
        a.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }
}
