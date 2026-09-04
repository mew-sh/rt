//! A stream multiplexer that is wire-compatible with [xtaci/smux] v1.
//!
//! gost layers smux on top of TLS, WebSocket, KCP and QUIC to get its
//! multiplexed transports (`mtls`, `mws`, `mwss`, and the KCP/QUIC tunnels),
//! so anything that wants to talk to a gost peer has to speak smux exactly.
//!
//! # Wire format
//!
//! Every frame is an 8-byte header followed by `length` bytes of payload:
//!
//! ```text
//! 0       1       2               4                               8
//! +-------+-------+---------------+-------------------------------+
//! |  ver  |  cmd  |  length (LE)  |          sid (LE u32)         |
//! +-------+-------+---------------+-------------------------------+
//! |                        data[length]                           |
//! +---------------------------------------------------------------+
//! ```
//!
//! Both multi-byte fields are **little-endian**, and `length` precedes the
//! stream id. This is easy to get subtly wrong: the natural guess -- stream id
//! first, big-endian -- produces a codec that round-trips against itself
//! perfectly and cannot talk to gost at all.
//!
//! Verified against smux v1.5.24 (the version pinned by `gost/go.mod`):
//! `frame.go` defines `headerSize = sizeOfVer + sizeOfCmd + sizeOfSid +
//! sizeOfLength` with accessors `Version() = h[0]`, `Cmd() = h[1]`,
//! `Length() = binary.LittleEndian.Uint16(h[2:])` and
//! `StreamID() = binary.LittleEndian.Uint32(h[4:])`; `session.go`'s `sendLoop`
//! assembles the header with `PutUint16(buf[2:], len(data))` and
//! `PutUint32(buf[4:], sid)`.
//!
//! # Protocol version
//!
//! Only **v1** is implemented. v2 adds `cmdUPD` window updates and a
//! credit-based per-stream flow control loop; a session that advertised v2
//! without honouring it would stall as soon as the peer exhausted its initial
//! window guess, so [`MuxConfig::verify`] rejects version 2 outright rather
//! than misbehaving silently. The frame codec does understand `CMD_UPD` so
//! that adding v2 later is a session-layer change only.
//!
//! # Flow control (v1)
//!
//! v1 has no per-stream window. Back-pressure comes from two bounded buffers,
//! mirroring smux:
//!
//! * **Receive side** -- a session-wide token bucket of
//!   [`MuxConfig::max_receive_buffer`] bytes. `cmdPSH` payloads spend tokens
//!   when they are queued on a stream and refund them when the application
//!   reads them. When the bucket is empty the reader task stops pulling frames
//!   off the socket, which pushes back on the peer through TCP. A stream that
//!   is never read therefore cannot grow the process's memory without bound.
//! * **Send side** -- the frame queue feeding the writer task is bounded by
//!   bytes. `poll_write` parks when it is full and is woken as the writer
//!   drains it. Control frames (SYN/FIN/NOP) bypass the bound because they are
//!   8 bytes each and must never deadlock behind data.
//!
//! [xtaci/smux]: https://github.com/xtaci/smux

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// smux protocol version 1.
pub const VERSION_1: u8 = 1;
/// smux protocol version 2. Recognised by the codec, not implemented by
/// [`MuxSession`]; see the module docs.
pub const VERSION_2: u8 = 2;

/// Open a stream.
pub const CMD_SYN: u8 = 0;
/// Close a stream / EOF marker.
pub const CMD_FIN: u8 = 1;
/// Data push.
pub const CMD_PSH: u8 = 2;
/// No-op, used for keepalive.
pub const CMD_NOP: u8 = 3;
/// v2 only: window update, `|4B consumed|4B window|`.
pub const CMD_UPD: u8 = 4;

/// `ver(1) + cmd(1) + length(2) + sid(4)`.
pub const HEADER_SIZE: usize = 8;

/// Payload size of a `CMD_UPD` frame (`szCmdUPD` in smux).
pub const UPD_SIZE: usize = 8;

/// smux's `DefaultConfig().MaxFrameSize`: the largest payload this session
/// will put in a single frame. Larger writes are split across frames.
pub const MAX_FRAME_SIZE: usize = 32768;

/// Hard protocol ceiling on a payload: `length` is a `u16`.
pub const MAX_FRAME_DATA: usize = u16::MAX as usize;

/// smux's `defaultAcceptBacklog`.
const DEFAULT_ACCEPT_BACKLOG: usize = 1024;

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------

/// A decoded smux frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxHeader {
    pub version: u8,
    pub cmd: u8,
    pub length: u16,
    pub sid: u32,
}

impl MuxHeader {
    /// Serialises the header exactly as smux's `sendLoop` does.
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0] = self.version;
        out[1] = self.cmd;
        out[2..4].copy_from_slice(&self.length.to_le_bytes());
        out[4..8].copy_from_slice(&self.sid.to_le_bytes());
        out
    }

    /// The inverse of [`MuxHeader::encode`], matching smux's `rawHeader`
    /// accessors.
    pub fn decode(buf: &[u8; HEADER_SIZE]) -> Self {
        Self {
            version: buf[0],
            cmd: buf[1],
            length: u16::from_le_bytes([buf[2], buf[3]]),
            sid: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        }
    }
}

/// A complete smux frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxFrame {
    pub version: u8,
    pub cmd: u8,
    pub sid: u32,
    pub data: Vec<u8>,
}

impl MuxFrame {
    /// A frame with no payload -- SYN, FIN and NOP are always empty.
    pub fn new(version: u8, cmd: u8, sid: u32) -> Self {
        Self {
            version,
            cmd,
            sid,
            data: Vec::new(),
        }
    }

    pub fn with_data(version: u8, cmd: u8, sid: u32, data: Vec<u8>) -> Self {
        Self {
            version,
            cmd,
            sid,
            data,
        }
    }

    pub fn header(&self) -> MuxHeader {
        MuxHeader {
            version: self.version,
            cmd: self.cmd,
            length: self.data.len() as u16,
            sid: self.sid,
        }
    }

    pub fn encoded_len(&self) -> usize {
        HEADER_SIZE + self.data.len()
    }

    /// Appends the encoded frame to `out`.
    ///
    /// Fails if the payload exceeds [`MAX_FRAME_DATA`], because `length` would
    /// truncate and desynchronise the peer's parser.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> io::Result<()> {
        if self.data.len() > MAX_FRAME_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "smux: frame payload {} exceeds the {}-byte protocol limit",
                    self.data.len(),
                    MAX_FRAME_DATA
                ),
            ));
        }
        out.extend_from_slice(&self.header().encode());
        out.extend_from_slice(&self.data);
        Ok(())
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Decodes one frame from the front of `buf`.
    ///
    /// Returns `Ok(None)` when `buf` does not yet hold a whole frame, and
    /// `Ok(Some((frame, consumed)))` otherwise.
    pub fn decode(buf: &[u8]) -> io::Result<Option<(MuxFrame, usize)>> {
        if buf.len() < HEADER_SIZE {
            return Ok(None);
        }
        let mut raw = [0u8; HEADER_SIZE];
        raw.copy_from_slice(&buf[..HEADER_SIZE]);
        let header = MuxHeader::decode(&raw);

        // SYN/FIN/NOP never carry a payload on the wire, so smux does not read
        // one for them; doing so here would desynchronise against a real peer.
        let want = match header.cmd {
            CMD_PSH | CMD_UPD => header.length as usize,
            CMD_SYN | CMD_FIN | CMD_NOP => 0,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("smux: invalid protocol, unknown command {other}"),
                ))
            }
        };

        if buf.len() < HEADER_SIZE + want {
            return Ok(None);
        }
        Ok(Some((
            MuxFrame {
                version: header.version,
                cmd: header.cmd,
                sid: header.sid,
                data: buf[HEADER_SIZE..HEADER_SIZE + want].to_vec(),
            },
            HEADER_SIZE + want,
        )))
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Mirrors smux's `Config`; [`MuxConfig::default`] is `smux.DefaultConfig()`.
#[derive(Debug, Clone)]
pub struct MuxConfig {
    /// Protocol version. Only [`VERSION_1`] is implemented; gost takes this
    /// from `?smuxver=`.
    pub version: u8,
    pub keep_alive_disabled: bool,
    pub keep_alive_interval: Duration,
    pub keep_alive_timeout: Duration,
    /// Largest payload put in one frame; larger writes are split.
    pub max_frame_size: usize,
    /// Session-wide receive credit in bytes. This is the v1 back-pressure
    /// knob: the reader stops draining the socket once it is spent.
    pub max_receive_buffer: usize,
    /// Per-stream receive window. Carried for parity with `smux.Config` and
    /// validated the same way, but only v2's `cmdUPD` flow control consults
    /// it, so it has no effect on a v1 session.
    pub max_stream_buffer: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            version: VERSION_1,
            keep_alive_disabled: false,
            keep_alive_interval: Duration::from_secs(10),
            keep_alive_timeout: Duration::from_secs(30),
            max_frame_size: MAX_FRAME_SIZE,
            max_receive_buffer: 4 * 1024 * 1024,
            max_stream_buffer: 65536,
        }
    }
}

impl MuxConfig {
    pub fn with_version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// smux's `VerifyConfig`, plus a hard rejection of v2.
    pub fn verify(&self) -> io::Result<()> {
        if self.version != VERSION_1 && self.version != VERSION_2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("smux: unsupported protocol version {}", self.version),
            ));
        }
        if self.version == VERSION_2 {
            // Advertising v2 without sending cmdUPD window updates would let
            // the peer write until its initial window guess ran out and then
            // hang forever. Refusing is the honest failure mode.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "smux: protocol version 2 is not implemented, use version 1",
            ));
        }
        if !self.keep_alive_disabled {
            if self.keep_alive_interval.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "smux: keep-alive interval must be positive",
                ));
            }
            if self.keep_alive_timeout < self.keep_alive_interval {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "smux: keep-alive timeout must be larger than keep-alive interval",
                ));
            }
        }
        if self.max_frame_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "smux: max frame size must be positive",
            ));
        }
        if self.max_frame_size > MAX_FRAME_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "smux: max frame size must not be larger than 65535",
            ));
        }
        if self.max_receive_buffer == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "smux: max receive buffer must be positive",
            ));
        }
        if self.max_stream_buffer == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "smux: max stream buffer must be positive",
            ));
        }
        if self.max_stream_buffer > self.max_receive_buffer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "smux: max stream buffer must not be larger than max receive buffer",
            ));
        }
        Ok(())
    }

    /// Bytes of PSH payload the send queue will hold before `poll_write`
    /// parks.
    fn send_queue_limit(&self) -> usize {
        self.max_frame_size.saturating_mul(8).max(65536)
    }
}

// ---------------------------------------------------------------------------
// Outbound frame queue
// ---------------------------------------------------------------------------

struct WriteQueueState {
    /// NOP keepalives. Unbounded (they are 8 bytes) and written first so a
    /// stalled data queue cannot starve the keepalive.
    ctrl: VecDeque<MuxFrame>,
    /// SYN, PSH and FIN, in per-stream order. SYN/FIN bypass `limit`.
    data: VecDeque<MuxFrame>,
    data_bytes: usize,
    pushed: u64,
    written: u64,
    closed: bool,
    space_wakers: Vec<Waker>,
    flush_wakers: Vec<Waker>,
}

struct WriteQueue {
    state: Mutex<WriteQueueState>,
    ready: Notify,
    limit: usize,
}

impl WriteQueue {
    fn new(limit: usize) -> Self {
        Self {
            state: Mutex::new(WriteQueueState {
                ctrl: VecDeque::new(),
                data: VecDeque::new(),
                data_bytes: 0,
                pushed: 0,
                written: 0,
                closed: false,
                space_wakers: Vec::new(),
                flush_wakers: Vec::new(),
            }),
            ready: Notify::new(),
            limit,
        }
    }

    fn push_ctrl(&self, frame: MuxFrame) -> bool {
        {
            let mut st = self.state.lock().unwrap();
            if st.closed {
                return false;
            }
            st.ctrl.push_back(frame);
            st.pushed += 1;
        }
        self.ready.notify_one();
        true
    }

    /// Queues a frame regardless of the byte limit, returning its sequence
    /// number for [`WriteQueue::poll_flushed`]. Used for the 8-byte SYN and
    /// FIN, which must keep their position relative to the stream's PSH
    /// frames and must never block.
    fn force_push_data(&self, frame: MuxFrame) -> io::Result<u64> {
        let seq = {
            let mut st = self.state.lock().unwrap();
            if st.closed {
                return Err(closed_err());
            }
            st.data_bytes += frame.data.len();
            st.data.push_back(frame);
            st.pushed += 1;
            st.pushed
        };
        self.ready.notify_one();
        Ok(seq)
    }

    /// Ready once the queue has room for another data frame.
    fn poll_reserve(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut st = self.state.lock().unwrap();
        if st.closed {
            return Poll::Ready(Err(closed_err()));
        }
        if st.data_bytes < self.limit {
            return Poll::Ready(Ok(()));
        }
        register(&mut st.space_wakers, cx);
        Poll::Pending
    }

    /// Ready once every frame queued up to and including `seq` has been
    /// written to the transport and flushed.
    fn poll_flushed(&self, cx: &mut Context<'_>, seq: u64) -> Poll<io::Result<()>> {
        let mut st = self.state.lock().unwrap();
        if st.written >= seq {
            return Poll::Ready(Ok(()));
        }
        if st.closed {
            return Poll::Ready(Err(closed_err()));
        }
        register(&mut st.flush_wakers, cx);
        Poll::Pending
    }

    /// Drains everything currently queued, control frames first.
    fn take_batch(&self) -> Option<Vec<MuxFrame>> {
        let mut st = self.state.lock().unwrap();
        if st.ctrl.is_empty() && st.data.is_empty() {
            return None;
        }
        let mut batch = Vec::with_capacity(st.ctrl.len() + st.data.len());
        batch.extend(st.ctrl.drain(..));
        batch.extend(st.data.drain(..));
        st.data_bytes = 0;
        let wakers = std::mem::take(&mut st.space_wakers);
        drop(st);
        wake_all(wakers);
        Some(batch)
    }

    fn mark_written(&self, count: u64) {
        let mut st = self.state.lock().unwrap();
        st.written += count;
        let wakers = std::mem::take(&mut st.flush_wakers);
        drop(st);
        wake_all(wakers);
    }

    fn close(&self) {
        let (space, flush) = {
            let mut st = self.state.lock().unwrap();
            if st.closed {
                return;
            }
            st.closed = true;
            (
                std::mem::take(&mut st.space_wakers),
                std::mem::take(&mut st.flush_wakers),
            )
        };
        wake_all(space);
        wake_all(flush);
        self.ready.notify_one();
    }

    fn is_closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }
}

fn register(wakers: &mut Vec<Waker>, cx: &Context<'_>) {
    if !wakers.iter().any(|w| w.will_wake(cx.waker())) {
        wakers.push(cx.waker().clone());
    }
}

fn wake_all(wakers: Vec<Waker>) {
    for w in wakers {
        w.wake();
    }
}

fn closed_err() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "smux: session closed")
}

// ---------------------------------------------------------------------------
// Per-stream shared state
// ---------------------------------------------------------------------------

struct StreamState {
    chunks: VecDeque<Vec<u8>>,
    /// Read offset into `chunks.front()`.
    head: usize,
    buffered: usize,
    /// Peer sent FIN: reads see EOF once `chunks` drains.
    fin: bool,
    /// Session died.
    dead: bool,
    read_waker: Option<Waker>,
}

struct StreamShared {
    id: u32,
    state: Mutex<StreamState>,
}

impl StreamShared {
    fn new(id: u32) -> Self {
        Self {
            id,
            state: Mutex::new(StreamState {
                chunks: VecDeque::new(),
                head: 0,
                buffered: 0,
                fin: false,
                dead: false,
                read_waker: None,
            }),
        }
    }

    fn push_bytes(&self, data: Vec<u8>) {
        let waker = {
            let mut st = self.state.lock().unwrap();
            st.buffered += data.len();
            st.chunks.push_back(data);
            st.read_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn set_fin(&self) {
        let waker = {
            let mut st = self.state.lock().unwrap();
            st.fin = true;
            st.read_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn set_dead(&self) {
        let waker = {
            let mut st = self.state.lock().unwrap();
            st.dead = true;
            st.read_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Discards any queued bytes and reports how many tokens to refund.
    fn recycle(&self) -> usize {
        let mut st = self.state.lock().unwrap();
        let n = st.buffered;
        st.chunks.clear();
        st.head = 0;
        st.buffered = 0;
        n
    }
}

// ---------------------------------------------------------------------------
// Session shared state
// ---------------------------------------------------------------------------

struct SessionShared {
    config: MuxConfig,
    streams: Mutex<HashMap<u32, Arc<StreamShared>>>,
    next_stream_id: Mutex<u32>,
    go_away: AtomicBool,
    closed: AtomicBool,
    error: Mutex<Option<(io::ErrorKind, String)>>,
    /// Session-wide receive credit, in bytes. See the module docs.
    bucket: AtomicI64,
    bucket_notify: Notify,
    /// Set by the reader on every header it decodes; cleared and inspected by
    /// the keepalive task.
    data_ready: AtomicBool,
    queue: Arc<WriteQueue>,
}

impl SessionShared {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn error(&self) -> io::Error {
        match &*self.error.lock().unwrap() {
            Some((kind, msg)) => io::Error::new(*kind, msg.clone()),
            None => closed_err(),
        }
    }

    /// Tears the session down, recording `err` as the cause if this is the
    /// first failure. Idempotent.
    fn fail(&self, err: io::Error) {
        {
            let mut slot = self.error.lock().unwrap();
            if slot.is_none() {
                *slot = Some((err.kind(), err.to_string()));
            }
        }
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        tracing::debug!("smux session closed: {}", err);
        self.queue.close();
        let streams: Vec<Arc<StreamShared>> = self
            .streams
            .lock()
            .unwrap()
            .drain()
            .map(|(_, s)| s)
            .collect();
        for s in streams {
            s.set_dead();
        }
        // Unpark the reader if it is waiting for receive credit.
        self.bucket_notify.notify_waiters();
        self.bucket_notify.notify_one();
    }

    /// smux's `OpenStream` id allocation: client ids start at 1 and server ids
    /// at 0, and each open pre-increments by 2. So the first client stream is
    /// 3 and the first server stream is 2 -- client ids are always odd, server
    /// ids always even, which is how the two ends avoid colliding.
    fn next_id(&self) -> io::Result<u32> {
        if self.go_away.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "smux: stream id overflow, no more streams",
            ));
        }
        let mut guard = self.next_stream_id.lock().unwrap();
        let sid = guard.wrapping_add(2);
        *guard = sid;
        // `sid == sid % 2` is only true for 0 and 1, i.e. the counter wrapped.
        if sid == sid % 2 {
            self.go_away.store(true, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "smux: stream id overflow, no more streams",
            ));
        }
        Ok(sid)
    }

    fn spend_tokens(&self, n: usize) {
        self.bucket.fetch_sub(n as i64, Ordering::AcqRel);
    }

    fn return_tokens(&self, n: usize) {
        if n == 0 {
            return;
        }
        let old = self.bucket.fetch_add(n as i64, Ordering::AcqRel);
        if old <= 0 && old + n as i64 > 0 {
            self.bucket_notify.notify_one();
        }
    }

    fn remove_stream(&self, sid: u32) -> Option<Arc<StreamShared>> {
        self.streams.lock().unwrap().remove(&sid)
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// A multiplexed smux session over a single transport.
///
/// The session is not generic over the transport: the stream is split and
/// moved into background tasks at construction, so nothing of `S` is left to
/// name. That keeps `MuxSession` storable in a connector or chain node without
/// threading a transport type parameter through it.
pub struct MuxSession {
    shared: Arc<SessionShared>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<MuxStream>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl MuxSession {
    /// Client end of a session: odd stream ids.
    pub fn client<S>(stream: S, config: MuxConfig) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new(stream, config, true)
    }

    /// Server end of a session: even stream ids.
    pub fn server<S>(stream: S, config: MuxConfig) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new(stream, config, false)
    }

    fn new<S>(stream: S, config: MuxConfig, is_client: bool) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        config.verify()?;

        let queue = Arc::new(WriteQueue::new(config.send_queue_limit()));
        let bucket = AtomicI64::new(config.max_receive_buffer as i64);
        let keep_alive = if config.keep_alive_disabled {
            None
        } else {
            Some((config.keep_alive_interval, config.keep_alive_timeout))
        };

        let shared = Arc::new(SessionShared {
            streams: Mutex::new(HashMap::new()),
            next_stream_id: Mutex::new(if is_client { 1 } else { 0 }),
            go_away: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            error: Mutex::new(None),
            bucket,
            bucket_notify: Notify::new(),
            data_ready: AtomicBool::new(false),
            queue: queue.clone(),
            config,
        });

        let (accept_tx, accept_rx) = mpsc::channel(DEFAULT_ACCEPT_BACKLOG);
        let (reader, writer) = tokio::io::split(stream);

        let mut tasks = Vec::with_capacity(3);
        tasks.push(tokio::spawn(reader_task(reader, shared.clone(), accept_tx)));
        tasks.push(tokio::spawn(writer_task(writer, shared.clone())));
        if let Some((interval, timeout)) = keep_alive {
            tasks.push(tokio::spawn(keepalive_task(
                shared.clone(),
                interval,
                timeout,
            )));
        }

        Ok(Self {
            shared,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            tasks: Mutex::new(tasks),
        })
    }

    /// Opens a stream and sends its SYN.
    pub async fn open_stream(&self) -> io::Result<MuxStream> {
        if self.shared.is_closed() {
            return Err(self.shared.error());
        }
        let sid = self.shared.next_id()?;
        let state = Arc::new(StreamShared::new(sid));
        self.shared
            .streams
            .lock()
            .unwrap()
            .insert(sid, state.clone());

        let version = self.shared.config.version;
        let seq = match self
            .shared
            .queue
            .force_push_data(MuxFrame::new(version, CMD_SYN, sid))
        {
            Ok(seq) => seq,
            Err(e) => {
                self.shared.remove_stream(sid);
                return Err(e);
            }
        };
        tracing::trace!(sid, "smux: opened stream");
        Ok(MuxStream::new(state, self.shared.clone(), seq))
    }

    /// Yields the next stream the peer opened, or `None` once the session is
    /// finished.
    pub async fn accept_stream(&self) -> Option<MuxStream> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv().await
    }

    pub fn is_closed(&self) -> bool {
        self.shared.is_closed()
    }

    /// The error that ended the session, if it has ended.
    pub fn error(&self) -> Option<io::Error> {
        if self.shared.is_closed() {
            Some(self.shared.error())
        } else {
            None
        }
    }

    /// Number of live streams.
    pub fn num_streams(&self) -> usize {
        self.shared.streams.lock().unwrap().len()
    }

    pub fn config(&self) -> &MuxConfig {
        &self.shared.config
    }

    /// Ends the session and every stream on it.
    pub fn close(&self) {
        self.shared.fail(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "smux: session closed",
        ));
        for task in self.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
    }
}

impl Drop for MuxSession {
    fn drop(&mut self) {
        self.close();
    }
}

impl std::fmt::Debug for MuxSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxSession")
            .field("version", &self.shared.config.version)
            .field("closed", &self.is_closed())
            .field("streams", &self.num_streams())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------------

async fn reader_task<R>(
    mut reader: R,
    shared: Arc<SessionShared>,
    accept_tx: mpsc::Sender<MuxStream>,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut header = [0u8; HEADER_SIZE];
    let mut upd = [0u8; UPD_SIZE];

    loop {
        // Receive-side back-pressure: stop draining the socket while the
        // session's buffers are full, so an unread stream stalls the peer
        // instead of growing our heap.
        while shared.bucket.load(Ordering::Acquire) <= 0 {
            if shared.is_closed() {
                return;
            }
            shared.bucket_notify.notified().await;
            if shared.is_closed() {
                return;
            }
        }

        if let Err(e) = reader.read_exact(&mut header).await {
            shared.fail(e);
            return;
        }
        shared.data_ready.store(true, Ordering::Release);

        let hdr = MuxHeader::decode(&header);
        if hdr.version != shared.config.version {
            shared.fail(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("smux: invalid protocol version {}", hdr.version),
            ));
            return;
        }

        match hdr.cmd {
            CMD_NOP => {}
            CMD_SYN => {
                let existing = shared.streams.lock().unwrap().contains_key(&hdr.sid);
                if !existing {
                    let state = Arc::new(StreamShared::new(hdr.sid));
                    shared
                        .streams
                        .lock()
                        .unwrap()
                        .insert(hdr.sid, state.clone());
                    let stream = MuxStream::new(state, shared.clone(), 0);
                    tracing::trace!(sid = hdr.sid, "smux: accepted stream");
                    if !deliver_accept(&accept_tx, stream, &shared).await {
                        return;
                    }
                }
            }
            CMD_FIN => {
                let stream = shared.streams.lock().unwrap().get(&hdr.sid).cloned();
                if let Some(s) = stream {
                    s.set_fin();
                }
            }
            CMD_PSH => {
                let len = hdr.length as usize;
                if len > 0 {
                    let mut data = vec![0u8; len];
                    if let Err(e) = reader.read_exact(&mut data).await {
                        shared.fail(e);
                        return;
                    }
                    let stream = shared.streams.lock().unwrap().get(&hdr.sid).cloned();
                    if let Some(s) = stream {
                        // Only bytes actually queued spend credit, so frames
                        // for a closed stream cannot leak tokens.
                        shared.spend_tokens(len);
                        s.push_bytes(data);
                    }
                }
            }
            CMD_UPD => {
                // v2 window update. A v1 peer never sends these; consume the
                // payload anyway so a stray frame cannot desynchronise us.
                if let Err(e) = reader.read_exact(&mut upd).await {
                    shared.fail(e);
                    return;
                }
            }
            other => {
                shared.fail(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("smux: invalid protocol, unknown command {other}"),
                ));
                return;
            }
        }
    }
}

/// Hands a newly accepted stream to [`MuxSession::accept_stream`]. Returns
/// `false` when the reader task should stop.
async fn deliver_accept(
    tx: &mpsc::Sender<MuxStream>,
    stream: MuxStream,
    shared: &Arc<SessionShared>,
) -> bool {
    let mut pending = stream;
    loop {
        match tx.try_send(pending) {
            Ok(()) => return true,
            Err(mpsc::error::TrySendError::Closed(_)) => return false,
            Err(mpsc::error::TrySendError::Full(s)) => {
                // The backlog is 1024 deep, so this only happens when the
                // application has stopped accepting entirely. Wait rather than
                // dropping the stream, but stay responsive to session death.
                if shared.is_closed() {
                    return false;
                }
                pending = s;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

async fn writer_task<W>(mut writer: W, shared: Arc<SessionShared>)
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let queue = shared.queue.clone();
    let mut out: Vec<u8> = Vec::with_capacity(HEADER_SIZE + MAX_FRAME_SIZE);

    loop {
        let batch = loop {
            if let Some(batch) = queue.take_batch() {
                break batch;
            }
            if queue.is_closed() {
                let _ = writer.shutdown().await;
                return;
            }
            queue.ready.notified().await;
        };

        out.clear();
        let count = batch.len() as u64;
        for frame in &batch {
            if let Err(e) = frame.encode_into(&mut out) {
                shared.fail(e);
                return;
            }
        }

        if let Err(e) = writer.write_all(&out).await {
            shared.fail(e);
            return;
        }
        if let Err(e) = writer.flush().await {
            shared.fail(e);
            return;
        }
        queue.mark_written(count);
    }
}

async fn keepalive_task(shared: Arc<SessionShared>, interval: Duration, timeout: Duration) {
    let mut ping = tokio::time::interval(interval);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut deadline = tokio::time::interval(timeout);
    deadline.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // `interval` fires immediately on the first tick; drop those.
    ping.tick().await;
    deadline.tick().await;

    loop {
        tokio::select! {
            _ = ping.tick() => {
                if !shared.queue.push_ctrl(MuxFrame::new(shared.config.version, CMD_NOP, 0)) {
                    return;
                }
                // smux notifies the bucket here so a session whose receive
                // credit is exhausted still re-checks liveness.
                shared.bucket_notify.notify_one();
            }
            _ = deadline.tick() => {
                if !shared.data_ready.swap(false, Ordering::AcqRel) {
                    // Nothing arrived for a whole timeout window. Only treat
                    // that as death if we were actually willing to read: an
                    // empty bucket means *we* stopped reading, not the peer.
                    if shared.bucket.load(Ordering::Acquire) > 0 {
                        shared.fail(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "smux: keepalive timeout",
                        ));
                        return;
                    }
                }
            }
        }
        if shared.is_closed() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

/// One multiplexed stream. Implements [`AsyncRead`] + [`AsyncWrite`], so it
/// drops straight into `ProxyConn`.
pub struct MuxStream {
    id: u32,
    state: Arc<StreamShared>,
    session: Arc<SessionShared>,
    version: u8,
    frame_size: usize,
    /// Sequence number of the last frame this stream queued, for `poll_flush`.
    last_push: u64,
    fin_sent: bool,
}

impl MuxStream {
    fn new(state: Arc<StreamShared>, session: Arc<SessionShared>, last_push: u64) -> Self {
        let version = session.config.version;
        let frame_size = session.config.max_frame_size;
        Self {
            id: state.id,
            state,
            session,
            version,
            frame_size,
            last_push,
            fin_sent: false,
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    /// True once the peer sent FIN or the session died.
    pub fn is_closed(&self) -> bool {
        let st = self.state.state.lock().unwrap();
        st.fin || st.dead || self.session.is_closed()
    }

    fn send_fin(&mut self) {
        if self.fin_sent {
            return;
        }
        self.fin_sent = true;
        // FIN goes on the data queue so it keeps its place behind this
        // stream's pending PSH frames rather than overtaking them.
        if let Ok(seq) =
            self.session
                .queue
                .force_push_data(MuxFrame::new(self.version, CMD_FIN, self.id))
        {
            self.last_push = seq;
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut st = me.state.state.lock().unwrap();
        let mut copied = 0usize;
        loop {
            if buf.remaining() == 0 {
                break;
            }
            let (n, chunk_done) = match st.chunks.front() {
                None => break,
                Some(front) => {
                    let avail = &front[st.head..];
                    let n = avail.len().min(buf.remaining());
                    buf.put_slice(&avail[..n]);
                    (n, st.head + n == front.len())
                }
            };
            st.head += n;
            st.buffered -= n;
            copied += n;
            if chunk_done {
                st.chunks.pop_front();
                st.head = 0;
            }
        }

        if copied > 0 {
            drop(st);
            // Refund the session's receive credit now that the application has
            // taken the bytes; this is what unblocks the reader task.
            me.session.return_tokens(copied);
            return Poll::Ready(Ok(()));
        }

        // Buffer empty. FIN wins over session death so a half-closed stream
        // still reports a clean EOF.
        if st.fin {
            return Poll::Ready(Ok(()));
        }
        if st.dead || me.session.is_closed() {
            return Poll::Ready(Err(me.session.error()));
        }
        st.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if me.fin_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux: stream is closed for writing",
            )));
        }
        if me.session.is_closed() {
            return Poll::Ready(Err(me.session.error()));
        }
        if me.state.state.lock().unwrap().dead {
            return Poll::Ready(Err(me.session.error()));
        }

        // Send-side back-pressure: park until the writer has drained enough of
        // the queue. This is what stops a fast writer from buffering without
        // bound when the peer stops reading.
        match me.session.queue.poll_reserve(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }

        // A write larger than the frame size becomes several PSH frames; we
        // report one frame's worth per call and let the caller loop.
        let n = buf.len().min(me.frame_size);
        let frame = MuxFrame::with_data(me.version, CMD_PSH, me.id, buf[..n].to_vec());
        match me.session.queue.force_push_data(frame) {
            Ok(seq) => {
                me.last_push = seq;
                Poll::Ready(Ok(n))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        me.session.queue.poll_flushed(cx, me.last_push)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if !me.fin_sent {
            if me.session.is_closed() {
                me.fin_sent = true;
                return Poll::Ready(Ok(()));
            }
            me.send_fin();
        }
        match me.session.queue.poll_flushed(cx, me.last_push) {
            // The session dying after the FIN was queued is not a shutdown
            // failure worth reporting.
            Poll::Ready(Err(_)) => Poll::Ready(Ok(())),
            other => other,
        }
    }
}

impl std::fmt::Debug for MuxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxStream")
            .field("id", &self.id)
            .field("fin_sent", &self.fin_sent)
            .finish()
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        self.send_fin();
        if self.session.remove_stream(self.id).is_some() {
            // Anything still queued on this stream will never be read, so give
            // its receive credit back to the session.
            let refund = self.state.recycle();
            self.session.return_tokens(refund);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // -- Frame codec: byte-exact against the smux v1.5.24 wire format. -------
    //
    // These assertions use hardcoded bytes on purpose. The implementation this
    // replaced round-tripped against itself perfectly and was still unable to
    // talk to gost, because it used a 7-byte big-endian header with a flags
    // bitmask. Only literal expected bytes catch that.

    #[test]
    fn test_syn_header_bytes() {
        // ver=1, cmd=SYN(0), length=0, sid=3 (first client stream).
        let frame = MuxFrame::new(VERSION_1, CMD_SYN, 3);
        assert_eq!(
            frame.encode().unwrap(),
            vec![0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_fin_header_bytes() {
        // sid = 258 = 0x0000_0102 -> little-endian 02 01 00 00.
        let frame = MuxFrame::new(VERSION_1, CMD_FIN, 258);
        assert_eq!(
            frame.encode().unwrap(),
            vec![0x01, 0x01, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn test_nop_header_bytes() {
        // The keepalive frame gost's peers expect: sid 0, no payload.
        let frame = MuxFrame::new(VERSION_1, CMD_NOP, 0);
        assert_eq!(
            frame.encode().unwrap(),
            vec![0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_psh_frame_bytes() {
        // sid = 0x01020304 -> LE 04 03 02 01; length 5 -> LE 05 00.
        let frame = MuxFrame::with_data(VERSION_1, CMD_PSH, 0x0102_0304, b"hello".to_vec());
        assert_eq!(
            frame.encode().unwrap(),
            vec![0x01, 0x02, 0x05, 0x00, 0x04, 0x03, 0x02, 0x01, b'h', b'e', b'l', b'l', b'o',]
        );
    }

    #[test]
    fn test_length_field_is_little_endian_and_precedes_sid() {
        // 0x0102 = 258 bytes of payload. Big-endian would put 0x01 first.
        let frame = MuxFrame::with_data(VERSION_1, CMD_PSH, 0xAABB_CCDD, vec![0x5A; 0x0102]);
        let bytes = frame.encode().unwrap();
        assert_eq!(
            &bytes[..HEADER_SIZE],
            &[0x01, 0x02, 0x02, 0x01, 0xDD, 0xCC, 0xBB, 0xAA]
        );
        assert_eq!(bytes.len(), HEADER_SIZE + 0x0102);
    }

    #[test]
    fn test_v2_upd_frame_bytes() {
        // v2 window update payload is |4B consumed LE|4B window LE|.
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u32.to_le_bytes());
        payload.extend_from_slice(&65536u32.to_le_bytes());
        let frame = MuxFrame::with_data(VERSION_2, CMD_UPD, 7, payload);
        assert_eq!(
            frame.encode().unwrap(),
            vec![
                0x02, 0x04, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, // header
                0xE8, 0x03, 0x00, 0x00, // consumed = 1000
                0x00, 0x00, 0x01, 0x00, // window = 65536
            ]
        );
    }

    #[test]
    fn test_decode_from_hardcoded_wire_bytes() {
        // A PSH frame produced by a real smux v1 peer.
        let wire = [
            0x01u8, 0x02, 0x03, 0x00, 0x39, 0x30, 0x00, 0x00, b'a', b'b', b'c',
        ];
        let (frame, used) = MuxFrame::decode(&wire).unwrap().unwrap();
        assert_eq!(used, 11);
        assert_eq!(frame.version, 1);
        assert_eq!(frame.cmd, CMD_PSH);
        assert_eq!(frame.sid, 0x3039); // 12345
        assert_eq!(frame.data, b"abc");

        let hdr = MuxHeader::decode(&[0x01, 0x02, 0x03, 0x00, 0x39, 0x30, 0x00, 0x00]);
        assert_eq!(hdr.length, 3);
        assert_eq!(hdr.sid, 12345);
    }

    #[test]
    fn test_decode_needs_more_bytes() {
        assert!(MuxFrame::decode(&[0x01, 0x02, 0x03]).unwrap().is_none());
        // Header says 5 payload bytes but only 2 are present.
        let partial = [0x01u8, 0x02, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, b'h', b'i'];
        assert!(MuxFrame::decode(&partial).unwrap().is_none());
    }

    #[test]
    fn test_decode_rejects_unknown_command() {
        let bad = [0x01u8, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        assert!(MuxFrame::decode(&bad).is_err());
    }

    #[test]
    fn test_encode_rejects_oversized_payload() {
        let frame = MuxFrame::with_data(VERSION_1, CMD_PSH, 1, vec![0u8; MAX_FRAME_DATA + 1]);
        assert!(frame.encode().is_err());
    }

    // -- Config -------------------------------------------------------------

    #[test]
    fn test_default_config_matches_smux() {
        let c = MuxConfig::default();
        assert_eq!(c.version, 1);
        assert_eq!(c.keep_alive_interval, Duration::from_secs(10));
        assert_eq!(c.keep_alive_timeout, Duration::from_secs(30));
        assert_eq!(c.max_frame_size, 32768);
        assert_eq!(c.max_receive_buffer, 4194304);
        assert_eq!(c.max_stream_buffer, 65536);
        c.verify().unwrap();
    }

    #[test]
    fn test_config_rejects_unsupported_versions() {
        // v2 is understood by the codec but not implemented by the session, so
        // it must be refused rather than silently misbehave.
        let v2 = MuxConfig::default().with_version(2);
        let err = v2.verify().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);

        let v3 = MuxConfig::default().with_version(3);
        assert_eq!(v3.verify().unwrap_err().kind(), io::ErrorKind::InvalidInput);

        let (_a, b) = tokio::io::duplex(64);
        assert!(MuxSession::client(b, MuxConfig::default().with_version(2)).is_err());
    }

    #[test]
    fn test_config_rejects_bad_keepalive_and_sizes() {
        let mut c = MuxConfig::default();
        c.keep_alive_timeout = Duration::from_secs(1);
        assert!(c.verify().is_err());

        let mut c = MuxConfig::default();
        c.max_frame_size = 70000;
        assert!(c.verify().is_err());

        let mut c = MuxConfig::default();
        c.max_stream_buffer = c.max_receive_buffer + 1;
        assert!(c.verify().is_err());
    }

    // -- Helpers ------------------------------------------------------------

    fn test_config() -> MuxConfig {
        // Keepalive off unless a test is specifically about it, so slow CI
        // cannot flake the data tests.
        MuxConfig {
            keep_alive_disabled: true,
            ..MuxConfig::default()
        }
    }

    /// A client/server session pair joined by an in-memory duplex.
    fn pair() -> (MuxSession, MuxSession) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = MuxSession::client(a, test_config()).unwrap();
        let server = MuxSession::server(b, test_config()).unwrap();
        (client, server)
    }

    /// Reads exactly one frame off a raw transport.
    async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> MuxFrame {
        let mut hdr = [0u8; HEADER_SIZE];
        r.read_exact(&mut hdr).await.unwrap();
        let h = MuxHeader::decode(&hdr);
        let want = match h.cmd {
            CMD_PSH | CMD_UPD => h.length as usize,
            _ => 0,
        };
        let mut data = vec![0u8; want];
        if want > 0 {
            r.read_exact(&mut data).await.unwrap();
        }
        MuxFrame {
            version: h.version,
            cmd: h.cmd,
            sid: h.sid,
            data,
        }
    }

    // -- Session ------------------------------------------------------------

    #[tokio::test]
    async fn test_open_accept_and_roundtrip() {
        let (client, server) = pair();

        let mut c = client.open_stream().await.unwrap();
        c.write_all(b"ping").await.unwrap();
        c.flush().await.unwrap();

        let mut s = server.accept_stream().await.unwrap();
        assert_eq!(s.id(), c.id());

        let mut got = [0u8; 4];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");

        s.write_all(b"pong").await.unwrap();
        s.flush().await.unwrap();
        let mut back = [0u8; 4];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");
    }

    #[tokio::test]
    async fn test_client_and_server_stream_id_parity() {
        // Read the SYNs straight off the wire so the ids being asserted are
        // the ones a gost peer would actually see.
        let (mut wire, transport) = tokio::io::duplex(64 * 1024);
        let client = MuxSession::client(transport, test_config()).unwrap();

        let a = client.open_stream().await.unwrap();
        let b = client.open_stream().await.unwrap();
        // smux: nextStreamID starts at 1 and pre-increments by 2.
        assert_eq!(a.id(), 3);
        assert_eq!(b.id(), 5);
        assert!(a.id() % 2 == 1 && b.id() % 2 == 1, "client ids must be odd");

        let f1 = read_frame(&mut wire).await;
        assert_eq!((f1.cmd, f1.sid), (CMD_SYN, 3));
        let f2 = read_frame(&mut wire).await;
        assert_eq!((f2.cmd, f2.sid), (CMD_SYN, 5));
        drop(client);

        let (mut wire, transport) = tokio::io::duplex(64 * 1024);
        let server = MuxSession::server(transport, test_config()).unwrap();
        let a = server.open_stream().await.unwrap();
        let b = server.open_stream().await.unwrap();
        assert_eq!(a.id(), 2);
        assert_eq!(b.id(), 4);
        assert!(
            a.id() % 2 == 0 && b.id() % 2 == 0,
            "server ids must be even"
        );

        let f1 = read_frame(&mut wire).await;
        assert_eq!((f1.cmd, f1.sid), (CMD_SYN, 2));
        let f2 = read_frame(&mut wire).await;
        assert_eq!((f2.cmd, f2.sid), (CMD_SYN, 4));
    }

    #[tokio::test]
    async fn test_two_streams_do_not_interleave() {
        let (client, server) = pair();
        let client = Arc::new(client);
        let server = Arc::new(server);

        // Echo everything the peer opens.
        let srv = server.clone();
        let echo = tokio::spawn(async move {
            let mut tasks = Vec::new();
            for _ in 0..2 {
                let mut s = srv.accept_stream().await.unwrap();
                tasks.push(tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }));
            }
            for t in tasks {
                let _ = t.await;
            }
        });

        // Two streams writing distinct, easily-corrupted patterns at once.
        let mut handles = Vec::new();
        for (tag, len) in [(b'A', 40_000usize), (b'B', 55_000usize)] {
            let cl = client.clone();
            handles.push(tokio::spawn(async move {
                let payload: Vec<u8> = (0..len).map(|i| tag ^ (i % 251) as u8).collect();
                let mut st = cl.open_stream().await.unwrap();
                let expect = payload.clone();
                let writer = tokio::spawn(async move {
                    st.write_all(&payload).await.unwrap();
                    st.flush().await.unwrap();
                    let mut got = vec![0u8; expect.len()];
                    st.read_exact(&mut got).await.unwrap();
                    assert_eq!(got, expect, "stream {} was corrupted", tag as char);
                });
                writer.await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), echo).await;
    }

    #[tokio::test]
    async fn test_large_payload_is_split_and_reassembled() {
        // First: verify on the raw wire that the split actually happens and
        // that no frame exceeds MAX_FRAME_SIZE.
        let (mut wire, transport) = tokio::io::duplex(1024 * 1024);
        let client = MuxSession::client(transport, test_config()).unwrap();
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 253) as u8).collect();

        let mut st = client.open_stream().await.unwrap();
        let p = payload.clone();
        let writer = tokio::spawn(async move {
            st.write_all(&p).await.unwrap();
            st.flush().await.unwrap();
            st
        });

        let syn = read_frame(&mut wire).await;
        assert_eq!(syn.cmd, CMD_SYN);

        let mut reassembled = Vec::new();
        let mut frames = 0;
        while reassembled.len() < payload.len() {
            let f = read_frame(&mut wire).await;
            assert_eq!(f.cmd, CMD_PSH);
            assert_eq!(f.sid, syn.sid);
            assert!(
                f.data.len() <= MAX_FRAME_SIZE,
                "frame of {} bytes exceeds MAX_FRAME_SIZE",
                f.data.len()
            );
            reassembled.extend_from_slice(&f.data);
            frames += 1;
        }
        assert_eq!(reassembled, payload);
        assert_eq!(frames, 100_000usize.div_ceil(MAX_FRAME_SIZE));
        let _ = writer.await;
        drop(client);

        // Second: end to end through a real session pair.
        let (client, server) = pair();
        let mut c = client.open_stream().await.unwrap();
        let p = payload.clone();
        let send = tokio::spawn(async move {
            c.write_all(&p).await.unwrap();
            c.flush().await.unwrap();
            c
        });
        let mut s = server.accept_stream().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
        let _ = send.await;
    }

    #[tokio::test]
    async fn test_fin_closes_one_stream_only() {
        let (client, server) = pair();

        let mut c1 = client.open_stream().await.unwrap();
        let mut c2 = client.open_stream().await.unwrap();
        c1.write_all(b"one").await.unwrap();
        c2.write_all(b"two").await.unwrap();
        c1.flush().await.unwrap();
        c2.flush().await.unwrap();

        let mut s1 = server.accept_stream().await.unwrap();
        let mut s2 = server.accept_stream().await.unwrap();
        let mut buf = [0u8; 3];
        s1.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"one");
        s2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"two");

        // FIN stream 1 only.
        c1.shutdown().await.unwrap();
        let n = s1.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "FIN must surface as EOF on that stream");

        // The session and the other stream keep working.
        assert!(!client.is_closed());
        assert!(!server.is_closed());
        c2.write_all(b"still here").await.unwrap();
        c2.flush().await.unwrap();
        let mut buf2 = [0u8; 10];
        s2.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"still here");

        // And a brand new stream can still be opened afterwards.
        let mut c3 = client.open_stream().await.unwrap();
        c3.write_all(b"third").await.unwrap();
        c3.flush().await.unwrap();
        let mut s3 = server.accept_stream().await.unwrap();
        let mut buf3 = [0u8; 5];
        s3.read_exact(&mut buf3).await.unwrap();
        assert_eq!(&buf3, b"third");
    }

    #[tokio::test]
    async fn test_dropping_a_stream_sends_fin() {
        let (mut wire, transport) = tokio::io::duplex(64 * 1024);
        let client = MuxSession::client(transport, test_config()).unwrap();

        let st = client.open_stream().await.unwrap();
        let sid = st.id();
        assert_eq!(read_frame(&mut wire).await.cmd, CMD_SYN);
        drop(st);

        let fin = read_frame(&mut wire).await;
        assert_eq!((fin.cmd, fin.sid), (CMD_FIN, sid));
        assert_eq!(client.num_streams(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_keepalive_sends_nop_frames() {
        let (mut wire, transport) = tokio::io::duplex(64 * 1024);
        let config = MuxConfig {
            keep_alive_interval: Duration::from_millis(100),
            keep_alive_timeout: Duration::from_millis(10_000),
            ..MuxConfig::default()
        };
        let _client = MuxSession::client(transport, config).unwrap();

        let nop = read_frame(&mut wire).await;
        assert_eq!(nop.cmd, CMD_NOP);
        assert_eq!(nop.sid, 0);
        assert!(nop.data.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_keepalive_timeout_fails_the_session() {
        // The peer end stays open but never sends anything, so the only thing
        // that can end this session is the keepalive deadline.
        let (_peer, transport) = tokio::io::duplex(64 * 1024);
        let config = MuxConfig {
            keep_alive_interval: Duration::from_millis(100),
            keep_alive_timeout: Duration::from_millis(300),
            ..MuxConfig::default()
        };
        let client = MuxSession::client(transport, config).unwrap();
        let mut stream = client.open_stream().await.unwrap();

        assert!(!client.is_closed());

        tokio::time::sleep(Duration::from_millis(1000)).await;

        assert!(
            client.is_closed(),
            "session must fail after keepalive timeout"
        );
        assert_eq!(
            client.error().unwrap().kind(),
            io::ErrorKind::TimedOut,
            "the session must fail for the keepalive reason, not a socket error"
        );

        // Streams on a dead session must report the failure, not hang.
        let mut buf = [0u8; 4];
        assert!(stream.read(&mut buf).await.is_err());
        assert!(stream.write_all(b"nope").await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn test_keepalive_does_not_fire_while_traffic_flows() {
        let config = MuxConfig {
            keep_alive_interval: Duration::from_millis(100),
            keep_alive_timeout: Duration::from_millis(300),
            ..MuxConfig::default()
        };
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = MuxSession::client(a, config.clone()).unwrap();
        let server = MuxSession::server(b, config).unwrap();

        // Both ends ping each other, so data_ready keeps getting set.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            !client.is_closed(),
            "keepalive traffic must keep the session alive"
        );
        assert!(!server.is_closed());
    }

    #[tokio::test]
    async fn test_session_close_ends_all_streams() {
        let (client, server) = pair();
        let mut c1 = client.open_stream().await.unwrap();
        let mut c2 = client.open_stream().await.unwrap();
        c1.write_all(b"x").await.unwrap();
        c1.flush().await.unwrap();
        let _s1 = server.accept_stream().await.unwrap();

        client.close();
        assert!(client.is_closed());

        let mut buf = [0u8; 8];
        assert!(c1.read(&mut buf).await.is_err());
        assert!(c2.read(&mut buf).await.is_err());
        assert!(client.open_stream().await.is_err());
    }

    #[tokio::test]
    async fn test_accept_returns_none_after_close() {
        let (client, server) = pair();
        drop(client);
        // The transport dies with the client, so the server's reader task
        // errors out and the accept channel closes.
        let got = tokio::time::timeout(Duration::from_secs(2), server.accept_stream()).await;
        assert!(
            matches!(got, Ok(None)),
            "accept must terminate, got {got:?}"
        );
    }

    #[tokio::test]
    async fn test_receive_credit_is_returned_after_reading() {
        let cfg = MuxConfig {
            keep_alive_disabled: true,
            max_receive_buffer: 128 * 1024,
            ..MuxConfig::default()
        };
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = MuxSession::client(a, cfg.clone()).unwrap();
        let server = MuxSession::server(b, cfg.clone()).unwrap();

        let payload = vec![7u8; 200_000];
        let mut c = client.open_stream().await.unwrap();
        let p = payload.clone();
        let send = tokio::spawn(async move {
            c.write_all(&p).await.unwrap();
            c.flush().await.unwrap();
            c
        });

        let mut s = server.accept_stream().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        // Would deadlock if credit were never refunded: the payload is larger
        // than the whole receive buffer.
        tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got))
            .await
            .expect("credit was not returned")
            .unwrap();
        assert_eq!(got, payload);
        let _ = send.await;
    }

    #[tokio::test]
    async fn test_unread_stream_does_not_grow_without_bound() {
        // A stream nobody reads must stall the sender rather than buffer
        // everything in memory.
        let cfg = MuxConfig {
            keep_alive_disabled: true,
            max_receive_buffer: 64 * 1024,
            ..MuxConfig::default()
        };
        let (a, b) = tokio::io::duplex(16 * 1024);
        let client = MuxSession::client(a, cfg.clone()).unwrap();
        let server = MuxSession::server(b, cfg).unwrap();

        let mut c = client.open_stream().await.unwrap();
        let _s = server.accept_stream().await.unwrap(); // accepted, never read

        let written = Arc::new(AtomicI64::new(0));
        let w = written.clone();
        let pump = tokio::spawn(async move {
            let chunk = vec![0u8; 8192];
            loop {
                if c.write_all(&chunk).await.is_err() {
                    break;
                }
                w.fetch_add(chunk.len() as i64, Ordering::Relaxed);
            }
        });

        tokio::time::sleep(Duration::from_millis(300)).await;
        let n = written.load(Ordering::Relaxed);
        pump.abort();
        // Bounded by receive buffer + send queue + duplex buffer, all of which
        // are well under a megabyte here.
        assert!(n < 4 * 1024 * 1024, "writer was never throttled: {n} bytes");
    }

    #[tokio::test]
    async fn test_partial_reads_across_poll_calls() {
        let (client, server) = pair();
        let mut c = client.open_stream().await.unwrap();
        c.write_all(b"abcdefghij").await.unwrap();
        c.flush().await.unwrap();

        let mut s = server.accept_stream().await.unwrap();
        // Read one byte at a time: exercises the chunk head cursor.
        let mut out = Vec::new();
        for _ in 0..10 {
            let mut one = [0u8; 1];
            s.read_exact(&mut one).await.unwrap();
            out.push(one[0]);
        }
        assert_eq!(out, b"abcdefghij");
    }

    #[tokio::test]
    async fn test_wire_bytes_of_a_live_session_are_smux_v1() {
        // End-to-end byte check: everything a session emits for a trivial
        // exchange, compared against literal expected bytes.
        let (mut wire, transport) = tokio::io::duplex(64 * 1024);
        let client = MuxSession::client(transport, test_config()).unwrap();

        let mut st = client.open_stream().await.unwrap();
        st.write_all(b"hi").await.unwrap();
        st.flush().await.unwrap();
        st.shutdown().await.unwrap();

        let mut got = vec![0u8; 8 + 10 + 8];
        wire.read_exact(&mut got).await.unwrap();
        assert_eq!(
            got,
            vec![
                // SYN sid=3
                0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // PSH sid=3 len=2 "hi"
                0x01, 0x02, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, b'h', b'i', // FIN sid=3
                0x01, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[tokio::test]
    async fn test_bad_version_kills_the_session() {
        let (mut wire, transport) = tokio::io::duplex(1024);
        let server = MuxSession::server(transport, test_config()).unwrap();

        // A v2 header on a v1 session is a protocol error in smux.
        wire.write_all(&[0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
            .await
            .unwrap();
        wire.flush().await.unwrap();

        let got = tokio::time::timeout(Duration::from_secs(2), server.accept_stream()).await;
        assert!(matches!(got, Ok(None)));
        assert!(server.is_closed());
        assert_eq!(server.error().unwrap().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_stream_drops_into_proxy_conn() {
        // The whole point of the AsyncRead + AsyncWrite + Unpin + Send bound:
        // a mux stream has to be usable anywhere a handler expects a socket.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MuxSession>();

        let (client, server) = pair();
        let c = client.open_stream().await.unwrap();
        let mut conn = crate::conn::ProxyConn::new(Box::new(c), None, None);
        conn.write_all(b"through ProxyConn").await.unwrap();
        conn.flush().await.unwrap();

        let mut s = server.accept_stream().await.unwrap();
        let mut got = [0u8; 17];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"through ProxyConn");
    }

    #[tokio::test]
    async fn test_many_streams_stay_independent() {
        let (client, server) = pair();
        let server = Arc::new(server);

        let srv = server.clone();
        let echo = tokio::spawn(async move {
            while let Some(mut s) = srv.accept_stream().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        for i in 0..16u32 {
            let mut st = client.open_stream().await.unwrap();
            let msg = format!("stream-{i}");
            st.write_all(msg.as_bytes()).await.unwrap();
            st.flush().await.unwrap();
            let mut got = vec![0u8; msg.len()];
            tokio::time::timeout(Duration::from_secs(5), st.read_exact(&mut got))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, msg.as_bytes());
        }

        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(2), echo).await;
    }
}
