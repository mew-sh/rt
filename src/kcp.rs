//! The KCP transport (`kcp://`), gost's kcp.go.
//!
//! KCP is an ARQ protocol over UDP: it gives an ordered, reliable byte stream
//! without TCP's congestion control, trading bandwidth for latency. gost runs
//! it through `github.com/xtaci/kcp-go/v5` and stacks four more layers on top
//! of the raw datagram. Outermost first, that stack is
//!
//! ```text
//!   smux            one session per peer, a stream per proxied request
//!   snappy          framed compression, unless ?nocomp
//!   KCP + FEC       the ARQ segments, each carrying an 8-byte FEC header
//!   block cipher    CFB over a fixed IV, with a 16-byte nonce and a CRC32
//!   UDP
//! ```
//!
//! # What is implemented here and what is borrowed
//!
//! The ARQ core — the 24-byte segment header and the retransmission state
//! machine — comes from the [`kcp`] crate. Both it and kcp-go are ports of
//! skywind3000's ikcp.c, so their segments are byte-identical: little-endian
//! `conv/cmd/frg/wnd/ts/sn/una/len`, the same four commands, the same
//! window and fast-retransmit rules. Nothing in that layer is re-derived here.
//!
//! Every layer kcp-go wraps *around* the ARQ is in this module, because no
//! Rust crate implements them:
//!
//! * [`Crypt`] — kcp-go's packet cipher (crypt.go). Not a standard mode: a
//!   16-byte random nonce and a little-endian CRC32 of everything after it are
//!   prepended, and the whole datagram is then run through CFB with the IV
//!   *fixed* for every packet (the nonce is what makes the keystream differ).
//!   The session key is `pbkdf2(key, "kcp-go", 4096, 32, sha1)`.
//! * [`FecHeader`] — the 8-byte Reed-Solomon framing (fec.go). See
//!   [`FecEncoder`] for the one deliberate gap: parity shards are framed for
//!   but not generated.
//! * [`SnappyStream`] — the snappy *framing* format that gost's
//!   `compStreamConn` (kcp.go:481-507) puts between smux and KCP. Block
//!   compression is the `snap` crate's; the chunk framing has to be driven
//!   asynchronously, so it is here.
//! * [`KcpStream`] — the async façade over the ARQ core, and the driver task
//!   that owns it.
//!
//! smux is [`crate::mux`], already verified against xtaci/smux, and the
//! session lifecycle is [`MuxHandler`] and [`MuxDialer`] from
//! [`crate::mux_transport`] verbatim: a KCP session is exactly an `mtls`
//! session with a different pipe underneath.
//!
//! # Configuration
//!
//! [`KcpConfig`] is gost's `KCPConfig` JSON, reached through `?c=file.json`.
//! Anything this module cannot honour is refused by [`KcpConfig::validate`] at
//! construction rather than ignored at runtime — a silently dropped crypto
//! option is worse than a listener that will not start. Today that is
//! `tcp: true` alone; all thirteen of gost's ciphers, both compression
//! settings and all four modes are implemented.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use cipher::{Array, Block, BlockCipherEncrypt, BlockSizeUser, KeyInit};
use rand::RngCore;
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::conn::{AsyncStream, ProxyConn};
use crate::handler::Handler;
use crate::mux::MuxConfig;
use crate::mux_transport::{
    mux_config_from_values, MuxDialer, MuxDialerPool, MuxHandler, MuxStreamConn, SessionCount,
};
use crate::node::Node;

/// The error type the rest of the crate's constructors use.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// PBKDF2 salt for the session key (`KCPSalt`, kcp.go:25).
pub const KCP_SALT: &str = "kcp-go";

/// gost's `DefaultKCPConfig.Key` (kcp.go:83), typo and all. A `kcp://` node
/// with no `?c=` config file uses it on both ends, so it is what an
/// unconfigured rt and an unconfigured gost agree on.
pub const DEFAULT_KEY: &str = "it's a secrect";

/// PBKDF2 rounds and key length for the session key (kcp.go:415).
const KEY_ROUNDS: u32 = 4096;
const KEY_LEN: usize = 32;

/// 16-byte per-packet nonce (sess.go:27).
const NONCE_SIZE: usize = 16;
/// 4-byte little-endian CRC32 of everything after it (sess.go:30).
const CRC_SIZE: usize = 4;
/// The two together are always present: gost's `blockCrypt` never returns a
/// nil `BlockCrypt`, not even for `crypt=none`, so kcp-go's "no header" path
/// is unreachable from gost (kcp.go:414-448, sess.go:33).
const CRYPT_HEADER_SIZE: usize = NONCE_SIZE + CRC_SIZE;

/// `seqid` (4) + `flag` (2) (fec.go:12).
const FEC_HEADER_SIZE: usize = 6;
/// ...plus the 2-byte payload size that sits inside the protected region
/// (fec.go:13). This is what a data shard actually costs.
const FEC_HEADER_SIZE_PLUS2: usize = FEC_HEADER_SIZE + 2;
/// Shard kinds. Chosen so they cannot be confused with a bare KCP segment:
/// bytes 4 and 5 of one are `cmd` (81-84) and `frg` (0-255), which never form
/// 0x00f1 or 0x00f2 (fec.go:15-16, sess.go:665).
const TYPE_DATA: u16 = 0xf1;
const TYPE_PARITY: u16 = 0xf2;

/// Largest datagram kcp-go will read (`mtuLimit`, sess.go:36). Anything longer
/// is truncated by its receive buffer, so nothing longer may be sent.
const MTU_LIMIT: usize = 1500;

/// The KCP segment header, `IKCP_OVERHEAD` (kcp.go:25 of kcp-go).
const IKCP_OVERHEAD: usize = kcp::KCP_OVERHEAD;
/// Offset of `sn` within a segment, used to identify a session's first packet
/// (`IKCP_SN_OFFSET`, kcp.go:31 of kcp-go).
const IKCP_SN_OFFSET: usize = 12;

/// The fixed CFB initialisation vector (crypt.go:23). Every packet starts the
/// keystream from the same place; the random nonce in the first 16 bytes is
/// what stops that from repeating.
const INITIAL_VECTOR: [u8; 16] = [
    167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107,
];

/// PBKDF2 salt for the `xor` cipher's key table (crypt.go:24).
const SALT_XOR: &str = "sH3CIVoF#rWLtJo6";

/// Snappy's stream identifier chunk, emitted once at the head of a stream.
const SNAPPY_MAGIC: [u8; 10] = [0xff, 0x06, 0x00, 0x00, b's', b'N', b'a', b'P', b'p', b'Y'];
/// Largest uncompressed payload in one snappy chunk.
const SNAPPY_MAX_BLOCK: usize = 65536;
/// Largest encoded chunk body: a full block plus its 4-byte checksum. Go's
/// `snappy.Reader` rejects anything larger, so nothing larger may be sent.
const SNAPPY_MAX_CHUNK: usize = SNAPPY_MAX_BLOCK + 4;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// KCP protocol configuration (compatible with gost's KCPConfig JSON format).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KcpConfig {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub crypt: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    #[serde(default = "default_sndwnd")]
    pub sndwnd: u32,
    #[serde(default = "default_rcvwnd")]
    pub rcvwnd: u32,
    #[serde(default = "default_datashard")]
    pub datashard: u32,
    #[serde(default = "default_parityshard")]
    pub parityshard: u32,
    #[serde(default)]
    pub dscp: u32,
    #[serde(default)]
    pub nocomp: bool,
    #[serde(default)]
    pub acknodelay: bool,
    #[serde(default)]
    pub nodelay: u32,
    #[serde(default = "default_interval")]
    pub interval: u32,
    #[serde(default)]
    pub resend: u32,
    #[serde(default)]
    pub nc: u32,
    #[serde(default = "default_sockbuf")]
    pub sockbuf: u32,
    #[serde(default)]
    pub smuxbuf: u32,
    #[serde(default)]
    pub streambuf: u32,
    #[serde(default = "default_smuxver")]
    pub smuxver: u32,
    #[serde(default = "default_keepalive")]
    pub keepalive: u32,
    #[serde(default)]
    pub tcp: bool,
}

fn default_mtu() -> u32 {
    1350
}
fn default_sndwnd() -> u32 {
    1024
}
fn default_rcvwnd() -> u32 {
    1024
}
fn default_datashard() -> u32 {
    10
}
fn default_parityshard() -> u32 {
    3
}
fn default_interval() -> u32 {
    50
}
fn default_sockbuf() -> u32 {
    4194304
}
fn default_smuxver() -> u32 {
    1
}
fn default_keepalive() -> u32 {
    10
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            // gost's `DefaultKCPConfig` (kcp.go:82-107), which is what a
            // `kcp://` node without `?c=` gets. The key matters: an empty one
            // derives a different session key and every packet a gost peer
            // sent would fail the CRC check.
            key: DEFAULT_KEY.to_string(),
            crypt: "aes".to_string(),
            mode: "fast".to_string(),
            mtu: default_mtu(),
            sndwnd: default_sndwnd(),
            rcvwnd: default_rcvwnd(),
            datashard: default_datashard(),
            parityshard: default_parityshard(),
            dscp: 0,
            nocomp: false,
            acknodelay: false,
            nodelay: 0,
            interval: default_interval(),
            resend: 0,
            nc: 0,
            sockbuf: default_sockbuf(),
            smuxbuf: 0,
            streambuf: 0,
            smuxver: default_smuxver(),
            keepalive: default_keepalive(),
            tcp: false,
        }
    }
}

impl KcpConfig {
    /// Initialize config with mode presets (matching gost behavior).
    pub fn init(&mut self) {
        match self.mode.as_str() {
            "normal" => {
                self.nodelay = 0;
                self.interval = 40;
                self.resend = 2;
                self.nc = 1;
            }
            "fast" => {
                self.nodelay = 0;
                self.interval = 30;
                self.resend = 2;
                self.nc = 1;
            }
            "fast2" => {
                self.nodelay = 1;
                self.interval = 20;
                self.resend = 2;
                self.nc = 1;
            }
            "fast3" => {
                self.nodelay = 1;
                self.interval = 10;
                self.resend = 2;
                self.nc = 1;
            }
            _ => {}
        }
        if self.smuxver == 0 {
            self.smuxver = 1;
        }
        if self.smuxbuf == 0 {
            self.smuxbuf = self.sockbuf;
        }
        if self.streambuf == 0 {
            self.streambuf = self.sockbuf / 2;
        }
    }

    /// Load KCP config from JSON file.
    ///
    /// Fields the file omits fall back to the serde defaults above, not to
    /// [`Default`] — which is also how gost behaves for everything except the
    /// numeric fields, where its zero values (`mtu: 0`) are unusable anyway.
    /// `key` is deliberately among them: gost's `parseKCPConfig` leaves it
    /// empty when the file does not set it (cfg.go:87-102).
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let mut config: KcpConfig = serde_json::from_str(&content)?;
        config.init();
        Ok(config)
    }

    /// The config for a `kcp://` node: `?c=` names a JSON file, and without one
    /// the defaults apply (route.go:190-202, route.go:426-438).
    ///
    /// `?tcp=true` is parsed so that it can be *refused*; see
    /// [`KcpConfig::validate`].
    pub fn from_node(node: &Node) -> Result<Self, BoxError> {
        let mut config = match node.get("c") {
            Some(path) if !path.is_empty() => KcpConfig::load(path)
                .map_err(|e| -> BoxError { format!("kcp: reading {}: {}", path, e).into() })?,
            _ => {
                let mut config = KcpConfig::default();
                config.tcp = node.get_bool("tcp");
                config
            }
        };
        config.init();
        config.validate()?;
        Ok(config)
    }

    /// Rejects what this module cannot honour, so a listener or dialer fails
    /// to start instead of quietly behaving differently from the peer.
    pub fn validate(&self) -> Result<(), BoxError> {
        if self.tcp {
            return Err(
                "kcp: ?tcp=true (tcpraw fake-TCP framing) is not implemented; \
                        remove it or use the ftcp:// transport"
                    .into(),
            );
        }
        if self.smuxver > 1 {
            return Err(format!(
                "kcp: smuxver={} is not implemented, only smux v1",
                self.smuxver
            )
            .into());
        }
        let reserved = CRYPT_HEADER_SIZE + self.fec_overhead();
        let mtu = self.mtu as usize;
        if mtu > MTU_LIMIT {
            return Err(format!(
                "kcp: mtu={} exceeds the {}-byte datagram a kcp-go peer will read",
                mtu, MTU_LIMIT
            )
            .into());
        }
        if mtu <= reserved + IKCP_OVERHEAD + 1 {
            return Err(format!(
                "kcp: mtu={} leaves no room for the {}-byte header and {}-byte KCP segment",
                mtu, reserved, IKCP_OVERHEAD
            )
            .into());
        }
        // Builds the cipher, which is where an unusable key length would show
        // up. Unknown names are *not* an error: gost's `blockCrypt` falls
        // through to aes for them (kcp.go:442-446), and refusing here would
        // reject a config a gost peer accepts.
        Crypt::new(&self.key, &self.crypt, KCP_SALT)?;
        // The smux half is verified on the same terms as mtls/mws/mwss.
        self.mux_config()?;
        Ok(())
    }

    /// Says out loud which half of the erasure coding is in place.
    ///
    /// Parity *is* generated now, so a kcp-go or gost peer can rebuild packets
    /// this side loses on the way out. The receive half still ignores parity
    /// shards, so losses on the way in are recovered by KCP retransmission
    /// rather than from parity — later, but not lost. Not an error, and the
    /// wire format is unchanged either way.
    fn warn_about_fec(&self) {
        if self.fec_overhead() != 0 {
            warn!(
                "[kcp] datashard={}/parityshard={}: Reed-Solomon parity is generated for \
                 outgoing packets, but incoming parity shards are not yet decoded; inbound \
                 losses are recovered by KCP retransmission instead",
                self.datashard, self.parityshard
            );
        }
    }

    /// Bytes reserved ahead of each KCP segment for the FEC header. Zero when
    /// FEC is off, which for kcp-go means either shard count being zero
    /// (fec.go:170).
    fn fec_overhead(&self) -> usize {
        if self.datashard > 0 && self.parityshard > 0 {
            FEC_HEADER_SIZE_PLUS2
        } else {
            0
        }
    }

    /// gost's smux settings for this session (kcp.go:249-256, 356-361).
    fn mux_config(&self) -> Result<MuxConfig, BoxError> {
        mux_config_from_values(
            self.smuxver,
            self.smuxbuf as usize,
            self.streambuf as usize,
            self.keepalive as u64,
        )
        .map_err(|e| -> BoxError { Box::new(e) })
    }

    /// The MTU handed to the ARQ core.
    ///
    /// kcp-go reserves the crypt and FEC headers *inside* its MTU with
    /// `ReserveBytes`, so its `mss` is `mtu - 24 - reserved` and its datagrams
    /// are at most `mtu`. The [`kcp`] crate has no reserve, so the same
    /// arithmetic is reached by handing it a smaller MTU: subtracting the
    /// reserve here gives an identical `mss` and identical datagram sizes.
    fn arq_mtu(&self) -> usize {
        self.mtu as usize - CRYPT_HEADER_SIZE - self.fec_overhead()
    }
}

// ---------------------------------------------------------------------------
// CRC32
// ---------------------------------------------------------------------------

const fn crc_table(poly: u32) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ poly
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// CRC-32/ISO-HDLC, the packet checksum (`crc32.ChecksumIEEE`, sess.go:540).
const CRC32_IEEE: [u32; 256] = crc_table(0xEDB8_8320);
/// CRC-32C, snappy's chunk checksum.
const CRC32_CASTAGNOLI: [u32; 256] = crc_table(0x82F6_3B78);

fn crc32(table: &[u32; 256], data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

fn crc32_ieee(data: &[u8]) -> u32 {
    crc32(&CRC32_IEEE, data)
}

/// snappy stores its CRC-32C rotated, so that a stream of checksums cannot be
/// mistaken for a stream of the data it covers.
fn crc32c_masked(data: &[u8]) -> u32 {
    let c = crc32(&CRC32_CASTAGNOLI, data);
    c.rotate_right(15).wrapping_add(0xa282_ead8)
}

// ---------------------------------------------------------------------------
// Block ciphers
// ---------------------------------------------------------------------------

/// The one operation kcp-go's CFB mode needs. Decryption never calls a block
/// cipher's inverse, so only the forward direction is required — which is why
/// TEA and XTEA below are ten lines each.
trait BlockEnc: Send + Sync {
    fn block_size(&self) -> usize;
    /// `block` is exactly [`BlockEnc::block_size`] bytes and is replaced.
    fn encrypt_block(&self, block: &mut [u8]);
}

/// Adapts any RustCrypto block cipher to [`BlockEnc`].
struct Rc<C>(C);

impl<C> BlockEnc for Rc<C>
where
    C: BlockCipherEncrypt + BlockSizeUser + Send + Sync,
{
    fn block_size(&self) -> usize {
        <C as BlockSizeUser>::block_size()
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        let b: &mut Block<C> = block
            .try_into()
            .expect("cfb_encrypt/cfb_decrypt pass exactly one block");
        self.0.encrypt_block(b);
    }
}

/// Go's `golang.org/x/crypto/tea` with kcp-go's 16 rounds (crypt.go:196).
struct Tea {
    k: [u32; 4],
    rounds: usize,
}

impl BlockEnc for Tea {
    fn block_size(&self) -> usize {
        8
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        let mut v0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut v1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        let delta: u32 = 0x9e37_79b9;
        let mut sum: u32 = 0;
        for _ in 0..self.rounds / 2 {
            sum = sum.wrapping_add(delta);
            v0 = v0.wrapping_add(
                ((v1 << 4).wrapping_add(self.k[0]))
                    ^ v1.wrapping_add(sum)
                    ^ ((v1 >> 5).wrapping_add(self.k[1])),
            );
            v1 = v1.wrapping_add(
                ((v0 << 4).wrapping_add(self.k[2]))
                    ^ v0.wrapping_add(sum)
                    ^ ((v0 >> 5).wrapping_add(self.k[3])),
            );
        }
        block[0..4].copy_from_slice(&v0.to_be_bytes());
        block[4..8].copy_from_slice(&v1.to_be_bytes());
    }
}

impl Tea {
    fn new(key: &[u8]) -> Self {
        let mut k = [0u32; 4];
        for (i, slot) in k.iter_mut().enumerate() {
            let j = i * 4;
            *slot = u32::from_be_bytes([key[j], key[j + 1], key[j + 2], key[j + 3]]);
        }
        Self { k, rounds: 16 }
    }
}

/// Go's `golang.org/x/crypto/xtea`, 64 rounds with a precomputed schedule.
struct Xtea {
    table: [u32; 64],
}

impl Xtea {
    fn new(key: &[u8]) -> Self {
        let mut k = [0u32; 4];
        for (i, slot) in k.iter_mut().enumerate() {
            let j = i * 4;
            *slot = u32::from_be_bytes([key[j], key[j + 1], key[j + 2], key[j + 3]]);
        }
        let delta: u32 = 0x9E37_79B9;
        let mut table = [0u32; 64];
        let mut sum: u32 = 0;
        let mut i = 0;
        while i < 64 {
            table[i] = sum.wrapping_add(k[(sum & 3) as usize]);
            i += 1;
            sum = sum.wrapping_add(delta);
            table[i] = sum.wrapping_add(k[((sum >> 11) & 3) as usize]);
            i += 1;
        }
        Self { table }
    }
}

impl BlockEnc for Xtea {
    fn block_size(&self) -> usize {
        8
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        let mut v0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut v1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        let mut i = 0;
        while i < 64 {
            v0 = v0.wrapping_add((((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ self.table[i]);
            i += 1;
            v1 = v1.wrapping_add((((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0)) ^ self.table[i]);
            i += 1;
        }
        block[0..4].copy_from_slice(&v0.to_be_bytes());
        block[4..8].copy_from_slice(&v1.to_be_bytes());
    }
}

/// kcp-go's packet cipher, `blockCrypt` (kcp.go:414-448).
///
/// Three shapes hide behind one name in kcp-go, and all three are here: a
/// block cipher in CFB, a stream cipher, and a fixed XOR table. `none` is a
/// real variant rather than "no encryption" — the nonce and checksum are still
/// written, so a `crypt=none` peer is not wire-compatible with one that skips
/// the header.
pub struct Crypt {
    kind: CryptKind,
}

enum CryptKind {
    /// Copies. gost's `NewNoneBlockCrypt`.
    None,
    /// A 1500-byte PBKDF2 table XORed over the packet.
    Xor(Vec<u8>),
    /// Salsa20 keyed by the packet's first 8 bytes, which pass through in the
    /// clear (crypt.go:50-57).
    Salsa20([u8; 32]),
    /// CFB over a fixed IV.
    Cfb(Box<dyn BlockEnc>),
}

impl Crypt {
    /// Derives the session key and builds the cipher gost's `blockCrypt`
    /// would.
    ///
    /// Unknown names fall through to aes, as in gost, rather than being
    /// refused: gost accepts them, and refusing would make rt the odd one
    /// out. It is logged, because a typo in `crypt` silently changing the
    /// algorithm is worth seeing.
    pub fn new(key: &str, crypt: &str, salt: &str) -> Result<Self, BoxError> {
        let mut pass = [0u8; KEY_LEN];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(key.as_bytes(), salt.as_bytes(), KEY_ROUNDS, &mut pass);

        let bad = |name: &str, e: cipher::InvalidLength| -> BoxError {
            format!("kcp: {} rejected its key: {}", name, e).into()
        };

        let kind = match crypt {
            "none" => CryptKind::None,
            "xor" => {
                let mut table = vec![0u8; MTU_LIMIT];
                pbkdf2::pbkdf2_hmac::<sha1::Sha1>(&pass, SALT_XOR.as_bytes(), 32, &mut table);
                CryptKind::Xor(table)
            }
            "salsa20" => CryptKind::Salsa20(pass),
            "sm4" => CryptKind::Cfb(Box::new(Rc(
                sm4::Sm4::new_from_slice(&pass[..16]).map_err(|e| bad("sm4", e))?
            ))),
            "tea" => CryptKind::Cfb(Box::new(Tea::new(&pass[..16]))),
            "xtea" => CryptKind::Cfb(Box::new(Xtea::new(&pass[..16]))),
            "aes-128" => CryptKind::Cfb(Box::new(Rc(
                aes::Aes128::new_from_slice(&pass[..16]).map_err(|e| bad("aes-128", e))?
            ))),
            "aes-192" => CryptKind::Cfb(Box::new(Rc(
                aes::Aes192::new_from_slice(&pass[..24]).map_err(|e| bad("aes-192", e))?
            ))),
            // Big-endian Blowfish, which is Go's `x/crypto/blowfish`; the
            // crate's `BlowfishLE` is a different cipher, and the byte order
            // is a defaulted type parameter that only an annotation pins down.
            "blowfish" => {
                let bf: blowfish::Blowfish =
                    blowfish::Blowfish::new_from_slice(&pass).map_err(|e| bad("blowfish", e))?;
                CryptKind::Cfb(Box::new(Rc(bf)))
            }
            "twofish" => CryptKind::Cfb(Box::new(Rc(
                twofish::Twofish::new_from_slice(&pass).map_err(|e| bad("twofish", e))?
            ))),
            "cast5" => CryptKind::Cfb(Box::new(Rc(
                cast5::Cast5::new_from_slice(&pass[..16]).map_err(|e| bad("cast5", e))?
            ))),
            "3des" => CryptKind::Cfb(Box::new(Rc(
                des::TdesEde3::new_from_slice(&pass[..24]).map_err(|e| bad("3des", e))?
            ))),
            "aes" | "" => CryptKind::Cfb(Box::new(Rc(
                aes::Aes256::new_from_slice(&pass).map_err(|e| bad("aes", e))?
            ))),
            other => {
                warn!(
                    "[kcp] crypt={:?} is not one of gost's ciphers; using aes, which is what \
                     a gost peer would also do",
                    other
                );
                CryptKind::Cfb(Box::new(Rc(
                    aes::Aes256::new_from_slice(&pass).map_err(|e| bad("aes", e))?
                )))
            }
        };
        Ok(Self { kind })
    }

    pub fn encrypt(&self, buf: &mut [u8]) {
        match &self.kind {
            CryptKind::None => {}
            CryptKind::Xor(table) => xor_in_place(buf, table),
            CryptKind::Salsa20(key) => salsa20_apply(key, buf),
            CryptKind::Cfb(block) => cfb_encrypt(block.as_ref(), buf),
        }
    }

    pub fn decrypt(&self, buf: &mut [u8]) {
        match &self.kind {
            CryptKind::None => {}
            CryptKind::Xor(table) => xor_in_place(buf, table),
            CryptKind::Salsa20(key) => salsa20_apply(key, buf),
            CryptKind::Cfb(block) => cfb_decrypt(block.as_ref(), buf),
        }
    }
}

impl std::fmt::Debug for Crypt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Crypt")
    }
}

fn xor_in_place(buf: &mut [u8], table: &[u8]) {
    for (b, t) in buf.iter_mut().zip(table.iter()) {
        *b ^= t;
    }
}

/// Salsa20 with the packet's own first 8 bytes as the nonce, left in the
/// clear. Involutive, so encryption and decryption are the same call.
fn salsa20_apply(key: &[u8; 32], buf: &mut [u8]) {
    use salsa20::cipher::{KeyIvInit, StreamCipher};
    if buf.len() <= 8 {
        return;
    }
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&buf[..8]);
    let mut c = salsa20::Salsa20::new(key.into(), (&nonce).into());
    c.apply_keystream(&mut buf[8..]);
}

/// CFB with a fixed IV (`encrypt`, crypt.go:241-250).
///
/// The keystream block is the encryption of the *previous ciphertext* block,
/// seeded with `E(INITIAL_VECTOR)`. A trailing partial block is XORed with
/// whatever keystream block is current, so the packet length is preserved
/// exactly — there is no padding.
fn cfb_encrypt(block: &dyn BlockEnc, buf: &mut [u8]) {
    let bs = block.block_size();
    let mut tbl = [0u8; 16];
    tbl[..bs].copy_from_slice(&INITIAL_VECTOR[..bs]);
    block.encrypt_block(&mut tbl[..bs]);

    let full = buf.len() / bs;
    for i in 0..full {
        let at = i * bs;
        for k in 0..bs {
            buf[at + k] ^= tbl[k];
        }
        tbl[..bs].copy_from_slice(&buf[at..at + bs]);
        block.encrypt_block(&mut tbl[..bs]);
    }
    let tail = full * bs;
    for (k, b) in buf[tail..].iter_mut().enumerate() {
        *b ^= tbl[k];
    }
}

/// The inverse of [`cfb_encrypt`] (`decrypt`, crypt.go:265-275). Still only
/// the cipher's *forward* direction: CFB decrypts by re-deriving the same
/// keystream, this time from the ciphertext it already has.
fn cfb_decrypt(block: &dyn BlockEnc, buf: &mut [u8]) {
    let bs = block.block_size();
    let mut tbl = [0u8; 16];
    tbl[..bs].copy_from_slice(&INITIAL_VECTOR[..bs]);
    block.encrypt_block(&mut tbl[..bs]);

    let full = buf.len() / bs;
    let mut next = [0u8; 16];
    for i in 0..full {
        let at = i * bs;
        next[..bs].copy_from_slice(&buf[at..at + bs]);
        block.encrypt_block(&mut next[..bs]);
        for k in 0..bs {
            buf[at + k] ^= tbl[k];
        }
        tbl[..bs].copy_from_slice(&next[..bs]);
    }
    let tail = full * bs;
    for (k, b) in buf[tail..].iter_mut().enumerate() {
        *b ^= tbl[k];
    }
}

// ---------------------------------------------------------------------------
// FEC framing
// ---------------------------------------------------------------------------

/// The 8-byte shard header: `seqid` (u32 LE), `flag` (u16 LE), `size` (u16 LE).
///
/// `size` counts itself and the payload after it, which is how a recovered
/// shard knows where the real data ends once it has been zero-padded out to
/// the longest shard in its group (fec.go:321-322, sess.go:687-691).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FecHeader {
    pub seqid: u32,
    pub flag: u16,
    pub size: u16,
}

impl FecHeader {
    fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < FEC_HEADER_SIZE_PLUS2 {
            return None;
        }
        Some(Self {
            seqid: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            flag: u16::from_le_bytes([data[4], data[5]]),
            size: u16::from_le_bytes([data[6], data[7]]),
        })
    }
}

/// Is this a shard header rather than the start of a bare KCP segment?
///
/// The same test kcp-go makes (sess.go:665): bytes 4-5 of a KCP segment are
/// `cmd` and `frg`, and `cmd` is only ever 81-84, so the value can never be
/// 0x00f1 or 0x00f2.
fn fec_flag(data: &[u8]) -> Option<u16> {
    if data.len() < FEC_HEADER_SIZE {
        return None;
    }
    let flag = u16::from_le_bytes([data[4], data[5]]);
    if flag == TYPE_DATA || flag == TYPE_PARITY {
        Some(flag)
    } else {
        None
    }
}

/// Strips the FEC framing from a decrypted packet, leaving the KCP segments.
///
/// Returns `None` for a parity shard, which carries no segments of its own.
/// Packets with no FEC header pass through: a kcp-go peer configured without
/// FEC sends them, and its own receive path accepts them either way.
fn fec_strip(data: &[u8]) -> Option<&[u8]> {
    match fec_flag(data) {
        Some(TYPE_DATA) if data.len() >= FEC_HEADER_SIZE_PLUS2 => {
            Some(&data[FEC_HEADER_SIZE_PLUS2..])
        }
        // A parity shard, or a data shard too short to hold its size field.
        Some(_) => None,
        None => Some(data),
    }
}

/// Writes the data-shard header kcp-go's receiver expects.
///
/// # What is missing
///
/// Reed-Solomon parity shards are *not* generated. Data shards are framed and
/// numbered exactly as kcp-go numbers them, and parity shards arriving from a
/// peer are recognised and discarded, so the wire format is honoured in both
/// directions — but a peer receiving from rt gets no erasure coding and
/// falls back to KCP's own retransmission for lost packets.
///
/// This is visible on a kcp-go peer only as its FEC decoder detecting that the
/// shard pattern does not match its configuration and disabling itself
/// (fec.go:76-118); the data path is unaffected, because kcp-go feeds every
/// data shard to the ARQ core whether or not its decoder is running
/// (sess.go:679-683).
struct FecEncoder {
    next: u32,
    /// `0xffffffff / shardSize * shardSize`, so the sequence wraps on a shard
    /// boundary and the peer's grid stays aligned (fec.go:298).
    paws: u32,
    datashard: usize,
    parityshard: usize,
    codec: ReedSolomon,
    /// Whole packets of the group so far, header included. kcp-go keeps the
    /// same cache and encodes over a window of it (fec.go:328-331).
    cache: Vec<Vec<u8>>,
    /// Longest packet in the group; every shard is zero-padded to it before
    /// encoding, because Reed-Solomon needs equal-sized shards.
    max_size: usize,
}

impl FecEncoder {
    fn new(datashard: u32, parityshard: u32) -> Option<Self> {
        if datashard == 0 || parityshard == 0 {
            return None;
        }
        let shard_size = datashard + parityshard;
        let codec = ReedSolomon::new(datashard as usize, parityshard as usize).ok()?;
        Some(Self {
            next: 0,
            paws: u32::MAX / shard_size * shard_size,
            datashard: datashard as usize,
            parityshard: parityshard as usize,
            codec,
            cache: Vec::with_capacity(datashard as usize),
            max_size: 0,
        })
    }

    /// Fills `header` (8 bytes) for a data shard whose payload — the size
    /// field included — is `payload_len` bytes.
    fn mark_data(&mut self, header: &mut [u8], payload_len: usize) {
        header[0..4].copy_from_slice(&self.next.to_le_bytes());
        header[4..6].copy_from_slice(&TYPE_DATA.to_le_bytes());
        header[6..8].copy_from_slice(&(payload_len as u16).to_le_bytes());
        self.next = self.next.wrapping_add(1);
        if self.next >= self.paws {
            self.next = 0;
        }
    }

    /// Stamps a parity header. Only the parity shard advances the sequence
    /// past a group boundary, which is where kcp-go applies the wrap
    /// (fec.go:382-387).
    fn mark_parity(&mut self, header: &mut [u8]) {
        header[0..4].copy_from_slice(&self.next.to_le_bytes());
        header[4..6].copy_from_slice(&TYPE_PARITY.to_le_bytes());
        self.next = (self.next + 1) % self.paws;
    }

    /// Records an outgoing data packet and, once a group is complete, returns
    /// the parity packets for it.
    ///
    /// The returned packets still need their nonce, checksum and encryption:
    /// kcp-go applies those per packet, parity included (sess.go:540-553).
    fn push(&mut self, packet: &[u8], payload_offset: usize) -> Vec<Vec<u8>> {
        self.max_size = self.max_size.max(packet.len());
        self.cache.push(packet.to_vec());
        if self.cache.len() < self.datashard {
            return Vec::new();
        }

        let max = self.max_size;
        // Equal-sized shards over the protected region only: the nonce and
        // checksum are per packet and are not covered.
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(self.datashard + self.parityshard);
        for packet in &self.cache {
            let mut shard = vec![0u8; max - payload_offset];
            let body = &packet[payload_offset..];
            shard[..body.len()].copy_from_slice(body);
            shards.push(shard);
        }
        for _ in 0..self.parityshard {
            shards.push(vec![0u8; max - payload_offset]);
        }

        let parity = match self.codec.encode(&mut shards) {
            Ok(()) => shards.split_off(self.datashard),
            Err(e) => {
                debug!("[kcp] FEC encode failed: {}", e);
                self.cache.clear();
                self.max_size = 0;
                return Vec::new();
            }
        };

        let mut out = Vec::with_capacity(self.parityshard);
        for body in parity {
            let mut packet = vec![0u8; max];
            packet[payload_offset..].copy_from_slice(&body);
            self.mark_parity(&mut packet[payload_offset - FEC_HEADER_SIZE..payload_offset]);
            out.push(packet);
        }

        self.cache.clear();
        self.max_size = 0;
        out
    }
}

// ---------------------------------------------------------------------------
// Packet framing
// ---------------------------------------------------------------------------

/// Wraps KCP segments into a datagram: FEC header, checksum, nonce, cipher.
///
/// This is gost's `UDPSession.output` (sess.go:526-553) and is the [`std::io::Write`]
/// the ARQ core writes into — one `write` call is one datagram, because the
/// core only ever hands over a complete, MTU-bounded packet.
struct PacketFramer {
    crypt: Arc<Crypt>,
    fec: Option<FecEncoder>,
    /// Finished datagrams, drained by the driver. Shared because the [`kcp`]
    /// crate owns its output and offers no way to borrow it back.
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl PacketFramer {
    /// Adds the per-packet nonce and checksum, then encrypts.
    fn seal(&self, pkt: &mut [u8]) {
        rand::thread_rng().fill_bytes(&mut pkt[..NONCE_SIZE]);
        let checksum = crc32_ieee(&pkt[CRYPT_HEADER_SIZE..]);
        pkt[NONCE_SIZE..CRYPT_HEADER_SIZE].copy_from_slice(&checksum.to_le_bytes());
        self.crypt.encrypt(pkt);
    }

    fn header_len(&self) -> usize {
        CRYPT_HEADER_SIZE
            + if self.fec.is_some() {
                FEC_HEADER_SIZE_PLUS2
            } else {
                0
            }
    }
}

impl io::Write for PacketFramer {
    fn write(&mut self, segments: &[u8]) -> io::Result<usize> {
        let header = self.header_len();
        let mut pkt = vec![0u8; header + segments.len()];
        pkt[header..].copy_from_slice(segments);

        let mut parity = Vec::new();
        if let Some(fec) = &mut self.fec {
            // The size field is inside the protected region and counts itself,
            // so it is the whole shard payload: 2 + the segments.
            let payload = 2 + segments.len();
            fec.mark_data(&mut pkt[CRYPT_HEADER_SIZE..CRYPT_HEADER_SIZE + 8], payload);
            // Parity is computed before the packet is sealed, because the
            // nonce and checksum differ per packet and must not be covered.
            parity = fec.push(&pkt, CRYPT_HEADER_SIZE + FEC_HEADER_SIZE);
        }

        self.seal(&mut pkt);
        let mut queue = self.queue.lock().unwrap();
        queue.push_back(pkt);
        for mut shard in parity {
            self.seal(&mut shard);
            queue.push_back(shard);
        }
        Ok(segments.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Undoes [`PacketFramer`] for one received datagram, in place.
///
/// Returns the offset of the KCP segments, or `None` if the packet is too
/// short, fails its checksum, or is a parity shard. A failed checksum is the
/// normal outcome for a stray datagram or one encrypted under a different key,
/// so it is not an error — kcp-go counts it and moves on (sess.go:650).
fn packet_unframe(crypt: &Crypt, buf: &mut [u8]) -> Option<std::ops::Range<usize>> {
    if buf.len() < CRYPT_HEADER_SIZE {
        return None;
    }
    crypt.decrypt(buf);
    let expected = u32::from_le_bytes([
        buf[NONCE_SIZE],
        buf[NONCE_SIZE + 1],
        buf[NONCE_SIZE + 2],
        buf[NONCE_SIZE + 3],
    ]);
    if crc32_ieee(&buf[CRYPT_HEADER_SIZE..]) != expected {
        return None;
    }
    let body = &buf[CRYPT_HEADER_SIZE..];
    let segments = fec_strip(body)?;
    if segments.len() < IKCP_OVERHEAD {
        return None;
    }
    let start = buf.len() - segments.len();
    Some(start..buf.len())
}

/// The `conv` and `sn` of a packet's first segment, used by the listener to
/// decide whether a datagram belongs to a live session or starts a new one
/// (sess.go:800-816).
fn peek_conv(segments: &[u8]) -> Option<(u32, u32)> {
    if segments.len() < IKCP_OVERHEAD {
        return None;
    }
    let conv = u32::from_le_bytes([segments[0], segments[1], segments[2], segments[3]]);
    let sn = u32::from_le_bytes([
        segments[IKCP_SN_OFFSET],
        segments[IKCP_SN_OFFSET + 1],
        segments[IKCP_SN_OFFSET + 2],
        segments[IKCP_SN_OFFSET + 3],
    ]);
    Some((conv, sn))
}

// ---------------------------------------------------------------------------
// The ARQ session driver
// ---------------------------------------------------------------------------

/// Where a session's datagrams go. The client owns its socket; every session
/// on a listener shares one.
#[derive(Clone)]
enum Wire {
    Connected(Arc<UdpSocket>),
    Peer(Arc<UdpSocket>, SocketAddr),
}

impl Wire {
    async fn send(&self, pkt: &[u8]) -> io::Result<usize> {
        match self {
            Wire::Connected(s) => s.send(pkt).await,
            Wire::Peer(s, addr) => s.send_to(pkt, *addr).await,
        }
    }
}

/// Bytes handed between the driver and the stream façade. Sized so one
/// channel slot is a useful amount of work rather than a single segment.
const DELIVER_CHUNK: usize = 32 * 1024;

/// One KCP session: an ordered, reliable byte stream over UDP.
///
/// Reads and writes are relayed to a driver task that owns the ARQ core. The
/// channels give the back-pressure a socket would: writing blocks once the
/// send window is full, and the driver stops draining the core once the reader
/// falls behind.
pub struct KcpStream {
    tx: PollSender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    pending: Option<(Vec<u8>, usize)>,
    peer: SocketAddr,
    local: SocketAddr,
    /// Bounds one `poll_write`, so a large write becomes several segments
    /// rather than one oversized allocation.
    max_write: usize,
    eof: bool,
}

impl KcpStream {
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if let Some((data, off)) = &mut me.pending {
                let n = std::cmp::min(buf.remaining(), data.len() - *off);
                buf.put_slice(&data[*off..*off + n]);
                *off += n;
                if *off == data.len() {
                    me.pending = None;
                }
                return Poll::Ready(Ok(()));
            }
            if me.eof {
                return Poll::Ready(Ok(()));
            }
            match me.rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => me.pending = Some((data, 0)),
                Poll::Ready(None) => {
                    me.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match me.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "kcp: session closed",
                )))
            }
            Poll::Pending => return Poll::Pending,
        }
        let n = std::cmp::min(buf.len(), me.max_write);
        match me.tx.send_item(buf[..n].to_vec()) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "kcp: session closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The driver flushes the ARQ core after every write it accepts
        // (gost's SetWriteDelay(false), kcp.go:230), so a queued write is
        // already on its way out.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        me.tx.close();
        Poll::Ready(Ok(()))
    }
}

impl std::fmt::Debug for KcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KcpStream")
            .field("peer", &self.peer)
            .field("local", &self.local)
            .finish()
    }
}

/// Builds a session and the task that drives it.
///
/// `inbound` carries decrypted, FEC-stripped KCP segments; the listener does
/// that work once for every session sharing its socket, exactly as kcp-go's
/// `Listener.packetInput` does (sess.go:781-798).
fn spawn_session(
    conv: u32,
    config: &KcpConfig,
    crypt: Arc<Crypt>,
    wire: Wire,
    inbound: mpsc::Receiver<Vec<u8>>,
    peer: SocketAddr,
    local: SocketAddr,
) -> io::Result<KcpStream> {
    let queue: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
    let framer = PacketFramer {
        crypt,
        fec: FecEncoder::new(config.datashard, config.parityshard),
        queue: queue.clone(),
    };

    // Stream mode, as gost sets on both ends (kcp.go:229, 345).
    let mut core = kcp::Kcp::new_stream(conv, framer);
    core.set_nodelay(
        config.nodelay != 0,
        config.interval as i32,
        config.resend as i32,
        config.nc != 0,
    );
    core.set_wndsize(
        config.sndwnd.min(u16::MAX as u32) as u16,
        config.rcvwnd.min(u16::MAX as u32) as u16,
    );
    core.set_mtu(config.arq_mtu())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let mss = core.mss();
    let (app_tx, app_rx) = mpsc::channel::<Vec<u8>>(8);
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(8);

    let driver = SessionDriver {
        core,
        queue,
        wire,
        interval: Duration::from_millis(config.interval.clamp(10, 5000) as u64),
        ack_nodelay: config.acknodelay,
        mss,
        start: Instant::now(),
    };
    tokio::spawn(driver.run(inbound, app_rx, out_tx));

    Ok(KcpStream {
        tx: PollSender::new(app_tx),
        rx: out_rx,
        pending: None,
        peer,
        local,
        max_write: DELIVER_CHUNK,
        eof: false,
    })
}

/// The task that owns the ARQ core.
///
/// The three channels are parameters of [`SessionDriver::run`] rather than
/// fields: `tokio::select!` borrows every branch's future for the whole
/// statement, so a channel living in `self` would keep `self` borrowed while
/// the branch bodies need it mutably.
struct SessionDriver {
    core: kcp::Kcp<PacketFramer>,
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    wire: Wire,
    interval: Duration,
    ack_nodelay: bool,
    mss: usize,
    start: Instant,
}

impl SessionDriver {
    fn now(&self) -> u32 {
        self.start.elapsed().as_millis() as u32
    }

    /// gost's update loop (kcp.go via kcp-go's `UDPSession.update`,
    /// sess.go): a fixed tick at the configured interval, rather than
    /// ikcp's `check`/`update` pair. kcp-go does the same, and the tick is
    /// what bounds ACK latency when `acknodelay` is off.
    async fn run(
        mut self,
        mut inbound: mpsc::Receiver<Vec<u8>>,
        mut app_rx: mpsc::Receiver<Vec<u8>>,
        out_tx: mpsc::Sender<Vec<u8>>,
    ) {
        // `flush` refuses to run before the first `update`, which is where the
        // core learns what "now" means.
        if self.core.update(self.now()).is_err() {
            return;
        }

        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Decoded bytes waiting for a slot on the way to the reader. While
        // this is `Some` the core is not drained further, which is the
        // back-pressure that eventually shrinks the window a peer sees.
        let mut deliver: Option<Vec<u8>> = None;
        let mut scratch = vec![0u8; DELIVER_CHUNK.max(MTU_LIMIT)];
        let mut writer_closed = false;

        loop {
            self.pump_out().await;

            if deliver.is_none() {
                deliver = self.drain_core(&mut scratch);
            }
            if self.core.is_dead_link() {
                debug!("[kcp] session dead-link, giving up");
                break;
            }
            // Nothing more can arrive from the application and nothing more
            // can be handed to it: the stream has been dropped at both ends.
            if writer_closed && out_tx.is_closed() {
                break;
            }

            let can_send = self.core.wait_snd() < self.core.snd_wnd() as usize;

            tokio::select! {
                biased;

                packet = inbound.recv() => match packet {
                    Some(segments) => self.input(&segments),
                    // The listener dropped this session, or the socket died.
                    None => break,
                },

                permit = out_tx.reserve(), if deliver.is_some() => match permit {
                    Ok(permit) => permit.send(deliver.take().expect("guarded by deliver.is_some")),
                    // The reader is gone. Keep running only if the writer is
                    // still around; the loop head decides when to stop.
                    Err(_) => {
                        deliver = None;
                        if writer_closed { break; }
                    }
                },

                data = app_rx.recv(), if can_send && !writer_closed => match data {
                    Some(data) => self.send(&data),
                    None => writer_closed = true,
                },

                _ = ticker.tick() => {
                    let now = self.now();
                    if self.core.update(now).is_err() {
                        break;
                    }
                }
            }
        }

        // A last flush, so an ACK or a final segment that is already formed
        // reaches the peer rather than dying with the task.
        self.pump_out().await;
    }

    /// Feeds one decrypted packet to the ARQ core.
    fn input(&mut self, segments: &[u8]) {
        if let Err(e) = self.core.input(segments) {
            // Routine: a packet from a previous session on the same address,
            // or a duplicate that arrived after the conv changed.
            debug!("[kcp] discarding a packet: {}", e);
            return;
        }
        if self.ack_nodelay {
            // gost's SetACKNoDelay: acknowledge without waiting for the tick
            // (kcp.go:234, 350).
            let _ = self.core.flush_ack();
        }
    }

    /// Hands application bytes to the ARQ core, split at the MSS the way
    /// kcp-go's `WriteBuffers` does (sess.go), then flushes because gost turns
    /// write delay off (kcp.go:230, 346).
    fn send(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let n = std::cmp::min(self.mss, data.len());
            if let Err(e) = self.core.send(&data[..n]) {
                error!("[kcp] send failed: {}", e);
                return;
            }
            data = &data[n..];
        }
        if let Err(e) = self.core.flush() {
            debug!("[kcp] flush failed: {}", e);
        }
    }

    /// Collects everything the core has reassembled into one buffer, so the
    /// reader gets a useful chunk rather than a segment at a time.
    fn drain_core(&mut self, scratch: &mut Vec<u8>) -> Option<Vec<u8>> {
        let mut out: Option<Vec<u8>> = None;
        loop {
            match self.core.recv(scratch) {
                Ok(0) => break,
                Ok(n) => {
                    let out = out.get_or_insert_with(Vec::new);
                    out.extend_from_slice(&scratch[..n]);
                    if out.len() >= DELIVER_CHUNK {
                        break;
                    }
                }
                Err(kcp::Error::UserBufTooSmall) => {
                    // A peer that is not in stream mode can reassemble a
                    // message larger than the scratch buffer.
                    scratch.resize(scratch.len() * 2, 0);
                }
                Err(_) => break,
            }
        }
        out
    }

    /// Puts every datagram the core has produced on the wire.
    async fn pump_out(&mut self) {
        loop {
            let pkt = match self.queue.lock().unwrap().pop_front() {
                Some(pkt) => pkt,
                None => return,
            };
            if let Err(e) = self.wire.send(&pkt).await {
                debug!("[kcp] datagram send failed: {}", e);
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Snappy framing
// ---------------------------------------------------------------------------

/// gost's `compStreamConn` (kcp.go:481-507): the snappy *framing* format
/// between smux and KCP, on unless `nocomp`.
///
/// The framing is a stream identifier followed by chunks, each a type byte, a
/// 3-byte little-endian length, a masked CRC-32C of the *uncompressed* bytes,
/// and the payload. A chunk is emitted uncompressed when compression does not
/// pay, which is the rule Go's writer uses and is why `hello` goes over the
/// wire verbatim.
///
/// Writes are buffered and drained on the next write or flush, so a full
/// socket never loses the bytes a caller has already been told were accepted.
pub struct SnappyStream<S> {
    inner: S,
    /// Encoded bytes not yet handed to `inner`.
    out: Vec<u8>,
    out_pos: usize,
    /// Raw bytes read from `inner` that do not yet form a whole chunk.
    in_buf: Vec<u8>,
    /// Decoded bytes not yet handed to the reader.
    dec: Vec<u8>,
    dec_pos: usize,
    /// The stream identifier has to come first, and only once.
    wrote_magic: bool,
    saw_magic: bool,
    read_eof: bool,
}

impl<S> SnappyStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            out: Vec::new(),
            out_pos: 0,
            in_buf: Vec::new(),
            dec: Vec::new(),
            dec_pos: 0,
            wrote_magic: false,
            saw_magic: false,
            read_eof: false,
        }
    }

    /// Appends one framed chunk covering `src` (at most
    /// [`SNAPPY_MAX_BLOCK`] bytes).
    fn encode_chunk(out: &mut Vec<u8>, src: &[u8]) {
        let checksum = crc32c_masked(src);
        let compressed = snap::raw::Encoder::new().compress_vec(src).ok();
        // Go's writer keeps the compressed form only when it saves more than
        // an eighth; below that the chunk goes out as-is.
        let use_compressed = match &compressed {
            Some(c) => c.len() < src.len() - src.len() / 8,
            None => false,
        };
        let (kind, body): (u8, &[u8]) = match (&compressed, use_compressed) {
            (Some(c), true) => (0x00, c),
            _ => (0x01, src),
        };
        let len = 4 + body.len();
        out.push(kind);
        out.extend_from_slice(&(len as u32).to_le_bytes()[..3]);
        out.extend_from_slice(&checksum.to_le_bytes());
        out.extend_from_slice(body);
    }

    /// Decodes whole chunks out of `in_buf` into `dec`.
    ///
    /// Returns `Ok(true)` when at least one chunk was consumed.
    fn decode_chunks(&mut self) -> io::Result<bool> {
        let mut progress = false;
        loop {
            if self.in_buf.len() < 4 {
                return Ok(progress);
            }
            let kind = self.in_buf[0];
            let len =
                u32::from_le_bytes([self.in_buf[1], self.in_buf[2], self.in_buf[3], 0]) as usize;
            if kind <= 0x01 && len > SNAPPY_MAX_CHUNK {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("snappy: {}-byte chunk exceeds the format's limit", len),
                ));
            }
            if self.in_buf.len() < 4 + len {
                return Ok(progress);
            }
            let body = self.in_buf[4..4 + len].to_vec();
            self.in_buf.drain(..4 + len);
            progress = true;

            match kind {
                // Compressed data.
                0x00 => {
                    if body.len() < 4 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snappy: compressed chunk has no checksum",
                        ));
                    }
                    let want = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                    let plain = snap::raw::Decoder::new()
                        .decompress_vec(&body[4..])
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    if plain.len() > SNAPPY_MAX_BLOCK {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snappy: block larger than the format allows",
                        ));
                    }
                    if crc32c_masked(&plain) != want {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snappy: chunk checksum mismatch",
                        ));
                    }
                    self.dec.extend_from_slice(&plain);
                }
                // Uncompressed data.
                0x01 => {
                    if body.len() < 4 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snappy: uncompressed chunk has no checksum",
                        ));
                    }
                    let want = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                    let plain = &body[4..];
                    if crc32c_masked(plain) != want {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snappy: chunk checksum mismatch",
                        ));
                    }
                    self.dec.extend_from_slice(plain);
                }
                // Stream identifier. Legal anywhere, not just at the head.
                0xff => {
                    if body != SNAPPY_MAGIC[4..] {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snappy: bad stream identifier",
                        ));
                    }
                    self.saw_magic = true;
                }
                // Reserved unskippable: the format says to give up.
                0x02..=0x7f => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("snappy: reserved chunk type {:#04x}", kind),
                    ))
                }
                // Reserved skippable.
                _ => {}
            }

            if !self.saw_magic && kind != 0xff {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snappy: data before the stream identifier",
                ));
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> SnappyStream<S> {
    /// Pushes as much of `out` to `inner` as it will take.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "snappy: the transport stopped accepting bytes",
                    )))
                }
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SnappyStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.dec_pos < me.dec.len() {
                let n = std::cmp::min(buf.remaining(), me.dec.len() - me.dec_pos);
                buf.put_slice(&me.dec[me.dec_pos..me.dec_pos + n]);
                me.dec_pos += n;
                if me.dec_pos == me.dec.len() {
                    me.dec.clear();
                    me.dec_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if me.read_eof {
                return Poll::Ready(Ok(()));
            }

            let mut scratch = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut scratch);
            match Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled().len();
                    if filled == 0 {
                        me.read_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    me.in_buf.extend_from_slice(rb.filled());
                    me.decode_chunks()?;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SnappyStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Drain first: a caller that never flushes must not be able to grow
        // the buffer without bound.
        if let Poll::Ready(Err(e)) = me.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        if me.out.len() - me.out_pos > 4 * SNAPPY_MAX_BLOCK {
            return Poll::Pending;
        }

        if !me.wrote_magic {
            me.out.extend_from_slice(&SNAPPY_MAGIC);
            me.wrote_magic = true;
        }
        let n = std::cmp::min(buf.len(), SNAPPY_MAX_BLOCK);
        Self::encode_chunk(&mut me.out, &buf[..n]);

        // Best effort: whatever is left goes out on the next call or flush.
        let _ = me.poll_drain(cx);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Puts the compression layer on a stream when the config asks for it.
fn layer_compression(stream: KcpStream, config: &KcpConfig) -> Box<dyn AsyncStream> {
    if config.nocomp {
        Box::new(stream)
    } else {
        Box::new(SnappyStream::new(stream))
    }
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

/// One live session on a listener.
struct PeerSession {
    /// Decrypted, FEC-stripped segments for this session's driver.
    tx: mpsc::Sender<Vec<u8>>,
    conv: u32,
    /// Distinguishes a session from its replacement on the same address, so a
    /// late close cannot evict the newcomer.
    id: u64,
}

/// Listener for the `kcp://` transport, gost's `kcpListener` (kcp.go:273-412).
///
/// One UDP socket serves every peer. A datagram is decrypted once, matched to
/// a session by source address, and handed to that session's driver; a
/// datagram from an unknown address with a readable `conv` starts a new one.
/// Each session becomes an smux server session, and every stream on it is
/// dispatched to the handler separately — the same shape as
/// [`MuxServer`](crate::mux_transport::MuxServer), and literally the same
/// [`MuxHandler`] doing the dispatching.
///
/// The lifecycle matches the other listeners: a [`CancellationToken`] to stop
/// accepting and a [`TaskTracker`] that [`serve`](Self::serve) drains before
/// returning.
pub struct KcpListener {
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    config: KcpConfig,
    crypt: Arc<Crypt>,
    pipeline: Arc<MuxHandler>,
    sessions: SessionCount,
    cancel: CancellationToken,
    tracker: TaskTracker,
}

impl KcpListener {
    /// Binds the socket and prepares the smux pipeline.
    ///
    /// The config is validated here, so an unimplemented option is a startup
    /// failure rather than a silent difference from the peer.
    pub async fn new(
        addr: &str,
        mut config: KcpConfig,
        handler: impl Handler + 'static,
    ) -> Result<Self, BoxError> {
        config.init();
        config.validate()?;
        config.warn_about_fec();

        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let local = socket.local_addr()?;
        let crypt = Arc::new(Crypt::new(&config.key, &config.crypt, KCP_SALT)?);

        let cancel = CancellationToken::new();
        let tracker = TaskTracker::new();
        let sessions = SessionCount::default();
        let pipeline = Arc::new(
            MuxHandler::new(handler, config.mux_config()?).with_lifecycle(
                "kcp",
                sessions.clone(),
                tracker.clone(),
                cancel.clone(),
            ),
        );

        info!("KCP listening on {} (udp)", local);

        Ok(Self {
            socket,
            local,
            config,
            crypt,
            pipeline,
            sessions,
            cancel,
            tracker,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// A handle to the number of smux sessions accepted so far, taken before
    /// [`serve`](Self::serve) consumes the listener.
    pub fn session_count(&self) -> SessionCount {
        self.sessions.clone()
    }

    /// Receives datagrams, demultiplexes them into sessions, and runs an smux
    /// server session over each.
    pub async fn serve(self) -> Result<(), BoxError> {
        let mut peers: HashMap<SocketAddr, PeerSession> = HashMap::new();
        let (closed_tx, mut closed_rx) = mpsc::channel::<(SocketAddr, u64)>(64);
        let mut next_id: u64 = 0;
        let mut buf = vec![0u8; MTU_LIMIT];

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    info!("[kcp] shutdown signal received, draining sessions...");
                    break;
                }

                Some((peer, id)) = closed_rx.recv() => {
                    if peers.get(&peer).map(|s| s.id) == Some(id) {
                        peers.remove(&peer);
                    }
                }

                result = self.socket.recv_from(&mut buf) => {
                    let (n, peer) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            // On Windows a UDP socket reports ICMP
                            // port-unreachable from a previous send as a recv
                            // error. Dropping the listener for that would be
                            // wrong, so it is logged and skipped.
                            debug!("[kcp] recv_from: {}", e);
                            continue;
                        }
                    };

                    let mut packet = buf[..n].to_vec();
                    let range = match packet_unframe(&self.crypt, &mut packet) {
                        Some(range) => range,
                        None => continue,
                    };
                    let segments = packet[range].to_vec();
                    let (conv, sn) = match peek_conv(&segments) {
                        Some(v) => v,
                        None => continue,
                    };

                    if let Some(session) = peers.get(&peer) {
                        if session.conv == conv {
                            if session.tx.try_send(segments).is_err() {
                                // Either the driver has gone or it is too far
                                // behind; a lost datagram is what KCP is for.
                                if session.tx.is_closed() {
                                    peers.remove(&peer);
                                }
                            }
                            continue;
                        }
                        if sn != 0 {
                            // A stale packet from the session this one
                            // replaced (sess.go:809-814).
                            continue;
                        }
                        peers.remove(&peer);
                    }

                    next_id += 1;
                    let id = next_id;
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
                    let stream = match spawn_session(
                        conv,
                        &self.config,
                        self.crypt.clone(),
                        Wire::Peer(self.socket.clone(), peer),
                        rx,
                        peer,
                        self.local,
                    ) {
                        Ok(stream) => stream,
                        Err(e) => {
                            error!("[kcp] {}: session setup failed: {}", peer, e);
                            continue;
                        }
                    };
                    let _ = tx.try_send(segments);
                    peers.insert(peer, PeerSession { tx, conv, id });

                    let inner = layer_compression(stream, &self.config);
                    let conn = ProxyConn::layered(inner, Some(peer), Some(self.local));
                    let pipeline = self.pipeline.clone();
                    let closed = closed_tx.clone();
                    let cancel = self.cancel.clone();

                    // The smux accept loop is this task; the streams it
                    // dispatches run on the same tracker, so shutdown drains
                    // both.
                    self.tracker.spawn(async move {
                        tokio::select! {
                            result = pipeline.handle(conn) => {
                                if let Err(e) = result {
                                    debug!("[kcp] {}: {}", peer, e);
                                }
                            }
                            _ = cancel.cancelled() => {
                                debug!("[kcp] {}: cancelled", peer);
                            }
                        }
                        let _ = closed.send((peer, id)).await;
                    });
                }
            }
        }

        drop(peers);
        self.tracker.close();
        self.tracker.wait().await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Transporter (client)
// ---------------------------------------------------------------------------

/// Client half of the `kcp://` transport, gost's `kcpTransporter`
/// (kcp.go:110-271).
///
/// gost keeps one KCP session per remote address and opens an smux stream on
/// it for every dial; so does this, by way of [`MuxDialerPool`]. A dialer that
/// built a session per request would pay for the handshake and the congestion
/// window every time and get nothing back.
pub struct KcpTransporter {
    config: KcpConfig,
    crypt: Arc<Crypt>,
    mux: MuxConfig,
    pool: MuxDialerPool,
    sessions: Arc<AtomicU64>,
}

impl KcpTransporter {
    /// Validates the config and prepares the cipher.
    ///
    /// Fails here rather than on the first dial, so an unimplemented option is
    /// reported when the chain is built.
    pub fn new(mut config: KcpConfig) -> Result<Self, BoxError> {
        config.init();
        config.validate()?;
        config.warn_about_fec();
        let crypt = Arc::new(Crypt::new(&config.key, &config.crypt, KCP_SALT)?);
        let mux = config.mux_config()?;
        Ok(Self {
            config,
            crypt,
            mux,
            pool: MuxDialerPool::new(),
            sessions: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn config(&self) -> &KcpConfig {
        &self.config
    }

    /// KCP sessions built since this transporter was created. One per remote
    /// address, unless a session died and was replaced.
    pub fn sessions_built(&self) -> u64 {
        self.sessions.load(Ordering::Relaxed)
    }

    /// The dialer for `addr`, creating it on first use.
    pub fn dialer(&self, addr: &str) -> Result<Arc<MuxDialer>, BoxError> {
        let addr = addr.to_string();
        let config = self.config.clone();
        let crypt = self.crypt.clone();
        let counter = self.sessions.clone();
        self.pool
            .get_or_create(&addr.clone(), self.mux.clone(), move || {
                let addr = addr.clone();
                let config = config.clone();
                let crypt = crypt.clone();
                let counter = counter.clone();
                async move {
                    let stream = kcp_connect(&addr, &config, crypt).await?;
                    counter.fetch_add(1, Ordering::Relaxed);
                    Ok::<_, BoxError>(layer_compression(stream, &config))
                }
            })
    }

    /// Opens a stream on the session for `addr`, building the session first if
    /// there is none or the cached one is dead.
    pub async fn dial(&self, addr: &str) -> Result<MuxStreamConn, BoxError> {
        self.dialer(addr)?.dial().await
    }

    /// Drops the session for `addr`, ending every stream on it.
    pub fn remove(&self, addr: &str) -> Option<Arc<MuxDialer>> {
        self.pool.remove(addr)
    }

    pub fn len(&self) -> usize {
        self.pool.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }
}

impl std::fmt::Debug for KcpTransporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KcpTransporter")
            .field("crypt", &self.config.crypt)
            .field("mode", &self.config.mode)
            .field("sessions_built", &self.sessions_built())
            .finish()
    }
}

/// Builds one KCP session towards `addr` on a socket of its own.
///
/// The socket is bound to the wildcard address of the remote's family and
/// connected, so the driver can `send` rather than `send_to` and the kernel
/// filters out datagrams from anyone else.
pub async fn kcp_connect(
    addr: &str,
    config: &KcpConfig,
    crypt: Arc<Crypt>,
) -> Result<KcpStream, BoxError> {
    let remote = tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| -> BoxError { format!("kcp: {} resolved to nothing", addr).into() })?;

    let bind: SocketAddr = if remote.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    socket.connect(remote).await?;
    let local = socket.local_addr()?;

    // kcp-go's client picks a random conversation id; the server learns it
    // from the first packet (sess.go's NewConn2).
    let conv = rand::random::<u32>();
    let (tx, rx) = mpsc::channel::<Vec<u8>>(256);

    let stream = spawn_session(
        conv,
        config,
        crypt.clone(),
        Wire::Connected(socket.clone()),
        rx,
        remote,
        local,
    )?;

    // One reader per client session: decrypt, strip the FEC framing, and hand
    // the segments to the driver. Ends when the driver's receiver is dropped.
    tokio::spawn(async move {
        let mut buf = vec![0u8; MTU_LIMIT];
        loop {
            let n = match socket.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    debug!("[kcp] client recv: {}", e);
                    // An ICMP-driven error on Windows must not end the
                    // session; a genuinely dead socket ends it via the
                    // channel below.
                    if tx.is_closed() {
                        return;
                    }
                    continue;
                }
            };
            let mut packet = buf[..n].to_vec();
            let range = match packet_unframe(&crypt, &mut packet) {
                Some(range) => range,
                None => continue,
            };
            let segments = packet[range].to_vec();
            if tx.send(segments).await.is_err() {
                return;
            }
        }
    });

    Ok(stream)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::HandlerError;
    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Anything that hangs would block the whole (single-threaded) run, so
    /// reads are bounded and fail loudly instead.
    const READ_TIMEOUT: Duration = Duration::from_secs(15);

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The plaintext the Go reference vectors below were taken over.
    fn sample(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    // -- configuration -----------------------------------------------------

    #[test]
    fn test_kcp_config_default() {
        let config = KcpConfig::default();
        assert_eq!(config.mtu, 1350);
        assert_eq!(config.mode, "fast");
        assert_eq!(config.sndwnd, 1024);
    }

    #[test]
    fn test_kcp_config_default_key_is_gosts() {
        // gost's DefaultKCPConfig.Key, typo included (kcp.go:83). An empty key
        // here would derive a different session key and every packet from an
        // unconfigured gost peer would fail its checksum.
        assert_eq!(KcpConfig::default().key, "it's a secrect");
    }

    #[test]
    fn test_kcp_config_init_modes() {
        let mut config = KcpConfig::default();

        config.mode = "normal".to_string();
        config.init();
        assert_eq!(config.nodelay, 0);
        assert_eq!(config.interval, 40);

        config.mode = "fast3".to_string();
        config.init();
        assert_eq!(config.nodelay, 1);
        assert_eq!(config.interval, 10);
    }

    #[test]
    fn test_kcp_config_json_parse() {
        let json = r#"{
            "key": "secret",
            "crypt": "aes",
            "mode": "fast2",
            "mtu": 1400,
            "sndwnd": 2048,
            "rcvwnd": 2048,
            "tcp": true
        }"#;

        let config: KcpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.key, "secret");
        assert_eq!(config.crypt, "aes");
        assert_eq!(config.mode, "fast2");
        assert_eq!(config.mtu, 1400);
        assert!(config.tcp);
    }

    #[test]
    fn test_kcp_config_json_roundtrip() {
        let config = KcpConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: KcpConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mtu, config.mtu);
        assert_eq!(parsed.mode, config.mode);
    }

    #[test]
    fn test_unimplemented_options_are_refused_not_ignored() {
        let mut config = KcpConfig::default();
        config.tcp = true;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("tcp"), "unhelpful error: {}", err);

        let mut config = KcpConfig::default();
        config.smuxver = 2;
        assert!(config.validate().is_err());

        // An MTU a kcp-go peer would truncate.
        let mut config = KcpConfig::default();
        config.mtu = 4000;
        assert!(config.validate().is_err());

        // An MTU with no room for the headers.
        let mut config = KcpConfig::default();
        config.mtu = 40;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_arq_mtu_matches_kcp_gos_reserved_layout() {
        // kcp-go: mss = mtu - IKCP_OVERHEAD - reserved, reserved = 20 + 8.
        let config = KcpConfig::default();
        assert_eq!(config.fec_overhead(), FEC_HEADER_SIZE_PLUS2);
        assert_eq!(config.arq_mtu(), 1350 - 20 - 8);
        assert_eq!(config.arq_mtu() - IKCP_OVERHEAD, 1350 - 24 - 28);

        let mut nofec = KcpConfig::default();
        nofec.parityshard = 0;
        assert_eq!(nofec.fec_overhead(), 0);
        assert_eq!(nofec.arq_mtu(), 1350 - 20);
    }

    // -- checksums ---------------------------------------------------------

    #[test]
    fn test_crc32_check_values() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(&CRC32_CASTAGNOLI, b"123456789"), 0xE306_9283);
    }

    // -- ciphers, against vectors produced by kcp-go itself ------------------

    /// Every vector below is `blockCrypt(...).Encrypt` from
    /// github.com/xtaci/kcp-go/v5 v5.6.7, keyed exactly as gost keys it:
    /// `pbkdf2("it's a secrect", "kcp-go", 4096, 32, sha1)`. Lengths 24, 28,
    /// 45, 64 and 130 straddle both block sizes so the partial-block tail is
    /// exercised in each.
    const GO_VECTORS: &[(&str, usize, &str)] = &[
        ("aes", 24, "86834343335b168ca911bf584a05f9900e1c6fda2c822a98"),
        ("aes", 28, "86834343335b168ca911bf584a05f9900e1c6fda2c822a981eb60909"),
        ("aes", 45, "86834343335b168ca911bf584a05f9900e1c6fda2c822a981eb60909411c15690afb116b0d6073935dd1a399f9"),
        ("aes", 64, "86834343335b168ca911bf584a05f9900e1c6fda2c822a981eb60909411c15690afb116b0d6073935dd1a399f9e6a343eb991b6b55bd85e3327d8f0db0a23918"),
        ("aes-128", 45, "ddd7e0a7981ba3e2a7f6d51f2a2663184531e844fe0ddec4d65df15b489c5ba3e15ff1881eaf077a23107a1086"),
        ("aes-192", 45, "b9db59f7dd1bce4922855fb7f8f8e261a4937c0d7360349b24871684eb7bca422017d9f232c59cd2e4603e8463"),
        ("none", 28, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b"),
        ("xor", 45, "0fff8b84a99173765c7011c3f60cb8237bdf1315a6805604d54b25a70367b293d08e441c63be35690d89fadcb2"),
        ("salsa20", 45, "00010203040506079aaa6e7faf75365c40a4761a0c7be4446a8a411f62e5954a4ac802ddae0f35e6455e56815a"),
        ("blowfish", 45, "186797305116055ece6531b898c4b2352cc7452301c8434ae21a1256aeb7305fb08d8648ad906dcc13c8fef8f0"),
        ("twofish", 45, "79a0668add94e7387471af7514bb1065027a4425d5bd62db2ba645c8b7f41fe83931f68d4c3ad655e8b3727308"),
        ("cast5", 45, "bb8f8d2209e0131c7d027b3e28d6b45788b9c798dc5b25fc905f95636f61bb1cf570dd159b95dc560e2c33a7ce"),
        ("3des", 45, "5dca5d4fac8f6accf083365ae9eb528a24c6879fd6daee12f406f9a17955efec4fa86c417ab7d94fa773772244"),
        ("sm4", 45, "0340e44fd923bb2259e375a7ab6ee54de9bca063ac2859b4bfd05a8a7ada8cfee0ee39b42f17db450a2e938ba4"),
        ("tea", 45, "fc9c4eb4a8e9502bde3d3c8b0679084d963bc6bfca609b1ba987df5d5e088440024c54fe55fe7a44ffe41b540e"),
        ("xtea", 45, "09256989438dfb5af0f2a323dfd1ac2c9af741cc94cf83fec52a72395260600933396d604d06cba2459225658d"),
        ("aes", 130, "86834343335b168ca911bf584a05f9900e1c6fda2c822a981eb60909411c15690afb116b0d6073935dd1a399f9e6a343eb991b6b55bd85e3327d8f0db0a2391880e4075b21cae95a4be5bf46e3305eaada4eeea0d74f6a003cc260c8240402f04873646525b2911f1a486850969945de713dfb3464487011fb6d1d263b08eb2fd2f3"),
        ("3des", 130, "5dca5d4fac8f6accf083365ae9eb528a24c6879fd6daee12f406f9a17955efec4fa86c417ab7d94fa7737722449a60ca9acdec1ea912a26b4dd6f96de3d46ef901723dbd409bfbc1b3b7a10a462a731cfdc3d0ff2ee135b8cf06ba4e87a2542b5ce5224edd4dadf0585bf767d0abafc4baa63a8ec9772b80c3896e57370f0d1e68da"),
    ];

    #[test]
    fn test_session_key_matches_kcp_go() {
        // pbkdf2("it's a secrect", "kcp-go", 4096, 32, sha1), from Go.
        let mut pass = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
            DEFAULT_KEY.as_bytes(),
            KCP_SALT.as_bytes(),
            4096,
            &mut pass,
        );
        assert_eq!(
            hex(&pass),
            "25d7d7bd51050742d8d791f2b653c6c8b2366b7e25a124cf7a2e12eaf4ffa444"
        );
    }

    #[test]
    fn test_ciphers_match_kcp_go_on_the_wire() {
        for (name, len, expect) in GO_VECTORS {
            let crypt = Crypt::new(DEFAULT_KEY, name, KCP_SALT).unwrap();
            let mut buf = sample(*len);
            crypt.encrypt(&mut buf);
            assert_eq!(
                hex(&buf),
                *expect,
                "{} at {} bytes does not match kcp-go",
                name,
                len
            );
            crypt.decrypt(&mut buf);
            assert_eq!(buf, sample(*len), "{} does not round-trip", name);
        }
    }

    #[test]
    fn test_every_gost_cipher_name_is_implemented() {
        // The full list from gost's blockCrypt (kcp.go:417-446). None of them
        // may fall through to the "unknown name" branch, which would silently
        // encrypt with the wrong algorithm.
        for name in [
            "sm4", "tea", "xor", "none", "aes-128", "aes-192", "blowfish", "twofish", "cast5",
            "3des", "xtea", "salsa20", "aes",
        ] {
            let crypt = Crypt::new(DEFAULT_KEY, name, KCP_SALT).unwrap();
            let mut buf = sample(64);
            crypt.encrypt(&mut buf);
            if name != "none" {
                assert_ne!(buf, sample(64), "{} did not encrypt", name);
            }
            crypt.decrypt(&mut buf);
            assert_eq!(buf, sample(64), "{} did not round-trip", name);
        }
        // An empty name is aes, which is the branch a config file that omits
        // `crypt` takes in gost too.
        let empty = Crypt::new(DEFAULT_KEY, "", KCP_SALT).unwrap();
        let aes = Crypt::new(DEFAULT_KEY, "aes", KCP_SALT).unwrap();
        let (mut a, mut b) = (sample(45), sample(45));
        empty.encrypt(&mut a);
        aes.encrypt(&mut b);
        assert_eq!(a, b);
    }

    // -- packet framing ----------------------------------------------------

    #[test]
    fn test_packet_framing_round_trips_through_the_cipher() {
        use std::io::Write;
        let crypt = Arc::new(Crypt::new(DEFAULT_KEY, "aes", KCP_SALT).unwrap());
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut framer = PacketFramer {
            crypt: crypt.clone(),
            fec: FecEncoder::new(10, 3),
            queue: queue.clone(),
        };

        let segments = sample(IKCP_OVERHEAD + 17);
        framer.write_all(&segments).unwrap();
        let mut pkt = queue.lock().unwrap().pop_front().unwrap();
        assert_eq!(
            pkt.len(),
            CRYPT_HEADER_SIZE + FEC_HEADER_SIZE_PLUS2 + segments.len()
        );

        let range = packet_unframe(&crypt, &mut pkt).expect("the packet must verify");
        assert_eq!(&pkt[range], &segments[..]);
    }

    #[test]
    fn test_the_fec_header_is_the_one_kcp_go_writes() {
        use std::io::Write;
        let crypt = Arc::new(Crypt::new(DEFAULT_KEY, "none", KCP_SALT).unwrap());
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut framer = PacketFramer {
            crypt,
            fec: FecEncoder::new(10, 3),
            queue: queue.clone(),
        };

        let segments = sample(IKCP_OVERHEAD);
        framer.write_all(&segments).unwrap();
        framer.write_all(&segments).unwrap();

        let first = queue.lock().unwrap().pop_front().unwrap();
        let second = queue.lock().unwrap().pop_front().unwrap();
        let h1 = FecHeader::parse(&first[CRYPT_HEADER_SIZE..]).unwrap();
        let h2 = FecHeader::parse(&second[CRYPT_HEADER_SIZE..]).unwrap();

        assert_eq!(h1.flag, TYPE_DATA);
        assert_eq!(h1.seqid, 0);
        assert_eq!(h2.seqid, 1, "seqid must advance once per data shard");
        // `size` counts itself plus the payload after it (fec.go:322).
        assert_eq!(h1.size as usize, 2 + segments.len());
    }

    #[test]
    fn test_parity_shards_are_recognised_and_dropped() {
        // What a gost peer sends every `datashard` packets. It carries no
        // segments of its own, so it must never reach the ARQ core.
        let mut parity = vec![0u8; FEC_HEADER_SIZE_PLUS2 + 40];
        parity[4..6].copy_from_slice(&TYPE_PARITY.to_le_bytes());
        assert!(fec_strip(&parity).is_none());

        let mut data = vec![0u8; FEC_HEADER_SIZE_PLUS2 + 40];
        data[4..6].copy_from_slice(&TYPE_DATA.to_le_bytes());
        assert_eq!(fec_strip(&data).unwrap().len(), 40);

        // A bare KCP segment: cmd=81 (PUSH), frg=0, so bytes 4-5 read as 81,
        // which is neither shard type. It must pass through untouched.
        let mut bare = vec![0u8; IKCP_OVERHEAD];
        bare[4] = 81;
        assert_eq!(fec_strip(&bare).unwrap().len(), IKCP_OVERHEAD);
    }

    #[test]
    fn test_a_packet_under_the_wrong_key_is_dropped_not_delivered() {
        use std::io::Write;
        let ours = Arc::new(Crypt::new("ours", "aes", KCP_SALT).unwrap());
        let theirs = Crypt::new("theirs", "aes", KCP_SALT).unwrap();
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut framer = PacketFramer {
            crypt: ours,
            fec: None,
            queue: queue.clone(),
        };
        framer.write_all(&sample(IKCP_OVERHEAD + 8)).unwrap();
        let mut pkt = queue.lock().unwrap().pop_front().unwrap();
        assert!(packet_unframe(&theirs, &mut pkt).is_none());
    }

    // -- snappy framing ----------------------------------------------------

    /// Streams produced by github.com/klauspost/compress/snappy's
    /// `NewBufferedWriter`, which is what gost's `compStreamConn` uses.
    #[tokio::test]
    async fn test_snappy_decodes_go_produced_streams() {
        let cases: &[(&str, &str)] = &[
            // A short, incompressible payload: Go emits a 0x01 chunk.
            ("hello", "ff060000734e6150705901090000bb1f1c1968656c6c6f"),
            // A compressible one: Go emits a 0x00 chunk.
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "ff060000734e61507059000a00000bf7423f340061ca0100",
            ),
            // Two writes, each flushed: the identifier appears once.
            (
                "firstsecond",
                "ff060000734e615070590109000055ff23e56669727374010a0000d3e0d3ca7365636f6e64",
            ),
        ];

        for (plain, wire) in cases {
            let (mut a, b) = tokio::io::duplex(4096);
            let mut stream = SnappyStream::new(b);
            a.write_all(&unhex(wire)).await.unwrap();
            let mut got = vec![0u8; plain.len()];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(String::from_utf8(got).unwrap(), *plain);
        }
    }

    #[tokio::test]
    async fn test_snappy_writes_a_stream_go_would_accept() {
        // Not compared byte-for-byte with Go's writer -- the framing permits
        // several encodings of the same bytes -- but the structure is fixed:
        // the identifier first, then one chunk per write, each with a masked
        // CRC-32C of the *uncompressed* payload.
        let (a, b) = tokio::io::duplex(65536);
        let mut stream = SnappyStream::new(a);
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();

        let mut wire = vec![0u8; 4096];
        let n = tokio::time::timeout(READ_TIMEOUT, {
            let mut b = b;
            async move {
                let n = b.read(&mut wire).await.unwrap();
                wire.truncate(n);
                wire
            }
        })
        .await
        .unwrap();

        assert_eq!(&n[..10], &SNAPPY_MAGIC);
        assert_eq!(n[10], 0x01, "5 incompressible bytes must go out raw");
        assert_eq!(u32::from_le_bytes([n[11], n[12], n[13], 0]), 4 + 5);
        assert_eq!(
            u32::from_le_bytes([n[14], n[15], n[16], n[17]]),
            crc32c_masked(b"hello")
        );
        assert_eq!(&n[18..23], b"hello");
        // The exact stream Go produced for the same input.
        assert_eq!(hex(&n), "ff060000734e6150705901090000bb1f1c1968656c6c6f");
    }

    #[tokio::test]
    async fn test_snappy_round_trips_more_than_one_block() {
        // 200 KiB crosses the 64 KiB chunk limit three times over.
        let payload: Vec<u8> = (0..200_000usize).map(|i| (i % 251) as u8).collect();
        let (a, b) = tokio::io::duplex(1024);
        let mut writer = SnappyStream::new(a);
        let mut reader = SnappyStream::new(b);

        let expected = payload.clone();
        tokio::spawn(async move {
            writer.write_all(&payload).await.ok();
            writer.flush().await.ok();
        });

        let mut got = vec![0u8; expected.len()];
        tokio::time::timeout(READ_TIMEOUT, reader.read_exact(&mut got))
            .await
            .expect("timed out on the large payload")
            .unwrap();
        assert_eq!(got, expected);
    }

    // -- end to end --------------------------------------------------------

    /// Echoes what it reads, so the transport is shown to carry an arbitrary
    /// inner protocol.
    struct EchoHandler;

    #[async_trait]
    impl Handler for EchoHandler {
        async fn handle(&self, mut conn: ProxyConn) -> Result<(), HandlerError> {
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if conn.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                conn.flush().await.ok();
            }
            Ok(())
        }
    }

    struct Running {
        addr: SocketAddr,
        cancel: CancellationToken,
        sessions: SessionCount,
    }

    async fn start(config: KcpConfig) -> Running {
        let listener = KcpListener::new("127.0.0.1:0", config, EchoHandler)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = listener.cancel_token();
        let sessions = listener.session_count();
        tokio::spawn(async move {
            listener.serve().await.ok();
        });
        Running {
            addr,
            cancel,
            sessions,
        }
    }

    async fn echo(stream: &mut MuxStreamConn, payload: &[u8]) -> Vec<u8> {
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut buf))
            .await
            .expect("timed out waiting for the echo")
            .unwrap();
        buf
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_two_streams_share_one_kcp_session() {
        let server = start(KcpConfig::default()).await;
        let client = KcpTransporter::new(KcpConfig::default()).unwrap();
        let addr = server.addr.to_string();

        let mut first = client.dial(&addr).await.unwrap();
        let mut second = client.dial(&addr).await.unwrap();
        assert_ne!(first.id(), second.id());

        assert_eq!(echo(&mut first, b"alpha").await, b"alpha");
        assert_eq!(echo(&mut second, b"bravo").await, b"bravo");

        // The whole point of gost's kcpTransporter: one UDP session per node,
        // a stream per request.
        assert_eq!(client.sessions_built(), 1);
        assert_eq!(server.sessions.get(), 1);
        server.cancel.cancel();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_payload_larger_than_the_send_window() {
        // 512 KiB is ~400 MTU-sized segments, so this exercises fragmentation,
        // the window, and the reader's back-pressure rather than a single
        // round trip.
        let server = start(KcpConfig::default()).await;
        let client = KcpTransporter::new(KcpConfig::default()).unwrap();

        let payload: Vec<u8> = (0..512 * 1024usize).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();

        let stream = client.dial(&server.addr.to_string()).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        tokio::spawn(async move {
            writer.write_all(&payload).await.ok();
            writer.flush().await.ok();
        });

        let mut got = vec![0u8; expected.len()];
        tokio::time::timeout(Duration::from_secs(60), reader.read_exact(&mut got))
            .await
            .expect("timed out on the large payload")
            .unwrap();
        assert_eq!(got, expected);
        server.cancel.cancel();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_compression_and_ciphers_end_to_end() {
        // One pass per configuration that changes the bytes on the wire.
        for (crypt, nocomp) in [
            ("aes", false),
            ("aes", true),
            ("none", false),
            ("salsa20", false),
            ("xor", false),
            ("3des", false),
            ("tea", true),
        ] {
            let mut config = KcpConfig::default();
            config.crypt = crypt.to_string();
            config.nocomp = nocomp;
            config.init();

            let server = start(config.clone()).await;
            let client = KcpTransporter::new(config).unwrap();
            let mut stream = client.dial(&server.addr.to_string()).await.unwrap();
            assert_eq!(
                echo(&mut stream, b"payload").await,
                b"payload",
                "crypt={} nocomp={}",
                crypt,
                nocomp
            );
            server.cancel.cancel();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_a_peer_with_the_wrong_key_never_connects() {
        let mut server_config = KcpConfig::default();
        server_config.key = "server-side".to_string();
        let server = start(server_config).await;

        let mut client_config = KcpConfig::default();
        client_config.key = "client-side".to_string();
        let client = KcpTransporter::new(client_config).unwrap();

        // smux v1 opens a stream without a round trip, so the dial itself
        // says nothing. What matters is that no byte ever crosses: every
        // packet fails its checksum after decryption under the wrong key and
        // is dropped, so the listener never sees a session at all.
        let mut stream = client.dial(&server.addr.to_string()).await.unwrap();
        stream.write_all(b"anyone there").await.unwrap();
        stream.flush().await.unwrap();

        let mut sink = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut sink)).await;
        match read {
            Err(_) => {}
            Ok(Ok(0)) => {}
            Ok(other) => panic!("a mismatched key produced a working session: {:?}", other),
        }
        assert_eq!(
            server.sessions.get(),
            0,
            "the listener must not have accepted a session"
        );
        server.cancel.cancel();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_no_fec_framing_still_interoperates_with_itself() {
        // datashard/parityshard of zero is kcp-go's "no FEC" configuration:
        // no 8-byte header, and 8 more bytes of payload per datagram.
        let mut config = KcpConfig::default();
        config.datashard = 0;
        config.parityshard = 0;
        config.init();

        let server = start(config.clone()).await;
        let client = KcpTransporter::new(config).unwrap();
        let mut stream = client.dial(&server.addr.to_string()).await.unwrap();
        assert_eq!(echo(&mut stream, b"no fec").await, b"no fec");
        server.cancel.cancel();
    }

    // -- interoperability with the real gost ------------------------------

    /// Both directions against a real `gost` binary, which is the only test
    /// that can tell a self-consistent codec from a correct one.
    ///
    /// Skipped unless `$GOST` points at a gost 2.12 executable:
    ///
    /// ```text
    /// GOST=/tmp/gost.exe cargo test --release --lib -- kcp::tests::test_interop
    /// ```
    ///
    /// Both sides run unconfigured, which is the case that matters: gost's
    /// `DefaultKCPConfig` and [`KcpConfig::default`] have to agree on the key,
    /// the cipher, the shard counts, the compression and the smux buffers, or
    /// nothing gets through.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_interop_with_gost_both_directions() {
        let gost = match std::env::var("GOST") {
            Ok(path) if std::path::Path::new(&path).exists() => path,
            _ => {
                eprintln!("skipping: set $GOST to a gost binary to run the interop test");
                return;
            }
        };

        let origin = spawn_origin().await;

        // The stock configuration on both sides. `?c=` is left off so gost
        // uses `DefaultKCPConfig` and rt uses `KcpConfig::default`, which
        // is the pairing an operator gets by typing `kcp://host:port`.
        interop_round(&gost, KcpConfig::default(), None, origin, "defaults").await;

        // ...and a configuration that changes every layer at once: a
        // different key, a different cipher family (a stream cipher rather
        // than a block one), no compression and no FEC framing. Passed to
        // gost as the JSON `?c=` file it reads, serialised from the very
        // struct rt runs on.
        let mut config = KcpConfig::default();
        config.key = "interop-shared-secret".to_string();
        config.crypt = "salsa20".to_string();
        config.mode = "fast3".to_string();
        config.nocomp = true;
        config.datashard = 0;
        config.parityshard = 0;
        config.mtu = 1200;
        config.init();

        let path = std::env::temp_dir().join("rt-kcp-interop.json");
        std::fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();
        let query = format!("?c={}", path.display());
        interop_round(&gost, config, Some(&query), origin, "salsa20/nocomp/nofec").await;
    }

    /// One configuration, both directions.
    async fn interop_round(
        gost: &str,
        config: KcpConfig,
        query: Option<&str>,
        origin: SocketAddr,
        label: &str,
    ) {
        let query = query.unwrap_or("");

        // Direction 1: rt dials a gost KCP server.
        {
            let port = free_port();
            let node = format!("kcp://127.0.0.1:{}{}", port, query);
            let _gost = Gost::spawn(gost, &["-L", &node]);
            wait_for_udp(port).await;

            let client = KcpTransporter::new(config.clone()).unwrap();
            let mut stream = client
                .dial(&format!("127.0.0.1:{}", port))
                .await
                .expect("dialling the gost KCP listener");
            let body = http_get_through_proxy(&mut stream, origin).await;
            assert!(
                body.contains("INTEROP-OK"),
                "[{}] rt client -> gost server returned: {:?}",
                label,
                body
            );

            // A second stream on the same KCP session, carrying a megabyte.
            let mut bulk = client.dial(&format!("127.0.0.1:{}", port)).await.unwrap();
            let got = http_get_big(&mut bulk, origin).await;
            assert_eq!(got.len(), BIG_LEN, "[{}] short bulk transfer", label);
            assert!(
                got.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8),
                "[{}] bulk transfer came back corrupted",
                label
            );
            assert_eq!(
                client.sessions_built(),
                1,
                "[{}] both streams must share one KCP session",
                label
            );
            eprintln!(
                "  PASS  {}  rt client -> gost server (probe + {} KiB)",
                label,
                BIG_LEN / 1024
            );
        }

        // Direction 2: gost dials an rt KCP server.
        {
            let listener = KcpListener::new(
                "127.0.0.1:0",
                config,
                crate::http_proxy::HttpHandler::new(crate::handler::HandlerOptions::default()),
            )
            .await
            .unwrap();
            let addr = listener.local_addr().unwrap();
            let cancel = listener.cancel_token();
            let sessions = listener.session_count();
            tokio::spawn(async move {
                listener.serve().await.ok();
            });

            let front = free_port();
            let _gost = Gost::spawn(
                gost,
                &[
                    "-L",
                    &format!("http://127.0.0.1:{}", front),
                    "-F",
                    &format!("kcp://127.0.0.1:{}{}", addr.port(), query),
                ],
            );
            wait_for_tcp(front).await;

            let mut stream = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::TcpStream::connect(("127.0.0.1", front)),
            )
            .await
            .expect("connecting to the gost HTTP front end timed out")
            .unwrap();
            let body = http_get_through_proxy(&mut stream, origin).await;
            assert!(
                body.contains("INTEROP-OK"),
                "[{}] gost client -> rt server returned: {:?}",
                label,
                body
            );
            // Proof the bytes went through KCP rather than some other path:
            // the listener turned a gost datagram into an smux session.
            assert_eq!(sessions.get(), 1, "[{}] no KCP session was accepted", label);

            let mut bulk = tokio::net::TcpStream::connect(("127.0.0.1", front))
                .await
                .unwrap();
            let got = http_get_big(&mut bulk, origin).await;
            assert_eq!(got.len(), BIG_LEN, "[{}] short bulk transfer", label);
            assert!(
                got.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8),
                "[{}] bulk transfer came back corrupted",
                label
            );
            eprintln!(
                "  PASS  {}  gost client -> rt server (probe + {} KiB)",
                label,
                BIG_LEN / 1024
            );
            cancel.cancel();
        }
    }

    /// A gost child process, killed when it goes out of scope.
    ///
    /// Set `$GOST_DEBUG` to run it with `-D` and let its log through, which is
    /// how to see the far end's view of a session that will not come up.
    struct Gost(std::process::Child);

    impl Gost {
        fn spawn(bin: &str, args: &[&str]) -> Self {
            let debug = std::env::var("GOST_DEBUG").is_ok();
            let mut command = std::process::Command::new(bin);
            if debug {
                command.arg("-D");
            }
            command.args(args);
            if debug {
                command.stdout(std::process::Stdio::inherit());
                command.stderr(std::process::Stdio::inherit());
            } else {
                command.stdout(std::process::Stdio::null());
                command.stderr(std::process::Stdio::null());
            }
            Self(command.spawn().expect("spawning gost"))
        }
    }

    impl Drop for Gost {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A port nothing is listening on. Bound and released, so it is free at
    /// the moment gost is told to use it.
    fn free_port() -> u16 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap().port()
    }

    async fn wait_for_tcp(port: u16) {
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("nothing came up on tcp/{}", port);
    }

    /// A UDP listener cannot be probed by connecting, so this is a fixed
    /// grace period for gost to bind.
    async fn wait_for_udp(_port: u16) {
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }

    /// The `/big` body, sized so a transfer needs hundreds of MTU-sized
    /// segments and, on a default gost, dozens of parity shards.
    const BIG_LEN: usize = 1024 * 1024;

    /// A minimal origin server. `/probe.txt` answers `INTEROP-OK`; `/big`
    /// answers a megabyte of a repeating pattern.
    async fn spawn_origin() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let big = buf[..n].windows(4).any(|w| w == b"/big");
                    if big {
                        let body: Vec<u8> = (0..BIG_LEN).map(|i| (i % 251) as u8).collect();
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = socket.write_all(head.as_bytes()).await;
                        let _ = socket.write_all(&body).await;
                    } else {
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n\
                                  INTEROP-OK",
                            )
                            .await;
                    }
                    let _ = socket.flush().await;
                });
            }
        });
        addr
    }

    /// Speaks the absolute-URI form of an HTTP proxy request over `stream`,
    /// which is what `curl -x` sends, and returns whatever comes back.
    async fn http_get_through_proxy<S>(stream: &mut S, origin: SocketAddr) -> String
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let body = http_get_bytes(stream, origin, "/probe.txt", |r| {
            r.windows(10).any(|w| w == b"INTEROP-OK")
        })
        .await;
        String::from_utf8_lossy(&body).to_string()
    }

    /// A megabyte through the tunnel, checked byte for byte.
    ///
    /// This is where a framing bug that a ten-byte reply cannot reach shows
    /// up: fragmentation across hundreds of segments, the send and receive
    /// windows, snappy chunk boundaries, and — against a default gost — the
    /// parity shards this module recognises but does not decode.
    async fn http_get_big<S>(stream: &mut S, origin: SocketAddr) -> Vec<u8>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let response = http_get_bytes(stream, origin, "/big", |r| r.len() >= BIG_LEN).await;
        match response.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(at) => response[at + 4..].to_vec(),
            None => Vec::new(),
        }
    }

    async fn http_get_bytes<S>(
        stream: &mut S,
        origin: SocketAddr,
        path: &str,
        done: impl Fn(&[u8]) -> bool,
    ) -> Vec<u8>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let request = format!(
            "GET http://{}{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            origin, path, origin
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut response = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, stream.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => {
                    response.extend_from_slice(&buf[..n]);
                    if done(&response) {
                        break;
                    }
                }
                Ok(Err(_)) => break,
            }
        }
        response
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_cancelling_the_listener_drains_and_returns() {
        let listener = KcpListener::new("127.0.0.1:0", KcpConfig::default(), EchoHandler)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = listener.cancel_token();
        let served = tokio::spawn(async move { listener.serve().await });

        let client = KcpTransporter::new(KcpConfig::default()).unwrap();
        let mut stream = client.dial(&addr.to_string()).await.unwrap();
        assert_eq!(echo(&mut stream, b"up").await, b"up");

        cancel.cancel();
        tokio::time::timeout(READ_TIMEOUT, served)
            .await
            .expect("serve did not return after cancellation")
            .unwrap()
            .unwrap();
    }
}

#[cfg(test)]
mod fec_compat_tests {
    use reed_solomon_erasure::galois_8::ReedSolomon;

    /// Pins the Reed-Solomon matrix against klauspost/reedsolomon v1.12.0,
    /// the library kcp-go itself uses.
    ///
    /// Both build a Vandermonde-derived matrix over GF(2^8), but "Reed-Solomon"
    /// alone does not pin the construction: a different matrix produces valid
    /// parity that a kcp-go peer cannot use. These bytes came out of a Go
    /// program calling klauspost/reedsolomon directly, so a mismatch here means
    /// the wire format diverges before anything else is worth testing.
    #[test]
    fn test_parity_matches_klauspost_reedsolomon() {
        const DATA: usize = 4;
        const PARITY: usize = 3;
        const LEN: usize = 16;

        let mut shards: Vec<Vec<u8>> = (0..DATA + PARITY).map(|_| vec![0u8; LEN]).collect();
        for (i, shard) in shards.iter_mut().take(DATA).enumerate() {
            for (j, byte) in shard.iter_mut().enumerate() {
                *byte = (i * 31 + j * 7 + 1) as u8;
            }
        }

        ReedSolomon::new(DATA, PARITY)
            .unwrap()
            .encode(&mut shards)
            .unwrap();

        assert_eq!(
            shards[DATA],
            vec![249, 36, 139, 210, 129, 48, 71, 227, 125, 144, 228, 173, 238, 135, 92, 181]
        );
        assert_eq!(
            shards[DATA + 1],
            vec![69, 35, 170, 233, 160, 104, 1, 239, 59, 189, 197, 150, 207, 184, 154, 89]
        );
        assert_eq!(
            shards[DATA + 2],
            vec![253, 10, 201, 176, 199, 34, 113, 53, 71, 29, 38, 79, 40, 97, 234, 99]
        );
    }

    /// Builds a data packet the way PacketFramer does, minus the sealing.
    fn data_packet(enc: &mut super::FecEncoder, segments: &[u8]) -> Vec<u8> {
        let header = super::CRYPT_HEADER_SIZE + super::FEC_HEADER_SIZE_PLUS2;
        let mut pkt = vec![0u8; header + segments.len()];
        pkt[header..].copy_from_slice(segments);
        enc.mark_data(
            &mut pkt[super::CRYPT_HEADER_SIZE..super::CRYPT_HEADER_SIZE + 8],
            2 + segments.len(),
        );
        pkt
    }

    #[test]
    fn test_parity_recovers_a_lost_data_shard() {
        // The point of the layer: lose a data packet and rebuild it from
        // parity, without waiting for a retransmission.
        const DATA: usize = 3;
        const PARITY: usize = 2;
        let payload_offset = super::CRYPT_HEADER_SIZE + super::FEC_HEADER_SIZE;

        let mut enc = super::FecEncoder::new(DATA as u32, PARITY as u32).unwrap();

        // Deliberately unequal lengths: that is the normal case, and the one
        // that needs zero-padding to a common size before encoding.
        let payloads: [&[u8]; DATA] = [b"first-segment", b"second", b"third-segment-longer"];
        let mut packets = Vec::new();
        let mut parity = Vec::new();
        for p in payloads {
            let pkt = data_packet(&mut enc, p);
            let out = enc.push(&pkt, payload_offset);
            packets.push(pkt);
            if !out.is_empty() {
                parity = out;
            }
        }

        assert_eq!(parity.len(), PARITY, "a full group must yield parity");
        let max = packets.iter().map(|p| p.len()).max().unwrap();
        for shard in &parity {
            assert_eq!(shard.len(), max, "parity is sized to the longest packet");
            let flag = u16::from_le_bytes([
                shard[super::CRYPT_HEADER_SIZE + 4],
                shard[super::CRYPT_HEADER_SIZE + 5],
            ]);
            assert_eq!(flag, super::TYPE_PARITY);
        }

        // Rebuild the grid as a receiver would, zero-padded to one size.
        let mut shards: Vec<Option<Vec<u8>>> = Vec::new();
        for pkt in &packets {
            let mut shard = vec![0u8; max - payload_offset];
            shard[..pkt.len() - payload_offset].copy_from_slice(&pkt[payload_offset..]);
            shards.push(Some(shard));
        }
        for shard in &parity {
            shards.push(Some(shard[payload_offset..].to_vec()));
        }

        // Lose the middle data shard.
        let lost = 1;
        let expected = shards[lost].clone().unwrap();
        shards[lost] = None;

        ReedSolomon::new(DATA, PARITY)
            .unwrap()
            .reconstruct(&mut shards)
            .unwrap();

        assert_eq!(
            shards[lost].as_ref().unwrap(),
            &expected,
            "the lost shard must come back byte for byte"
        );

        // And it still declares its own length correctly.
        let recovered = shards[lost].as_ref().unwrap();
        let size = u16::from_le_bytes([recovered[0], recovered[1]]) as usize;
        assert_eq!(size, 2 + payloads[lost].len());
        assert_eq!(&recovered[2..size], payloads[lost]);
    }

    #[test]
    fn test_sequence_numbers_run_data_then_parity() {
        // kcp-go's grid depends on the ordering: dataShards data seqids
        // followed by parityShards parity seqids, contiguous.
        const DATA: usize = 2;
        const PARITY: usize = 2;
        let payload_offset = super::CRYPT_HEADER_SIZE + super::FEC_HEADER_SIZE;

        let mut enc = super::FecEncoder::new(DATA as u32, PARITY as u32).unwrap();
        let mut seqids = Vec::new();
        let mut parity = Vec::new();
        for i in 0..DATA {
            let pkt = data_packet(&mut enc, &[i as u8; 8]);
            seqids.push(u32::from_le_bytes([
                pkt[super::CRYPT_HEADER_SIZE],
                pkt[super::CRYPT_HEADER_SIZE + 1],
                pkt[super::CRYPT_HEADER_SIZE + 2],
                pkt[super::CRYPT_HEADER_SIZE + 3],
            ]));
            let out = enc.push(&pkt, payload_offset);
            if !out.is_empty() {
                parity = out;
            }
        }
        for shard in &parity {
            seqids.push(u32::from_le_bytes([
                shard[super::CRYPT_HEADER_SIZE],
                shard[super::CRYPT_HEADER_SIZE + 1],
                shard[super::CRYPT_HEADER_SIZE + 2],
                shard[super::CRYPT_HEADER_SIZE + 3],
            ]));
        }

        assert_eq!(seqids, vec![0, 1, 2, 3]);
    }
}
