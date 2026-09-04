//! SSH transport and port forwarding — the Rust side of gost's `ssh.go`.
//!
//! # Scope
//!
//! gost's `ssh.go` contains two unrelated features that happen to share a file:
//!
//! 1. **SSH port forwarding** (`-L forward+ssh://`, `-F direct+ssh://`,
//!    `-F remote+ssh://`). The client opens RFC 4254 `direct-tcpip` channels, or
//!    asks for a `tcpip-forward` bind and receives `forwarded-tcpip` channels
//!    back. **This is implemented here, in both directions, and interoperates
//!    with gost 2.12.0.**
//!
//! 2. **The SSH *tunnel* transport** (`-L http+ssh://`, `-F http+ssh://`), where
//!    the client opens a channel whose type string is `gost-tunnel`
//!    (`GostSSHTunnelRequest`, ssh.go:27) and the resulting byte stream carries
//!    an inner proxy protocol, the way TLS or WebSocket do elsewhere in this
//!    crate. **This is NOT implemented, and asking for it is a hard error.**
//!
//!    The reason is a hard limit in `russh`, the only pure-Rust SSH *server*
//!    library: its channel types are a closed enum
//!    (`russh::parsing::ChannelType`). A client can only open `session`, `x11`,
//!    `direct-tcpip` or `direct-streamlocal`, and a server answers any channel
//!    type it does not recognise with `SSH_MSG_CHANNEL_OPEN_FAILURE`
//!    (`russh/src/server/encrypted.rs`, `ChannelType::Unknown`). There is no
//!    escape hatch for a custom type string on either side, so neither half of
//!    gost's `gost-tunnel` handshake can be spoken.
//!
//!    A tunnel built on `direct-tcpip` instead would work between two copies of
//!    this crate and would be silently incompatible with every real gost peer,
//!    which is worse than not shipping it. [`SshTunnelTransporter::new`] and
//!    [`SshTunnelListener::new`] therefore fail at construction time; see
//!    [`ssh_listener_support`] and [`ssh_chain_support`] for the gate a caller
//!    should run at startup.
//!
//! # Authentication
//!
//! gost sets `NoClientAuth = true` when a listener has no authenticator
//! (ssh.go:521-523, 748-750), which makes `-L forward+ssh://:2222` an
//! unauthenticated forwarder that will connect anywhere on the operator's
//! behalf. This module refuses that configuration: [`SshForwardHandler::new`]
//! returns an error unless a password source (inline userinfo or a secrets
//! file) or an `?ssh_authorized_keys=` file is configured. Likewise the client
//! refuses to hand out a session with no credentials.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use russh::keys::ssh_key::PublicKey;
use russh::keys::{decode_secret_key, PrivateKey, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelOpenFailure, MethodKind, MethodSet};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::auth::Authenticator;
use crate::chain::Chain;
use crate::conn::ProxyConn;
use crate::handler::{Handler, HandlerError, HandlerOptions};
use crate::node::Node;
use crate::permissions::Can;
use crate::transport::transport;

// SSH request/channel types for port forwarding — RFC 4254 7.x, gost ssh.go:21-28.
const DIRECT_FORWARD_REQUEST: &str = "direct-tcpip";
const REMOTE_FORWARD_REQUEST: &str = "tcpip-forward";
const FORWARDED_TCP_RETURN_REQUEST: &str = "forwarded-tcpip";
const CANCEL_REMOTE_FORWARD_REQUEST: &str = "cancel-tcpip-forward";
/// gost's extended channel type for its SSH tunnel transport. Named here only
/// so the error messages can be precise; this crate cannot speak it (see the
/// module documentation).
const GOST_SSH_TUNNEL_REQUEST: &str = "gost-tunnel";

/// How long a client waits for the TCP connect plus the SSH handshake, when the
/// node did not set `?timeout=`.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on the queue of connections waiting to become `forwarded-tcpip`
/// channels, mirroring gost's 1024-deep `connChan` (ssh.go:261).
const REMOTE_FORWARD_BACKLOG: usize = 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// A configuration that cannot be made secure, or key material that will
    /// not load. Always fatal at startup.
    #[error("ssh: {0}")]
    Config(String),
    #[error("ssh: {0}")]
    Protocol(String),
    #[error("ssh: authentication failed")]
    AuthFailed,
    #[error("ssh: {0}")]
    Russh(#[from] russh::Error),
    #[error("ssh: key error: {0}")]
    Key(#[from] russh::keys::Error),
    #[error("chain error: {0}")]
    Chain(#[from] crate::chain::ChainError),
}

impl From<SshError> for HandlerError {
    fn from(e: SshError) -> Self {
        match e {
            SshError::Io(e) => HandlerError::Io(e),
            SshError::AuthFailed => HandlerError::AuthFailed,
            SshError::Chain(e) => HandlerError::Chain(e),
            other => HandlerError::Proxy(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// SSH configuration — gost's `SSHConfig` (ssh.go:717-723) plus the client-side
/// handshake options gost passes separately as `HandshakeOption`s.
#[derive(Clone, Default)]
pub struct SshConfig {
    /// `?ssh_key=`: the host key on a listener, the client identity on a chain
    /// node. gost's `ParseSSHKeyFile` (ssh.go:33-40).
    pub key_file: Option<String>,
    /// `?ssh_authorized_keys=`: public keys a listener will accept. gost's
    /// `ParseSSHAuthorizedKeysFile` (ssh.go:42-58).
    pub authorized_keys_file: Option<String>,
    /// Passphrase for an encrypted `key_file`. gost has no equivalent; it can
    /// only load unencrypted keys.
    pub key_passphrase: Option<String>,
    /// Client-side password, taken from the node's userinfo.
    pub password: Option<String>,
    /// Client-side username, taken from the node's userinfo.
    pub user: Option<String>,
    /// `?ssh_host_key=`: a public key file the client pins the server to.
    ///
    /// gost always installs `ssh.InsecureIgnoreHostKey()` (ssh.go:225, 339), so
    /// leaving this unset matches gost — and, like gost, leaves the session open
    /// to an active man in the middle, who would also see the password. The
    /// fingerprint of whatever key the server offered is logged so an operator
    /// can pin it.
    pub host_key_file: Option<String>,
    /// `?ping=`: keepalive interval. gost sends a custom `ping` global request
    /// (ssh.go:461-470); russh sends `keepalive@openssh.com`, which any SSH
    /// server answers, so it serves the same liveness purpose.
    pub ping_interval: Duration,
    /// `?retry=`: unanswered keepalives tolerated before the session is
    /// considered dead (gost's `retries`, ssh.go:416-418).
    pub ping_retries: usize,
    /// `?timeout=`: dial plus handshake budget.
    pub timeout: Duration,
}

impl std::fmt::Debug for SshConfig {
    // Hand-written so a `-v` dump of the node config cannot print the password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConfig")
            .field("key_file", &self.key_file)
            .field("authorized_keys_file", &self.authorized_keys_file)
            .field("key_passphrase", &self.key_passphrase.as_ref().map(|_| "<redacted>"))
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("user", &self.user)
            .field("host_key_file", &self.host_key_file)
            .field("ping_interval", &self.ping_interval)
            .field("ping_retries", &self.ping_retries)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl SshConfig {
    /// Reads the SSH settings out of a parsed node URL, using gost's query
    /// parameter names (`ssh_key`, `ssh_authorized_keys`, route.go:298,451).
    pub fn from_node(node: &Node) -> Self {
        let (user, password) = match node.user.as_ref() {
            Some((u, p)) => (Some(u.clone()), p.clone()),
            None => (None, None),
        };
        Self {
            key_file: node.get("ssh_key").filter(|s| !s.is_empty()).map(String::from),
            authorized_keys_file: node
                .get("ssh_authorized_keys")
                .filter(|s| !s.is_empty())
                .map(String::from),
            key_passphrase: node
                .get("ssh_key_passphrase")
                .filter(|s| !s.is_empty())
                .map(String::from),
            password,
            user,
            host_key_file: node
                .get("ssh_host_key")
                .filter(|s| !s.is_empty())
                .map(String::from),
            ping_interval: node.get_duration("ping"),
            ping_retries: node.get_int("retry").max(0) as usize,
            timeout: node.get_duration("timeout"),
        }
    }

    fn handshake_timeout(&self) -> Duration {
        if self.timeout.is_zero() {
            DEFAULT_HANDSHAKE_TIMEOUT
        } else {
            self.timeout
        }
    }
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

/// Parses an SSH private key file — gost's `ParseSSHKeyFile` (ssh.go:33-40).
///
/// Accepts every format `russh` understands: OpenSSH, PKCS#1, PKCS#8, PKCS#5
/// and PuTTY, encrypted or not. gost's `ssh.ParsePrivateKey` handles only
/// unencrypted keys, so `passphrase` is a superset of its behaviour.
pub fn parse_ssh_key_file(path: &str, passphrase: Option<&str>) -> Result<PrivateKey, SshError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        SshError::Config(format!("cannot read ssh key file {:?}: {}", path, e))
    })?;
    decode_secret_key(&text, passphrase)
        .map_err(|e| SshError::Config(format!("cannot parse ssh key file {:?}: {}", path, e)))
}

/// A set of public keys a listener will accept — gost's
/// `map[string]bool` of marshalled keys (ssh.go:42-58).
#[derive(Clone, Default)]
pub struct AuthorizedKeys {
    /// SHA-256 fingerprints. gost keys its map on the SSH wire encoding of the
    /// key; a fingerprint of that same encoding is equivalent for lookup and
    /// keeps no key material in memory.
    fingerprints: HashSet<String>,
}

impl AuthorizedKeys {
    /// Parses the contents of an `authorized_keys` file. A malformed entry is
    /// fatal, as it is in gost: silently dropping a line would quietly narrow
    /// the set of principals the operator believes they granted.
    pub fn parse(text: &str) -> Result<Self, SshError> {
        let mut fingerprints = HashSet::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let key = PublicKey::from_openssh(line).map_err(|e| {
                SshError::Config(format!("authorized_keys line {}: {}", n + 1, e))
            })?;
            fingerprints.insert(fingerprint(&key));
        }
        Ok(Self { fingerprints })
    }

    pub fn contains(&self, key: &PublicKey) -> bool {
        self.fingerprints.contains(&fingerprint(key))
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }
}

/// Parses an SSH authorized keys file — gost's `ParseSSHAuthorizedKeysFile`
/// (ssh.go:42-58).
pub fn parse_ssh_authorized_keys_file(path: &str) -> Result<AuthorizedKeys, SshError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        SshError::Config(format!("cannot read authorized_keys file {:?}: {}", path, e))
    })?;
    AuthorizedKeys::parse(&text)
}

fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(russh::keys::HashAlg::Sha256).to_string()
}

/// Generates an ephemeral Ed25519 host key.
///
/// gost derives its host key from the TLS key pair when none is configured
/// (ssh.go:752-759), which in practice means the certificate `-cert`/`-key`
/// point at, or the self-signed one it makes at startup. This crate has no
/// process-wide default TLS identity to borrow, so a fresh key is generated and
/// its fingerprint logged — a client that pins the key must be given a real
/// `?ssh_key=` instead.
///
/// Built through `rcgen`, which is already a dependency, rather than
/// `PrivateKey::random`: the latter wants an RNG implementing `rand_core` 0.10's
/// traits and this crate is on `rand` 0.8.
pub fn generate_host_key() -> Result<PrivateKey, SshError> {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| SshError::Config(format!("cannot generate ssh host key: {}", e)))?;
    decode_secret_key(&kp.serialize_pem(), None)
        .map_err(|e| SshError::Config(format!("cannot convert generated host key: {}", e)))
}

// ---------------------------------------------------------------------------
// Startup gates
// ---------------------------------------------------------------------------

/// Whether a `+ssh` **listener** for this protocol can actually be served.
///
/// Only `forward+ssh` can. Every other protocol over `+ssh` is gost's
/// `gost-tunnel` transport, which this crate cannot speak; accepting it would
/// mean binding a plain TCP listener under a scheme that promises SSH.
///
/// Call this from the listener setup before binding.
pub fn ssh_listener_support(protocol: &str) -> Result<(), SshError> {
    match protocol {
        "forward" => Ok(()),
        other => Err(SshError::Config(format!(
            "listener {}+ssh is gost's {:?} tunnel transport, which is not implemented \
             (russh has a closed set of channel types and cannot accept a custom one); \
             refusing to start rather than serve plaintext TCP. \
             Only forward+ssh is supported on a listener.",
            if other.is_empty() { "auto" } else { other },
            GOST_SSH_TUNNEL_REQUEST,
        ))),
    }
}

/// Whether a `+ssh` **chain node** for this protocol can actually be dialled.
///
/// `direct+ssh` and `remote+ssh` use SSH port forwarding and are implemented;
/// `forward+ssh` is how gost spells the same thing when the listener is
/// `tcp://` or `rtcp://` (route.go:489-506), so it is accepted too. Anything
/// else is the `gost-tunnel` transport.
pub fn ssh_chain_support(protocol: &str) -> Result<(), SshError> {
    match protocol {
        "direct" | "remote" | "forward" => Ok(()),
        other => Err(SshError::Config(format!(
            "chain node {}+ssh is gost's {:?} tunnel transport, which is not implemented \
             (russh has a closed set of channel types and cannot open a custom one); \
             refusing to start rather than dial in cleartext. \
             Use direct+ssh, remote+ssh or forward+ssh.",
            if other.is_empty() { "auto" } else { other },
            GOST_SSH_TUNNEL_REQUEST,
        ))),
    }
}

// ---------------------------------------------------------------------------
// Server side: forward+ssh
// ---------------------------------------------------------------------------

/// The credentials a `forward+ssh` listener will accept.
///
/// Unlike gost, an empty set is not representable: [`SshServerAuth::build`]
/// fails rather than produce one, so there is no path on which the handler runs
/// without checking anything.
struct SshServerAuth {
    /// Inline `user:pass@` credentials from the listener URL.
    users: HashMap<String, String>,
    /// A `?secrets=` file, reloaded in the background by the caller.
    authenticator: Option<Arc<dyn Authenticator>>,
    authorized_keys: AuthorizedKeys,
}

impl SshServerAuth {
    fn build(options: &HandlerOptions, config: &SshConfig) -> Result<Self, SshError> {
        let authorized_keys = match config.authorized_keys_file.as_deref() {
            Some(path) => parse_ssh_authorized_keys_file(path)?,
            None => AuthorizedKeys::default(),
        };

        let users: HashMap<String, String> = options
            .users
            .iter()
            .map(|(u, p)| (u.clone(), p.clone().unwrap_or_default()))
            .collect();

        if users.is_empty() && options.authenticator.is_none() && authorized_keys.is_empty() {
            return Err(SshError::Config(
                "forward+ssh listener has no authentication configured. gost would enable \
                 NoClientAuth here (ssh.go:521-523), turning the listener into an open \
                 forwarder that will connect anywhere on your behalf. Configure \
                 `-L forward+ssh://user:pass@addr`, `?secrets=<file>`, or \
                 `?ssh_authorized_keys=<file>`."
                    .into(),
            ));
        }

        Ok(Self {
            users,
            authenticator: options.authenticator.clone(),
            authorized_keys,
        })
    }

    fn password_enabled(&self) -> bool {
        !self.users.is_empty() || self.authenticator.is_some()
    }

    fn check_password(&self, user: &str, password: &str) -> bool {
        // Inline userinfo first, then the secrets file — the same two sources
        // every other handler in this crate consults.
        if let Some(expected) = self.users.get(user) {
            if constant_time_eq(expected.as_bytes(), password.as_bytes()) {
                return true;
            }
        }
        if let Some(au) = self.authenticator.as_ref() {
            if au.authenticate(user, password) {
                return true;
            }
        }
        false
    }

    fn check_publickey(&self, key: &PublicKey) -> bool {
        self.authorized_keys.contains(key)
    }
}

/// A length-independent comparison, so a wrong password cannot be narrowed down
/// by timing the reply. russh already pads rejections to a constant
/// `auth_rejection_time`, this covers the accept path as well.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SSH port-forwarding server — gost's `sshForwardHandler` (ssh.go:497-716).
///
/// Serves `-L forward+ssh://`. Runs a real SSH server over the accepted
/// connection, authenticates the client, and then handles:
///
/// * `direct-tcpip` channels — dial the requested address through this
///   listener's chain and splice (ssh.go:599-629);
/// * `tcpip-forward` / `cancel-tcpip-forward` requests — bind a local listener
///   and hand each accepted connection back over a `forwarded-tcpip` channel
///   (ssh.go:637-715).
pub struct SshForwardHandler {
    options: HandlerOptions,
    server_config: Arc<russh::server::Config>,
    auth: Arc<SshServerAuth>,
}

impl SshForwardHandler {
    /// Builds the handler, loading the host key and the accepted credentials.
    ///
    /// Fails when no authentication is configured; see [`SshServerAuth::build`].
    pub fn new(options: HandlerOptions, config: SshConfig) -> Result<Self, SshError> {
        let auth = Arc::new(SshServerAuth::build(&options, &config)?);

        let host_key = match config.key_file.as_deref() {
            Some(path) => parse_ssh_key_file(path, config.key_passphrase.as_deref())?,
            None => {
                let key = generate_host_key()?;
                warn!(
                    "[ssh-forward] no ?ssh_key= given; generated an ephemeral host key \
                     {} — it changes on every restart, so clients cannot pin it",
                    fingerprint(&key.public_key())
                );
                key
            }
        };
        info!(
            "[ssh-forward] host key fingerprint {}",
            fingerprint(&host_key.public_key())
        );

        // Offer exactly the methods that can succeed. Advertising `none` would
        // let a client believe it had authenticated; advertising `password`
        // with no password source just wastes a round trip.
        let mut methods = Vec::new();
        if auth.password_enabled() {
            methods.push(MethodKind::Password);
        }
        if !auth.authorized_keys.is_empty() {
            methods.push(MethodKind::PublicKey);
        }

        let server_config = russh::server::Config {
            keys: vec![host_key],
            methods: MethodSet::from(&methods[..]),
            auth_rejection_time: Duration::from_secs(1),
            inactivity_timeout: Some(Duration::from_secs(600)),
            ..Default::default()
        };

        Ok(Self {
            options,
            server_config: Arc::new(server_config),
            auth: auth.clone(),
        })
    }

    /// The listener address, for logging — gost's `h.options.Node.Addr`.
    fn node_addr(&self) -> String {
        self.options
            .node
            .as_ref()
            .map(|n| n.addr.clone())
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| self.options.addr.clone())
    }
}

#[async_trait]
impl Handler for SshForwardHandler {
    async fn handle(&self, conn: ProxyConn) -> Result<(), HandlerError> {
        let peer_addr = conn.peer_addr_str();
        let peer = conn.peer_addr();
        let node_addr = self.node_addr();

        let session = ForwardSession {
            options: self.options.clone(),
            auth: self.auth.clone(),
            peer,
            peer_addr: peer_addr.clone(),
            node_addr: node_addr.clone(),
            user: String::new(),
            forwards: HashMap::new(),
        };

        // `run_stream` takes the already-accepted connection, so this works over
        // whatever the listener produced — a raw socket today, and any future
        // transport underneath without changes here.
        let running = russh::server::run_stream(self.server_config.clone(), conn, session)
            .await
            .map_err(|e: SshError| {
                debug!("[ssh-forward] {} -> {} : {}", peer_addr, node_addr, e);
                e
            })?;

        info!("[ssh-forward] {} <-> {}", peer_addr, node_addr);
        let result = running.await;
        info!("[ssh-forward] {} >-< {}", peer_addr, node_addr);

        match result {
            Ok(()) => Ok(()),
            // A client that just hangs up mid-session is routine, not an error
            // worth surfacing to the accept loop.
            Err(e) => {
                debug!("[ssh-forward] {} : {}", peer_addr, e);
                Ok(())
            }
        }
    }
}

/// Per-connection SSH server state.
struct ForwardSession {
    options: HandlerOptions,
    auth: Arc<SshServerAuth>,
    peer: Option<SocketAddr>,
    peer_addr: String,
    node_addr: String,
    /// The authenticated principal, for logging.
    user: String,
    /// Listeners opened by `tcpip-forward`, so `cancel-tcpip-forward` and the
    /// end of the session both stop them. gost ties them to a `quit` channel
    /// closed when `handleForward` returns (ssh.go:552-553).
    forwards: HashMap<(String, u32), CancellationToken>,
}

impl ForwardSession {
    fn chain(&self) -> Chain {
        self.options.chain.clone().unwrap_or_default()
    }

    /// gost's access checks before a forwarded dial (ssh.go:604-612).
    fn allowed(&self, action: &str, addr: &str) -> bool {
        if !Can(
            action,
            addr,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            warn!("[ssh-{}] unauthorized to connect to {}", action, addr);
            return false;
        }
        if let Some(bypass) = self.options.bypass.as_ref() {
            if bypass.contains(addr) {
                debug!("[ssh-{}] [bypass] {}", action, addr);
                return false;
            }
        }
        true
    }
}

impl russh::server::Handler for ForwardSession {
    type Error = SshError;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<russh::server::Auth, Self::Error> {
        if self.auth.check_password(user, password) {
            self.user = user.to_string();
            debug!("[ssh-forward] {} authenticated as {:?} by password", self.peer_addr, user);
            return Ok(russh::server::Auth::Accept);
        }
        warn!(
            "[ssh-forward] {} -> {} : password rejected for {:?}",
            self.peer_addr, self.node_addr, user
        );
        Ok(russh::server::Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        if self.auth.check_publickey(public_key) {
            self.user = user.to_string();
            debug!(
                "[ssh-forward] {} authenticated as {:?} by key {}",
                self.peer_addr,
                user,
                fingerprint(public_key)
            );
            return Ok(russh::server::Auth::Accept);
        }
        warn!(
            "[ssh-forward] {} -> {} : unknown public key {} for {:?}",
            self.peer_addr,
            self.node_addr,
            fingerprint(public_key),
            user
        );
        Ok(russh::server::Auth::reject())
    }

    /// RFC 4254 7.2 — gost's `directPortForwardChannel` (ssh.go:599-629).
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<russh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        // gost normalises the `<nil>` host Go's ssh.Unmarshal can produce
        // (ssh.go:583-585).
        let host = if host_to_connect == "<nil>" {
            ""
        } else {
            host_to_connect
        };
        let raddr = join_host_port(host, port_to_connect);

        if !self.allowed("tcp", &raddr) {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        reply.accept().await;

        let chain = self.chain();
        let node_addr = self.node_addr.clone();
        tokio::spawn(async move {
            debug!("[ssh-tcp] {} - {}", node_addr, raddr);
            let remote = match chain.dial(&raddr).await {
                Ok(c) => c,
                Err(e) => {
                    warn!("[ssh-tcp] {} - {} : {}", node_addr, raddr, e);
                    return;
                }
            };
            info!("[ssh-tcp] {} <-> {}", node_addr, raddr);
            transport(channel.into_stream(), remote).await.ok();
            info!("[ssh-tcp] {} >-< {}", node_addr, raddr);
        });

        Ok(())
    }

    /// RFC 4254 7.1 — gost's `tcpipForwardRequest` (ssh.go:637-715).
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        let bind = join_host_port(address, *port);

        if !Can(
            "rtcp",
            &bind,
            self.options.whitelist.as_ref(),
            self.options.blacklist.as_ref(),
        ) {
            warn!("[ssh-rtcp] unauthorized to bind {}", bind);
            return Ok(false);
        }

        // gost binds exactly what was asked for, including a bare `:port`.
        let bind_addr = if address.is_empty() {
            format!("0.0.0.0:{}", port)
        } else {
            bind.clone()
        };

        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                warn!("[ssh-rtcp] cannot bind {}: {}", bind_addr, e);
                return Ok(false);
            }
        };
        let local = listener.local_addr()?;
        // A client asking for port 0 is told which port it actually got, which
        // russh sends back in the reply (ssh.go:659-671).
        if *port == 0 {
            *port = local.port() as u32;
        }
        info!("[ssh-rtcp] listening on tcp {}", local);

        let cancel = CancellationToken::new();
        self.forwards
            .insert((address.to_string(), *port), cancel.clone());

        let handle = session.handle();
        let connected_address = address.to_string();
        let connected_port = *port;
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = cancel.cancelled() => break,
                    r = listener.accept() => r,
                };
                let (stream, from) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("[ssh-rtcp] {} accept: {}", local, e);
                        break;
                    }
                };

                let handle = handle.clone();
                let connected_address = connected_address.clone();
                tokio::spawn(async move {
                    let channel = match handle
                        .channel_open_forwarded_tcpip(
                            connected_address,
                            connected_port,
                            from.ip().to_string(),
                            from.port() as u32,
                        )
                        .await
                    {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("[ssh-rtcp] open {} channel: {}", FORWARDED_TCP_RETURN_REQUEST, e);
                            return;
                        }
                    };
                    info!("[ssh-rtcp] {} <-> {}", from, local);
                    transport(channel.into_stream(), stream).await.ok();
                    info!("[ssh-rtcp] {} >-< {}", from, local);
                });
            }
            debug!("[ssh-rtcp] {} closed", local);
        });

        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        match self.forwards.remove(&(address.to_string(), port)) {
            Some(cancel) => {
                cancel.cancel();
                debug!("[ssh-rtcp] {} {}:{}", CANCEL_REMOTE_FORWARD_REQUEST, address, port);
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl Drop for ForwardSession {
    fn drop(&mut self) {
        // gost closes its remote-forward listeners when handleForward returns;
        // without this a client could leave bound ports behind by disconnecting.
        for (_, cancel) in self.forwards.drain() {
            cancel.cancel();
        }
    }
}

// ---------------------------------------------------------------------------
// Client side: direct+ssh / remote+ssh
// ---------------------------------------------------------------------------

/// A live, authenticated SSH client session — gost's `sshSession` (ssh.go:398-406).
pub struct SshSession {
    addr: String,
    handle: russh::client::Handle<SshClientSession>,
    /// Connections the server accepted on a port bound by `tcpip-forward`.
    ///
    /// The queue lives here rather than in the handler because russh gives no
    /// way back to a running client handler; the handler keeps only the sender.
    forwarded: Mutex<tokio::sync::mpsc::Receiver<ProxyConn>>,
}

impl SshSession {
    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// Opens a `direct-tcpip` channel to `raddr` — gost's
    /// `sshDirectForwardConnector.ConnectContext` (ssh.go:71-101).
    pub async fn connect(&self, raddr: &str) -> Result<ProxyConn, SshError> {
        let (host, port) = split_host_port(raddr)?;
        let channel = self
            .handle
            .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
            .await
            .map_err(|e| {
                SshError::Protocol(format!(
                    "{} to {} via {} failed: {}",
                    DIRECT_FORWARD_REQUEST, raddr, self.addr, e
                ))
            })?;
        debug!("[ssh-tcp] {} -> {}", self.addr, raddr);
        Ok(ProxyConn::layered(Box::new(channel.into_stream()), None, None))
    }

    /// Asks the server to bind `address` and stream back the connections it
    /// accepts — gost's `sshRemoteForwardConnector` (ssh.go:110-164).
    pub async fn remote_forward(&self, address: &str) -> Result<u16, SshError> {
        // gost rewrites a bare `:port` to `0.0.0.0:port` (ssh.go:133-135).
        let address = if let Some(port) = address.strip_prefix(':') {
            format!("0.0.0.0:{}", port)
        } else {
            address.to_string()
        };
        let (host, port) = split_host_port(&address)?;
        let bound = self
            .handle
            .tcpip_forward(host, port as u32)
            .await
            .map_err(|e| {
                SshError::Protocol(format!(
                    "{} {} via {} failed: {}",
                    REMOTE_FORWARD_REQUEST, address, self.addr, e
                ))
            })?;
        let bound = if port == 0 { bound as u16 } else { port };
        info!("[ssh-rtcp] {} listening on {}:{}", self.addr, host, bound);
        Ok(bound)
    }

    /// Receives the next connection the server accepted on a bound port.
    ///
    /// Returns `None` once the session ends.
    pub async fn accept_forwarded(&self) -> Option<ProxyConn> {
        self.forwarded.lock().await.recv().await
    }
}

/// The russh client callbacks: host key policy and inbound `forwarded-tcpip`
/// channels.
struct SshClientSession {
    /// The public key the server must present, when `?ssh_host_key=` pinned one.
    pinned_host_key: Option<String>,
    addr: String,
    /// Connections arriving on a `tcpip-forward` bind, queued for
    /// [`SshSession::accept_forwarded`]. gost uses a 1024-deep channel and drops
    /// on overflow (ssh.go:149-154).
    forwarded: tokio::sync::mpsc::Sender<ProxyConn>,
}

impl russh::client::Handler for SshClientSession {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = match server_public_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            russh::keys::PublicKeyOrCertificate::Certificate(c) => {
                // A certificate is not a bare key; pinning one is out of scope,
                // so it is only accepted when nothing is pinned.
                match &self.pinned_host_key {
                    Some(_) => {
                        warn!(
                            "[ssh] {} offered a host certificate, which ?ssh_host_key= cannot pin",
                            self.addr
                        );
                        return Ok(false);
                    }
                    None => {
                        info!("[ssh] {} host certificate for {:?}", self.addr, c.key_id());
                        return Ok(true);
                    }
                }
            }
        };

        let fp = fingerprint(&key);
        match &self.pinned_host_key {
            Some(expected) => {
                if constant_time_eq(expected.as_bytes(), fp.as_bytes()) {
                    debug!("[ssh] {} host key {} matches the pin", self.addr, fp);
                    Ok(true)
                } else {
                    error!(
                        "[ssh] {} host key mismatch: pinned {}, offered {}",
                        self.addr, expected, fp
                    );
                    Ok(false)
                }
            }
            None => {
                // gost's default (ssh.InsecureIgnoreHostKey, ssh.go:225/339).
                // Logged at info so the fingerprint can be copied into
                // ?ssh_host_key= to close the MITM window.
                info!(
                    "[ssh] {} host key {} accepted unverified; set ?ssh_host_key= to pin it",
                    self.addr, fp
                );
                Ok(true)
            }
        }
    }

    /// RFC 4254 7.2 inbound half — a connection the server accepted on a port we
    /// asked it to bind.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<russh::client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        debug!(
            "[ssh-rtcp] {}:{} <- {}:{}",
            connected_address, connected_port, originator_address, originator_port
        );
        let conn = ProxyConn::layered(Box::new(channel.into_stream()), None, None);
        // Drop rather than block the session loop when nothing is accepting,
        // as gost does with its full `connChan`.
        if self.forwarded.try_send(conn).is_err() {
            warn!("[ssh-rtcp] {} connection queue is full", self.addr);
        }
        Ok(())
    }
}

/// SSH port-forwarding client — gost's `sshForwardTransporter` (ssh.go:166-278).
///
/// Holds one authenticated session per SSH server address and opens a channel
/// per dial, which is the whole point of the transport: gost's `Multiplex()`
/// returns true for it (ssh.go:276-278).
pub struct SshForwardTransporter {
    config: SshConfig,
    identity: Option<Arc<PrivateKey>>,
    pinned_host_key: Option<String>,
    sessions: Mutex<HashMap<String, Arc<SshSession>>>,
}

impl SshForwardTransporter {
    /// Builds the client, loading `?ssh_key=` and `?ssh_host_key=`.
    ///
    /// Fails when neither a password nor a private key is configured: an SSH
    /// client with no credentials can only reach a server that accepts
    /// `none` authentication, which is exactly the configuration this module
    /// refuses to serve.
    pub fn new(config: SshConfig) -> Result<Self, SshError> {
        let identity = match config.key_file.as_deref() {
            Some(path) => Some(Arc::new(parse_ssh_key_file(
                path,
                config.key_passphrase.as_deref(),
            )?)),
            None => None,
        };

        if identity.is_none() && config.password.as_deref().unwrap_or("").is_empty() {
            return Err(SshError::Config(
                "ssh chain node has no credentials: give `user:password@` in the node URL \
                 or `?ssh_key=<file>`. Connecting without either would only work against a \
                 server that requires no authentication at all."
                    .into(),
            ));
        }

        let pinned_host_key = match config.host_key_file.as_deref() {
            Some(path) => {
                let text = std::fs::read_to_string(path).map_err(|e| {
                    SshError::Config(format!("cannot read ssh host key file {:?}: {}", path, e))
                })?;
                let key = PublicKey::from_openssh(text.trim()).map_err(|e| {
                    SshError::Config(format!("cannot parse ssh host key file {:?}: {}", path, e))
                })?;
                Some(fingerprint(&key))
            }
            None => None,
        };

        Ok(Self {
            config,
            identity,
            pinned_host_key,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the live session for `addr`, dialling a TCP connection and
    /// authenticating if there is none — gost's `Dial` + `Handshake` pair
    /// (ssh.go:178-274).
    pub async fn session(&self, addr: &str) -> Result<Arc<SshSession>, SshError> {
        let timeout = self.config.handshake_timeout();
        let target = addr.to_string();
        self.session_over(addr, || async move {
            let stream = tokio::time::timeout(timeout, TcpStream::connect(&target))
                .await
                .map_err(|_| {
                    SshError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("timed out connecting to {}", target),
                    ))
                })??;
            Ok(stream)
        })
        .await
    }

    /// Like [`session`](Self::session), but the caller supplies the transport.
    ///
    /// This is what a chain hop needs: gost reaches an SSH node through the rest
    /// of the chain (`opts.Chain.Dial(addr)`, ssh.go:194-198) rather than with a
    /// direct socket. `dial` runs only on a pool miss, so a chained hop still
    /// gets one SSH session shared by every stream on it.
    pub async fn session_over<F, Fut, S>(
        &self,
        addr: &str,
        dial: F,
    ) -> Result<Arc<SshSession>, SshError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<S, SshError>>,
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // The lock is held across the handshake on purpose: two concurrent
        // dials to a cold node must produce one session, not two.
        let mut sessions = self.sessions.lock().await;
        if let Some(existing) = sessions.get(addr) {
            if !existing.is_closed() {
                return Ok(existing.clone());
            }
            sessions.remove(addr);
        }

        let stream = dial().await?;
        let session = tokio::time::timeout(
            self.config.handshake_timeout(),
            self.handshake(stream, addr),
        )
        .await
        .map_err(|_| SshError::Protocol(format!("timed out in the SSH handshake with {}", addr)))??;

        let session = Arc::new(session);
        sessions.insert(addr.to_string(), session.clone());
        Ok(session)
    }

    /// Runs the SSH handshake and authentication over an already-connected
    /// stream, so a chain hop can put SSH on top of whatever it produced.
    pub async fn handshake<S>(&self, stream: S, addr: &str) -> Result<SshSession, SshError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(REMOTE_FORWARD_BACKLOG);
        let handler = SshClientSession {
            pinned_host_key: self.pinned_host_key.clone(),
            addr: addr.to_string(),
            forwarded: tx,
        };

        let client_config = russh::client::Config {
            keepalive_interval: if self.config.ping_interval.is_zero() {
                None
            } else {
                Some(self.config.ping_interval)
            },
            keepalive_max: self.config.ping_retries.max(1),
            ..Default::default()
        };

        let mut handle =
            russh::client::connect_stream(Arc::new(client_config), stream, handler).await?;

        let user = self.config.user.clone().unwrap_or_default();
        let mut authenticated = false;

        // Key first, then password — the order OpenSSH uses, and the order that
        // avoids sending the password when a key would have done.
        if let Some(key) = self.identity.as_ref() {
            let with_hash = PrivateKeyWithHashAlg::new(key.clone(), None);
            match handle.authenticate_publickey(user.clone(), with_hash).await {
                Ok(r) if r.success() => authenticated = true,
                Ok(_) => debug!("[ssh] {} rejected the public key for {:?}", addr, user),
                Err(e) => debug!("[ssh] {} public key auth failed: {}", addr, e),
            }
        }

        if !authenticated {
            if let Some(password) = self.config.password.as_deref().filter(|p| !p.is_empty()) {
                if handle
                    .authenticate_password(user.clone(), password)
                    .await?
                    .success()
                {
                    authenticated = true;
                }
            }
        }

        if !authenticated {
            return Err(SshError::AuthFailed);
        }

        info!("[ssh] authenticated to {} as {:?}", addr, user);
        Ok(SshSession {
            addr: addr.to_string(),
            handle,
            forwarded: Mutex::new(rx),
        })
    }

    /// Opens a forwarded connection to `raddr` through the SSH server at `addr`.
    ///
    /// This is the `direct+ssh` chain connector: `SSHDirectForwardConnector` +
    /// `SSHForwardTransporter` in gost (route.go:265-266, 489-493).
    pub async fn connect(&self, addr: &str, raddr: &str) -> Result<ProxyConn, SshError> {
        let session = self.session(addr).await?;
        match session.connect(raddr).await {
            Ok(conn) => Ok(conn),
            Err(e) => {
                // A channel refused because the session died underneath us is
                // worth exactly one retry on a fresh session; gost gets the same
                // effect by dropping dead sessions from its map.
                if session.is_closed() {
                    self.sessions.lock().await.remove(addr);
                    let session = self.session(addr).await?;
                    return session.connect(raddr).await;
                }
                Err(e)
            }
        }
    }

    /// Binds `bind` on the SSH server and returns a handle that yields each
    /// connection it accepts — the `remote+ssh` chain connector.
    pub async fn remote_forward(
        &self,
        addr: &str,
        bind: &str,
    ) -> Result<SshRemoteForward, SshError> {
        let session = self.session(addr).await?;
        let port = session.remote_forward(bind).await?;
        Ok(SshRemoteForward { session, port })
    }
}

/// A port bound on the SSH server by `tcpip-forward`.
pub struct SshRemoteForward {
    session: Arc<SshSession>,
    port: u16,
}

impl SshRemoteForward {
    /// The port actually bound, which differs from the request when it asked
    /// for 0.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Waits for the next connection the server accepted on the bound port.
    pub async fn accept(&self) -> Option<ProxyConn> {
        self.session.accept_forwarded().await
    }
}

/// SSH direct port forwarding connector — gost's `sshDirectForwardConnector`
/// (ssh.go:60-101). A thin named wrapper over [`SshForwardTransporter`], kept so
/// the chain wiring can name the two forwarding modes apart.
pub struct SshDirectForwardConnector {
    transporter: SshForwardTransporter,
}

impl SshDirectForwardConnector {
    pub fn new(config: SshConfig) -> Result<Self, SshError> {
        Ok(Self {
            transporter: SshForwardTransporter::new(config)?,
        })
    }

    pub async fn connect(&self, ssh_addr: &str, raddr: &str) -> Result<ProxyConn, SshError> {
        self.transporter.connect(ssh_addr, raddr).await
    }
}

/// SSH remote port forwarding connector — gost's `sshRemoteForwardConnector`
/// (ssh.go:103-164).
pub struct SshRemoteForwardConnector {
    transporter: SshForwardTransporter,
}

impl SshRemoteForwardConnector {
    pub fn new(config: SshConfig) -> Result<Self, SshError> {
        Ok(Self {
            transporter: SshForwardTransporter::new(config)?,
        })
    }

    pub async fn bind(&self, ssh_addr: &str, bind: &str) -> Result<SshRemoteForward, SshError> {
        self.transporter.remote_forward(ssh_addr, bind).await
    }
}

// ---------------------------------------------------------------------------
// The gost-tunnel transport: not implemented, and never silently downgraded
// ---------------------------------------------------------------------------

/// SSH tunnel transporter — gost's `sshTunnelTransporter` (ssh.go:280-396).
///
/// **Not implemented.** The construction below always fails; see the module
/// documentation for why `russh` cannot open a `gost-tunnel` channel.
///
/// The previous version of this type connected a TCP socket and returned it as
/// "the SSH tunnel", so `-F http+ssh://` sent proxy traffic in cleartext to a
/// peer that was expecting SSH. Failing loudly is the only safe replacement.
pub struct SshTunnelTransporter {
    _config: SshConfig,
}

impl SshTunnelTransporter {
    pub fn new(_config: SshConfig) -> Result<Self, SshError> {
        Err(unsupported_tunnel("chain node"))
    }

    pub async fn dial(&self, _ssh_addr: &str, _remote_addr: &str) -> Result<ProxyConn, SshError> {
        Err(unsupported_tunnel("chain node"))
    }
}

/// SSH tunnel listener — gost's `sshTunnelListener` (ssh.go:725-839).
///
/// **Not implemented**, for the same reason as [`SshTunnelTransporter`]: russh's
/// server rejects any channel type outside its fixed set, so it can never accept
/// the `gost-tunnel` channel a gost client opens.
pub struct SshTunnelListener {
    _addr: String,
    _config: SshConfig,
}

impl SshTunnelListener {
    pub fn new(_addr: &str, _config: SshConfig) -> Result<Self, SshError> {
        Err(unsupported_tunnel("listener"))
    }
}

fn unsupported_tunnel(role: &str) -> SshError {
    SshError::Config(format!(
        "the SSH tunnel transport ({:?} channel) is not implemented, so this {} cannot be \
         served. russh exposes a closed set of channel types and offers no way to open or \
         accept a custom one, and a tunnel built on `direct-tcpip` instead would be \
         incompatible with every real gost peer while looking identical from this side. \
         Use forward+ssh with direct+ssh / remote+ssh for SSH port forwarding, or \
         +tls / +ws for a general-purpose encrypted transport.",
        GOST_SSH_TUNNEL_REQUEST, role
    ))
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

/// Joins a host and port the way Go's `net.JoinHostPort` does, bracketing an
/// IPv6 literal.
fn join_host_port(host: &str, port: u32) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn split_host_port(addr: &str) -> Result<(&str, u16), SshError> {
    let (host, port) = if let Some(rest) = addr.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| SshError::Protocol(format!("unbalanced IPv6 brackets in {:?}", addr)))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| SshError::Protocol(format!("missing port in {:?}", addr)))?;
        (host, port)
    } else {
        addr.rsplit_once(':')
            .ok_or_else(|| SshError::Protocol(format!("invalid address {:?}", addr)))?
    };
    let port = port
        .parse()
        .map_err(|_| SshError::Protocol(format!("invalid port in {:?}", addr)))?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn options_with_password(user: &str, pass: &str) -> HandlerOptions {
        HandlerOptions {
            users: vec![(user.to_string(), Some(pass.to_string()))],
            ..Default::default()
        }
    }

    /// Writes a freshly generated host key to a temp file and returns the path.
    /// Nothing is committed to the repository, as required.
    fn temp_key_file(name: &str) -> (String, PrivateKey) {
        let key = generate_host_key().unwrap();
        let pem = key.to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap();
        let path = std::env::temp_dir().join(format!("rustun-ssh-test-{}-{}", std::process::id(), name));
        std::fs::write(&path, pem.as_bytes()).unwrap();
        (path.to_string_lossy().into_owned(), key)
    }

    // -- configuration and key material ------------------------------------

    #[test]
    fn test_ssh_config_default() {
        let config = SshConfig::default();
        assert!(config.key_file.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_ssh_config_debug_redacts_password() {
        let config = SshConfig {
            password: Some("hunter2".into()),
            user: Some("bob".into()),
            ..Default::default()
        };
        let rendered = format!("{:?}", config);
        assert!(!rendered.contains("hunter2"), "password leaked: {}", rendered);
        assert!(rendered.contains("bob"));
    }

    #[test]
    fn test_ssh_config_from_node() {
        let node = Node::parse("forward+ssh://u:p@127.0.0.1:2222?ssh_key=/k&ping=10s").unwrap();
        let config = SshConfig::from_node(&node);
        assert_eq!(config.user.as_deref(), Some("u"));
        assert_eq!(config.password.as_deref(), Some("p"));
        assert_eq!(config.key_file.as_deref(), Some("/k"));
        assert_eq!(config.ping_interval, Duration::from_secs(10));
    }

    #[test]
    fn test_parse_ssh_key_file_not_found() {
        assert!(parse_ssh_key_file("nonexistent_key", None).is_err());
    }

    #[test]
    fn test_parse_ssh_key_file_roundtrip() {
        let (path, key) = temp_key_file("roundtrip");
        let loaded = parse_ssh_key_file(&path, None).unwrap();
        assert_eq!(fingerprint(&loaded.public_key()), fingerprint(&key.public_key()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_parse_authorized_keys_not_found() {
        assert!(parse_ssh_authorized_keys_file("nonexistent_keys").is_err());
    }

    #[test]
    fn test_authorized_keys_parse_and_lookup() {
        let key = generate_host_key().unwrap();
        let other = generate_host_key().unwrap();
        let line = key.public_key().to_openssh().unwrap();

        let keys = AuthorizedKeys::parse(&format!("# comment\n\n{}\n", line)).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&key.public_key()));
        assert!(!keys.contains(&other.public_key()));
    }

    #[test]
    fn test_authorized_keys_rejects_garbage() {
        // Skipping an unparseable line would silently shrink the set of
        // principals the operator thinks they authorized.
        assert!(AuthorizedKeys::parse("ssh-ed25519 not-base64 user@host").is_err());
    }

    #[test]
    fn test_generated_host_key_is_ed25519_and_unique() {
        let a = generate_host_key().unwrap();
        let b = generate_host_key().unwrap();
        assert_ne!(fingerprint(&a.public_key()), fingerprint(&b.public_key()));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn test_join_and_split_host_port() {
        assert_eq!(join_host_port("1.2.3.4", 80), "1.2.3.4:80");
        assert_eq!(join_host_port("::1", 80), "[::1]:80");
        assert_eq!(split_host_port("1.2.3.4:80").unwrap(), ("1.2.3.4", 80));
        assert_eq!(split_host_port("[::1]:80").unwrap(), ("::1", 80));
        assert!(split_host_port("nonsense").is_err());
    }

    // -- the security fix: no unauthenticated path -------------------------

    #[test]
    fn test_forward_handler_refuses_without_auth() {
        // The bug this module exists to fix: gost sets NoClientAuth here, and
        // the previous version of this file did not even run a handshake.
        let err = SshForwardHandler::new(HandlerOptions::default(), SshConfig::default())
            .err()
            .expect("a forward+ssh listener with no credentials must not start");
        assert!(
            err.to_string().contains("no authentication configured"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_forward_handler_accepts_password_config() {
        assert!(
            SshForwardHandler::new(options_with_password("u", "p"), SshConfig::default()).is_ok()
        );
    }

    #[test]
    fn test_forward_handler_accepts_authorized_keys_only() {
        let key = generate_host_key().unwrap();
        let path = std::env::temp_dir()
            .join(format!("rustun-ssh-test-ak-{}", std::process::id()));
        std::fs::write(&path, key.public_key().to_openssh().unwrap()).unwrap();

        let config = SshConfig {
            authorized_keys_file: Some(path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        assert!(SshForwardHandler::new(HandlerOptions::default(), config).is_ok());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_transporter_refuses_without_credentials() {
        let err = SshForwardTransporter::new(SshConfig::default())
            .err()
            .expect("an ssh chain node with no credentials must not start");
        assert!(err.to_string().contains("no credentials"), "got: {}", err);
    }

    #[test]
    fn test_tunnel_transport_is_a_hard_error() {
        // Never a silent plaintext relay: both halves refuse to be built.
        let e = SshTunnelTransporter::new(SshConfig::default()).err().unwrap();
        assert!(e.to_string().contains("gost-tunnel"), "got: {}", e);
        let e = SshTunnelListener::new("127.0.0.1:0", SshConfig::default())
            .err()
            .unwrap();
        assert!(e.to_string().contains("not implemented"), "got: {}", e);
    }

    #[test]
    fn test_startup_gates() {
        assert!(ssh_listener_support("forward").is_ok());
        for p in ["http", "socks5", "", "tcp"] {
            assert!(
                ssh_listener_support(p).is_err(),
                "{}+ssh listener must be rejected",
                p
            );
        }
        for p in ["direct", "remote", "forward"] {
            assert!(ssh_chain_support(p).is_ok(), "{}+ssh chain must be allowed", p);
        }
        for p in ["http", "socks5", ""] {
            assert!(ssh_chain_support(p).is_err(), "{}+ssh chain must be rejected", p);
        }
    }

    // -- end-to-end, this crate against itself -----------------------------

    /// Starts a target that echoes a fixed banner, a `forward+ssh` listener and
    /// returns both addresses.
    async fn start_forward_server(
        options: HandlerOptions,
        config: SshConfig,
    ) -> (SocketAddr, SocketAddr) {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = target.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    c.write_all(b"SSH-FORWARD-OK").await.ok();
                });
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_addr = listener.local_addr().unwrap();
        let handler = Arc::new(SshForwardHandler::new(options, config).unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((c, _)) = listener.accept().await else {
                    return;
                };
                let handler = handler.clone();
                tokio::spawn(async move {
                    handler.handle(ProxyConn::from_tcp(c)).await.ok();
                });
            }
        });

        (ssh_addr, target_addr)
    }

    #[tokio::test]
    async fn test_direct_tcpip_forward_end_to_end() {
        let (ssh_addr, target_addr) =
            start_forward_server(options_with_password("u", "p"), SshConfig::default()).await;

        let client = SshForwardTransporter::new(SshConfig {
            user: Some("u".into()),
            password: Some("p".into()),
            ..Default::default()
        })
        .unwrap();

        let mut conn = client
            .connect(&ssh_addr.to_string(), &target_addr.to_string())
            .await
            .unwrap();

        let mut buf = [0u8; 14];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"SSH-FORWARD-OK");
    }

    #[tokio::test]
    async fn test_session_is_reused_across_dials() {
        // The point of the transporter: gost's Multiplex() is true, so a second
        // dial must not build a second SSH session.
        let (ssh_addr, target_addr) =
            start_forward_server(options_with_password("u", "p"), SshConfig::default()).await;

        let client = SshForwardTransporter::new(SshConfig {
            user: Some("u".into()),
            password: Some("p".into()),
            ..Default::default()
        })
        .unwrap();

        let a = client.session(&ssh_addr.to_string()).await.unwrap();
        let _ = client
            .connect(&ssh_addr.to_string(), &target_addr.to_string())
            .await
            .unwrap();
        let b = client.session(&ssh_addr.to_string()).await.unwrap();
        assert!(Arc::ptr_eq(&a, &b), "each dial built a new SSH session");
    }

    #[tokio::test]
    async fn test_wrong_password_is_rejected() {
        let (ssh_addr, _) =
            start_forward_server(options_with_password("u", "p"), SshConfig::default()).await;

        let client = SshForwardTransporter::new(SshConfig {
            user: Some("u".into()),
            password: Some("wrong".into()),
            ..Default::default()
        })
        .unwrap();

        let err = client.session(&ssh_addr.to_string()).await.err().unwrap();
        assert!(matches!(err, SshError::AuthFailed), "got: {}", err);
    }

    #[tokio::test]
    async fn test_public_key_auth_end_to_end() {
        let (key_path, key) = temp_key_file("pubkey-auth");
        let ak_path = std::env::temp_dir()
            .join(format!("rustun-ssh-test-ak2-{}", std::process::id()));
        std::fs::write(&ak_path, key.public_key().to_openssh().unwrap()).unwrap();

        let (ssh_addr, target_addr) = start_forward_server(
            HandlerOptions::default(),
            SshConfig {
                authorized_keys_file: Some(ak_path.to_string_lossy().into_owned()),
                ..Default::default()
            },
        )
        .await;

        let client = SshForwardTransporter::new(SshConfig {
            user: Some("u".into()),
            key_file: Some(key_path.clone()),
            ..Default::default()
        })
        .unwrap();

        let mut conn = client
            .connect(&ssh_addr.to_string(), &target_addr.to_string())
            .await
            .unwrap();
        let mut buf = [0u8; 14];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"SSH-FORWARD-OK");

        std::fs::remove_file(&key_path).ok();
        std::fs::remove_file(&ak_path).ok();
    }

    #[tokio::test]
    async fn test_unauthorized_key_is_rejected() {
        let (key_path, _) = temp_key_file("bad-pubkey");
        let authorized = generate_host_key().unwrap();
        let ak_path = std::env::temp_dir()
            .join(format!("rustun-ssh-test-ak3-{}", std::process::id()));
        std::fs::write(&ak_path, authorized.public_key().to_openssh().unwrap()).unwrap();

        let (ssh_addr, _) = start_forward_server(
            HandlerOptions::default(),
            SshConfig {
                authorized_keys_file: Some(ak_path.to_string_lossy().into_owned()),
                ..Default::default()
            },
        )
        .await;

        let client = SshForwardTransporter::new(SshConfig {
            user: Some("u".into()),
            key_file: Some(key_path.clone()),
            ..Default::default()
        })
        .unwrap();

        assert!(client.session(&ssh_addr.to_string()).await.is_err());

        std::fs::remove_file(&key_path).ok();
        std::fs::remove_file(&ak_path).ok();
    }

    #[tokio::test]
    async fn test_blacklist_blocks_direct_forward() {
        let mut options = options_with_password("u", "p");
        options.blacklist = Some(crate::permissions::Permissions::parse("tcp:*:*").unwrap());
        let (ssh_addr, target_addr) = start_forward_server(options, SshConfig::default()).await;

        let client = SshForwardTransporter::new(SshConfig {
            user: Some("u".into()),
            password: Some("p".into()),
            ..Default::default()
        })
        .unwrap();

        assert!(
            client
                .connect(&ssh_addr.to_string(), &target_addr.to_string())
                .await
                .is_err(),
            "a blacklisted target must not be forwarded"
        );
    }

    #[tokio::test]
    async fn test_host_key_pinning_rejects_a_different_key() {
        let (ssh_addr, _) =
            start_forward_server(options_with_password("u", "p"), SshConfig::default()).await;

        // Pin an unrelated key: the handshake must fail rather than proceed and
        // hand the password to whoever answered.
        let other = generate_host_key().unwrap();
        let pin_path = std::env::temp_dir()
            .join(format!("rustun-ssh-test-pin-{}", std::process::id()));
        std::fs::write(&pin_path, other.public_key().to_openssh().unwrap()).unwrap();

        let client = SshForwardTransporter::new(SshConfig {
            user: Some("u".into()),
            password: Some("p".into()),
            host_key_file: Some(pin_path.to_string_lossy().into_owned()),
            ..Default::default()
        })
        .unwrap();

        assert!(client.session(&ssh_addr.to_string()).await.is_err());
        std::fs::remove_file(&pin_path).ok();
    }

    #[tokio::test]
    async fn test_host_key_pinning_accepts_the_right_key() {
        let (key_path, key) = temp_key_file("pin-ok");
        let (ssh_addr, target_addr) = start_forward_server(
            options_with_password("u", "p"),
            SshConfig {
                key_file: Some(key_path.clone()),
                ..Default::default()
            },
        )
        .await;

        let pin_path = std::env::temp_dir()
            .join(format!("rustun-ssh-test-pin2-{}", std::process::id()));
        std::fs::write(&pin_path, key.public_key().to_openssh().unwrap()).unwrap();

        let client = SshForwardTransporter::new(SshConfig {
            user: Some("u".into()),
            password: Some("p".into()),
            host_key_file: Some(pin_path.to_string_lossy().into_owned()),
            ..Default::default()
        })
        .unwrap();

        let mut conn = client
            .connect(&ssh_addr.to_string(), &target_addr.to_string())
            .await
            .unwrap();
        let mut buf = [0u8; 14];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"SSH-FORWARD-OK");

        std::fs::remove_file(&key_path).ok();
        std::fs::remove_file(&pin_path).ok();
    }

    #[tokio::test]
    async fn test_remote_forward_end_to_end() {
        let (ssh_addr, _) =
            start_forward_server(options_with_password("u", "p"), SshConfig::default()).await;

        let client = SshForwardTransporter::new(SshConfig {
            user: Some("u".into()),
            password: Some("p".into()),
            ..Default::default()
        })
        .unwrap();

        let forward = client
            .remote_forward(&ssh_addr.to_string(), "127.0.0.1:0")
            .await
            .unwrap();
        assert_ne!(forward.port(), 0, "the server must report the bound port");

        // Something connecting to the bound port must surface as a channel.
        let bound = format!("127.0.0.1:{}", forward.port());
        tokio::spawn(async move {
            if let Ok(mut c) = TcpStream::connect(&bound).await {
                c.write_all(b"REMOTE-OK").await.ok();
            }
        });

        let mut conn = tokio::time::timeout(Duration::from_secs(10), forward.accept())
            .await
            .expect("timed out waiting for the forwarded connection")
            .expect("session closed before a connection arrived");

        let mut buf = [0u8; 9];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"REMOTE-OK");
    }

    // -- interoperability with the real gost binary ------------------------
    //
    // These run only when a gost 2.12.0 binary is present; they are skipped
    // elsewhere rather than failing, so the suite stays portable.

    /// Locates the gost binary.
    ///
    /// `/tmp` is not a real path for a Windows process — the MSYS shell that
    /// documents `/tmp/gost.exe` maps it to `%TEMP%` — so the platform temp
    /// directory is checked as well. Getting this wrong makes the interop tests
    /// silently skip while still reporting `ok`.
    fn gost_binary() -> Option<String> {
        let mut candidates: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(explicit) = std::env::var("GOST_BIN") {
            candidates.push(explicit.into());
        }
        for name in ["gost.exe", "gost"] {
            candidates.push(std::env::temp_dir().join(name));
            candidates.push(std::path::PathBuf::from("/tmp").join(name));
            candidates.push(std::path::PathBuf::from("C:/tmp").join(name));
        }
        candidates
            .into_iter()
            .find(|p| p.is_file())
            .map(|p| p.to_string_lossy().into_owned())
    }

    async fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// A child process killed when the guard is dropped.
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            self.0.kill().ok();
            self.0.wait().ok();
        }
    }

    #[tokio::test]
    async fn test_interop_rustun_client_to_gost_forward_ssh_server() {
        let Some(gost) = gost_binary() else {
            eprintln!("skipping: no gost binary found");
            return;
        };

        // A target for the forwarded connection to reach.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut c, _)) = target.accept().await {
                c.write_all(b"GOST-SERVER-OK").await.ok();
            }
        });

        let port = free_port().await;
        let _gost = Child(
            std::process::Command::new(&gost)
                .arg(format!("-L=forward+ssh://u:p@127.0.0.1:{}", port))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("cannot spawn gost"),
        );
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let client = SshForwardTransporter::new(SshConfig {
            user: Some("u".into()),
            password: Some("p".into()),
            ..Default::default()
        })
        .unwrap();

        let mut conn = tokio::time::timeout(
            Duration::from_secs(15),
            client.connect(&format!("127.0.0.1:{}", port), &target_addr.to_string()),
        )
        .await
        .expect("timed out dialling gost")
        .expect("direct-tcpip through gost failed");

        let mut buf = [0u8; 14];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"GOST-SERVER-OK");
    }

    #[tokio::test]
    async fn test_interop_gost_enforces_the_password() {
        // Guards against the interop test above passing for the wrong reason:
        // if gost had fallen back to NoClientAuth, a wrong password would also
        // get through and the test would prove nothing about authentication.
        let Some(gost) = gost_binary() else {
            eprintln!("skipping: no gost binary found");
            return;
        };

        let port = free_port().await;
        let _gost = Child(
            std::process::Command::new(&gost)
                .arg(format!("-L=forward+ssh://u:p@127.0.0.1:{}", port))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("cannot spawn gost"),
        );
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let client = SshForwardTransporter::new(SshConfig {
            user: Some("u".into()),
            password: Some("definitely-wrong".into()),
            ..Default::default()
        })
        .unwrap();

        let err = tokio::time::timeout(
            Duration::from_secs(15),
            client.session(&format!("127.0.0.1:{}", port)),
        )
        .await
        .expect("timed out dialling gost")
        .err()
        .expect("gost accepted a wrong password: it is not enforcing authentication");
        assert!(matches!(err, SshError::AuthFailed), "got: {}", err);
    }

    #[tokio::test]
    async fn test_interop_gost_client_to_rustun_forward_ssh_server() {
        let Some(gost) = gost_binary() else {
            eprintln!("skipping: no gost binary found");
            return;
        };

        let (ssh_addr, target_addr) =
            start_forward_server(options_with_password("u", "p"), SshConfig::default()).await;

        // gost's `-L tcp://` + `-F forward+ssh://` swaps in its SSH direct
        // forward connector (route.go:489-493), so this is a real gost SSH
        // client talking to our server.
        let local = free_port().await;
        let _gost = Child(
            std::process::Command::new(&gost)
                .arg(format!("-L=tcp://127.0.0.1:{}/{}", local, target_addr))
                .arg(format!("-F=forward+ssh://u:p@{}", ssh_addr))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("cannot spawn gost"),
        );
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let mut conn = tokio::time::timeout(
            Duration::from_secs(15),
            TcpStream::connect(format!("127.0.0.1:{}", local)),
        )
        .await
        .expect("timed out connecting to the gost listener")
        .expect("gost listener refused the connection");

        let mut buf = [0u8; 14];
        tokio::time::timeout(Duration::from_secs(15), conn.read_exact(&mut buf))
            .await
            .expect("timed out reading through the gost -> rustun ssh forward")
            .expect("read failed");
        assert_eq!(&buf, b"SSH-FORWARD-OK");
    }
}
