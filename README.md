# rustun

A multi-protocol security tunnel written in Rust, ported from [gost](https://github.com/ginuerzh/gost) (GO Simple Tunnel).

rustun provides a unified command-line interface for proxying, tunneling, and forwarding network traffic across a wide range of protocols. It supports listening on multiple ports simultaneously, multi-level proxy chaining, standard and extended proxy protocols, pluggable transport obfuscation, local and remote port forwarding, transparent proxying, DNS proxying, TUN/TAP device tunneling, authentication, access control, load balancing, and live configuration reload.

## Table of Contents

1. [Installation](#1-installation)
2. [Getting Started](#2-getting-started)
3. [Command Line Reference](#3-command-line-reference)
4. [Node Address Format](#4-node-address-format)
5. [Configuration File](#5-configuration-file)
6. [Proxy Protocols](#6-proxy-protocols)
7. [Transport Types](#7-transport-types)
8. [Proxy Chaining](#8-proxy-chaining)
9. [Port Forwarding](#9-port-forwarding)
10. [DNS Proxy](#10-dns-proxy)
11. [SNI Proxy](#11-sni-proxy)
12. [Transparent Proxy](#12-transparent-proxy)
13. [Relay Protocol](#13-relay-protocol)
14. [Shadowsocks](#14-shadowsocks)
15. [Authentication](#15-authentication)
16. [Access Control](#16-access-control)
17. [Load Balancing](#17-load-balancing)
18. [TLS and Encryption](#18-tls-and-encryption)
19. [Obfuscation](#19-obfuscation)
20. [TUN/TAP Device](#20-tuntap-device)
21. [Live Reload](#21-live-reload)
22. [Architecture](#22-architecture)
23. [Platform Compatibility](#23-platform-compatibility)
24. [Docker](#24-docker)
25. [Examples](#25-examples)
26. [Build Profile](#26-build-profile)
27. [Implementation Status](#27-implementation-status)
28. [Module Reference](#28-module-reference)
29. [Testing](#29-testing)
30. [License](#30-license)

---

## 1. Installation

### From Source

```bash
git clone https://github.com/mew-sh/rustun
cd rustun
cargo build --release
```

The compiled binary is located at `target/release/rustun` (or `target/release/rustun.exe` on Windows).

### Verify Installation

```bash
rustun -V
```

Output:

```
rustun 0.1.0 (rustc windows/x86_64)
```

---

## 2. Getting Started

### No Forward Proxy

The simplest usage is to start a standard proxy server. When no scheme is specified, rustun starts in auto-detection mode and determines the protocol (HTTP, SOCKS4, or SOCKS5) from the first byte of each incoming connection.

Start a standard HTTP/SOCKS5 auto-detecting proxy:

```bash
rustun -L :8080
```

Start an explicit HTTP proxy:

```bash
rustun -L http://:8080
```

Start an explicit SOCKS5 proxy:

```bash
rustun -L socks5://:1080
```

Start a proxy with authentication:

```bash
rustun -L admin:123456@localhost:8080
```

Start multiple authentication credentials from a secrets file:

```bash
rustun -L "localhost:8080?secrets=secrets.txt"
```

The `secrets.txt` file format is one `username password` pair per line. Lines beginning with `#` are treated as comments and ignored:

```
# username password

test001 123456
test002 12345678
```

Listen on multiple ports simultaneously:

```bash
rustun -L http2://:443 -L socks5://:1080 -L ss://aes-128-gcm:123456@:8338
```

### Forward Proxy

Route traffic through an upstream proxy server:

```bash
rustun -L :8080 -F 192.168.1.1:8081
```

Forward through a proxy with authentication:

```bash
rustun -L :8080 -F http://admin:123456@192.168.1.1:8081
```

### Multi-Level Forward Proxy (Proxy Chain)

Create a chain of proxy servers. rustun forwards each request through the chain in the order specified by the `-F` flags. Each proxy in the chain can use any supported protocol:

```bash
rustun -L :8080 -F quic://192.168.1.1:6121 -F socks5+wss://192.168.1.2:1080 -F http2://192.168.1.3:443
```

In this example, the traffic path is:

```
client -> rustun(:8080) -> quic(192.168.1.1:6121) -> socks5+wss(192.168.1.2:1080) -> http2(192.168.1.3:443) -> target
```

---

## 3. Command Line Reference

```
Usage: rustun [OPTIONS]

Options:
  -L <LISTEN>       Listen address, can listen on multiple ports (required)
  -F <FORWARD>      Forward address, can make a forward chain
  -M <MARK>         Specify out connection mark [default: 0]
  -C <CONFIG_FILE>  Configure file
  -I <INTERFACE>    Interface to bind
  -D                Enable debug log
  -V                Print version
  -P <PPROF_ADDR>   Profiling HTTP server address [default: :6060]
  -h, --help        Print help
```

### -L (Listen)

Specifies one or more local listening addresses. Each `-L` flag starts an independent service. The address follows the node address format described in Section 4. At least one `-L` flag is required unless a configuration file is provided via `-C`.

```bash
rustun -L http://:8080                        # HTTP proxy on port 8080
rustun -L socks5://admin:pass@:1080           # SOCKS5 with authentication on port 1080
rustun -L tcp://:2222/192.168.1.1:22          # TCP port forwarding, local 2222 to remote 22
rustun -L http://:8080 -L socks5://:1080      # Two listeners simultaneously
```

### -F (Forward)

Specifies one or more upstream proxy nodes to form a forward chain. Each `-F` flag appends a node to the chain. When multiple `-F` flags are given, they form a multi-hop chain: the first `-F` is the entry proxy, the last `-F` is the exit proxy closest to the target.

```bash
rustun -L :8080 -F http://proxy1:3128                           # Single-hop HTTP proxy chain
rustun -L :8080 -F http://proxy1:3128 -F socks5://proxy2:1080   # Two-hop chain: HTTP then SOCKS5
```

### -M (Mark)

Sets the `SO_MARK` socket option on all outgoing connections. This integer value is used by the Linux kernel for policy-based routing (e.g., routing marked packets through specific interfaces or VPN tunnels via `ip rule` and `iptables`). Has no effect on platforms that do not support socket marks. Default value is `0` (no mark).

```bash
rustun -L :8080 -M 100
```

### -C (Configure File)

Loads configuration from a JSON file instead of (or in addition to) command-line flags. The JSON format is described in Section 5. When both `-C` and `-L`/`-F` flags are present, the configuration file takes precedence.

```bash
rustun -C config.json
```

### -I (Interface)

Binds all outgoing connections to the specified network interface name. This is useful on multi-homed hosts where traffic should exit through a particular interface. The value is an interface name such as `eth0`, `wlan0`, or `tun0`.

```bash
rustun -L :8080 -I eth0
```

### -D (Debug)

Enables debug-level logging. Without this flag, only informational messages and above are printed. With this flag, detailed per-connection diagnostics including protocol handshakes, address resolution, and data flow are logged.

```bash
rustun -L :8080 -D
```

### -V (Version)

Prints the version string and exits immediately. The output format is `rustun <version> (rustc <os>/<arch>)`, which mirrors the gost version output format `gost <version> (go<version> <os>/<arch>)`.

```bash
rustun -V
# Output: rustun 0.1.0 (rustc windows/x86_64)
```

### -P (Profiling)

Specifies the address for a profiling HTTP server. This server is only started when the `PROFILING` environment variable is set to a non-empty value. Default address is `:6060`.

```bash
PROFILING=1 rustun -L :8080 -P :6060
```

### No Arguments

When rustun is invoked with no arguments at all, it prints the usage help text and exits with code 0. This matches the behavior of gost.

---

## 4. Node Address Format

All `-L` (listen) and `-F` (forward) addresses follow the same URL-based format:

```
[scheme://][user:password@][host]:port[/remote_address][?parameters]
```

### Scheme

The scheme defines both the protocol and the transport, separated by `+`:

```
protocol+transport://...
```

If only one component is given (e.g., `http://`), the transport defaults to `tcp`. If no scheme is given at all (e.g., `:8080`), the protocol is auto-detected and the transport is `tcp`.

Examples:

| Scheme | Protocol | Transport | Meaning |
|--------|----------|-----------|---------|
| `http` | HTTP | TCP | HTTP proxy over TCP |
| `socks5` | SOCKS5 | TCP | SOCKS5 proxy over TCP |
| `http+tls` | HTTP | TLS | HTTP proxy over TLS (HTTPS proxy) |
| `socks5+ws` | SOCKS5 | WebSocket | SOCKS5 proxy over WebSocket |
| `ss` | Shadowsocks | TCP | Shadowsocks over TCP |
| `relay+tls` | Relay | TLS | Relay protocol over TLS |
| `tcp` | TCP forward | TCP | TCP port forwarding |
| `kcp` | KCP | KCP | KCP transport (UDP-based) |

### User and Password

Inline authentication credentials are specified before the `@` sign:

```
socks5://admin:secret@:1080
```

For Shadowsocks, the format is `method:password`:

```
ss://aes-128-gcm:mypassword@:8338
```

### Host and Port

The host may be omitted to listen on all interfaces (equivalent to `0.0.0.0`). IPv6 addresses must be enclosed in brackets:

```
:8080                    # Listen on all interfaces, port 8080
127.0.0.1:8080           # Listen on loopback only
[::1]:8080               # Listen on IPv6 loopback
```

### Remote Address (Path)

For forwarding protocols (`tcp`, `udp`, `rtcp`, `rudp`, `dns`), the path component specifies the remote target address:

```
tcp://:2222/192.168.1.1:22    # Forward local port 2222 to 192.168.1.1:22
dns://:5353/8.8.8.8:53        # Forward DNS queries to Google DNS
```

Multiple remote addresses may be separated by commas for load balancing:

```
tcp://:8080/10.0.0.1:80,10.0.0.2:80,10.0.0.3:80
```

### Query Parameters

Additional configuration is passed as URL query parameters. The table below shows all recognized parameters and their implementation status.

**Fully implemented** parameters are extracted from the node URL and applied at runtime. **Parsed only** parameters are stored in the node's value map and available to handler code, but the handler does not yet act on them. **Type only** parameters have corresponding configuration types defined but no runtime extraction.

| Parameter | Applies To | Description | Status |
|-----------|-----------|-------------|--------|
| `secrets` | HTTP, SOCKS5 | Path to authentication file | Fully implemented |
| `bypass` | All handlers | Comma-separated bypass rules, prefix `~` for reverse | Fully implemented |
| `whitelist` | All handlers | Permission whitelist (`action:host:port`) | Fully implemented |
| `blacklist` | All handlers | Permission blacklist (`action:host:port`) | Fully implemented |
| `hosts` | All handlers | Path to hosts file for static resolution | Fully implemented |
| `timeout` | All | Connection timeout (e.g., `5s`, `30s`) | Fully implemented |
| `retry` | All handlers | Per-handler retry count | Fully implemented |
| `method` | Shadowsocks | Cipher method name | Fully implemented |
| `ip` | Forward | Additional IP addresses (comma-separated) | Fully implemented |
| `proxyAgent` | HTTP | Custom Proxy-Agent header value | Fully implemented |
| `host` | SNI | Target host for SNI proxy | Fully implemented |
| `dns` | All handlers | DNS resolver address(es), comma-separated | Parsed only |
| `strategy` | Chain nodes | Load balancing strategy: `round`, `random`, `fifo` | Parsed only |
| `max_fails` | Chain nodes | Maximum failures before marking node dead | Parsed only |
| `fail_timeout` | Chain nodes | Duration before a dead node is retried | Parsed only |
| `fastest_count` | Chain nodes | Number of top fastest nodes to keep | Parsed only |
| `ttl` | UDP, DNS | UDP connection idle timeout (e.g., `60s`) | Parsed only |
| `cert` | TLS | Path to TLS certificate PEM file | Parsed only |
| `key` | TLS | Path to TLS private key PEM file | Parsed only |
| `ca` | TLS | Path to CA certificate for pinning | Parsed only |
| `secure` | TLS client | Enable server certificate verification | Parsed only |
| `path` | WebSocket, H2 | URL path for the WebSocket/H2 endpoint | Parsed only |
| `ping` | SSH, HTTP/2 | Heartbeat interval in seconds | Parsed only |
| `c` | KCP | Path to KCP JSON configuration file | Parsed only |
| `tcp` | KCP | Enable TCP mode for KCP | Parsed only |
| `keepalive` | QUIC | Enable QUIC keep-alive | Parsed only |
| `probe_resist` | HTTP | Probe resistance mode (code, web, host, file) | Parsed only |
| `knock` | HTTP | Knocking host for probe resistance | Parsed only |
| `backlog` | UDP | UDP listener connection backlog | Parsed only |
| `queue` | UDP | UDP listener queue size | Parsed only |
| `name` | TUN/TAP | Device name | Parsed only |
| `net` | TUN/TAP | Device network address (CIDR notation) | Parsed only |
| `mtu` | TUN/TAP | Maximum transmission unit | Parsed only |
| `route` | TUN/TAP | Routing entries (CIDR, comma-separated) | Parsed only |
| `gw` | TUN/TAP | Default gateway IP | Parsed only |
| `peer` | TUN (macOS) | Peer address for point-to-point | Parsed only |
| `nodelay` | Relay, SS | Send address header immediately (no buffering) | Parsed only |
| `notls` | SOCKS5 | Disable TLS method in SOCKS5 | Parsed only |
| `httpTunnel` | HTTP | Force HTTP tunnel mode | Parsed only |

All parameters in the "Parsed only" column are stored in `node.values` and accessible via `node.get("key")`, `node.get_bool("key")`, `node.get_int("key")`, and `node.get_duration("key")`. They are available for handler implementations to consume but are not yet wired into the default CLI server startup path. Contributions to wire additional parameters are welcome.

---

## 5. Configuration File

The JSON configuration file provides the same capabilities as command-line flags. The top-level object defines the default route, and additional routes are defined in the `Routes` array.

### Full Example

```json
{
    "Debug": true,
    "ServeNodes": [
        "http://:8080",
        "socks5://:1080"
    ],
    "ChainNodes": [
        "http://proxy:3128"
    ],
    "Retries": 3,
    "Mark": 100,
    "Interface": "eth0",
    "Routes": [
        {
            "ServeNodes": ["relay+tls://:8443"],
            "ChainNodes": ["http://upstream:8080"],
            "Retries": 1,
            "Mark": 0,
            "Interface": ""
        },
        {
            "ServeNodes": ["ss://aes-256-gcm:password@:8338"],
            "ChainNodes": [],
            "Retries": 0
        }
    ]
}
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Debug` | boolean | `false` | Enable debug-level logging |
| `ServeNodes` | string[] | `[]` | Listen addresses for the default route. Each string follows the node address format. |
| `ChainNodes` | string[] | `[]` | Proxy chain nodes for the default route. Ordered from entry to exit. |
| `Retries` | integer | `0` | Number of times to retry a failed connection through the chain. A value of 0 means no retries (one attempt). |
| `Mark` | integer | `0` | SO_MARK value applied to all outgoing connections in this route. Used for Linux policy routing. |
| `Interface` | string | `""` | Network interface name to bind outgoing connections. Empty string means no binding. |
| `Routes` | object[] | `[]` | Additional independent routes. Each route object has the same fields as the top level (excluding `Debug` and `Routes`). |

### Multiple Routes

Each route operates independently: it has its own set of listeners (`ServeNodes`), its own proxy chain (`ChainNodes`), and its own connection parameters. This allows a single rustun instance to serve multiple proxy protocols on different ports with different upstream chains.

---

## 6. Proxy Protocols

### HTTP Proxy

The HTTP proxy handler supports both the CONNECT method (for HTTPS tunneling) and direct HTTP request forwarding.

When a client sends an HTTP CONNECT request, rustun establishes a TCP tunnel to the target and relays data bidirectionally. When a client sends a plain HTTP request (GET, POST, etc.), rustun forwards the request to the target server and streams the response back.

Server:

```bash
rustun -L http://:8080
```

The handler performs the following steps for CONNECT:

1. Read the HTTP request line and headers from the client.
2. Extract the target host from the CONNECT URI or the Host header.
3. Verify the target against bypass rules, whitelist, and blacklist.
4. Authenticate the client using the Proxy-Authorization header if an authenticator is configured.
5. Connect to the target through the proxy chain (or directly if no chain is configured).
6. Send `HTTP/1.1 200 Connection established` back to the client.
7. Relay data bidirectionally between client and target until either side closes.

For plain HTTP requests, the handler forwards the request (stripping proxy-specific headers such as `Proxy-Connection` and `Proxy-Authorization`) to the target server and relays the response.

The HTTP proxy sets the `Proxy-Agent` response header to `rustun/<version>` by default. This can be customized with the `proxyAgent` query parameter.

### Probe Resistance

The HTTP proxy supports probe resistance to defend against active probing. When authentication is configured and a client fails to authenticate, the proxy can disguise itself rather than returning a `407 Proxy Authentication Required` response. Modes:

- `code:<status>` -- Return the specified HTTP status code.
- `web:<url>` -- Fetch and return the content from the given URL.
- `host:<addr>` -- Forward the request to the given address.
- `file:<path>` -- Serve the content of the given file.

```bash
rustun -L "http://user:pass@:8080?probe_resist=code:404"
rustun -L "http://user:pass@:8080?probe_resist=web:example.com&knock=secret.example.com"
```

The `knock` parameter specifies a knocking host. Only requests to this host bypass probe resistance and receive the real `407` response, allowing legitimate clients to discover that authentication is required.

### SOCKS5 Proxy

The SOCKS5 handler implements RFC 1928 (SOCKS Protocol Version 5) and RFC 1929 (Username/Password Authentication for SOCKS V5).

Server:

```bash
rustun -L socks5://:1080
```

Client (using rustun as a chain node):

```bash
rustun -L :8080 -F socks5://server_ip:1080
```

Supported SOCKS5 features:

- **Authentication methods**: No authentication (`0x00`), Username/Password (`0x02`).
- **Commands**: CONNECT (`0x01`), UDP ASSOCIATE (`0x03`).
- **Address types**: IPv4 (`0x01`), Domain name (`0x03`), IPv6 (`0x04`).

The handler performs the following steps:

1. Read the SOCKS5 greeting (version byte, number of methods, method list).
2. Select the appropriate authentication method based on whether an authenticator is configured.
3. If username/password is selected, read and verify the credentials.
4. Read the SOCKS5 request (command, address type, destination address, port).
5. For CONNECT: verify permissions, connect to the target through the chain, send a success reply, and relay data bidirectionally.
6. For UDP ASSOCIATE: send a reply with the local address and keep the TCP connection alive.

### SOCKS4 and SOCKS4a Proxy

The SOCKS4 handler implements the original SOCKS4 protocol (IPv4 addresses only) and the SOCKS4a extension (which adds domain name support).

Server:

```bash
rustun -L socks4://:1080
```

SOCKS4a is automatically supported: when the client sets the IP address to `0.0.0.x` (where `x` is non-zero) and appends a null-terminated domain name after the user ID, the handler resolves the domain name to connect to the target.

The SOCKS4 handler does not support authentication (as per the SOCKS4 specification). For security, the auto-detection handler (which handles both SOCKS4 and SOCKS5) will reject SOCKS4 connections when credentials are configured on the listener.

### Auto-Detection

When no scheme is specified (e.g., `-L :8080`), the auto-detection handler examines the first byte of each incoming connection to determine the protocol:

| First Byte | Protocol | Handler |
|------------|----------|---------|
| `0x05` | SOCKS5 | Socks5Handler |
| `0x04` | SOCKS4/4a | Socks4Handler |
| Any other | HTTP | HttpHandler |

This allows a single port to serve all three proxy protocols simultaneously.

---

## 7. Transport Types

The transport layer determines how data is carried on the wire between rustun and the next proxy node. The transport is specified after the `+` in the scheme:

```bash
rustun -L http+tls://:443       # HTTP proxy over TLS
rustun -L :8080 -F socks5+ws://proxy:8080  # SOCKS5 over WebSocket
```

### TCP (default)

Raw TCP connection. Used when no transport is specified.

### TLS

TLS encrypts the TCP connection. rustun supports custom certificates, client certificate authentication (mTLS), and certificate pinning.

Server (with custom certificate):

```bash
rustun -L "http+tls://:443?cert=cert.pem&key=key.pem"
```

Client (with server verification):

```bash
rustun -L :8080 -F "http+tls://server:443?secure=true"
```

Client (with CA certificate pinning):

```bash
rustun -L :8080 -F "http+tls://server:443?ca=ca.pem"
```

If no certificate files are provided, rustun looks for `cert.pem` and `key.pem` in the current working directory. If those are not found, a random self-signed certificate is generated.

### WebSocket

WebSocket transport frames proxy data as binary WebSocket messages. This is useful for traversing HTTP proxies and firewalls that only allow WebSocket traffic.

Server:

```bash
rustun -L "socks5+ws://:8080?path=/ws"
```

Client:

```bash
rustun -L :8080 -F "socks5+ws://server:8080?path=/ws"
```

The `path` parameter sets the WebSocket endpoint URL path. Both `ws` (plain) and `wss` (TLS-encrypted) variants are supported. Multiplexed variants `mws` and `mwss` use stream multiplexing over a single WebSocket connection.

### SSH

SSH transport uses the SSH protocol (RFC 4253/4254) for encrypted tunneling with two modes:

**Forward Tunnel**: Used for local and remote TCP port forwarding through SSH.

Server:

```bash
rustun -L forward+ssh://:2222
```

Client (remote port forwarding):

```bash
rustun -L rtcp://:1222/:22 -F forward+ssh://server:2222
```

**Transport Tunnel**: Used as a general-purpose encrypted transport for proxy protocols.

Server:

```bash
rustun -L ssh://:2222
```

Client:

```bash
rustun -L :8080 -F "ssh://server:2222?ping=60"
```

The `ping` parameter enables heartbeat detection with the specified interval in seconds.

### KCP

KCP is a UDP-based reliable transport protocol that provides faster delivery than TCP at the cost of higher bandwidth consumption. It is based on the KCP protocol specification.

Server:

```bash
rustun -L kcp://:8388
```

Client:

```bash
rustun -L :8080 -F kcp://server:8388
```

KCP configuration is loaded from a JSON file. rustun automatically loads `kcp.json` from the working directory if it exists, or you can specify a path:

```bash
rustun -L "kcp://:8388?c=/path/to/kcp.json"
```

KCP JSON configuration fields:

```json
{
    "key": "encryption-key",
    "crypt": "aes",
    "mode": "fast",
    "mtu": 1350,
    "sndwnd": 1024,
    "rcvwnd": 1024,
    "datashard": 10,
    "parityshard": 3,
    "dscp": 0,
    "nocomp": false,
    "nodelay": 0,
    "interval": 50,
    "resend": 0,
    "nc": 0,
    "sockbuf": 4194304,
    "keepalive": 10,
    "tcp": false
}
```

Mode presets (`mode` field) adjust `nodelay`, `interval`, `resend`, and `nc` to predefined values: `normal`, `fast`, `fast2`, `fast3`.

KCP nodes can only be used as the first node of a proxy chain.

### QUIC

QUIC is a UDP-based multiplexed transport protocol. It provides built-in encryption (via TLS 1.3) and supports multiple concurrent streams over a single connection.

Server:

```bash
rustun -L quic://:6121
```

Client:

```bash
rustun -L :8080 -F "quic://server:6121?keepalive=true"
```

QUIC nodes can only be used as the first node of a proxy chain.

### HTTP/2

HTTP/2 transport supports two modes:

**Standard Proxy** (`http2`): Acts as an HTTP/2 proxy using the CONNECT method, and is backwards-compatible with HTTPS proxies.

```bash
# Server
rustun -L http2://:443

# Client
rustun -L :8080 -F "http2://server:443?ping=30"
```

**Tunnel** (`h2` / `h2c`): Uses HTTP/2 as a pure transport tunnel. `h2` uses TLS encryption; `h2c` uses cleartext HTTP/2.

```bash
# Server (TLS)
rustun -L h2://:443

# Server (cleartext)
rustun -L h2c://:8080

# Client
rustun -L :8080 -F h2://server:443
```

### FakeTCP

FakeTCP disguises UDP traffic as TCP packets using raw sockets. This is useful for KCP-based tunnels in environments where UDP traffic is blocked or throttled but TCP is allowed. Requires raw socket capabilities (CAP_NET_RAW on Linux).

### VSOCK

VSOCK (Virtual Socket) provides communication between a virtual machine and its host. The address format is `contextID:port`. Only available on Linux with the `vsock` kernel module loaded.

---

## 8. Proxy Chaining

Proxy chains route traffic through a sequence of proxy servers. Each `-F` flag appends a node to the chain. When a client connects, rustun dials through the chain sequentially:

```bash
rustun -L :8080 -F http://proxy1:3128 -F socks5://proxy2:1080
```

The connection process:

1. Establish a TCP connection to `proxy1:3128`.
2. Send an HTTP CONNECT request to `proxy1` requesting connection to `proxy2:1080`.
3. Upon receiving `200 Connection established`, perform a SOCKS5 handshake with `proxy2` through the tunnel.
4. Send a SOCKS5 CONNECT request to `proxy2` for the final target address.
5. Upon success, relay data bidirectionally between the client and the target.

Each node in the chain can use any supported protocol+transport combination. The chain supports:

- Configurable retry count per chain (via `Retries` in config or per-node `retry` parameter).
- Connection timeout (via `timeout` parameter).
- Custom DNS resolution per chain (via `dns` parameter).
- Custom hosts file per chain (via `hosts` parameter).
- Bypass rules that stop chain traversal when a matching address is encountered.

### Chain with Different Transports

```bash
rustun -L :8080 \
    -F "http+tls://proxy1:443?secure=true" \
    -F "socks5+ws://proxy2:8080?path=/tunnel" \
    -F "relay+tls://proxy3:8443"
```

---

## 9. Port Forwarding

### Local TCP Port Forwarding

Forward all TCP connections arriving on a local port to a remote target address. The remote address is specified as the path component of the URL:

```bash
rustun -L tcp://:2222/192.168.1.1:22
```

This binds to local port 2222 and forwards every incoming connection to `192.168.1.1:22`. If a proxy chain is specified via `-F`, the forwarding goes through the chain:

```bash
rustun -L tcp://:2222/192.168.1.1:22 -F http://proxy:8080
```

When the last node of the chain uses SSH forward transport, rustun uses SSH direct port forwarding (RFC 4254 Section 7.2):

```bash
rustun -L tcp://:2222/192.168.1.1:22 -F forward+ssh://server:2222
```

Multiple remote addresses may be specified (comma-separated) for load balancing:

```bash
rustun -L tcp://:8080/10.0.0.1:80,10.0.0.2:80,10.0.0.3:80
```

### Local UDP Port Forwarding

Forward all UDP datagrams arriving on a local port to a remote target address:

```bash
rustun -L "udp://:5353/192.168.1.1:53?ttl=60"
```

Each UDP forwarding channel has an idle timeout. When no data is exchanged within this period, the channel is closed. The timeout is set via the `ttl` parameter (default: 60 seconds).

When forwarding UDP data through a proxy chain, the last node in the chain must be a SOCKS5 proxy, which uses UDP-over-TCP to carry the datagrams.

### Remote TCP Port Forwarding

In remote forwarding, rustun listens on a port at the remote end (the last proxy in the chain) and forwards connections back to a local target:

```bash
rustun -L rtcp://:2222/192.168.1.1:22 -F socks5://172.24.10.1:1080
```

This causes port 2222 on `172.24.10.1` to forward connections to `192.168.1.1:22`. When the last node uses SSH forward transport, rustun uses SSH remote port forwarding (RFC 4254 Section 7.1):

```bash
rustun -L rtcp://:2222/192.168.1.1:22 -F forward+ssh://server:2222
```

### Remote UDP Port Forwarding

```bash
rustun -L "rudp://:5353/192.168.1.1:53?ttl=60" -F socks5://172.24.10.1:1080
```

---

## 10. DNS Proxy

The DNS proxy handler forwards DNS queries to an upstream DNS resolver. The upstream address is specified as the path component:

```bash
rustun -L dns://:5353/8.8.8.8:53
```

This listens for DNS queries on local port 5353 (TCP) and forwards them to Google Public DNS at `8.8.8.8:53` via UDP.

The DNS resolver module also supports DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH) when used as a chain component.

---

## 11. SNI Proxy

The SNI (Server Name Indication) proxy inspects the TLS ClientHello message to extract the server name, then routes the connection to the appropriate backend server.

```bash
rustun -L sni://:443
```

The handler performs the following steps:

1. Peek at the first bytes of the incoming connection.
2. If the first byte is `0x16` (TLS Handshake), parse the ClientHello to extract the SNI hostname.
3. Connect to `<hostname>:443` (or the port specified by the `host` parameter).
4. Forward the original ClientHello and all subsequent data bidirectionally.

If the connection does not begin with a TLS handshake, it is treated as a plain HTTP request and delegated to the HTTP handler.

---

## 12. Transparent Proxy

Transparent proxying intercepts connections without requiring client-side proxy configuration. This uses iptables REDIRECT or TPROXY rules on Linux.

```bash
rustun -L redirect://:12345 -F http2://server:443
```

The transparent proxy handler uses the `SO_ORIGINAL_DST` socket option to recover the original destination address (set by iptables REDIRECT). It then connects to that address through the proxy chain.

Example iptables rule:

```bash
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 12345
```

UDP transparent proxying is also supported via TPROXY:

```bash
rustun -L "redu://:12345?ttl=60"
```

---

## 13. Relay Protocol

The relay protocol is a lightweight custom protocol designed for efficient tunneling with built-in support for user authentication and target address specification.

Server (with fixed target):

```bash
rustun -L relay://:8443/192.168.1.1:80
```

Server (dynamic target from client):

```bash
rustun -L relay://user:pass@:8443
```

Client:

```bash
rustun -L :8080 -F relay://user:pass@server:8443
```

The relay protocol frame format includes a version byte, flags (including a UDP flag for UDP relay), and feature fields for user authentication and address specification.

---

## 14. Shadowsocks

Shadowsocks is an encrypted proxy protocol. The cipher method and password are specified in the URL credentials as `method:password`:

Server:

```bash
rustun -L ss://aes-128-gcm:123456@:8338
```

Client:

```bash
rustun -L :8080 -F ss://aes-128-gcm:123456@server:8338
```

Supported cipher methods:

| Cipher | Key Size |
|--------|----------|
| `aes-128-gcm` | 16 bytes |
| `aes-256-gcm` | 32 bytes |
| `chacha20-ietf-poly1305` | 32 bytes |
| `plain` / `none` | 0 (no encryption, for testing only) |

Key derivation uses the EVP_BytesToKey algorithm (OpenSSL-compatible) to convert the password string into a fixed-length key.

### Shadowsocks UDP Relay

UDP relay is supported via the `ssu` scheme:

```bash
rustun -L ssu://aes-128-gcm:123456@:8338
```

---

## 15. Authentication

### Inline Credentials

The simplest authentication method embeds credentials directly in the URL:

```bash
rustun -L http://admin:secret@:8080
rustun -L socks5://user:password@:1080
```

When inline credentials are provided on a `-L` address, the handler requires all incoming clients to authenticate with those exact credentials.

### Secrets File

For multiple user accounts, use a secrets file:

```bash
rustun -L "http://:8080?secrets=users.txt"
```

The file contains one `username password` pair per line. Lines starting with `#` are comments. Blank lines are ignored. A special `reload` directive sets the live-reload interval:

```
# Authentication secrets file
reload 30s

admin       strongpassword
readonly    simplepass
operator    0p3r@t0r!
```

The authenticator periodically checks the file modification time and reloads automatically.

### Authentication Interaction with Proxy Protocols

- **HTTP**: Uses the `Proxy-Authorization: Basic <base64>` header.
- **SOCKS5**: Uses the Username/Password Authentication sub-negotiation (RFC 1929, method `0x02`).
- **SOCKS4**: Does not support authentication. When credentials are configured on a listener, the auto-detect handler rejects SOCKS4 connections entirely.
- **Relay**: Uses a `UserAuth` feature in the relay protocol frame.
- **Shadowsocks**: Authentication is implicit via the shared cipher method and password (any client with the correct password is authenticated).

---

## 16. Access Control

### Bypass (Routing Control)

The bypass system determines which addresses are allowed or denied. A bypass list contains matcher patterns applied to the target address of each connection.

```bash
rustun -L "http://:8080?bypass=192.168.0.0/16,*.internal.com,10.0.0.1"
```

Matcher types:

- **IP Matcher**: Matches a specific IP address exactly. Example: `192.168.1.1`.
- **CIDR Matcher**: Matches any IP within a subnet. Example: `10.0.0.0/8`.
- **Domain Matcher**: Matches domain names using glob patterns. Example: `*.example.com` matches `sub.example.com`. A leading dot `.example.com` is equivalent to `*.example.com` and also matches `example.com` itself.

By default (non-reversed mode), when a target address matches any bypass pattern, the connection is rejected with a `403 Forbidden` response.

**Reversed mode**: Prefix the bypass value with `~` to invert the logic. In reversed mode, only addresses matching the patterns are allowed; all others are rejected.

```bash
rustun -L "http://:8080?bypass=~*.allowed.com,10.0.0.0/8"
```

Bypass patterns can also be loaded from a file (one pattern per line) with live-reload support:

```
# bypass.txt
reload 10s
reverse true

192.168.0.0/16
*.internal.com
10.0.0.0/8
```

### Permissions (Whitelist and Blacklist)

Permissions provide fine-grained access control using the format `action:host_pattern:port_range`. Multiple permission rules are separated by spaces.

```bash
rustun -L "http://:8080?whitelist=tcp:*:80,443&blacklist=tcp:evil.com:*"
```

The access check logic is:

```
allowed = (whitelist is empty OR whitelist matches) AND (blacklist is empty OR blacklist does NOT match)
```

**Action**: The protocol action to match. Currently `tcp` for TCP connections and `udp` for UDP.

**Host Pattern**: A glob pattern for the hostname. `*` matches any host. `*.example.com` matches all subdomains.

**Port Range**: A port specification. Formats: `80` (single port), `80-443` (range), `*` (all ports), `80,443,8000-9000` (comma-separated mix).

Examples:

```bash
# Only allow TCP connections to ports 80 and 443 on any host
whitelist=tcp:*:80,443

# Block all access to evil.com on any port
blacklist=tcp:evil.com:*

# Allow only connections to specific hosts on specific ports
whitelist=tcp:api.example.com,cdn.example.com:80,443

# Combine whitelist and blacklist
whitelist=tcp:*:80,443&blacklist=tcp:malware.com,ads.tracker.com:*
```

---

## 17. Load Balancing

When a proxy chain node group contains multiple nodes, rustun selects among them using a configurable strategy.

Multiple nodes are configured either through the `ip` query parameter or through a peer configuration file:

```bash
rustun -L :8080 -F "http://proxy1:8080?ip=proxy2:8080,proxy3:8080&strategy=round&max_fails=3&fail_timeout=30s"
```

### Selection Strategies

| Strategy | Name | Description |
|----------|------|-------------|
| Round Robin | `round` | Cycles through nodes in order. This is the default strategy. |
| Random | `random` | Selects a node at random for each connection. |
| FIFO | `fifo` | Always selects the first available node. Falls back to subsequent nodes only when the first node is marked as dead. |

### Failure Detection

Nodes are monitored for connection failures. When a node fails, its fail counter is incremented and its fail timestamp is recorded.

- `max_fails` (default: 1): The maximum number of consecutive failures before a node is marked as dead.
- `fail_timeout` (default: 30s): The duration after which a dead node is reconsidered.

When all nodes are dead, the strategy operates on the full list regardless of failure state to avoid complete service outage.

### Fastest Filter

The `fastest_count` parameter enables latency-based filtering. Nodes are periodically probed via TCP connection, sorted by latency, and only the top N fastest nodes are kept in the selection pool:

```bash
-F "http://proxy1:8080?ip=proxy2:8080,proxy3:8080&fastest_count=2"
```

---

## 18. TLS and Encryption

### Built-in Certificate

rustun includes the ability to generate a random self-signed TLS certificate at startup. This is used when no certificate files are provided.

### Custom Certificate

Place `cert.pem` (public key) and `key.pem` (private key) in the current working directory, and rustun loads them automatically. Alternatively, specify paths explicitly:

```bash
rustun -L "http+tls://:443?cert=/path/to/cert.pem&key=/path/to/key.pem"
```

### Server Certificate Verification

By default, clients do not verify the server certificate (matching gost behavior for self-signed certificates). Enable verification with:

```bash
rustun -L :8080 -F "http+tls://server:443?secure=true"
```

### Certificate Pinning

Specify a CA certificate to restrict which certificates are trusted:

```bash
rustun -L :8080 -F "http+tls://server:443?ca=ca.pem"
```

### SOCKS5 TLS Extension

When both client and server are rustun (or gost) instances, SOCKS5 connections negotiate TLS encryption using extended methods `0x80` (TLS) and `0x82` (TLS with authentication). This provides end-to-end encryption without requiring a separate TLS transport layer.

---

## 19. Obfuscation

Obfuscation transports disguise proxy traffic as benign protocols to evade deep packet inspection (DPI).

### HTTP Obfuscation

Disguises the connection as an HTTP WebSocket upgrade. The handshake sends a legitimate-looking HTTP GET request with `Connection: Upgrade` and `Upgrade: websocket` headers, and the server responds with `101 Switching Protocols`.

Server:

```bash
rustun -L http+ohttp://:8080
```

Client:

```bash
rustun -L :8080 -F http+ohttp://server:8080
```

### TLS Obfuscation

Disguises the connection as a TLS handshake. The client sends a synthetic TLS ClientHello with a valid SNI extension, and the server responds with a synthetic ServerHello. After the handshake, data flows as raw bytes (not actually TLS-encrypted, but appearing as TLS to passive observers).

Server:

```bash
rustun -L http+otls://:8443
```

Client:

```bash
rustun -L :8080 -F http+otls://server:8443
```

### Obfs4

Obfs4 is a pluggable transport from the Tor Project that provides strong obfuscation against active probing.

Server:

```bash
rustun -L obfs4://:443
```

The server prints the client connection string (including the `cert` parameter). Client:

```bash
rustun -L :8080 -F "obfs4://server:443?cert=<base64-cert>&iat-mode=0"
```

---

## 20. TUN/TAP Device

TUN (Layer 3) and TAP (Layer 2) virtual network devices allow rustun to operate as a VPN tunnel.

### TUN

```bash
rustun -L "tun://:0?name=tun0&net=10.0.0.1/24&mtu=1350&route=192.168.0.0/16&gw=10.0.0.1"
```

Parameters:

- `name`: Device name (e.g., `tun0`).
- `net`: Device IP address in CIDR notation (e.g., `10.0.0.1/24`).
- `peer`: Peer address for point-to-point mode (macOS).
- `mtu`: Maximum transmission unit (default: 1350).
- `route`: Comma-separated CIDR routes to add.
- `gw`: Default gateway IP.

### TAP

```bash
rustun -L "tap://:0?name=tap0&net=10.0.0.1/24&mtu=1500&route=192.168.0.0/16&gw=10.0.0.1"
```

TAP devices operate at the Ethernet frame level (Layer 2), supporting broadcast, ARP, and other Layer 2 protocols.

---

## 21. Live Reload

Configuration files, authenticator secrets files, bypass lists, hosts files, and DNS resolver configurations support automatic live reloading. When the file modification time changes, rustun re-reads and applies the new content without restarting.

The reload period is specified within the file using a `reload` directive:

```
# bypass.txt
reload 10s
reverse true

192.168.1.0/24
*.internal.com
```

```
# hosts.txt
reload 30s

10.0.0.1 server1
10.0.0.2 server2 alias2
```

```
# secrets.txt
reload 1m

admin secretpassword
user  userpassword
```

A reload period of `0` disables reloading. A negative period (set internally by calling `stop()`) permanently stops reloading.

---

## 22. Architecture

rustun follows a layered architecture that mirrors the design of gost:

```
    +--------------------------------------------+
    |                    CLI                      |
    |  Parses -L, -F, -C, -M, -I, -D flags      |
    +--------------------+-----------------------+
                         |
    +--------------------v-----------------------+
    |               Config / Router               |
    |  Creates Server + Handler + Chain per route |
    +--------------------+-----------------------+
                         |
    +--------------------v-----------------------+
    |                  Server                     |
    |  TCP listener, accepts connections,         |
    |  exponential backoff on accept errors       |
    +--------------------+-----------------------+
                         |
    +--------------------v-----------------------+
    |                 Handler                     |
    |  Protocol-specific connection processing    |
    |  (HTTP, SOCKS4/5, SS, Relay, SNI, DNS, ...) |
    +-------+----------------+-------------------+
            |                |
    +-------v------+  +-----v-----------+
    |    Chain      |  |  Access Control  |
    |  Multi-hop    |  |  Bypass, WL/BL,  |
    |  tunneling    |  |  Authenticator   |
    +-------+------+  +-----------------+
            |
    +-------v------+
    |  NodeGroup    |
    |  Selection,   |
    |  LB strategy, |
    |  Fail filter  |
    +-------+------+
            |
    +-------v------+
    |    Node       |
    |  Connector +  |
    |  Transporter  |
    +-------+------+
            |
    +-------v------+
    |   Transport   |
    |  TCP, TLS,    |
    |  WS, KCP, ... |
    +-------+------+
            |
    +-------v------+
    |    Target     |
    +--------------+
```

### Core Types

**Node**: A proxy endpoint parsed from a URL string. Contains protocol, transport, address, credentials, and configuration parameters. The `FailMarker` tracks connection failures using atomic counters.

**NodeGroup**: A collection of Nodes used for load balancing. Contains a list of nodes, a selection strategy, and filters. The `next()` method selects a node by applying filters (FailFilter removes dead nodes, InvalidFilter removes nodes with invalid ports) and then applying the strategy.

**Chain**: An ordered sequence of NodeGroups forming a proxy chain. The `dial()` method connects through each node sequentially, establishing tunnels via HTTP CONNECT or SOCKS5 at each hop.

**Handler**: An async trait with a single method `handle(conn: TcpStream) -> Result<(), HandlerError>`. Each protocol implements this trait. The `AutoHandler` delegates to the appropriate protocol handler based on the first byte.

**Server**: Wraps a `TcpListener` and a `Handler`. The `serve()` method accepts connections in a loop, spawning a new task for each connection. Uses exponential backoff (5ms to 1s) on accept errors.

**Transport**: The `transport()` function takes two bidirectional streams and relays data between them using two concurrent copy tasks (one per direction) with 32KB buffers.

---

## 23. Platform Compatibility

Certain features require platform-specific system calls or commands. The table below shows availability by operating system.

| Feature | Linux | macOS | Windows | Other Unix |
|---------|-------|-------|---------|------------|
| Socket mark (`-M` / SO_MARK) | Functional | No-op | No-op | No-op |
| Interface bind (`-I` / SO_BINDTODEVICE) | Functional | No-op | No-op | No-op |
| TCP transparent proxy (redirect) | Functional (SO_ORIGINAL_DST) | Returns error | Returns error | Returns error |
| UDP transparent proxy (tproxy) | Stub (requires tproxy setup) | Returns error | Returns error | Returns error |
| Signal handling (SIGUSR1) | SIGUSR1 dumps diagnostics | SIGUSR1 dumps diagnostics | No-op | SIGUSR1 dumps diagnostics |
| TUN device creation | `ip link`/`ip address`/`ip route` | `ifconfig`/`route` (with peer) | `netsh` (requires TAP driver) | `ifconfig`/`route` |
| TAP device creation | `ip link`/`ip address`/`ip route` | Not supported (returns error) | `netsh` (requires TAP driver) | `ifconfig`/`route` |
| VSOCK transport | Requires vsock kernel module | Not supported | Not supported | Not supported |
| FakeTCP transport | Requires CAP_NET_RAW | Not supported | Not supported | Not supported |

Platform-specific code is gated using `#[cfg(target_os = "...")]` attributes. Non-Linux stubs return `Ok(())` (for no-ops like socket marks) or `Err(...)` (for features that cannot function, like transparent proxy).

---

## 24. Docker

A multi-stage `Dockerfile` and a `docker-compose.yml` are provided for containerized deployment.

### Building the Docker Image

```bash
docker build -t rustun .
```

### Running with Docker

```bash
# HTTP proxy
docker run -p 8080:8080 rustun -L http://:8080

# SOCKS5 proxy with authentication
docker run -p 1080:1080 rustun -L socks5://admin:pass@:1080

# From a config file
docker run -v ./config.json:/etc/rustun/config.json rustun -C /etc/rustun/config.json
```

### Docker Compose

The `docker-compose.yml` defines 10 services covering all major deployment topologies:

```bash
docker compose up -d             # start all services
docker compose up http-proxy     # start a single service
docker compose logs -f           # follow logs
docker compose down              # stop everything
```

Services defined: `http-proxy` (8080), `socks5-proxy` (1080), `auto-proxy` (8888), `shadowsocks` (8338), `relay-server` (8443), `tcp-forward` (2222), `dns-proxy` (5353), `sni-proxy` (4443), `chained-proxy` (9080), `multi-listener` (18080/11080).

---

## 25. Examples

Shell scripts in the `examples/` directory demonstrate each major feature with real network commands. Each script starts a rustun instance, sends test traffic, and verifies the result.

| Script | Feature Tested |
|--------|----------------|
| `examples/01_http_proxy.sh` | HTTP and HTTPS CONNECT proxy via curl |
| `examples/02_socks5_proxy.sh` | SOCKS5 authentication success and rejection |
| `examples/03_port_forwarding.sh` | TCP forwarding with echo server verification |
| `examples/04_proxy_chain.sh` | Two-hop chain: HTTP proxy then SOCKS5 proxy |
| `examples/05_auto_detect.sh` | Single port serving HTTP, SOCKS4, and SOCKS5 simultaneously |
| `examples/06_config_file.sh` | Multiple services from a single JSON config |
| `examples/config.json` | Example JSON configuration with multiple routes |

---

## 26. Build Profile

The release profile enables thin LTO with a single codegen unit. The hot path is
a chain of thin wrappers — `ProxyConn` over `SsStream` / `WsStream` /
`MuxStream` over the socket — each a separate crate-local `poll_read` /
`poll_write` that only pays off once it can be inlined through. It also strips
symbols, which takes the binary from 7.9 MB to 5.8 MB.

The cost is build time: a full release build takes about three minutes, and
`cargo test --release` pays it too. `cargo test` in debug is unaffected, which
is what CI uses; `cargo build --release` is the shipping path in the Dockerfile
and the release workflow, so that is where the cost belongs.

---

## 27. Implementation Status

This table records the honest state of each gost feature in rustun, audited
module by module against ginuerzh/gost. It is deliberately conservative: a row
says **Working** only when the feature is reachable from the command line and
covered by tests, not merely when the types exist.

**Working**: reachable from the CLI and covered by tests.
**Partial**: works for the common case, with the named gap.
**Types only**: types and config parsing exist but nothing is wired to the CLI.
**Absent**: not implemented.

Transports marked *Types only* are **rejected at startup** rather than served as
plaintext TCP. Earlier versions bound a plain TCP listener for `-L http+tls://`,
reporting success while accepting unencrypted traffic.

The TLS listener is backed by rustls, so the server identity is built the same
way on every platform. The end-to-end tests drive a native-tls client against it,
making them cross-implementation rather than self-consistent.

| gost Feature | rustun Status | Notes |
|--------------|---------------|-------|
| HTTP proxy (CONNECT + forward) | Working | Auth, bypass, whitelist/blacklist; request bodies preserved; origin-form forwarding |
| HTTP probe_resist / knock | Working | All four modes (`code:`/`web:`/`host:`/`file:`) with nginx camouflage headers; `?knock=` bypass. `web:` supports http:// decoys only |
| SOCKS5 CONNECT | Working | User/pass auth, IPv4/IPv6/domain, all-zero bound address in the reply |
| SOCKS5 UDP ASSOCIATE | Working | Real relay socket, per-datagram ACL, fragments dropped, torn down with the control connection |
| SOCKS5 BIND | Working | Two-reply sequence |
| SOCKS5 `CmdUDPTun` (0xF3) | Working (server) | UDP over the TCP control connection, with the length carried in the repurposed `RSV` field as gost does. Client side exists; not yet wired to a chain hop |
| SOCKS5 other gost extensions | Absent | MethodTLS 0x80, MethodTLSAuth 0x82, CmdMuxBind 0xF2 |
| SOCKS4/4a proxy | Working | CONNECT and BIND |
| Auto-detect handler | Working | Refuses SOCKS4 when credentials are configured, as gost does |
| Proxy chain (multi-hop) | Partial | HTTP/SOCKS4/SOCKS4a/SOCKS5 connectors with authentication; unknown protocols are a hard error. No transport layer mid-chain |
| Shadowsocks (TCP) | Working | Real AEAD: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305. Unknown ciphers fail closed |
| Shadowsocks over UDP (`ssu`) | Working | `salt || AEAD(addr+payload)` per datagram with a zero nonce and a fresh salt; per-datagram ACL. No chain support (Chain::dial is TCP-only) |
| Relay protocol | Working | Wire-compatible header, UDP length framing, lazy handshake |
| TCP direct/remote forwarding | Working | Multi-target with a fail-filter selector |
| UDP direct forwarding | Partial | Does not route through the chain; no idle expiry |
| UDP listener | Working | One virtual connection per source address, with backlog, per-peer queue and TTL expiry, so `-L udp://` is served by the ordinary handlers |
| UDP remote forwarding (`rudp`) | Absent | Needs the UDP remote-forward listener |
| DNS proxy | Working | udp, tcp, tls and https modes; multi-upstream with failover |
| DNS resolver | Working | udp/tcp/DoT/DoH nameservers, cache with TTL, prefer ipv4/ipv6, EDNS0 client subnet. DoT not covered end to end |
| Hosts file | Working | Exact-match, as in gost v2; live reload |
| SNI proxy | Partial | Server side only; the client connector and the 0xFFFE host extension are absent |
| Transparent proxy (TCP) | Working on Linux | SO_ORIGINAL_DST |
| Transparent proxy (UDP) | Absent | Needs tproxy |
| Authentication | Working | Inline credentials and secrets file, with live reload |
| Bypass / permissions | Working | go-glob semantics for permissions, IPv6-correct, fails closed |
| Load balancing | Working | round/random/fifo with FailFilter, InvalidFilter and FastestFilter (`?fastest_count=`) |
| Live reload | Working | Driven for secrets, bypass, hosts and dns |
| Configuration file | Working | gost v2 JSON format |
| TLS transport (listener) | Working | `-L xxx+tls://` terminates TLS via rustls and runs the handler over it; `?cert=`/`?key=` or a generated self-signed cert |
| TLS transport (chain / `-F`) | Working | `-F http+tls://proxy:443` layers TLS then speaks the hop's protocol inside it; `?secure=true` enables verification, off by default as in gost |
| mTLS transport | Absent | Needs smux |
| WS / WSS transport | Working | Listener and chain hop; default path `/ws` as in gost. `?compression=`/`?rbuf=` parse but have no effect (tungstenite has no equivalent) |
| MTLS / MWS / MWSS transport | Working | Listener: one accepted connection becomes an smux session, every stream a separate handler invocation. Chain: `-F http+mtls://` opens a stream per dial on one reused session. Only supported on the first hop |
| KCP transport | Types only | Config parsing only; no KCP crate |
| QUIC transport | Types only | quinn present but no accept loop and no ALPN |
| HTTP/2, h2, h2c transport | Types only | The `http2` handler falls back to HTTP/1.1, which gost cannot speak |
| Obfuscation (ohttp / otls) | Types only | Handshake only; otls has no record framing |
| Obfuscation (obfs4) | Absent | Dropped in go-gost v3 as well |
| SSH tunnelling | Types only | Rejected at startup; russh is not wired |
| Multiplexing (smux) | Working (v1) | Wire-verified against xtaci/smux v1.5.24: 8-byte little-endian header, keepalive, session-wide receive credit. v2 (`?smuxver=2`) is rejected rather than silently misbehaving |
| TUN / TAP | Types only | Configures an existing interface; no device creation or packet loop |
| FakeTCP, VSOCK | Types only | Need raw sockets and a vsock crate |
| Socket mark / interface bind | Working on Linux | `-M` / `-I` applied to outbound sockets before connect; no-op elsewhere |

## 28. Module Reference

| Module | Source File | Description |
|--------|-------------|-------------|
| auth | auth.rs | `Authenticator` trait and `LocalAuthenticator` with key-value credential store and live-reload support |
| bypass | bypass.rs | Address filtering using `IpMatcher`, `CidrMatcher`, and `DomainMatcher` with glob support; reversed mode |
| chain | chain.rs | Proxy chain with multi-hop HTTP CONNECT and SOCKS5 tunneling, retry logic, and DNS resolution |
| client | client.rs | `Client`, `Connector`, and `Transporter` trait definitions; `DialOptions`, `HandshakeOptions`, `ConnectOptions` |
| config | config.rs | JSON configuration file parser compatible with gost format; `RouteConfig` and `Config` types |
| dns_proxy | dns_proxy.rs | DNS proxy handler (TCP) and UDP DNS proxy; forwards queries to upstream resolvers |
| forward | forward.rs | `TcpDirectForwardHandler` and `UdpDirectForwardHandler` with multi-target load balancing |
| ftcp | ftcp.rs | FakeTCP transport types and configuration (raw socket UDP-over-TCP framing) |
| handler | handler.rs | `Handler` async trait, `AutoHandler` (protocol auto-detection), `HandlerOptions`, `basic_proxy_auth` |
| hosts | hosts.rs | Static hostname-to-IP table with aliases and live-reload support |
| http_proxy | http_proxy.rs | HTTP proxy handler (CONNECT tunneling and request forwarding) and HTTP CONNECT connector |
| http2_transport | http2_transport.rs | HTTP/2 connector, transporter (h2/h2c), and handler |
| kcp | kcp.rs | KCP transport configuration with JSON parsing, mode presets, and encryption settings |
| lib | lib.rs | Library crate root; re-exports all public types and constants |
| mux | mux.rs | Stream multiplexing: `MuxSession` and `MuxFrame` (encode/decode) for multiplexed transports |
| node | node.rs | `Node` (URL parsing, parameter access), `NodeGroup` (load balancing), `FailMarker` (atomic failure tracking) |
| obfs | obfs.rs | HTTP obfuscation (WebSocket upgrade simulation), TLS obfuscation (ClientHello/ServerHello), obfs4 types |
| permissions | permissions.rs | `Permissions` (whitelist/blacklist), `PortRange`, `PortSet`, `StringSet`, `Can()` function |
| quic_transport | quic_transport.rs | QUIC transport and listener using quinn; `QuicConfig` with keep-alive and encryption settings |
| redirect | redirect.rs | TCP/UDP transparent proxy handlers; `SO_ORIGINAL_DST` on Linux, error on other platforms |
| relay | relay.rs | Relay protocol connector and handler with user authentication and address features |
| reload | reload.rs | `Reloader` and `Stoppable` traits; `period_reload` file-watching function |
| remote_forward | remote_forward.rs | `TcpRemoteForwardHandler` and `TcpRemoteForwardListener` for reverse port forwarding |
| resolver | resolver.rs | DNS resolver with IPv4/IPv6 preference; uses system resolver via `tokio::net::lookup_host` |
| selector | selector.rs | `NodeSelector`, `Strategy` (Round/Random/FIFO), `Filter` (FailFilter/InvalidFilter/FastestFilter) |
| server | server.rs | TCP server with exponential backoff on accept errors; dispatches to `Handler` |
| signal | signal.rs | Platform-specific signal handling; SIGUSR1 on Unix, no-op on Windows |
| sni | sni.rs | SNI proxy handler: TLS ClientHello SNI extraction, HTTP fallback |
| sockopts | sockopts.rs | Platform-specific socket options: `SO_MARK` and `SO_BINDTODEVICE` (Linux), no-op stubs elsewhere |
| socks4 | socks4.rs | SOCKS4/4a handler (server) and connectors (client); domain resolution for SOCKS4a |
| socks5 | socks5.rs | SOCKS5 handler (server) and connector (client); auth methods, CONNECT, UDP ASSOCIATE, IPv4/IPv6/domain |
| ss | ss.rs | Shadowsocks handler, connector, UDP connector; cipher support (AES-GCM, ChaCha20-Poly1305); EVP_BytesToKey |
| ssh | ssh.rs | SSH tunnel transporter, forward handler, key file parsing, authorized keys parsing |
| tls_listener | tls_listener.rs | TLS server: wraps TCP listener with TLS acceptor using native-tls |
| tls_transport | tls_transport.rs | TLS client: `tls_connect`, `insecure_tls_connector`, `default_tls_connector` |
| transport | transport.rs | Bidirectional async data relay (`transport` function) with 32KB buffered copy |
| tuntap | tuntap.rs | TUN/TAP configuration, IP route parsing, IPv4 header parsing, platform-specific device creation commands |
| vsock_transport | vsock_transport.rs | VSOCK address parsing, transporter, and listener (Linux VM communication) |
| ws | ws.rs | WebSocket transport (WS/WSS), handler with binary message relay, `WsOptions` |

---

## 29. Testing

### Running Tests

Run the full test suite (191 unit tests + 20 integration tests = 211 total):

```bash
cargo test
```

Run tests for a specific module:

```bash
cargo test chain::tests
cargo test socks5::tests
cargo test http_proxy::tests
cargo test handler::tests
```

Run only the integration tests:

```bash
cargo test --test integration_tests
```

Run tests with full output:

```bash
cargo test -- --nocapture
```

Run a single test by name:

```bash
cargo test test_chain_dial_through_socks5_proxy
```

### Test Categories

The test suite contains 211 tests organized into unit tests (in each module's `#[cfg(test)]` block) and integration tests (in `tests/integration_tests.rs`).

**Unit Tests** (191): Verify individual functions and data structures in isolation. Examples include node URL parsing, bypass matcher logic, permission rule evaluation, configuration JSON parsing, KCP config mode presets, MuxFrame encode/decode, IPv4 header parsing, VSOCK address parsing, Shadowsocks key derivation, obfuscation handshake building, and platform-specific signal handler creation.

**Integration Tests** (20): Start real TCP listeners and verify end-to-end protocol behavior. These tests create actual server/client pairs communicating over loopback:

- HTTP proxy CONNECT tunnel with data relay
- HTTP proxy blacklist rejection
- SOCKS5 CONNECT via IPv4
- SOCKS5 authentication (success path and rejection path)
- SOCKS4 CONNECT via IPv4
- SOCKS4a CONNECT via domain name
- TCP direct forwarding with echo verification
- TCP remote forwarding with echo verification
- Relay protocol with fixed target
- Shadowsocks plain cipher end-to-end
- Proxy chain through HTTP proxy
- Proxy chain through SOCKS5 proxy
- AutoHandler HTTP detection
- AutoHandler SOCKS5 detection
- Bypass blocks matched address via SOCKS5
- HTTP obfuscation client-server roundtrip
- TLS obfuscation client-server roundtrip
- Configuration file parsing with all fields
- Complex node URL parsing
- Server handling 10 concurrent connections

**Configuration Tests**: Verify JSON parsing, field defaults, missing files, malformed input, and field compatibility (Mark, Interface, Retries, Routes).

**Timeout and Error Tests**: Verify behavior under adverse conditions including connection timeouts to non-routable addresses, DNS resolution failures, and retry exhaustion.

---

## 30. License

This project is a Rust port of [gost](https://github.com/ginuerzh/gost), which is licensed under the MIT License.
