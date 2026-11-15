//! PROXY protocol v2 on the listener, for a TLS-passthrough proxy (#399).
//!
//! A passthrough proxy forwards the TLS bytes untouched, so it cannot add an
//! HTTP header naming the client, and every client would have the proxy's
//! address: one `[auth.rate_limit]` per-address bucket and one set of REST
//! relay slots for all of them. With `[server.proxy_protocol] trusted` set, a
//! connection from a listed proxy opens with a PROXY protocol v2 header, read
//! here before TLS, and the address it names becomes the connection's
//! `ConnectInfo`. Everything keyed by client address reads that.
//!
//! It fails closed. A connection from a trusted proxy that does not send a
//! valid v2 header in time is closed, never served under the proxy's own
//! address. A connection from anyone else is served as before and its bytes
//! are never parsed as a PROXY header. Only v2 is accepted: v1 is a text line
//! that a client could otherwise smuggle in front of a request.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;
use tokio::io::{AsyncRead, AsyncReadExt};

/// The 12-byte signature every v2 header opens with.
const SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

/// The fixed part: signature, version and command, family and transport, and
/// the length of what follows.
const FIXED: usize = 16;

/// The longest header accepted, fixed part included. An IPv6 address block is
/// 36 bytes; the rest is room for TLVs, which are skipped. A load balancer that
/// sends more TLVs than this has its connections closed.
pub const MAX_HEADER: usize = 536;

/// Why a trusted proxy's connection was closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    #[error("no PROXY protocol v2 header within {0:?}")]
    Timeout(Duration),
    #[error("the connection closed before the PROXY header was complete")]
    Truncated,
    #[error("not a PROXY protocol v2 header")]
    NotV2,
    #[error("PROXY protocol command {0:#x} is not LOCAL or PROXY")]
    Command(u8),
    #[error("PROXY header of {0} bytes is over the {MAX_HEADER}-byte limit")]
    TooLong(usize),
    #[error("PROXY header names family/transport {0:#04x}; only TCP over IPv4 or IPv6 is accepted")]
    Family(u8),
    #[error("PROXY header's address block is shorter than its family needs")]
    ShortAddress,
}

/// What a header says about the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Header {
    /// The proxy speaking for itself (a health check): keep its address.
    Local,
    /// A client's connection: its source address and port.
    Proxied(SocketAddr),
}

/// Parse a complete v2 header: its 16-byte fixed part and the `len` bytes that
/// follow.
pub fn parse(fixed: &[u8; FIXED], rest: &[u8]) -> Result<Header, HeaderError> {
    if fixed[..12] != SIGNATURE || fixed[12] >> 4 != 2 {
        return Err(HeaderError::NotV2);
    }
    let command = fixed[12] & 0x0f;
    let family = fixed[13];
    match command {
        // LOCAL: the address block, if any, is ignored.
        0x0 => return Ok(Header::Local),
        0x1 => {}
        other => return Err(HeaderError::Command(other)),
    }
    match family {
        // TCP over IPv4: source, destination, source port, destination port.
        0x11 => {
            let a = rest.get(..12).ok_or(HeaderError::ShortAddress)?;
            let ip = Ipv4Addr::new(a[0], a[1], a[2], a[3]);
            let port = u16::from_be_bytes([a[8], a[9]]);
            Ok(Header::Proxied(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        // TCP over IPv6.
        0x21 => {
            let a = rest.get(..36).ok_or(HeaderError::ShortAddress)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&a[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([a[32], a[33]]);
            Ok(Header::Proxied(SocketAddr::new(
                IpAddr::V6(ip).to_canonical(),
                port,
            )))
        }
        // UNSPEC, UDP, Unix sockets: nothing this server can key a limit on.
        other => Err(HeaderError::Family(other)),
    }
}

/// `[server.proxy_protocol]`, resolved at boot.
#[derive(Debug, Clone)]
pub struct ProxyProtocol {
    trusted: Vec<IpNet>,
    timeout: Duration,
}

impl ProxyProtocol {
    /// `None` when `trusted` is empty, which leaves the listener as it was.
    /// An entry that is neither an address nor a CIDR refuses the boot.
    pub fn from_config(
        section: &jig_config::v0_0_2_server::ProxyProtocolSection,
    ) -> Result<Option<Self>, String> {
        if section.trusted.is_empty() {
            return Ok(None);
        }
        if section.header_timeout_ms == 0 || section.header_timeout_ms > 60_000 {
            return Err(format!(
                "[server.proxy_protocol] header_timeout_ms must be 1 to 60000, not {}",
                section.header_timeout_ms
            ));
        }
        let trusted = section
            .trusted
            .iter()
            .map(|entry| {
                entry
                    .parse::<IpNet>()
                    .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                    .map(|net| net.trunc())
                    .map_err(|_| {
                        format!(
                            "[server.proxy_protocol] trusted: `{entry}` is not an IP address \
                             or CIDR"
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(Self {
            trusted,
            timeout: Duration::from_millis(section.header_timeout_ms),
        }))
    }

    /// The trusted proxies, for the startup log.
    pub fn trusted(&self) -> &[IpNet] {
        &self.trusted
    }

    /// Whether `ip` is a trusted proxy. An IPv4 peer on a dual-stack socket
    /// arrives as `::ffff:a.b.c.d` and matches its IPv4 entry.
    pub fn trusts(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.trusted.iter().any(|net| net.contains(&ip))
    }

    /// The address to serve `io` under. For a trusted `peer`, read its PROXY
    /// v2 header off `io` and return the client it names (or `peer` itself for
    /// LOCAL); the header is consumed and nothing after it. Any other peer is
    /// returned as it is and nothing is read.
    pub async fn client_addr<S: AsyncRead + Unpin>(
        &self,
        io: &mut S,
        peer: SocketAddr,
    ) -> Result<SocketAddr, HeaderError> {
        if !self.trusts(peer.ip()) {
            return Ok(peer);
        }
        let header = tokio::time::timeout(self.timeout, read_header(io))
            .await
            .map_err(|_| HeaderError::Timeout(self.timeout))??;
        Ok(match header {
            Header::Local => peer,
            Header::Proxied(client) => client,
        })
    }
}

/// Read exactly one v2 header off `io`: the fixed part, then the length it
/// gives, refusing a length over [`MAX_HEADER`] before reading it.
async fn read_header<S: AsyncRead + Unpin>(io: &mut S) -> Result<Header, HeaderError> {
    let mut fixed = [0u8; FIXED];
    io.read_exact(&mut fixed)
        .await
        .map_err(|_| HeaderError::Truncated)?;
    if fixed[..12] != SIGNATURE || fixed[12] >> 4 != 2 {
        return Err(HeaderError::NotV2);
    }
    let len = usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    if FIXED + len > MAX_HEADER {
        return Err(HeaderError::TooLong(FIXED + len));
    }
    let mut rest = vec![0u8; len];
    io.read_exact(&mut rest)
        .await
        .map_err(|_| HeaderError::Truncated)?;
    parse(&fixed, &rest)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use jig_config::v0_0_2_server::ProxyProtocolSection;

    /// A v2 PROXY header over TCP for `client` → `server`, with `tlv_len`
    /// bytes of TLVs appended.
    pub(crate) fn v2_header(client: SocketAddr, server: SocketAddr, tlv_len: usize) -> Vec<u8> {
        let mut block = Vec::new();
        let family = match (client.ip(), server.ip()) {
            (IpAddr::V4(c), IpAddr::V4(s)) => {
                block.extend_from_slice(&c.octets());
                block.extend_from_slice(&s.octets());
                0x11
            }
            (IpAddr::V6(c), IpAddr::V6(s)) => {
                block.extend_from_slice(&c.octets());
                block.extend_from_slice(&s.octets());
                0x21
            }
            _ => panic!("one family"),
        };
        block.extend_from_slice(&client.port().to_be_bytes());
        block.extend_from_slice(&server.port().to_be_bytes());
        block.extend(std::iter::repeat_n(0u8, tlv_len));
        let mut out = SIGNATURE.to_vec();
        out.push(0x21);
        out.push(family);
        out.extend_from_slice(&(block.len() as u16).to_be_bytes());
        out.extend(block);
        out
    }

    fn proxy(trusted: &[&str]) -> ProxyProtocol {
        ProxyProtocol::from_config(&ProxyProtocolSection {
            trusted: trusted.iter().map(|s| s.to_string()).collect(),
            header_timeout_ms: 200,
        })
        .unwrap()
        .unwrap()
    }

    async fn read(bytes: &[u8]) -> Result<Header, HeaderError> {
        let mut io = bytes;
        read_header(&mut io).await
    }

    #[tokio::test]
    async fn a_v4_and_a_v6_header_name_the_client() {
        let c4: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let s4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert_eq!(read(&v2_header(c4, s4, 0)).await, Ok(Header::Proxied(c4)));
        let c6: SocketAddr = "[2001:db8::7]:40000".parse().unwrap();
        let s6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(read(&v2_header(c6, s6, 0)).await, Ok(Header::Proxied(c6)));
        // TLVs are skipped, up to the limit.
        let tlvs = MAX_HEADER - FIXED - 12;
        assert_eq!(
            read(&v2_header(c4, s4, tlvs)).await,
            Ok(Header::Proxied(c4))
        );
    }

    #[tokio::test]
    async fn a_local_header_keeps_the_proxy_address() {
        let mut h = SIGNATURE.to_vec();
        h.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        assert_eq!(read(&h).await, Ok(Header::Local));
    }

    #[tokio::test]
    async fn anything_else_is_refused() {
        let c: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let s: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let good = v2_header(c, s, 0);

        assert_eq!(
            read(b"PROXY TCP4 198.51.100.7 192.0.2.1 40000 443\r\n").await,
            Err(HeaderError::NotV2),
            "v1 text"
        );
        assert_eq!(
            read(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x00\x00\x00\x00\x00").await,
            Err(HeaderError::NotV2),
            "a TLS ClientHello"
        );
        let mut v1 = good.clone();
        v1[12] = 0x11;
        assert_eq!(read(&v1).await, Err(HeaderError::NotV2), "version 1");
        let mut cmd = good.clone();
        cmd[12] = 0x22;
        assert_eq!(read(&cmd).await, Err(HeaderError::Command(2)));
        for family in [0x00, 0x12, 0x22, 0x31] {
            let mut f = good.clone();
            f[13] = family;
            assert_eq!(read(&f).await, Err(HeaderError::Family(family)));
        }
        let over = v2_header(c, s, MAX_HEADER - FIXED - 12 + 1);
        assert_eq!(read(&over).await, Err(HeaderError::TooLong(MAX_HEADER + 1)));
        assert_eq!(read(&good[..20]).await, Err(HeaderError::Truncated));
        let mut short = good.clone();
        short[15] = 4;
        short.truncate(FIXED + 4);
        assert_eq!(read(&short).await, Err(HeaderError::ShortAddress));
    }

    #[tokio::test]
    async fn only_a_trusted_peer_is_read_and_it_must_send_in_time() {
        let p = proxy(&["10.0.0.5", "10.0.1.0/24", "2001:db8::/48"]);
        assert!(p.trusts("10.0.0.5".parse().unwrap()));
        assert!(p.trusts("10.0.1.200".parse().unwrap()));
        assert!(p.trusts("::ffff:10.0.0.5".parse().unwrap()), "v4-mapped");
        assert!(p.trusts("2001:db8:0:1::9".parse().unwrap()));
        assert!(!p.trusts("10.0.0.6".parse().unwrap()));

        let client: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let header = v2_header(client, "192.0.2.1:443".parse().unwrap(), 0);
        let untrusted: SocketAddr = "203.0.113.9:5000".parse().unwrap();
        let mut io = &header[..];
        assert_eq!(p.client_addr(&mut io, untrusted).await, Ok(untrusted));
        assert_eq!(
            io.len(),
            header.len(),
            "an untrusted peer's bytes are not read"
        );

        let trusted: SocketAddr = "10.0.0.5:6000".parse().unwrap();
        let mut stream = header.clone();
        stream.extend_from_slice(b"rest");
        let mut io = &stream[..];
        assert_eq!(p.client_addr(&mut io, trusted).await, Ok(client));
        assert_eq!(io, b"rest", "the header and nothing after it is consumed");

        let (mut silent, _keep_open) = tokio::io::duplex(64);
        assert_eq!(
            p.client_addr(&mut silent, trusted).await,
            Err(HeaderError::Timeout(Duration::from_millis(200)))
        );
    }

    #[test]
    fn the_config_is_checked_at_boot() {
        let off = ProxyProtocolSection::default();
        assert!(ProxyProtocol::from_config(&off).unwrap().is_none());
        let bad = ProxyProtocolSection {
            trusted: vec!["proxy.internal".to_string()],
            ..off.clone()
        };
        assert!(
            ProxyProtocol::from_config(&bad)
                .unwrap_err()
                .contains("proxy.internal")
        );
        let zero = ProxyProtocolSection {
            trusted: vec!["10.0.0.5".to_string()],
            header_timeout_ms: 0,
        };
        assert!(ProxyProtocol::from_config(&zero).is_err());
    }
}
