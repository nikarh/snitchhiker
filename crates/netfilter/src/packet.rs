//! The headers of a queued packet: addresses, protocol and ports, read in place.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_UDPLITE: u8 = 136;
pub const IPPROTO_SCTP: u8 = 132;

/// IPv6 extension headers that can come between the fixed header and the transport header.
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_DESTINATION: u8 = 60;
/// How many extension headers are followed before giving up.
const MAX_EXTENSIONS: usize = 8;

/// What the daemon needs of a packet's headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Headers {
    pub source: IpAddr,
    pub destination: IpAddr,
    /// The transport protocol (after IPv6 extension headers).
    pub protocol: u8,
    /// Ports of TCP, UDP, UDP-Lite and SCTP; 0 otherwise, or when the transport header isn't there (a fragment).
    pub source_port: u16,
    pub destination_port: u16,
    /// TCP flags, 0 for other protocols.
    pub tcp_flags: u8,
    /// Where the transport header starts in the packet (0 when it isn't there).
    pub transport_offset: usize,
}

/// The UDP payload of a packet whose headers are `headers`, if it is UDP and has one.
#[must_use]
pub fn udp_payload<'a>(packet: &'a [u8], headers: &Headers) -> Option<&'a [u8]> {
    if headers.protocol != IPPROTO_UDP || headers.transport_offset == 0 {
        return None;
    }
    packet.get(headers.transport_offset + 8..)
}

/// Reads the headers of a packet starting at its IP header. `None` when it isn't IPv4 or IPv6, or is truncated before
/// the addresses.
#[must_use]
pub fn parse(packet: &[u8]) -> Option<Headers> {
    match packet.first()? >> 4 {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        _ => None,
    }
}

fn parse_v4(packet: &[u8]) -> Option<Headers> {
    let header_length = usize::from(packet.first()? & 0x0f) * 4;
    let protocol = *packet.get(9)?;
    let source = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(12..16)?).ok()?);
    let destination = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(16..20)?).ok()?);
    // A fragment other than the first has no transport header.
    let fragment_offset = u16::from_be_bytes(packet.get(6..8)?.try_into().ok()?) & 0x1fff;
    let transport = if fragment_offset == 0 {
        packet.get(header_length..).unwrap_or_default()
    } else {
        &[]
    };
    Some(with_transport(
        IpAddr::V4(source),
        IpAddr::V4(destination),
        protocol,
        transport,
        if transport.is_empty() {
            0
        } else {
            header_length
        },
    ))
}

fn parse_v6(packet: &[u8]) -> Option<Headers> {
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    let mut next = *packet.get(6)?;
    let mut offset = 40;
    let mut first_fragment = true;
    for _ in 0..MAX_EXTENSIONS {
        match next {
            IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DESTINATION => {
                let length = (usize::from(*packet.get(offset + 1)?) + 1) * 8;
                next = *packet.get(offset)?;
                offset += length;
            }
            IPV6_FRAGMENT => {
                let fragment_offset =
                    u16::from_be_bytes(packet.get(offset + 2..offset + 4)?.try_into().ok()?) >> 3;
                first_fragment = fragment_offset == 0;
                next = *packet.get(offset)?;
                offset += 8;
            }
            _ => break,
        }
    }
    let transport = if first_fragment {
        packet.get(offset..).unwrap_or_default()
    } else {
        &[]
    };
    Some(with_transport(
        IpAddr::V6(source),
        IpAddr::V6(destination),
        next,
        transport,
        if transport.is_empty() { 0 } else { offset },
    ))
}

fn with_transport(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    transport: &[u8],
    transport_offset: usize,
) -> Headers {
    let port = |at: usize| {
        transport
            .get(at..at + 2)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u16::from_be_bytes)
    };
    let has_ports = matches!(
        protocol,
        IPPROTO_TCP | IPPROTO_UDP | IPPROTO_UDPLITE | IPPROTO_SCTP
    );
    Headers {
        source,
        destination,
        protocol,
        source_port: if has_ports { port(0) } else { 0 },
        destination_port: if has_ports { port(2) } else { 0 },
        tcp_flags: if protocol == IPPROTO_TCP {
            transport.get(13).copied().unwrap_or(0)
        } else {
            0
        },
        transport_offset,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn ipv4(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let mut packet = vec![
            0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, protocol, 0, 0, 192, 0, 2, 1, 198, 51, 100, 7,
        ];
        packet.extend_from_slice(transport);
        packet
    }

    fn tcp_syn(source: u16, destination: u16) -> Vec<u8> {
        let mut tcp = vec![0; 20];
        tcp[0..2].copy_from_slice(&source.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination.to_be_bytes());
        tcp[13] = 0x02;
        tcp
    }

    #[test]
    fn reads_an_ipv4_tcp_syn() {
        let headers = parse(&ipv4(IPPROTO_TCP, &tcp_syn(40000, 443))).unwrap();
        assert_eq!(headers.source, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(
            headers.destination,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))
        );
        assert_eq!(
            (
                headers.protocol,
                headers.source_port,
                headers.destination_port,
                headers.tcp_flags
            ),
            (IPPROTO_TCP, 40000, 443, 0x02)
        );
    }

    #[test]
    fn has_no_ports_for_icmp_or_later_fragments() {
        let headers = parse(&ipv4(IPPROTO_ICMP, &[8, 0, 0, 0])).unwrap();
        assert_eq!((headers.source_port, headers.destination_port), (0, 0));
        let mut fragment = ipv4(IPPROTO_UDP, &[0x9c, 0x40, 0, 53]);
        fragment[7] = 1;
        let headers = parse(&fragment).unwrap();
        assert_eq!(headers.destination_port, 0);
    }

    #[test]
    fn follows_ipv6_extension_headers() {
        let mut packet = vec![0x60, 0, 0, 0, 0, 16, IPV6_HOP_BY_HOP, 64];
        packet.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        // Hop-by-hop options: next header UDP, length 0 (8 bytes).
        packet.extend_from_slice(&[IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
        packet.extend_from_slice(&[0x13, 0x88, 0, 53, 0, 8, 0, 0]);
        let headers = parse(&packet).unwrap();
        assert_eq!(
            (
                headers.protocol,
                headers.source_port,
                headers.destination_port
            ),
            (IPPROTO_UDP, 5000, 53)
        );
    }

    #[test]
    fn rejects_other_versions_and_truncated_headers() {
        assert_eq!(parse(&[0x50; 40]), None);
        assert_eq!(parse(&[0x45, 0, 0]), None);
        assert_eq!(parse(&[]), None);
    }
}
