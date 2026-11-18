//! Safe, allocation-light packet parsing: Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS.
//! Every read is bounds-checked; malformed input yields `ParseError`, never a panic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 101;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Truncated(&'static str),
    BadVersion(u8),
    BadHeaderLength,
    UnsupportedLinkType(u32),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Truncated(w) => write!(f, "truncated {w}"),
            ParseError::BadVersion(v) => write!(f, "bad IP version {v}"),
            ParseError::BadHeaderLength => write!(f, "bad header length"),
            ParseError::UnsupportedLinkType(l) => write!(f, "unsupported link type {l}"),
        }
    }
}
impl std::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Tcp {
        src_port: u16,
        dst_port: u16,
        flags: u8,
        seq: u32,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        payload_len: usize,
    },
    Icmp {
        icmp_type: u8,
        code: u8,
    },
    Icmpv6 {
        icmp_type: u8,
        code: u8,
    },
    /// Fragmented or unknown transport: carries the IP protocol number.
    Other(u8),
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsInfo {
    pub transaction_id: u16,
    pub is_response: bool,
    pub rcode: u8,
    pub qname: Option<String>,
    pub qtype: u16,
    pub answer_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub ts_us: u64,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ip_version: u8,
    pub ip_proto: u8,
    pub wire_len: usize,
    pub transport: Transport,
    pub dns: Option<DnsInfo>,
}

impl Packet {
    pub fn src_port(&self) -> Option<u16> {
        match self.transport {
            Transport::Tcp { src_port, .. } | Transport::Udp { src_port, .. } => Some(src_port),
            _ => None,
        }
    }
    pub fn dst_port(&self) -> Option<u16> {
        match self.transport {
            Transport::Tcp { dst_port, .. } | Transport::Udp { dst_port, .. } => Some(dst_port),
            _ => None,
        }
    }
    pub fn protocol_name(&self) -> &'static str {
        match self.transport {
            Transport::Tcp { .. } => "TCP",
            Transport::Udp { .. } if self.dns.is_some() => "DNS",
            Transport::Udp { .. } => "UDP",
            Transport::Icmp { .. } | Transport::Icmpv6 { .. } => "ICMP",
            Transport::Other(_) => "OTHER",
        }
    }
}

fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(o)?, *b.get(o + 1)?]))
}
fn be32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(o)?,
        *b.get(o + 1)?,
        *b.get(o + 2)?,
        *b.get(o + 3)?,
    ]))
}

/// Parse a captured frame according to its pcap link type.
pub fn parse_frame(ts_us: u64, data: &[u8], link_type: u32) -> Result<Packet, ParseError> {
    match link_type {
        LINKTYPE_ETHERNET => parse_ethernet(ts_us, data),
        LINKTYPE_RAW => parse_ip(ts_us, data),
        other => Err(ParseError::UnsupportedLinkType(other)),
    }
}

pub fn parse_ethernet(ts_us: u64, data: &[u8]) -> Result<Packet, ParseError> {
    if data.len() < 14 {
        return Err(ParseError::Truncated("ethernet header"));
    }
    let mut ethertype = be16(data, 12).ok_or(ParseError::Truncated("ethertype"))?;
    let mut off = 14usize;
    // Up to two VLAN tags (802.1Q / QinQ).
    for _ in 0..2 {
        if ethertype == 0x8100 || ethertype == 0x88a8 {
            ethertype = be16(data, off + 2).ok_or(ParseError::Truncated("vlan tag"))?;
            off += 4;
        }
    }
    match ethertype {
        0x0800 | 0x86dd => parse_ip(ts_us, &data[off..]),
        _ => Err(ParseError::Truncated("non-IP ethertype")),
    }
}

/// Parse an IP datagram (IPv4 or IPv6) starting at the IP header.
pub fn parse_ip(ts_us: u64, data: &[u8]) -> Result<Packet, ParseError> {
    let first = *data.first().ok_or(ParseError::Truncated("ip header"))?;
    match first >> 4 {
        4 => parse_ipv4(ts_us, data),
        6 => parse_ipv6(ts_us, data),
        v => Err(ParseError::BadVersion(v)),
    }
}

fn parse_ipv4(ts_us: u64, data: &[u8]) -> Result<Packet, ParseError> {
    if data.len() < 20 {
        return Err(ParseError::Truncated("ipv4 header"));
    }
    let ihl = ((data[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ihl > data.len() {
        return Err(ParseError::BadHeaderLength);
    }
    let total_len = be16(data, 2).ok_or(ParseError::Truncated("ipv4 total length"))? as usize;
    let frag = be16(data, 6).unwrap_or(0);
    let proto = data[9];
    let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
    // Clamp to the bytes actually captured (snaplen may truncate).
    let end = total_len.clamp(ihl, data.len());
    let is_fragment = (frag & 0x1fff) != 0 || (frag & 0x2000) != 0;
    let transport = if is_fragment {
        Transport::Other(proto)
    } else {
        parse_transport(proto, &data[ihl..end], false)?
    };
    Ok(finish(
        ts_us,
        src,
        dst,
        4,
        proto,
        total_len,
        transport,
        &data[ihl..end],
    ))
}

fn parse_ipv6(ts_us: u64, data: &[u8]) -> Result<Packet, ParseError> {
    if data.len() < 40 {
        return Err(ParseError::Truncated("ipv6 header"));
    }
    let payload_len = be16(data, 4).ok_or(ParseError::Truncated("ipv6 payload length"))? as usize;
    let mut next = data[6];
    let mut src_b = [0u8; 16];
    let mut dst_b = [0u8; 16];
    src_b.copy_from_slice(&data[8..24]);
    dst_b.copy_from_slice(&data[24..40]);
    let mut off = 40usize;
    let end = (40 + payload_len).min(data.len());
    // Walk a bounded number of extension headers: hop-by-hop(0), routing(43), dest opts(60).
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let nh = *data
                    .get(off)
                    .ok_or(ParseError::Truncated("ipv6 ext header"))?;
                let hl = *data
                    .get(off + 1)
                    .ok_or(ParseError::Truncated("ipv6 ext length"))?
                    as usize;
                next = nh;
                off += (hl + 1) * 8;
                if off > end {
                    return Err(ParseError::Truncated("ipv6 ext body"));
                }
            }
            44 => {
                // Fragment header: only the first fragment carries a transport header.
                let nh = *data
                    .get(off)
                    .ok_or(ParseError::Truncated("ipv6 frag header"))?;
                let frag_off = be16(data, off + 2).unwrap_or(0) & 0xfff8;
                if frag_off != 0 {
                    return Ok(finish(
                        ts_us,
                        IpAddr::V6(Ipv6Addr::from(src_b)),
                        IpAddr::V6(Ipv6Addr::from(dst_b)),
                        6,
                        44,
                        payload_len,
                        Transport::Other(44),
                        &[],
                    ));
                }
                next = nh;
                off += 8;
            }
            _ => break,
        }
    }
    let transport = if off > end {
        Transport::Other(next)
    } else {
        parse_transport(next, &data[off..end], true)?
    };
    Ok(finish(
        ts_us,
        IpAddr::V6(Ipv6Addr::from(src_b)),
        IpAddr::V6(Ipv6Addr::from(dst_b)),
        6,
        next,
        payload_len + 40,
        transport,
        &data[off.min(end)..end],
    ))
}

#[allow(clippy::too_many_arguments)]
fn finish(
    ts_us: u64,
    src: IpAddr,
    dst: IpAddr,
    ver: u8,
    proto: u8,
    wire_len: usize,
    transport: Transport,
    seg: &[u8],
) -> Packet {
    let dns = match &transport {
        Transport::Udp {
            src_port, dst_port, ..
        } if *src_port == 53 || *dst_port == 53 => seg.get(8..).and_then(parse_dns),
        _ => None,
    };
    Packet {
        ts_us,
        src,
        dst,
        ip_version: ver,
        ip_proto: proto,
        wire_len,
        transport,
        dns,
    }
}

fn parse_transport(proto: u8, seg: &[u8], v6: bool) -> Result<Transport, ParseError> {
    match proto {
        6 => {
            if seg.len() < 20 {
                return Err(ParseError::Truncated("tcp header"));
            }
            let doff = ((seg[12] >> 4) as usize) * 4;
            if doff < 20 || doff > seg.len() {
                return Err(ParseError::BadHeaderLength);
            }
            Ok(Transport::Tcp {
                src_port: be16(seg, 0).ok_or(ParseError::Truncated("tcp"))?,
                dst_port: be16(seg, 2).ok_or(ParseError::Truncated("tcp"))?,
                seq: be32(seg, 4).ok_or(ParseError::Truncated("tcp seq"))?,
                flags: seg[13],
            })
        }
        17 => {
            if seg.len() < 8 {
                return Err(ParseError::Truncated("udp header"));
            }
            let src_port = be16(seg, 0).ok_or(ParseError::Truncated("udp"))?;
            let dst_port = be16(seg, 2).ok_or(ParseError::Truncated("udp"))?;
            Ok(Transport::Udp {
                src_port,
                dst_port,
                payload_len: seg.len() - 8,
            })
        }
        1 if !v6 => {
            if seg.len() < 4 {
                return Err(ParseError::Truncated("icmp header"));
            }
            Ok(Transport::Icmp {
                icmp_type: seg[0],
                code: seg[1],
            })
        }
        58 if v6 => {
            if seg.len() < 4 {
                return Err(ParseError::Truncated("icmpv6 header"));
            }
            Ok(Transport::Icmpv6 {
                icmp_type: seg[0],
                code: seg[1],
            })
        }
        p => Ok(Transport::Other(p)),
    }
}

/// Parse a DNS message (UDP payload). Returns None if it is not plausibly DNS.
pub fn parse_dns(msg: &[u8]) -> Option<DnsInfo> {
    if msg.len() < 12 {
        return None;
    }
    let id = be16(msg, 0)?;
    let flags = be16(msg, 2)?;
    let qd = be16(msg, 4)?;
    let an = be16(msg, 6)?;
    let qname = if qd > 0 {
        read_name(msg, 12).map(|(n, _)| n)
    } else {
        None
    };
    let qtype = if qd > 0 {
        let (_, after) = read_name(msg, 12)?;
        be16(msg, after)?
    } else {
        0
    };
    Some(DnsInfo {
        transaction_id: id,
        is_response: flags & 0x8000 != 0,
        rcode: (flags & 0x000f) as u8,
        qname,
        qtype,
        answer_count: an,
    })
}

/// Read a (possibly compressed) DNS name. Returns (name, offset after the name in the original position).
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_pos: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            if end_pos.is_none() {
                end_pos = Some(pos + 1);
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 16 || ptr >= msg.len() {
                return None;
            }
            pos = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
        if labels.len() > 128 {
            return None;
        }
    }
    Some((labels.join("."), end_pos?))
}
