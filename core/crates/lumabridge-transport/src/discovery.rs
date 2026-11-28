// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust mDNS (`_lumabridge._udp.local`) discovery codec + manual IP fallback (`ADR-0005`).
//!
//! Security note: all discovered endpoints and TXT metadata are **untrusted network hints**
//! until verified by mTLS + `TrustStore` during TLS 1.3 handshake completion.

use crate::error::{map_io_error, TransportError};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};

/// Standard DNS-SD service type for `LumaBridge` endpoints on LAN.
pub const LUMABRIDGE_MDNS_SERVICE: &str = "_lumabridge._udp.local";

/// Standard mDNS IPv4 multicast destination.
pub const MDNS_MULTICAST_V4: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);

const MAX_DNS_NAME_JUMPS: usize = 8;
const MAX_DNS_PACKET_BYTES: usize = 1500;
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;
const CLASS_IN: u16 = 1;

/// Manual fallback endpoint when multicast mDNS is unavailable or disabled on the LAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualEndpoint {
    pub addr: SocketAddr,
    pub label: Option<String>,
}

/// Untrusted endpoint hint published or discovered on LAN via mDNS or manual configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeerHint {
    pub instance_name: String,
    pub short_device_id_hex: String,
    pub friendly_name: String,
    pub addrs: Vec<SocketAddr>,
    pub tcp_port: Option<u16>,
    pub protocol_major: u16,
}

/// Service advertisement published by an acceptor listening on LAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryAdvertisement {
    pub short_device_id_hex: String,
    pub friendly_name: String,
    pub host_ip: Ipv4Addr,
    pub quic_port: u16,
    pub tcp_port: Option<u16>,
}

fn sanitize_dns_label(raw: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_len));
    for ch in raw.chars() {
        if out.len() >= max_len {
            break;
        }
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == ' ' {
            out.push(ch);
        }
    }
    if out.is_empty() {
        "lumabridge".to_owned()
    } else {
        out
    }
}

fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> Result<(), TransportError> {
    let trimmed = name.trim_end_matches('.');
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(TransportError::Discovery("invalid DNS label length"));
        }
        out.push(u8::try_from(label.len()).map_err(|_| TransportError::Discovery("label"))?);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn decode_dns_name(packet: &[u8], start: usize) -> Result<(String, usize), TransportError> {
    let mut pos = start;
    let mut end_after_first_jump = None;
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0usize;

    loop {
        let len_byte = *packet
            .get(pos)
            .ok_or(TransportError::Discovery("truncated DNS name"))?;
        if len_byte == 0 {
            pos += 1;
            break;
        }
        if (len_byte & 0xC0) == 0xC0 {
            jumps += 1;
            if jumps > MAX_DNS_NAME_JUMPS {
                return Err(TransportError::Discovery("DNS pointer compression loop"));
            }
            let second = *packet
                .get(pos + 1)
                .ok_or(TransportError::Discovery("truncated DNS pointer"))?;
            let ptr = ((usize::from(len_byte & 0x3F)) << 8) | usize::from(second);
            if ptr >= packet.len() || ptr == pos {
                return Err(TransportError::Discovery("invalid DNS compression pointer"));
            }
            if end_after_first_jump.is_none() {
                end_after_first_jump = Some(pos + 2);
            }
            pos = ptr;
            continue;
        }
        if (len_byte & 0xC0) != 0 {
            return Err(TransportError::Discovery("unsupported DNS label flags"));
        }
        let len = usize::from(len_byte);
        let label_bytes = packet
            .get(pos + 1..pos + 1 + len)
            .ok_or(TransportError::Discovery("truncated DNS label"))?;
        let text = core::str::from_utf8(label_bytes)
            .map_err(|_| TransportError::Discovery("non-UTF8 DNS label"))?;
        labels.push(text.to_owned());
        pos += 1 + len;
    }

    let next_pos = end_after_first_jump.unwrap_or(pos);
    Ok((labels.join("."), next_pos))
}

fn read_u16_be(packet: &[u8], pos: &mut usize) -> Result<u16, TransportError> {
    let slice = packet
        .get(*pos..*pos + 2)
        .ok_or(TransportError::Discovery("truncated u16"))?;
    *pos += 2;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

/// Encode a compact mDNS PTR query for `_lumabridge._udp.local`.
pub fn encode_mdns_query(tx_id: u16) -> Result<Vec<u8>, TransportError> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&tx_id.to_be_bytes());
    buf.extend_from_slice(&0x0000u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    encode_dns_name(LUMABRIDGE_MDNS_SERVICE, &mut buf)?;
    buf.extend_from_slice(&TYPE_PTR.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(buf)
}

/// Returns `true` if `packet` is a valid mDNS query requesting `_lumabridge._udp.local`.
#[must_use]
pub fn is_lumabridge_mdns_query(packet: &[u8]) -> bool {
    if packet.len() < 12 || packet.len() > MAX_DNS_PACKET_BYTES {
        return false;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) != 0 {
        return false;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let mut pos = 12usize;
    for _ in 0..qdcount.min(8) {
        let Ok((qname, next)) = decode_dns_name(packet, pos) else {
            return false;
        };
        pos = next;
        let Ok(qtype) = read_u16_be(packet, &mut pos) else {
            return false;
        };
        let Ok(_qclass) = read_u16_be(packet, &mut pos) else {
            return false;
        };
        if qname.eq_ignore_ascii_case(LUMABRIDGE_MDNS_SERVICE)
            && (qtype == TYPE_PTR || qtype == 255)
        {
            return true;
        }
    }
    false
}

/// Encode an mDNS response packet advertising one [`DiscoveryAdvertisement`].
pub fn encode_mdns_response(
    tx_id: u16,
    adv: &DiscoveryAdvertisement,
    ttl_secs: u32,
) -> Result<Vec<u8>, TransportError> {
    let short_id = sanitize_dns_label(&adv.short_device_id_hex, 24);
    let safe_name = sanitize_dns_label(&adv.friendly_name, 32);
    let instance_fqdn = format!("lb-{short_id}.{LUMABRIDGE_MDNS_SERVICE}");
    let host_fqdn = format!("lb-{short_id}.local");

    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&tx_id.to_be_bytes());
    out.extend_from_slice(&0x8400u16.to_be_bytes()); // Response + Authoritative
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes()); // PTR + SRV + TXT + A
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());

    // 1. PTR record
    let mut ptr_rdata = Vec::new();
    encode_dns_name(&instance_fqdn, &mut ptr_rdata)?;
    write_rr(
        &mut out,
        LUMABRIDGE_MDNS_SERVICE,
        TYPE_PTR,
        ttl_secs,
        &ptr_rdata,
    )?;

    // 2. SRV record
    let mut srv_rdata = Vec::new();
    srv_rdata.extend_from_slice(&0u16.to_be_bytes());
    srv_rdata.extend_from_slice(&0u16.to_be_bytes());
    srv_rdata.extend_from_slice(&adv.quic_port.to_be_bytes());
    encode_dns_name(&host_fqdn, &mut srv_rdata)?;
    write_rr(&mut out, &instance_fqdn, TYPE_SRV, ttl_secs, &srv_rdata)?;

    // 3. TXT record
    let mut txt_items = vec![
        "ver=1".to_owned(),
        format!("id={short_id}"),
        format!("quic={}", adv.quic_port),
        format!("name={safe_name}"),
    ];
    if let Some(tcp_p) = adv.tcp_port {
        txt_items.push(format!("tcp={tcp_p}"));
    }
    let mut txt_rdata = Vec::new();
    for item in txt_items {
        let len =
            u8::try_from(item.len()).map_err(|_| TransportError::Discovery("TXT item too long"))?;
        txt_rdata.push(len);
        txt_rdata.extend_from_slice(item.as_bytes());
    }
    write_rr(&mut out, &instance_fqdn, TYPE_TXT, ttl_secs, &txt_rdata)?;

    // 4. A record
    write_rr(
        &mut out,
        &host_fqdn,
        TYPE_A,
        ttl_secs,
        &adv.host_ip.octets(),
    )?;

    if out.len() > MAX_DNS_PACKET_BYTES {
        return Err(TransportError::Discovery("mDNS response exceeded 1500 B"));
    }
    Ok(out)
}

fn write_rr(
    out: &mut Vec<u8>,
    name: &str,
    rr_type: u16,
    ttl_secs: u32,
    rdata: &[u8],
) -> Result<(), TransportError> {
    encode_dns_name(name, out)?;
    out.extend_from_slice(&rr_type.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl_secs.to_be_bytes());
    let rdlen = u16::try_from(rdata.len())
        .map_err(|_| TransportError::Discovery("RDATA length overflow"))?;
    out.extend_from_slice(&rdlen.to_be_bytes());
    out.extend_from_slice(rdata);
    Ok(())
}

/// Decode an mDNS response packet into untrusted [`DiscoveredPeerHint`] entries.
pub fn decode_mdns_response(packet: &[u8]) -> Result<Vec<DiscoveredPeerHint>, TransportError> {
    if packet.len() < 12 || packet.len() > MAX_DNS_PACKET_BYTES {
        return Err(TransportError::Discovery("invalid mDNS packet length"));
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if (flags & 0x8000) == 0 {
        return Ok(Vec::new());
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let nscount = u16::from_be_bytes([packet[8], packet[9]]);
    let additional_count = u16::from_be_bytes([packet[10], packet[11]]);

    let mut pos = 12usize;
    for _ in 0..qdcount.min(16) {
        let (_, next) = decode_dns_name(packet, pos)?;
        pos = next;
        let _ = read_u16_be(packet, &mut pos)?;
        let _ = read_u16_be(packet, &mut pos)?;
    }

    let total_rrs = usize::from(ancount)
        .saturating_add(usize::from(nscount))
        .saturating_add(usize::from(additional_count));
    if total_rrs > 64 {
        return Err(TransportError::Discovery("too many DNS RRs"));
    }

    let mut ptr_instances: BTreeSet<String> = BTreeSet::new();
    let mut srvs: BTreeMap<String, (u16, String)> = BTreeMap::new();
    let mut txts: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut host_ips: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();

    for _ in 0..total_rrs {
        let (rr_name, next) = decode_dns_name(packet, pos)?;
        pos = next;
        let rr_type = read_u16_be(packet, &mut pos)?;
        let _rr_class = read_u16_be(packet, &mut pos)?;
        if pos + 4 > packet.len() {
            return Err(TransportError::Discovery("truncated RR TTL"));
        }
        pos += 4;
        let rdlen = usize::from(read_u16_be(packet, &mut pos)?);
        let rdata_start = pos;
        let rdata_end = pos.saturating_add(rdlen);
        if rdata_end > packet.len() {
            return Err(TransportError::Discovery("truncated RR RDATA"));
        }

        match rr_type {
            TYPE_PTR if rr_name.eq_ignore_ascii_case(LUMABRIDGE_MDNS_SERVICE) => {
                let (target, _) = decode_dns_name(packet, rdata_start)?;
                ptr_instances.insert(target.to_ascii_lowercase());
            }
            TYPE_SRV if rdlen > 6 => {
                let mut sp = rdata_start + 4;
                let port = read_u16_be(packet, &mut sp)?;
                let (target, _) = decode_dns_name(packet, sp)?;
                srvs.insert(
                    rr_name.to_ascii_lowercase(),
                    (port, target.to_ascii_lowercase()),
                );
            }
            TYPE_TXT => {
                let mut kv = BTreeMap::new();
                let mut tp = rdata_start;
                while tp < rdata_end {
                    let slen = usize::from(packet[tp]);
                    tp += 1;
                    let s_end = tp.saturating_add(slen);
                    if s_end > rdata_end {
                        return Err(TransportError::Discovery("truncated TXT string"));
                    }
                    if let Ok(text) = core::str::from_utf8(&packet[tp..s_end]) {
                        if let Some((k, v)) = text.split_once('=') {
                            kv.insert(k.to_owned(), v.to_owned());
                        }
                    }
                    tp = s_end;
                }
                txts.insert(rr_name.to_ascii_lowercase(), kv);
            }
            TYPE_A if rdlen == 4 => {
                let ip = Ipv4Addr::new(
                    packet[rdata_start],
                    packet[rdata_start + 1],
                    packet[rdata_start + 2],
                    packet[rdata_start + 3],
                );
                host_ips
                    .entry(rr_name.to_ascii_lowercase())
                    .or_default()
                    .push(IpAddr::V4(ip));
            }
            _ => {}
        }
        pos = rdata_end;
    }

    let mut out = Vec::new();
    for instance in ptr_instances {
        let Some((port, target)) = srvs.get(&instance) else {
            continue;
        };
        let Some(ips) = host_ips.get(target) else {
            continue;
        };
        let kv = txts.get(&instance);
        let ver = kv
            .and_then(|m| m.get("ver"))
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(1);
        let id_hex = kv.and_then(|m| m.get("id")).cloned().unwrap_or_default();
        let name = kv
            .and_then(|m| m.get("name"))
            .cloned()
            .unwrap_or_else(|| instance.clone());
        let tcp_port = kv
            .and_then(|m| m.get("tcp"))
            .and_then(|p| p.parse::<u16>().ok());
        let addrs = ips.iter().map(|&ip| SocketAddr::new(ip, *port)).collect();
        out.push(DiscoveredPeerHint {
            instance_name: instance,
            short_device_id_hex: id_hex,
            friendly_name: name,
            addrs,
            tcp_port,
            protocol_major: ver,
        });
    }
    Ok(out)
}

/// Async LAN UDP responder handle; drops cleanly when [`Self::shutdown`] is called.
pub struct DiscoveryResponder {
    local_addr: SocketAddr,
    stop_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl DiscoveryResponder {
    /// Start an mDNS responder bound to `bind_addr` (e.g., `127.0.0.1:0` in tests or `0.0.0.0:5353` on LAN).
    pub async fn bind(
        bind_addr: SocketAddr,
        adv: DiscoveryAdvertisement,
        join_multicast: bool,
    ) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| map_io_error(&e))?;
        if join_multicast {
            socket
                .join_multicast_v4(*MDNS_MULTICAST_V4.ip(), Ipv4Addr::UNSPECIFIED)
                .map_err(|e| map_io_error(&e))?;
        }
        let local_addr = socket.local_addr().map_err(|e| map_io_error(&e))?;
        let (stop_tx, mut stop_rx) = watch::channel(false);

        let task = tokio::spawn(async move {
            let mut buf = [0u8; MAX_DNS_PACKET_BYTES];
            loop {
                tokio::select! {
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    recv = socket.recv_from(&mut buf) => {
                        let Ok((len, src)) = recv else {
                            break;
                        };
                        let pkt = &buf[..len];
                        if is_lumabridge_mdns_query(pkt) {
                            let tx_id = u16::from_be_bytes([pkt[0], pkt[1]]);
                            if let Ok(resp) = encode_mdns_response(tx_id, &adv, 120) {
                                let _ = socket.send_to(&resp, src).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            stop_tx,
            task,
        })
    }

    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(self) {
        let _ = self.stop_tx.send(true);
        let _ = self.task.await;
    }
}

/// Browse for `_lumabridge._udp.local` services against `target_addr` (multicast or loopback socket)
/// and merge optional [`ManualEndpoint`] fallbacks.
pub async fn discover_peers(
    target_addr: SocketAddr,
    timeout: Duration,
    manual_fallbacks: &[ManualEndpoint],
) -> Result<Vec<DiscoveredPeerHint>, TransportError> {
    let bind_addr: SocketAddr = if target_addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| map_io_error(&e))?;
    let query = encode_mdns_query(0x4C42)?;
    let _ = socket.send_to(&query, target_addr).await;

    let mut hints = Vec::new();
    let mut seen_instances = BTreeSet::new();
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; MAX_DNS_PACKET_BYTES];

    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remain = deadline - now;
        match tokio::time::timeout(remain, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                if let Ok(parsed) = decode_mdns_response(&buf[..len]) {
                    for h in parsed {
                        if seen_instances.insert(h.instance_name.clone()) {
                            hints.push(h);
                        }
                    }
                    if !hints.is_empty() {
                        break;
                    }
                }
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }

    for (idx, manual) in manual_fallbacks.iter().enumerate() {
        hints.push(DiscoveredPeerHint {
            instance_name: format!("manual-{idx}"),
            short_device_id_hex: String::new(),
            friendly_name: manual
                .label
                .clone()
                .unwrap_or_else(|| "manual-endpoint".to_owned()),
            addrs: vec![manual.addr],
            tcp_port: Some(manual.addr.port()),
            protocol_major: 1,
        });
    }

    Ok(hints)
}
