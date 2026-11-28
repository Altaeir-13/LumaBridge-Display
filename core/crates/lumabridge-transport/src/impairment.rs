// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Deterministic seeded network impairment proxies (delay, jitter, loss, duplication,
//! reordering, dynamic bandwidth caps, and link cuts) over real loopback OS sockets.

use crate::error::{map_io_error, TransportError};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Duration;

/// Deterministic splitmix64 PRNG so impairment scenarios are 100% reproducible.
#[derive(Debug, Clone)]
pub struct SeededPrng(u64);

impl SeededPrng {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn hit_ppm(&mut self, ppm: u32) -> bool {
        if ppm == 0 {
            return false;
        }
        if ppm >= 1_000_000 {
            return true;
        }
        (self.next_u64() % 1_000_000) < u64::from(ppm)
    }

    pub fn range_u64(&mut self, max_inclusive: u64) -> u64 {
        if max_inclusive == 0 {
            return 0;
        }
        self.next_u64() % (max_inclusive + 1)
    }
}

/// Dynamically updatable network impairment profile applied in-flight by loopback proxies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImpairmentProfile {
    pub base_delay_ms: u64,
    pub jitter_ms: u64,
    pub drop_ppm: u32,
    pub duplicate_ppm: u32,
    pub reorder_ppm: u32,
    pub extra_reorder_delay_ms: u64,
    pub bandwidth_cap_bps: Option<u64>,
    pub link_cut: bool,
    /// Optional filter to drop ONLY QUIC 1-RTT short-header datagram-sized media packets or all non-initial UDP packets (`min_drop_bytes`).
    pub min_drop_payload_bytes: usize,
}

#[derive(Eq, PartialEq)]
struct ScheduledUdpPacket {
    deliver_at: tokio::time::Instant,
    seq: u64,
    pkt: Vec<u8>,
    dup: bool,
}

impl Ord for ScheduledUdpPacket {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deliver_at
            .cmp(&other.deliver_at)
            .then_with(|| self.seq.cmp(&other.seq))
    }
}

impl PartialOrd for ScheduledUdpPacket {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    if let Some(t) = deadline {
        tokio::time::sleep_until(t).await;
    } else {
        std::future::pending::<()>().await;
    }
}

/// Real loopback UDP forwarding proxy simulating LAN/Wi-Fi impairments for QUIC tests & benchmarks.
pub struct UdpImpairmentProxy {
    listen_addr: SocketAddr,
    profile: Arc<RwLock<ImpairmentProfile>>,
    stop_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl UdpImpairmentProxy {
    /// Start an impairment proxy forwarding between `127.0.0.1:0` and `upstream`.
    #[allow(clippy::too_many_lines)]
    pub async fn start(
        upstream: SocketAddr,
        seed: u64,
        initial: ImpairmentProfile,
    ) -> Result<Self, TransportError> {
        let client_facing = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|e| map_io_error(&e))?;
        let upstream_facing = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|e| map_io_error(&e))?;
        upstream_facing
            .connect(upstream)
            .await
            .map_err(|e| map_io_error(&e))?;

        let listen_addr = client_facing.local_addr().map_err(|e| map_io_error(&e))?;
        let profile = Arc::new(RwLock::new(initial));
        let profile_c = Arc::clone(&profile);
        let (stop_tx, mut stop_rx) = watch::channel(false);

        let client_sock = Arc::new(client_facing);
        let upstream_sock = Arc::new(upstream_facing);

        let task = tokio::spawn(async move {
            let mut prng = SeededPrng::new(seed);
            let mut last_client: Option<SocketAddr> = None;
            let mut buf_c = vec![0u8; 65_536];
            let mut buf_u = vec![0u8; 65_536];
            let mut next_free_tx_up = tokio::time::Instant::now();
            let mut next_free_tx_down = tokio::time::Instant::now();
            let mut last_scheduled_up = next_free_tx_up;
            let mut last_scheduled_down = next_free_tx_down;
            let mut up_seq = 0u64;
            let mut down_seq = 0u64;
            let mut up_heap: BinaryHeap<Reverse<ScheduledUdpPacket>> = BinaryHeap::new();
            let mut down_heap: BinaryHeap<Reverse<ScheduledUdpPacket>> = BinaryHeap::new();

            loop {
                let next_deadline = match (up_heap.peek(), down_heap.peek()) {
                    (Some(u), Some(d)) => Some(u.0.deliver_at.min(d.0.deliver_at)),
                    (Some(u), None) => Some(u.0.deliver_at),
                    (None, Some(d)) => Some(d.0.deliver_at),
                    (None, None) => None,
                };
                tokio::select! {
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    () = sleep_until_opt(next_deadline), if next_deadline.is_some() => {
                        let now = tokio::time::Instant::now();
                        while let Some(head) = up_heap.peek() {
                            if head.0.deliver_at > now {
                                break;
                            }
                            if let Some(Reverse(item)) = up_heap.pop() {
                                let _ = upstream_sock.send(&item.pkt).await;
                                if item.dup {
                                    let _ = upstream_sock.send(&item.pkt).await;
                                }
                            }
                        }
                        while let Some(head) = down_heap.peek() {
                            if head.0.deliver_at > now {
                                break;
                            }
                            if let Some(Reverse(item)) = down_heap.pop() {
                                if let Some(dest) = last_client {
                                    let _ = client_sock.send_to(&item.pkt, dest).await;
                                    if item.dup {
                                        let _ = client_sock.send_to(&item.pkt, dest).await;
                                    }
                                }
                            }
                        }
                    }
                    res = client_sock.recv_from(&mut buf_c) => {
                        let Ok((len, src)) = res else {
                            break;
                        };
                        last_client = Some(src);
                        let prof = profile_c.read().map_or_else(|_| ImpairmentProfile::default(), |p| *p);
                        if prof.link_cut {
                            continue;
                        }
                        if len >= prof.min_drop_payload_bytes && prng.hit_ppm(prof.drop_ppm) {
                            continue;
                        }
                        let pkt = buf_c[..len].to_vec();
                        let delay_ms = compute_delay_and_pace(&mut prng, prof, len, &mut next_free_tx_up);
                        let dup = prng.hit_ppm(prof.duplicate_ppm);
                        if up_heap.is_empty() && delay_ms == 0 && !dup {
                            let _ = upstream_sock.send(&pkt).await;
                        } else {
                            let mut deliver_at = tokio::time::Instant::now() + Duration::from_millis(delay_ms);
                            if prof.reorder_ppm == 0 {
                                deliver_at = deliver_at.max(last_scheduled_up);
                                last_scheduled_up = deliver_at;
                            }
                            up_seq = up_seq.wrapping_add(1);
                            up_heap.push(Reverse(ScheduledUdpPacket {
                                deliver_at,
                                seq: up_seq,
                                pkt,
                                dup,
                            }));
                        }
                    }
                    res = upstream_sock.recv(&mut buf_u) => {
                        let Ok(len) = res else {
                            break;
                        };
                        let Some(dest) = last_client else {
                            continue;
                        };
                        let prof = profile_c.read().map_or_else(|_| ImpairmentProfile::default(), |p| *p);
                        if prof.link_cut {
                            continue;
                        }
                        if len >= prof.min_drop_payload_bytes && prng.hit_ppm(prof.drop_ppm) {
                            continue;
                        }
                        let pkt = buf_u[..len].to_vec();
                        let delay_ms = compute_delay_and_pace(&mut prng, prof, len, &mut next_free_tx_down);
                        let dup = prng.hit_ppm(prof.duplicate_ppm);
                        if down_heap.is_empty() && delay_ms == 0 && !dup {
                            let _ = client_sock.send_to(&pkt, dest).await;
                        } else {
                            let mut deliver_at = tokio::time::Instant::now() + Duration::from_millis(delay_ms);
                            if prof.reorder_ppm == 0 {
                                deliver_at = deliver_at.max(last_scheduled_down);
                                last_scheduled_down = deliver_at;
                            }
                            down_seq = down_seq.wrapping_add(1);
                            down_heap.push(Reverse(ScheduledUdpPacket {
                                deliver_at,
                                seq: down_seq,
                                pkt,
                                dup,
                            }));
                        }
                    }
                }
            }
        });

        Ok(Self {
            listen_addr,
            profile,
            stop_tx,
            task,
        })
    }

    #[must_use]
    pub const fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn set_profile(&self, next: ImpairmentProfile) {
        if let Ok(mut guard) = self.profile.write() {
            *guard = next;
        }
    }

    pub async fn shutdown(self) {
        let _ = self.stop_tx.send(true);
        let _ = self.task.await;
    }
}

fn compute_delay_and_pace(
    prng: &mut SeededPrng,
    prof: ImpairmentProfile,
    len: usize,
    next_free_tx: &mut tokio::time::Instant,
) -> u64 {
    let mut delay = prof.base_delay_ms + prng.range_u64(prof.jitter_ms);
    if prng.hit_ppm(prof.reorder_ppm) {
        delay += prof.extra_reorder_delay_ms.max(5);
    }
    if let Some(bps) = prof.bandwidth_cap_bps {
        let wire_bits = (len as u64).saturating_mul(8);
        let ser_us = wire_bits.saturating_mul(1_000_000) / bps.max(1_000);
        let now = tokio::time::Instant::now();
        if *next_free_tx < now {
            *next_free_tx = now;
        }
        *next_free_tx += Duration::from_micros(ser_us);
        let q_ms = u64::try_from((*next_free_tx - now).as_millis()).unwrap_or(1_000);
        delay = delay.saturating_add(q_ms.min(500));
    }
    delay
}

/// Real loopback TCP forwarding proxy adding controlled delay and dynamic bandwidth throttling.
pub struct TcpImpairmentProxy {
    listen_addr: SocketAddr,
    profile: Arc<RwLock<ImpairmentProfile>>,
    stop_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl TcpImpairmentProxy {
    pub async fn start(
        upstream: SocketAddr,
        initial: ImpairmentProfile,
    ) -> Result<Self, TransportError> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|e| map_io_error(&e))?;
        let listen_addr = listener.local_addr().map_err(|e| map_io_error(&e))?;
        let profile = Arc::new(RwLock::new(initial));
        let profile_c = Arc::clone(&profile);
        let (stop_tx, mut stop_rx) = watch::channel(false);

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((client, _)) = accepted else {
                            break;
                        };
                        let Ok(server) = TcpStream::connect(upstream).await else {
                            continue;
                        };
                        let _ = client.set_nodelay(true);
                        let _ = server.set_nodelay(true);
                        let (cr, cw) = client.into_split();
                        let (sr, sw) = server.into_split();
                        let p1 = Arc::clone(&profile_c);
                        let p2 = Arc::clone(&profile_c);
                        tokio::spawn(relay_tcp_half(cr, sw, p1));
                        tokio::spawn(relay_tcp_half(sr, cw, p2));
                    }
                }
            }
        });

        Ok(Self {
            listen_addr,
            profile,
            stop_tx,
            task,
        })
    }

    #[must_use]
    pub const fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn set_profile(&self, next: ImpairmentProfile) {
        if let Ok(mut guard) = self.profile.write() {
            *guard = next;
        }
    }

    pub async fn shutdown(self) {
        let _ = self.stop_tx.send(true);
        let _ = self.task.await;
    }
}

async fn relay_tcp_half(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    profile: Arc<RwLock<ImpairmentProfile>>,
) {
    let mut buf = vec![0u8; 16_384];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let prof = profile
                    .read()
                    .map_or_else(|_| ImpairmentProfile::default(), |p| *p);
                if prof.link_cut {
                    break;
                }
                let mut delay_ms = prof.base_delay_ms;
                if let Some(bps) = prof.bandwidth_cap_bps {
                    let ser_ms = (n as u64).saturating_mul(8).saturating_mul(1000) / bps.max(1_000);
                    delay_ms = delay_ms.saturating_add(ser_ms);
                }
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                if writer.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = writer.shutdown().await;
}
