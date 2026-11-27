// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

//! Reproducible comparative `ADR-0005` benchmark:
//! `QUIC Datagrams (RFC 9221)` vs `QUIC Streams` vs `TCP / TLS 1.3 (TCP_NODELAY)`.
//!
//! Includes:
//! 1. Historical M1.4 45-frame (< 1 Mbps) baseline scenarios (preserved for traceability).
//! 2. Expanded non-admin representative 1080p60 (~11.85 Mbps offered, 180 frames @ 60 fps)
//!    qualification differentiating Latency, Goodput, Delivery Rate, GOP Recovery, Saturation,
//!    and Environmental Conditions (explicitly flagging TCP loss comparison as
//!    `BLOCKED_BY_ENVIRONMENT` under user-space loopback proxies).

use lumabridge_protocol::control::{
    CodecCapability, ControlMessage, Heartbeat, InputCapabilities, NodeCapabilities,
    OsGraphicsPlatform, Permissions, RoleFlags,
};
use lumabridge_protocol::limits::RecoveryConfig;
use lumabridge_protocol::media::fragmentation::FrameKind;
use lumabridge_protocol::media::header::VideoFlags;
use lumabridge_protocol::version::CodecId;
use lumabridge_security::certificate::generate_self_signed_device_cert;
use lumabridge_security::identity::{IdentityKeyPair, PeerRole};
use lumabridge_security::secret::CheckedOsCryptoRng;
use lumabridge_security::tls::{TlsPeerTrustPolicy, LUMABRIDGE_ALPN_V1};
use lumabridge_security::trust_store::InMemoryTrustStore;
use lumabridge_transport::config::{TransportConfig, TransportKind};
use lumabridge_transport::connection::{
    connect_client_link, MediaRxEvent, OperationalConnection, TransportServer,
};
use lumabridge_transport::impairment::{ImpairmentProfile, TcpImpairmentProxy, UdpImpairmentProxy};
use lumabridge_transport::queue::OutboundVideoFrame;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
struct Scenario {
    name: &'static str,
    profile: ImpairmentProfile,
    frames: u32,
}

#[derive(Debug)]
struct BenchRow {
    scenario: &'static str,
    kind: TransportKind,
    frame_p50_ms: f64,
    frame_p95_ms: f64,
    frame_p99_ms: f64,
    ctrl_p95_ms: f64,
    delivered_frames: usize,
    total_frames: u32,
    idr_requests: u64,
    goodput_mbps: f64,
}

#[derive(Debug)]
struct Profile1080p60 {
    name: &'static str,
    profile: ImpairmentProfile,
    frames: u32,
    gop_interval: u32,
    idr_bytes: usize,
    p_bytes: usize,
    udp_loss_only: bool,
    env_note: &'static str,
}

#[derive(Debug)]
struct Row1080p60 {
    scenario: &'static str,
    kind: TransportKind,
    frame_p50_ms: f64,
    frame_p95_ms: f64,
    frame_p99_ms: f64,
    ctrl_p95_ms: f64,
    offered_mbps: f64,
    goodput_mbps: f64,
    delivered_frames: usize,
    total_frames: u32,
    idr_sent: u64,
    idr_requests: u64,
    gop_rec_p95_ms: Option<f64>,
    gop_rec_max_ms: Option<f64>,
    tx_drops: u64,
    rx_dep_drops: usize,
    advised_mbps: f64,
    env_note: &'static str,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn percentile(sorted: &[f64], pct: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len().saturating_sub(1)) * pct) / 100;
    sorted[idx]
}

fn percentile_opt(sorted: &[f64], pct: usize) -> Option<f64> {
    if sorted.is_empty() {
        None
    } else {
        Some(percentile(sorted, pct))
    }
}

fn caps() -> NodeCapabilities {
    NodeCapabilities {
        roles_mask: RoleFlags::CAN_RECEIVE_VIDEO.union(RoleFlags::CAN_EXTEND_SESSION),
        platform: OsGraphicsPlatform::LinuxWaylandGnome,
        codecs: vec![CodecCapability {
            codec_id: CodecId::H264,
            can_encode: true,
            can_decode: true,
            hw_accelerated: true,
            max_width: 1920,
            max_height: 1080,
            max_fps_num: 60,
            max_fps_den: 1,
            max_b_frames: 0,
        }],
        max_virtual_displays: 2,
        supports_scale: true,
        supports_rotation: true,
        input_caps_mask: InputCapabilities::POINTER,
    }
}

async fn run_one(kind: TransportKind, scenario: &Scenario) -> BenchRow {
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let s_kp = IdentityKeyPair::generate(&mut rng).expect("s");
    let r_kp = IdentityKeyPair::generate(&mut rng).expect("r");
    let now = now_unix();
    let s_cert = generate_self_signed_device_cert(&s_kp, now, now + 3600).expect("sc");
    let r_cert = generate_self_signed_device_cert(&r_kp, now, now + 3600).expect("rc");
    let s_id = s_kp.public_identity().clone();
    let r_id = r_kp.public_identity().clone();
    let r_dev_id = r_id.device_id();
    let s_store = Arc::new(InMemoryTrustStore::new());
    let r_store = Arc::new(InMemoryTrustStore::new());
    let perms = Permissions::EXTEND_DISPLAY;
    s_store
        .insert_trusted_peer_for_testing(&r_id, PeerRole::Controller, "Rx", perms, now)
        .expect("s");
    r_store
        .insert_trusted_peer_for_testing(&s_id, PeerRole::Host, "Tx", perms, now)
        .expect("r");

    let mut cfg = TransportConfig {
        kind,
        heartbeat_timeout_ms: 10_000,
        ..TransportConfig::default()
    };
    cfg.recovery_config = RecoveryConfig {
        idr_request_cooldown_us: 150_000,
        reorder_gap_timeout_us: 100_000,
        ..RecoveryConfig::default()
    };

    let srv = TransportServer::bind(
        kind,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &r_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: r_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("bind");
    let raw_addr = srv.local_addr().expect("addr");

    let use_proxy = scenario.profile != ImpairmentProfile::default();
    let mut udp_proxy = None;
    let mut tcp_proxy = None;
    let connect_addr = if use_proxy {
        match kind {
            TransportKind::QuicDatagram | TransportKind::QuicStream => {
                let p = UdpImpairmentProxy::start(raw_addr, 0x5EED_0001, scenario.profile)
                    .await
                    .expect("udp proxy");
                let a = p.listen_addr();
                udp_proxy = Some(p);
                a
            }
            TransportKind::TcpTls => {
                let p = TcpImpairmentProxy::start(raw_addr, scenario.profile)
                    .await
                    .expect("tcp proxy");
                let a = p.listen_addr();
                tcp_proxy = Some(p);
                a
            }
        }
    } else {
        raw_addr
    };

    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            kind,
            connect_addr,
            &s_cert,
            TlsPeerTrustPolicy::PinnedPeer {
                trust_store: s_store.clone(),
                expected_role: PeerRole::Controller,
                expected_device_id: r_id.device_id(),
            },
            r_id.device_id(),
            LUMABRIDGE_ALPN_V1,
            now,
            &cfg,
        ),
        srv.accept_link(LUMABRIDGE_ALPN_V1, now),
    );
    let cli_link = cli_res.expect("cli connect");
    let srv_link = srv_res.expect("accept");

    let mut cli = OperationalConnection::from_link(cli_link, cfg.clone(), true, None).expect("c");
    let mut rx = OperationalConnection::from_link(srv_link, cfg, false, None).expect("r");

    let t0 = Instant::now();
    let total_frames = scenario.frames;
    let rx_task = tokio::spawn(async move {
        rx.handshake_acceptor(r_dev_id, r_store.as_ref(), PeerRole::Host, caps())
            .await
            .expect("ha");
        rx.set_active_session(100, perms);

        let mut frame_lats_ms = Vec::new();
        let mut ctrl_lats_ms = Vec::new();
        let mut delivered_bytes = 0usize;
        let mut delivered = 0usize;
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline && delivered < (total_frames as usize) {
            if let Ok(Some(MediaRxEvent::Frame(f))) =
                rx.recv_media_event(Duration::from_millis(25)).await
            {
                let rx_us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(0);
                let lat_ms = rx_us.saturating_sub(f.encode_done_ts_us) as f64 / 1000.0;
                frame_lats_ms.push(lat_ms);
                delivered_bytes = delivered_bytes.saturating_add(f.payload.len());
                delivered += 1;
            }
            while let Ok(Ok(ControlMessage::Heartbeat(hb))) =
                tokio::time::timeout(Duration::from_millis(2), rx.recv_feedback_message()).await
            {
                let rx_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(0);
                ctrl_lats_ms.push(rx_ms.saturating_sub(hb.uptime_ms) as f64);
            }
        }
        let snap = rx.snapshot_congestion();
        (
            frame_lats_ms,
            ctrl_lats_ms,
            delivered,
            delivered_bytes,
            snap.idr_requests_emitted,
        )
    });

    cli.handshake_initiator(
        s_id.device_id(),
        s_store.as_ref(),
        PeerRole::Controller,
        "0.1.0",
        caps(),
    )
    .await
    .expect("hi");
    cli.set_active_session(100, perms);

    let wall_start = Instant::now();
    for fid in 1..=scenario.frames {
        // Closed-loop ADR-0005 recovery: poll remote MediaFeedback without blocking TX cadence.
        if let Ok(Ok(ControlMessage::MediaFeedback(fb))) =
            tokio::time::timeout(Duration::from_millis(1), cli.recv_feedback_message()).await
        {
            cli.on_remote_feedback(&fb);
        }
        let force_idr = cli.take_tx_force_idr_request() || cli.is_tx_chain_broken();
        let is_idr = fid == 1 || fid % 15 == 1 || force_idr;
        let size = if is_idr { 12_000 } else { 4_000 };
        let tx_us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(0);
        let _ = cli
            .send_video_frame(OutboundVideoFrame {
                session_id: 100,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: fid,
                gop_id: u16::try_from((fid - 1) / 15 + 1).unwrap_or(1),
                capture_ts_us: tx_us,
                encode_done_ts_us: tx_us,
                kind: if is_idr {
                    FrameKind::Keyframe { chain_reset: true }
                } else {
                    FrameKind::InterFrame
                },
                has_codec_config: is_idr,
                mirror_source: false,
                payload: vec![(fid & 0xFF) as u8; size],
            })
            .await;

        if fid % 5 == 0 {
            let tx_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(0);
            let _ = cli
                .send_feedback_message(&ControlMessage::Heartbeat(Heartbeat {
                    session_id: Some(100),
                    seq: u64::from(fid / 5),
                    uptime_ms: tx_ms,
                }))
                .await;
        }
        tokio::time::sleep(Duration::from_millis(16)).await;
    }

    let (mut frame_lats, mut ctrl_lats, delivered, delivered_bytes, idr_reqs) =
        rx_task.await.expect("rx join");
    let wall_s = wall_start.elapsed().as_secs_f64().max(0.001);
    frame_lats.sort_by(f64::total_cmp);
    ctrl_lats.sort_by(f64::total_cmp);

    if let Some(p) = udp_proxy {
        p.shutdown().await;
    }
    if let Some(p) = tcp_proxy {
        p.shutdown().await;
    }
    srv.close();

    BenchRow {
        scenario: scenario.name,
        kind,
        frame_p50_ms: percentile(&frame_lats, 50),
        frame_p95_ms: percentile(&frame_lats, 95),
        frame_p99_ms: percentile(&frame_lats, 99),
        ctrl_p95_ms: percentile(&ctrl_lats, 95),
        delivered_frames: delivered,
        total_frames: scenario.frames,
        idr_requests: idr_reqs,
        goodput_mbps: (delivered_bytes as f64 * 8.0) / (wall_s * 1_000_000.0),
    }
}

async fn pace_until(deadline: Instant) {
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let rem = deadline - now;
        if rem > Duration::from_millis(20) {
            tokio::time::sleep(rem - Duration::from_millis(16)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }
}

async fn run_1080p60(kind: TransportKind, spec: &Profile1080p60) -> Row1080p60 {
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let s_kp = IdentityKeyPair::generate(&mut rng).expect("s");
    let r_kp = IdentityKeyPair::generate(&mut rng).expect("r");
    let now = now_unix();
    let s_cert = generate_self_signed_device_cert(&s_kp, now, now + 3600).expect("sc");
    let r_cert = generate_self_signed_device_cert(&r_kp, now, now + 3600).expect("rc");
    let s_id = s_kp.public_identity().clone();
    let r_id = r_kp.public_identity().clone();
    let r_dev_id = r_id.device_id();
    let s_store = Arc::new(InMemoryTrustStore::new());
    let r_store = Arc::new(InMemoryTrustStore::new());
    let perms = Permissions::EXTEND_DISPLAY;
    s_store
        .insert_trusted_peer_for_testing(&r_id, PeerRole::Controller, "Rx", perms, now)
        .expect("s");
    r_store
        .insert_trusted_peer_for_testing(&s_id, PeerRole::Host, "Tx", perms, now)
        .expect("r");

    let mut cfg = TransportConfig {
        kind,
        heartbeat_timeout_ms: 15_000,
        initial_bitrate_bps: 15_000_000,
        min_bitrate_bps: 2_000_000,
        max_bitrate_bps: 40_000_000,
        ..TransportConfig::default()
    };
    cfg.recovery_config = RecoveryConfig {
        idr_request_cooldown_us: 150_000,
        reorder_gap_timeout_us: 100_000,
        ..RecoveryConfig::default()
    };

    let srv = TransportServer::bind(
        kind,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &r_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: r_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("bind");
    let raw_addr = srv.local_addr().expect("addr");

    let use_proxy = spec.profile != ImpairmentProfile::default();
    let mut udp_proxy = None;
    let mut tcp_proxy = None;
    let connect_addr = if use_proxy {
        match kind {
            TransportKind::QuicDatagram | TransportKind::QuicStream => {
                let p = UdpImpairmentProxy::start(raw_addr, 0x5EED_1080, spec.profile)
                    .await
                    .expect("udp proxy");
                let a = p.listen_addr();
                udp_proxy = Some(p);
                a
            }
            TransportKind::TcpTls => {
                let p = TcpImpairmentProxy::start(raw_addr, spec.profile)
                    .await
                    .expect("tcp proxy");
                let a = p.listen_addr();
                tcp_proxy = Some(p);
                a
            }
        }
    } else {
        raw_addr
    };

    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            kind,
            connect_addr,
            &s_cert,
            TlsPeerTrustPolicy::PinnedPeer {
                trust_store: s_store.clone(),
                expected_role: PeerRole::Controller,
                expected_device_id: r_id.device_id(),
            },
            r_id.device_id(),
            LUMABRIDGE_ALPN_V1,
            now,
            &cfg,
        ),
        srv.accept_link(LUMABRIDGE_ALPN_V1, now),
    );
    let cli_link = cli_res.expect("cli connect");
    let srv_link = srv_res.expect("accept");

    let mut cli = OperationalConnection::from_link(cli_link, cfg.clone(), true, None).expect("c");
    let mut rx = OperationalConnection::from_link(srv_link, cfg, false, None).expect("r");

    let t0 = Instant::now();
    let _total_frames = spec.frames;
    let rx_task = tokio::spawn(async move {
        rx.handshake_acceptor(r_dev_id, r_store.as_ref(), PeerRole::Host, caps())
            .await
            .expect("ha");
        rx.set_active_session(200, perms);

        let mut frame_lats_ms = Vec::new();
        let mut ctrl_lats_ms = Vec::new();
        let mut gop_rec_lats_ms = Vec::new();
        let mut recovery_started_at: Option<Instant> = None;
        let mut delivered_bytes = 0usize;
        let mut delivered = 0usize;
        let mut rx_dep_drops = 0usize;
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut saw_end_blank = false;

        while Instant::now() < deadline && !saw_end_blank {
            match rx.recv_media_event(Duration::from_millis(50)).await {
                Ok(Some(MediaRxEvent::Frame(f))) => {
                    let rx_us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(0);
                    let lat_ms = rx_us.saturating_sub(f.encode_done_ts_us) as f64 / 1000.0;
                    frame_lats_ms.push(lat_ms);
                    delivered_bytes = delivered_bytes.saturating_add(f.payload.len());
                    delivered += 1;
                    if f.flags.contains(VideoFlags::KEYFRAME) {
                        if let Some(rec_t0) = recovery_started_at.take() {
                            gop_rec_lats_ms.push(rec_t0.elapsed().as_secs_f64() * 1000.0);
                        }
                    }
                }
                Ok(Some(MediaRxEvent::FeedbackRequested(fb))) => {
                    if fb.request_idr && recovery_started_at.is_none() {
                        recovery_started_at = Some(Instant::now());
                    }
                }
                Ok(Some(MediaRxEvent::DroppedDependentFrames(n))) => {
                    rx_dep_drops = rx_dep_drops.saturating_add(n);
                    if recovery_started_at.is_none() {
                        recovery_started_at = Some(Instant::now());
                    }
                }
                Ok(Some(MediaRxEvent::ProtectedBlank(_))) => {
                    saw_end_blank = true;
                }
                Ok(Some(MediaRxEvent::SessionRenewalRequired)) | Ok(None) => {}
                Err(_) => break,
            }
            while let Ok(Ok(ControlMessage::Heartbeat(hb))) =
                tokio::time::timeout(Duration::ZERO, rx.recv_feedback_message()).await
            {
                let rx_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(0);
                ctrl_lats_ms.push(rx_ms.saturating_sub(hb.uptime_ms) as f64);
            }
        }

        // Drain any remaining Heartbeat latencies emitted near end-of-stream
        while let Ok(Ok(ControlMessage::Heartbeat(hb))) =
            tokio::time::timeout(Duration::from_millis(25), rx.recv_feedback_message()).await
        {
            let rx_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(0);
            ctrl_lats_ms.push(rx_ms.saturating_sub(hb.uptime_ms) as f64);
        }

        let snap = rx.snapshot_congestion();
        (
            frame_lats_ms,
            ctrl_lats_ms,
            gop_rec_lats_ms,
            delivered,
            delivered_bytes,
            snap.idr_requests_emitted,
            rx_dep_drops,
        )
    });

    cli.handshake_initiator(
        s_id.device_id(),
        s_store.as_ref(),
        PeerRole::Controller,
        "0.1.0",
        caps(),
    )
    .await
    .expect("hi");
    cli.set_active_session(200, perms);

    let wall_start = Instant::now();
    let frame_period = Duration::from_micros(16_667);
    let mut offered_bytes = 0usize;
    let mut idr_sent = 0u64;
    let mut gop_id = 1u16;

    for fid in 1..=spec.frames {
        let next_tick = wall_start + frame_period * fid;
        let force_idr = cli.take_tx_force_idr_request() || cli.is_tx_chain_broken();
        let is_idr = fid == 1 || (fid - 1) % spec.gop_interval == 0 || force_idr;
        if is_idr && fid > 1 {
            gop_id = gop_id.wrapping_add(1).max(1);
        }
        let size = if is_idr { spec.idr_bytes } else { spec.p_bytes };

        let tx_us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(0);
        if cli
            .send_video_frame(OutboundVideoFrame {
                session_id: 200,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: fid,
                gop_id,
                capture_ts_us: tx_us,
                encode_done_ts_us: tx_us,
                kind: if is_idr {
                    FrameKind::Keyframe { chain_reset: true }
                } else {
                    FrameKind::InterFrame
                },
                has_codec_config: is_idr,
                mirror_source: false,
                payload: vec![(fid & 0xFF) as u8; size],
            })
            .await
            .is_err()
        {
            break;
        }
        if is_idr {
            idr_sent += 1;
        }
        offered_bytes = offered_bytes.saturating_add(size);

        if fid % 15 == 0 {
            let tx_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(0);
            let _ = cli
                .send_feedback_message(&ControlMessage::Heartbeat(Heartbeat {
                    session_id: Some(200),
                    seq: u64::from(fid / 15),
                    uptime_ms: tx_ms,
                }))
                .await;
        }

        // Poll feedback opportunistically until next 60 Hz frame deadline without 15 ms sleep stalls.
        loop {
            let now_i = Instant::now();
            if now_i >= next_tick {
                break;
            }
            tokio::select! {
                biased;
                fb_res = cli.recv_feedback_message() => {
                    if let Ok(ControlMessage::MediaFeedback(fb)) = fb_res {
                        cli.on_remote_feedback(&fb);
                    } else if fb_res.is_err() {
                        break;
                    }
                }
                () = pace_until(next_tick) => {
                    break;
                }
            }
        }
    }

    let tx_wall_s = wall_start.elapsed().as_secs_f64().max(0.001);
    let blank_us = u64::try_from(t0.elapsed().as_micros()).unwrap_or(0);
    let _ = cli
        .send_video_frame(OutboundVideoFrame {
            session_id: 200,
            display_id: 0,
            codec_id: CodecId::H264,
            frame_id: spec.frames + 1,
            gop_id,
            capture_ts_us: blank_us,
            encode_done_ts_us: blank_us,
            kind: FrameKind::ProtectedBlank,
            has_codec_config: false,
            mirror_source: false,
            payload: Vec::new(),
        })
        .await;

    let (
        mut frame_lats,
        mut ctrl_lats,
        mut gop_rec_lats,
        delivered,
        delivered_bytes,
        idr_reqs,
        rx_dep_drops,
    ) = rx_task.await.expect("rx join");
    let total_wall_s = wall_start.elapsed().as_secs_f64().max(0.001);
    let tx_snap = cli.snapshot_congestion();

    frame_lats.sort_by(f64::total_cmp);
    ctrl_lats.sort_by(f64::total_cmp);
    gop_rec_lats.sort_by(f64::total_cmp);

    if let Some(p) = udp_proxy {
        p.shutdown().await;
    }
    if let Some(p) = tcp_proxy {
        p.shutdown().await;
    }
    srv.close();

    Row1080p60 {
        scenario: spec.name,
        kind,
        frame_p50_ms: percentile(&frame_lats, 50),
        frame_p95_ms: percentile(&frame_lats, 95),
        frame_p99_ms: percentile(&frame_lats, 99),
        ctrl_p95_ms: percentile(&ctrl_lats, 95),
        offered_mbps: (offered_bytes as f64 * 8.0) / (tx_wall_s * 1_000_000.0),
        goodput_mbps: (delivered_bytes as f64 * 8.0) / (total_wall_s * 1_000_000.0),
        delivered_frames: delivered,
        total_frames: spec.frames,
        idr_sent,
        idr_requests: idr_reqs,
        gop_rec_p95_ms: percentile_opt(&gop_rec_lats, 95),
        gop_rec_max_ms: gop_rec_lats.last().copied(),
        tx_drops: tx_snap
            .dropped_stale_frames
            .saturating_add(tx_snap.dropped_broken_gop_frames),
        rx_dep_drops,
        advised_mbps: tx_snap.pacing_rate_bps as f64 / 1_000_000.0,
        env_note: spec.env_note,
    }
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio rt");

    let historical_scenarios = [
        Scenario {
            name: "Clean-Loopback",
            profile: ImpairmentProfile::default(),
            frames: 45,
        },
        Scenario {
            name: "WiFi-Mild-0.5pct",
            profile: ImpairmentProfile {
                base_delay_ms: 8,
                jitter_ms: 4,
                drop_ppm: 5_000,
                ..ImpairmentProfile::default()
            },
            frames: 45,
        },
        Scenario {
            name: "WiFi-Harsh-2pct",
            profile: ImpairmentProfile {
                base_delay_ms: 12,
                jitter_ms: 8,
                drop_ppm: 20_000,
                reorder_ppm: 20_000,
                extra_reorder_delay_ms: 6,
                ..ImpairmentProfile::default()
            },
            frames: 45,
        },
        Scenario {
            name: "Constrained-8Mbps",
            profile: ImpairmentProfile {
                base_delay_ms: 6,
                bandwidth_cap_bps: Some(8_000_000),
                ..ImpairmentProfile::default()
            },
            frames: 45,
        },
    ];

    println!("=== Historical M1.4 45-Frame (<1 Mbps) Baseline ===");
    println!("| Scenario | Transport | Frame p50 (ms) | Frame p95 (ms) | Frame p99 (ms) | Ctrl p95 (ms) | Delivered | IDR Req | Goodput (Mbps) |");
    println!("|---|---|---|---|---|---|---|---|---|");
    for sc in &historical_scenarios {
        for kind in [
            TransportKind::QuicDatagram,
            TransportKind::QuicStream,
            TransportKind::TcpTls,
        ] {
            let row = rt.block_on(run_one(kind, sc));
            println!(
                "| {} | {:?} | {:.2} | {:.2} | {:.2} | {:.2} | {}/{} | {} | {:.2} |",
                row.scenario,
                row.kind,
                row.frame_p50_ms,
                row.frame_p95_ms,
                row.frame_p99_ms,
                row.ctrl_p95_ms,
                row.delivered_frames,
                row.total_frames,
                row.idr_requests,
                row.goodput_mbps
            );
        }
    }

    let profiles_1080p60 = [
        Profile1080p60 {
            name: "1080p60-Clean-12Mbps",
            profile: ImpairmentProfile::default(),
            frames: 180,
            gop_interval: 60,
            idr_bytes: 65_000,
            p_bytes: 24_000,
            udp_loss_only: false,
            env_note: "Loopback OS sockets, no proxy",
        },
        Profile1080p60 {
            name: "1080p60-LAN-Delay-4ms",
            profile: ImpairmentProfile {
                base_delay_ms: 4,
                jitter_ms: 1,
                ..ImpairmentProfile::default()
            },
            frames: 180,
            gop_interval: 60,
            idr_bytes: 65_000,
            p_bytes: 24_000,
            udp_loss_only: false,
            env_note: "Loopback + user-space delay/jitter proxy (no L3 loss)",
        },
        Profile1080p60 {
            name: "1080p60-Saturated-8Mbps",
            profile: ImpairmentProfile {
                base_delay_ms: 6,
                bandwidth_cap_bps: Some(8_000_000),
                ..ImpairmentProfile::default()
            },
            frames: 180,
            gop_interval: 60,
            idr_bytes: 65_000,
            p_bytes: 24_000,
            udp_loss_only: false,
            env_note: "Loopback + 8 Mbps user-space bandwidth cap (<11.85 Mbps offered)",
        },
        Profile1080p60 {
            name: "1080p60-WiFi-Mild-0.5pct-UDP",
            profile: ImpairmentProfile {
                base_delay_ms: 8,
                jitter_ms: 4,
                drop_ppm: 5_000,
                ..ImpairmentProfile::default()
            },
            frames: 180,
            gop_interval: 60,
            idr_bytes: 65_000,
            p_bytes: 24_000,
            udp_loss_only: true,
            env_note: "UDP proxy 0.5% drop; TCP L3 loss BLOCKED_BY_ENVIRONMENT",
        },
        Profile1080p60 {
            name: "1080p60-WiFi-Harsh-2pct-UDP",
            profile: ImpairmentProfile {
                base_delay_ms: 12,
                jitter_ms: 8,
                drop_ppm: 20_000,
                reorder_ppm: 20_000,
                extra_reorder_delay_ms: 6,
                ..ImpairmentProfile::default()
            },
            frames: 180,
            gop_interval: 60,
            idr_bytes: 65_000,
            p_bytes: 24_000,
            udp_loss_only: true,
            env_note: "UDP proxy 2% drop + 2% reorder; TCP L3 loss BLOCKED_BY_ENVIRONMENT",
        },
    ];

    println!();
    println!("=== Expanded Non-Admin 1080p60 Qualification (~11.85 Mbps, 180 frames @ 60 fps) ===");
    println!("| Scenario | Transport | Frame p50/p95/p99 (ms) | Ctrl p95 (ms) | Offered/Goodput (Mbps) | Delivery | GOP Rec (idr_req/sent, p95/max ms) | Saturation (tx_drop/rx_dep/advised_Mbps) | Environment |");
    println!("|---|---|---|---|---|---|---|---|---|");
    for sc in &profiles_1080p60 {
        for kind in [
            TransportKind::QuicDatagram,
            TransportKind::QuicStream,
            TransportKind::TcpTls,
        ] {
            if sc.udp_loss_only && kind == TransportKind::TcpTls {
                println!(
                    "| {} | TcpTls | BLOCKED_BY_ENVIRONMENT | — | — | — | — | — | User-space TcpImpairmentProxy lacks L3 segment loss (requires Linux tc netem) |",
                    sc.name
                );
                continue;
            }
            let r = rt.block_on(run_1080p60(kind, sc));
            let del_pct = (r.delivered_frames as f64 / f64::from(r.total_frames)) * 100.0;
            let gop_rec_str = match (r.gop_rec_p95_ms, r.gop_rec_max_ms) {
                (Some(p95), Some(max)) => format!("{p95:.2}/{max:.2}"),
                _ => "—".to_owned(),
            };
            println!(
                "| {} | {:?} | {:.2}/{:.2}/{:.2} | {:.2} | {:.2}/{:.2} | {}/{} ({:.1}%) | {}/{}, {} | {}/{}/{:.2} | {} |",
                r.scenario,
                r.kind,
                r.frame_p50_ms,
                r.frame_p95_ms,
                r.frame_p99_ms,
                r.ctrl_p95_ms,
                r.offered_mbps,
                r.goodput_mbps,
                r.delivered_frames,
                r.total_frames,
                del_pct,
                r.idr_requests,
                r.idr_sent,
                gop_rec_str,
                r.tx_drops,
                r.rx_dep_drops,
                r.advised_mbps,
                r.env_note
            );
        }
    }
}
