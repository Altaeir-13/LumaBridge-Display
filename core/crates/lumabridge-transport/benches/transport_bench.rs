// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

//! Reproducible comparative `ADR-0005` benchmark:
//! `QUIC Datagrams (RFC 9221)` vs `QUIC Streams` vs `TCP / TLS 1.3 (TCP_NODELAY)`.

use lumabridge_protocol::control::{
    CodecCapability, ControlMessage, Heartbeat, InputCapabilities, NodeCapabilities,
    OsGraphicsPlatform, Permissions, RoleFlags,
};
use lumabridge_protocol::limits::RecoveryConfig;
use lumabridge_protocol::media::fragmentation::FrameKind;
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

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio rt");

    let scenarios = [
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

    println!("| Scenario | Transport | Frame p50 (ms) | Frame p95 (ms) | Frame p99 (ms) | Ctrl p95 (ms) | Delivered | IDR Req | Goodput (Mbps) |");
    println!("|---|---|---|---|---|---|---|---|---|");
    for sc in &scenarios {
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
}
