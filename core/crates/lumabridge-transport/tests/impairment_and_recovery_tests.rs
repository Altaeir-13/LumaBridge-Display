// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]

use lumabridge_protocol::control::{
    CodecCapability, ControlMessage, InputCapabilities, NodeCapabilities, OsGraphicsPlatform,
    Permissions, RoleFlags,
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
use lumabridge_transport::queue::{MediaTxScheduler, OutboundVideoFrame};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn caps() -> NodeCapabilities {
    NodeCapabilities {
        roles_mask: RoleFlags::CAN_RECEIVE_VIDEO.union(RoleFlags::CAN_EXTEND_SESSION),
        platform: OsGraphicsPlatform::LinuxWaylandGnome,
        codecs: vec![CodecCapability {
            codec_id: CodecId::H264,
            can_encode: false,
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

#[tokio::test]
async fn quic_under_loss_jitter_reorder_triggers_awaiting_idr_and_recovers_cleanly() {
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let s_kp = IdentityKeyPair::generate(&mut rng).expect("skp");
    let r_kp = IdentityKeyPair::generate(&mut rng).expect("rkp");
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
        kind: TransportKind::QuicDatagram,
        heartbeat_timeout_ms: 8_000,
        ..TransportConfig::default()
    };
    cfg.reassembly_config.fragment_timeout_us = 150_000;
    cfg.recovery_config = RecoveryConfig {
        idr_request_cooldown_us: 150_000,
        reorder_gap_timeout_us: 150_000,
        max_reorder_completed_frames: 2,
        ..RecoveryConfig::default()
    };

    let srv = TransportServer::bind(
        TransportKind::QuicDatagram,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &r_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: r_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("srv");
    let proxy = UdpImpairmentProxy::start(
        srv.local_addr().expect("addr"),
        0x1234_5678,
        ImpairmentProfile {
            base_delay_ms: 8,
            jitter_ms: 6,
            drop_ppm: 80_000,
            duplicate_ppm: 50_000,
            reorder_ppm: 80_000,
            extra_reorder_delay_ms: 12,
            bandwidth_cap_bps: None,
            link_cut: false,
            min_drop_payload_bytes: 0,
        },
    )
    .await
    .expect("proxy");

    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            TransportKind::QuicDatagram,
            proxy.listen_addr(),
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
    let cli_link = cli_res.expect("connect");
    let srv_link = srv_res.expect("acc");

    let mut cli = OperationalConnection::from_link(cli_link, cfg.clone(), true, None).expect("cc");
    let mut rx = OperationalConnection::from_link(srv_link, cfg, false, None).expect("sc");

    let session_ready = Arc::new(tokio::sync::Notify::new());
    let session_ready_rx = Arc::clone(&session_ready);
    let recovered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let recovered_rx = Arc::clone(&recovered);

    let rx_task = tokio::spawn(async move {
        rx.handshake_acceptor(r_dev_id, r_store.as_ref(), PeerRole::Host, caps())
            .await
            .expect("ha");
        rx.set_active_session(404, perms);
        session_ready_rx.notify_one();

        let mut delivered_ids = Vec::new();
        let mut saw_recovery_idr = false;
        let mut saw_feedback_requested = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Some(ev)) = rx.recv_media_event(Duration::from_millis(80)).await {
                match ev {
                    MediaRxEvent::Frame(f) => {
                        if let Some(&prev) = delivered_ids.last() {
                            assert!(f.frame_id > prev);
                        }
                        if f.gop_id >= 2
                            && f.flags
                                .contains(lumabridge_protocol::media::header::VideoFlags::KEYFRAME)
                        {
                            saw_recovery_idr = true;
                        }
                        delivered_ids.push(f.frame_id);
                        if saw_recovery_idr
                            && (saw_feedback_requested
                                || rx.snapshot_congestion().idr_requests_emitted > 0)
                            && delivered_ids.len() >= 3
                        {
                            recovered_rx.store(true, std::sync::atomic::Ordering::Release);
                            break;
                        }
                    }
                    MediaRxEvent::FeedbackRequested(fb) => {
                        assert!(fb.request_idr);
                        saw_feedback_requested = true;
                    }
                    MediaRxEvent::DroppedDependentFrames(_)
                    | MediaRxEvent::ProtectedBlank(_)
                    | MediaRxEvent::SessionRenewalRequired => {}
                }
            }
        }
        assert!(
            saw_recovery_idr,
            "must recover cleanly on fresh IDR under 8% UDP loss"
        );
        assert!(
            saw_feedback_requested || rx.snapshot_congestion().idr_requests_emitted > 0,
            "receiver must detect GOP loss and emit FeedbackRequested"
        );
        rx
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
    cli.set_active_session(404, perms);
    session_ready.notified().await;

    for fid in 1u32..=12 {
        let is_idr = fid == 1;
        let _ = cli
            .send_video_frame(OutboundVideoFrame {
                session_id: 404,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: fid,
                gop_id: 1,
                capture_ts_us: u64::from(fid) * 16_000,
                encode_done_ts_us: u64::from(fid) * 16_000 + 1_000,
                kind: if is_idr {
                    FrameKind::Keyframe { chain_reset: true }
                } else {
                    FrameKind::InterFrame
                },
                has_codec_config: is_idr,
                mirror_source: false,
                payload: vec![fid as u8; 4_800],
            })
            .await;
        tokio::time::sleep(Duration::from_millis(12)).await;
    }

    // Allow receiver fragment/reorder timers to flush GOP 1 loss into AwaitingIdr before recovery IDRs.
    tokio::time::sleep(Duration::from_millis(180)).await;

    let mut gop2_fid = 13u32;
    for recovery_attempt in 0u16..10 {
        if recovered.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        let gop_id = 2 + recovery_attempt;
        let _ = cli
            .send_video_frame(OutboundVideoFrame {
                session_id: 404,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: gop2_fid,
                gop_id,
                capture_ts_us: u64::from(gop2_fid) * 16_000,
                encode_done_ts_us: u64::from(gop2_fid) * 16_000 + 1_000,
                kind: FrameKind::Keyframe { chain_reset: true },
                has_codec_config: true,
                mirror_source: false,
                payload: vec![0x77u8; 3_000],
            })
            .await;
        gop2_fid += 1;
        for _ in 0..3 {
            if recovered.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            let _ = cli
                .send_video_frame(OutboundVideoFrame {
                    session_id: 404,
                    display_id: 0,
                    codec_id: CodecId::H264,
                    frame_id: gop2_fid,
                    gop_id,
                    capture_ts_us: u64::from(gop2_fid) * 16_000,
                    encode_done_ts_us: u64::from(gop2_fid) * 16_000 + 1_000,
                    kind: FrameKind::InterFrame,
                    has_codec_config: false,
                    mirror_source: false,
                    payload: vec![0x55u8; 2_200],
                })
                .await;
            gop2_fid += 1;
            tokio::time::sleep(Duration::from_millis(18)).await;
        }
    }

    let rx_done = rx_task.await.expect("rx");
    drop(rx_done);
    proxy.shutdown().await;
    srv.close();
}

#[tokio::test]
async fn reliable_protected_blank_precedes_and_suppresses_stale_p_frames_under_loss() {
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let s_kp = IdentityKeyPair::generate(&mut rng).expect("skp");
    let r_kp = IdentityKeyPair::generate(&mut rng).expect("rkp");
    let now = now_unix();
    let s_cert = generate_self_signed_device_cert(&s_kp, now, now + 3600).expect("sc");
    let r_cert = generate_self_signed_device_cert(&r_kp, now, now + 3600).expect("rc");
    let s_id = s_kp.public_identity().clone();
    let r_id = r_kp.public_identity().clone();
    let s_dev_id = s_id.device_id();

    let s_store = Arc::new(InMemoryTrustStore::new());
    let r_store = Arc::new(InMemoryTrustStore::new());
    let perms = Permissions::EXTEND_DISPLAY;
    s_store
        .insert_trusted_peer_for_testing(&r_id, PeerRole::Controller, "Rx", perms, now)
        .expect("s");
    r_store
        .insert_trusted_peer_for_testing(&s_id, PeerRole::Host, "Tx", perms, now)
        .expect("r");

    let cfg = TransportConfig {
        kind: TransportKind::QuicDatagram,
        ..TransportConfig::default()
    };

    let srv = TransportServer::bind(
        TransportKind::QuicDatagram,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &r_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: r_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("srv");
    let proxy = UdpImpairmentProxy::start(
        srv.local_addr().expect("addr"),
        0xCAFE_BABE,
        ImpairmentProfile {
            base_delay_ms: 5,
            jitter_ms: 20,
            drop_ppm: 200_000,
            duplicate_ppm: 0,
            reorder_ppm: 100_000,
            extra_reorder_delay_ms: 15,
            bandwidth_cap_bps: None,
            link_cut: false,
            min_drop_payload_bytes: 0,
        },
    )
    .await
    .expect("proxy");

    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            TransportKind::QuicDatagram,
            proxy.listen_addr(),
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
    let cli_link = cli_res.expect("connect");
    let srv_link = srv_res.expect("acc");

    let mut cli = OperationalConnection::from_link(cli_link, cfg.clone(), true, None).expect("cc");
    let mut rx = OperationalConnection::from_link(srv_link, cfg, false, None).expect("sc");

    let blank_done = Arc::new(tokio::sync::Notify::new());
    let blank_done_tx = Arc::clone(&blank_done);
    let t = tokio::spawn(async move {
        cli.handshake_initiator(
            s_dev_id,
            s_store.as_ref(),
            PeerRole::Controller,
            "0.1.0",
            caps(),
        )
        .await
        .expect("hi");
        cli.set_active_session(88, perms);
        let _ = cli
            .send_video_frame(OutboundVideoFrame {
                session_id: 88,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: 1,
                gop_id: 1,
                capture_ts_us: 1000,
                encode_done_ts_us: 1200,
                kind: FrameKind::Keyframe { chain_reset: true },
                has_codec_config: true,
                mirror_source: false,
                payload: vec![0xAA; 1024],
            })
            .await;
        let _ = cli
            .send_video_frame(OutboundVideoFrame {
                session_id: 88,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: 2,
                gop_id: 1,
                capture_ts_us: 2000,
                encode_done_ts_us: 2200,
                kind: FrameKind::ProtectedBlank,
                has_codec_config: false,
                mirror_source: false,
                payload: Vec::new(),
            })
            .await;
        let sup = cli
            .send_video_frame(OutboundVideoFrame {
                session_id: 88,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: 3,
                gop_id: 1,
                capture_ts_us: 3000,
                encode_done_ts_us: 3200,
                kind: FrameKind::InterFrame,
                has_codec_config: false,
                mirror_source: false,
                payload: vec![0xBB; 1024],
            })
            .await
            .expect("sup");
        assert!(!sup.admitted);
        assert_eq!(sup.dropped_broken_gop_frames, 1);
        let _ = tokio::time::timeout(Duration::from_secs(5), blank_done_tx.notified()).await;
    });

    rx.handshake_acceptor(r_id.device_id(), r_store.as_ref(), PeerRole::Host, caps())
        .await
        .expect("ha");
    rx.set_active_session(88, perms);

    let mut saw_blank = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(ev)) = rx.recv_media_event(Duration::from_millis(80)).await {
            match ev {
                MediaRxEvent::ProtectedBlank(b) => {
                    assert_eq!(b.frame_id, 2);
                    saw_blank = true;
                    break;
                }
                MediaRxEvent::Frame(f) => {
                    assert!(
                        f.frame_id < 2,
                        "stale/later P-frame cannot follow blank without IDR"
                    );
                }
                _ => {}
            }
        }
    }
    assert!(
        saw_blank,
        "ProtectedBlank MUST arrive reliably under heavy datagram loss"
    );
    blank_done.notify_one();
    t.await.expect("join");
    proxy.shutdown().await;
    srv.close();
}

#[tokio::test]
async fn tx_scheduler_saturation_and_tcp_capacity_change_preserve_control_and_gop_safety() {
    let mut sched = MediaTxScheduler::new(2, 16_384).expect("sched");
    let idr = sched.enqueue(OutboundVideoFrame {
        session_id: 1,
        display_id: 0,
        codec_id: CodecId::H264,
        frame_id: 1,
        gop_id: 10,
        capture_ts_us: 1,
        encode_done_ts_us: 2,
        kind: FrameKind::Keyframe { chain_reset: true },
        has_codec_config: true,
        mirror_source: false,
        payload: vec![1u8; 8_000],
    });
    assert!(idr.admitted);
    let p1 = sched.enqueue(OutboundVideoFrame {
        session_id: 1,
        display_id: 0,
        codec_id: CodecId::H264,
        frame_id: 2,
        gop_id: 10,
        capture_ts_us: 3,
        encode_done_ts_us: 4,
        kind: FrameKind::InterFrame,
        has_codec_config: false,
        mirror_source: false,
        payload: vec![2u8; 4_000],
    });
    assert!(p1.admitted);
    let p2 = sched.enqueue(OutboundVideoFrame {
        session_id: 1,
        display_id: 0,
        codec_id: CodecId::H264,
        frame_id: 3,
        gop_id: 10,
        capture_ts_us: 5,
        encode_done_ts_us: 6,
        kind: FrameKind::InterFrame,
        has_codec_config: false,
        mirror_source: false,
        payload: vec![3u8; 4_000],
    });
    assert!(!p2.admitted);
    assert!(p2.force_idr_required);
    assert!(sched.is_chain_broken());
    assert!(sched.take_force_idr_request());

    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let s_kp = IdentityKeyPair::generate(&mut rng).expect("skp");
    let r_kp = IdentityKeyPair::generate(&mut rng).expect("rkp");
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

    let cfg = TransportConfig {
        kind: TransportKind::TcpTls,
        max_media_queue_frames: 4,
        ..TransportConfig::default()
    };
    let srv = TransportServer::bind(
        TransportKind::TcpTls,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &r_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: r_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("srv");
    let proxy = TcpImpairmentProxy::start(
        srv.local_addr().expect("addr"),
        ImpairmentProfile {
            base_delay_ms: 4,
            bandwidth_cap_bps: Some(150_000),
            ..ImpairmentProfile::default()
        },
    )
    .await
    .expect("tcp proxy");

    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            TransportKind::TcpTls,
            proxy.listen_addr(),
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
    let cli_link = cli_res.expect("connect");
    let srv_link = srv_res.expect("acc");

    let mut cli = OperationalConnection::from_link(cli_link, cfg.clone(), true, None).expect("c");
    let mut rx = OperationalConnection::from_link(srv_link, cfg, false, None).expect("r");

    let r_task = tokio::spawn(async move {
        rx.handshake_acceptor(r_dev_id, r_store.as_ref(), PeerRole::Host, caps())
            .await
            .expect("ha");
        rx.set_active_session(55, perms);
        let msg = rx.recv_control_message().await.expect("ctrl");
        assert!(matches!(msg, ControlMessage::SessionClose(_)));
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
    cli.set_active_session(55, perms);

    // Saturate TCP+TLS media queue under tight pacing and verify bounded drop + broken-chain flag
    // while Channel 0 Control delivery (`SessionClose`) remains completely unblocked.
    let mut saw_saturation_drop = false;
    for fid in 1u32..=128 {
        let res = cli
            .send_video_frame(OutboundVideoFrame {
                session_id: 55,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: fid,
                gop_id: 1,
                capture_ts_us: u64::from(fid) * 16_000,
                encode_done_ts_us: u64::from(fid) * 16_000 + 500,
                kind: if fid == 1 {
                    FrameKind::Keyframe { chain_reset: true }
                } else {
                    FrameKind::InterFrame
                },
                has_codec_config: fid == 1,
                mirror_source: false,
                payload: vec![0x33u8; 32_768],
            })
            .await;
        match res {
            Ok(outcome) if outcome.force_idr_required || outcome.dropped_stale_frames > 0 => {
                saw_saturation_drop = true;
                break;
            }
            Err(lumabridge_transport::error::TransportError::QueueFull(_)) => {
                saw_saturation_drop = true;
                break;
            }
            _ => {}
        }
    }
    assert!(
        saw_saturation_drop || cli.snapshot_congestion().dropped_stale_frames > 0,
        "TCP+TLS media queue must drop cleanly under severe bandwidth cap"
    );

    proxy.set_profile(ImpairmentProfile {
        base_delay_ms: 1,
        bandwidth_cap_bps: Some(12_000_000),
        ..ImpairmentProfile::default()
    });
    cli.send_control_message(&ControlMessage::SessionClose(
        lumabridge_protocol::control::SessionClose {
            session_id: 55,
            reason_code: lumabridge_protocol::control::CloseReasonCode::UserRequested,
            teardown_virtual_displays: false,
        },
    ))
    .await
    .expect("send close");

    r_task.await.expect("r join");
    proxy.shutdown().await;
    srv.close();
}

#[tokio::test]
async fn udp_proxy_preserves_fifo_order_without_reorder_or_jitter() {
    let rx_sock = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind rx");
    let rx_addr = rx_sock.local_addr().expect("rx addr");
    let proxy = UdpImpairmentProxy::start(
        rx_addr,
        0xF1F0,
        ImpairmentProfile {
            base_delay_ms: 4,
            jitter_ms: 0,
            reorder_ppm: 0,
            ..ImpairmentProfile::default()
        },
    )
    .await
    .expect("start proxy");

    let tx_sock = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind tx");
    tx_sock.connect(proxy.listen_addr()).await.expect("connect");

    let count = 32u32;
    for seq in 0..count {
        let mut buf = [0u8; 64];
        buf[..4].copy_from_slice(&seq.to_be_bytes());
        tx_sock.send(&buf).await.expect("send");
    }

    let mut received = Vec::with_capacity(count as usize);
    let mut rbuf = [0u8; 128];
    for _ in 0..count {
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), rx_sock.recv_from(&mut rbuf))
            .await
            .expect("recv timeout")
            .expect("recv");
        assert_eq!(n, 64);
        received.push(u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]));
    }
    let expected: Vec<u32> = (0..count).collect();
    assert_eq!(
        received, expected,
        "UdpImpairmentProxy must preserve strict FIFO order when jitter_ms=0 and reorder_ppm=0"
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn quic_datagram_delivers_large_idr_under_delay_jitter_without_self_expiring() {
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let s_kp = IdentityKeyPair::generate(&mut rng).expect("skp");
    let r_kp = IdentityKeyPair::generate(&mut rng).expect("rkp");
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

    let cfg = TransportConfig {
        kind: TransportKind::QuicDatagram,
        heartbeat_timeout_ms: 8_000,
        min_bitrate_bps: 2_000_000,
        initial_bitrate_bps: 15_000_000,
        max_bitrate_bps: 40_000_000,
        ..TransportConfig::default()
    };
    let srv = TransportServer::bind(
        TransportKind::QuicDatagram,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &r_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: r_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("srv");
    let proxy = UdpImpairmentProxy::start(
        srv.local_addr().expect("addr"),
        0x1080_65A0,
        ImpairmentProfile {
            base_delay_ms: 4,
            jitter_ms: 1,
            ..ImpairmentProfile::default()
        },
    )
    .await
    .expect("proxy");

    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            TransportKind::QuicDatagram,
            proxy.listen_addr(),
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
    let mut cli = OperationalConnection::from_link(cli_res.expect("cli"), cfg.clone(), true, None)
        .expect("c");
    let mut rx =
        OperationalConnection::from_link(srv_res.expect("srv"), cfg, false, None).expect("r");

    let rx_task = tokio::spawn(async move {
        rx.handshake_acceptor(r_dev_id, r_store.as_ref(), PeerRole::Host, caps())
            .await
            .expect("ha");
        rx.set_active_session(77, perms);
        let mut delivered = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
        while delivered < 4 && tokio::time::Instant::now() < deadline {
            if let Ok(Some(MediaRxEvent::Frame(_))) =
                rx.recv_media_event(Duration::from_millis(50)).await
            {
                delivered += 1;
            }
        }
        delivered
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
    cli.set_active_session(77, perms);

    for fid in 1u32..=4 {
        let is_idr = fid == 1;
        cli.send_video_frame(OutboundVideoFrame {
            session_id: 77,
            display_id: 0,
            codec_id: CodecId::H264,
            frame_id: fid,
            gop_id: 1,
            capture_ts_us: u64::from(fid) * 16_667,
            encode_done_ts_us: u64::from(fid) * 16_667,
            kind: if is_idr {
                FrameKind::Keyframe { chain_reset: true }
            } else {
                FrameKind::InterFrame
            },
            has_codec_config: is_idr,
            mirror_source: false,
            payload: vec![0xAB; if is_idr { 65_000 } else { 24_000 }],
        })
        .await
        .expect("send");
    }

    let delivered = rx_task.await.expect("rx join");
    assert_eq!(
        delivered, 4,
        "65 KB IDR + P-frames must deliver intact under 4ms delay / 1ms jitter without self-expiring"
    );
    proxy.shutdown().await;
    srv.close();
}

#[test]
fn windowed_loss_allows_bitrate_advisor_recovery_after_transient_loss() {
    use lumabridge_transport::metrics::{BitrateAdvisor, CongestionSnapshot};

    let mut advisor = BitrateAdvisor::new(2_000_000, 15_000_000, 40_000_000);
    // Transient 2% loss interval drops advised bitrate.
    let drop_snap = CongestionSnapshot {
        packet_loss_ppm: 25_000,
        rtt_us: 20_000,
        tx_queue_frames: 0,
        ..CongestionSnapshot::default()
    };
    let reduced = advisor
        .update(&drop_snap, 100_000)
        .expect("transient loss must reduce bitrate");
    assert!(reduced < 15_000_000);

    // Once windowed interval loss resets to 0 ppm, clean intervals allow AIMD recovery.
    let clean_snap = CongestionSnapshot {
        packet_loss_ppm: 0,
        rtt_us: 10_000,
        tx_queue_frames: 0,
        ..CongestionSnapshot::default()
    };
    let mut now_us = 250_000u64;
    let mut recovered = reduced;
    for _ in 0..4 {
        if let Some(next) = advisor.update(&clean_snap, now_us) {
            recovered = next;
        }
        now_us += 150_000;
    }
    assert!(
        recovered > reduced,
        "BitrateAdvisor must recover upward ({recovered}) above {reduced} once transient loss ends"
    );
}

#[tokio::test]
async fn operational_connection_windowed_loss_persists_through_cooldown_and_recovers() {
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let s_kp = IdentityKeyPair::generate(&mut rng).expect("skp");
    let r_kp = IdentityKeyPair::generate(&mut rng).expect("rkp");
    let now = now_unix();
    let s_cert =
        generate_self_signed_device_cert(&s_kp, now.saturating_sub(60), now + 3600).expect("sc");
    let r_cert =
        generate_self_signed_device_cert(&r_kp, now.saturating_sub(60), now + 3600).expect("rc");
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

    let cfg = TransportConfig {
        kind: TransportKind::QuicDatagram,
        heartbeat_timeout_ms: 8_000,
        min_bitrate_bps: 2_000_000,
        initial_bitrate_bps: 15_000_000,
        max_bitrate_bps: 40_000_000,
        ..TransportConfig::default()
    };
    let srv = TransportServer::bind(
        TransportKind::QuicDatagram,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &r_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: r_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("srv");
    let proxy = UdpImpairmentProxy::start(
        srv.local_addr().expect("addr"),
        0x7777_1111,
        ImpairmentProfile {
            base_delay_ms: 1,
            drop_ppm: 120_000,
            ..ImpairmentProfile::default()
        },
    )
    .await
    .expect("proxy");

    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            TransportKind::QuicDatagram,
            proxy.listen_addr(),
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
    let mut cli = OperationalConnection::from_link(cli_res.expect("cli"), cfg.clone(), true, None)
        .expect("c");
    let mut rx =
        OperationalConnection::from_link(srv_res.expect("srv"), cfg, false, None).expect("r");

    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let rx_task = tokio::spawn(async move {
        rx.handshake_acceptor(r_dev_id, r_store.as_ref(), PeerRole::Host, caps())
            .await
            .expect("ha");
        rx.set_active_session(88, perms);
        while !*stop_rx.borrow() {
            tokio::select! {
                res = rx.recv_media_event(Duration::from_millis(20)) => {
                    if res.is_err() {
                        break;
                    }
                }
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        break;
                    }
                }
            }
        }
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
    cli.set_active_session(88, perms);

    let mut min_advised = 15_000_000u64;
    let mut saw_nonzero_loss = false;
    for fid in 1u32..=12 {
        let is_idr = fid == 1;
        cli.send_video_frame(OutboundVideoFrame {
            session_id: 88,
            display_id: 0,
            codec_id: CodecId::H264,
            frame_id: fid,
            gop_id: 1,
            capture_ts_us: u64::from(fid) * 16_667,
            encode_done_ts_us: u64::from(fid) * 16_667,
            kind: if is_idr {
                FrameKind::Keyframe { chain_reset: true }
            } else {
                FrameKind::InterFrame
            },
            has_codec_config: is_idr,
            mirror_source: false,
            payload: vec![0xCD; 24_000],
        })
        .await
        .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (snap, suggested) = cli.poll_congestion_and_advise_bitrate();
        if snap.packet_loss_ppm > 0 {
            saw_nonzero_loss = true;
        }
        if let Some(bps) = suggested {
            min_advised = min_advised.min(bps);
        }
    }
    assert!(
        saw_nonzero_loss && min_advised < 15_000_000,
        "lossy QUIC phase must report non-zero windowed loss and reduce bitrate (saw={saw_nonzero_loss}, min_advised={min_advised})"
    );

    // Clear loss, let QUIC finish declaring losses for already-sent frames,
    // and then pump clean frames across multiple 100ms advisor intervals.
    proxy.set_profile(ImpairmentProfile::default());
    tokio::time::sleep(Duration::from_millis(80)).await;
    let (_, settle_bps) = cli.poll_congestion_and_advise_bitrate();
    let mut post_loss_bps = settle_bps.unwrap_or_else(|| cli.snapshot_congestion().pacing_rate_bps);
    post_loss_bps = post_loss_bps.min(min_advised);

    let mut recovered = post_loss_bps;
    let mut final_loss_ppm = u32::MAX;
    for fid in 13u32..=44 {
        let is_idr = fid == 13;
        cli.send_video_frame(OutboundVideoFrame {
            session_id: 88,
            display_id: 0,
            codec_id: CodecId::H264,
            frame_id: fid,
            gop_id: 2,
            capture_ts_us: u64::from(fid) * 16_667,
            encode_done_ts_us: u64::from(fid) * 16_667,
            kind: if is_idr {
                FrameKind::Keyframe { chain_reset: true }
            } else {
                FrameKind::InterFrame
            },
            has_codec_config: is_idr,
            mirror_source: false,
            payload: vec![0xCE; 24_000],
        })
        .await
        .expect("clean send");
        tokio::time::sleep(Duration::from_millis(35)).await;
        let (snap, suggested) = cli.poll_congestion_and_advise_bitrate();
        final_loss_ppm = snap.packet_loss_ppm;
        if fid <= 16 {
            // Any tail losses detected from pre-clear in-flight QUIC packets settle here.
            post_loss_bps = post_loss_bps.min(snap.pacing_rate_bps);
        }
        if let Some(bps) = suggested {
            recovered = bps;
        }
    }
    assert!(
        final_loss_ppm == 0 && recovered > post_loss_bps,
        "after clearing impairment, OperationalConnection windowed loss must drop to 0 ({final_loss_ppm}) and recover bitrate ({recovered} > {post_loss_bps})"
    );

    let _ = stop_tx.send(true);
    let _ = rx_task.await;
    proxy.shutdown().await;
    srv.close();
}

#[tokio::test]
async fn udp_proxy_enforces_bandwidth_cap_without_clamping() {
    use tokio::net::UdpSocket;

    let rx = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind rx");
    let rx_addr = rx.local_addr().expect("addr");
    let proxy = UdpImpairmentProxy::start(
        rx_addr,
        0xCAFE_8000,
        ImpairmentProfile {
            base_delay_ms: 6,
            bandwidth_cap_bps: Some(8_000_000),
            ..ImpairmentProfile::default()
        },
    )
    .await
    .expect("proxy");
    let tx = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind tx");
    tx.connect(proxy.listen_addr()).await.expect("connect");

    // Send 600 x 1,200 B = 720,000 B (5.76 Mbit) in paced bursts at ~19.2 Mbps offered (> 8 Mbps cap)
    // without overflowing the OS loopback UDP socket buffer. At 8 Mbps cap, delivery MUST take >= 0.72 s
    // and measured wire rate MUST stay <= 8.05 Mbps.
    let total_pkts = 600usize;
    let t0 = tokio::time::Instant::now();
    let tx_task = tokio::spawn(async move {
        let pkt = vec![0x5Au8; 1_200];
        for idx in 0..total_pkts {
            tx.send(&pkt).await.expect("send");
            if (idx + 1) % 16 == 0 {
                tokio::time::sleep(Duration::from_millis(8)).await;
            }
        }
    });

    let mut rbuf = [0u8; 2048];
    let mut rx_bytes = 0usize;
    for _ in 0..total_pkts {
        let n = tokio::time::timeout(Duration::from_secs(5), rx.recv(&mut rbuf))
            .await
            .expect("recv timeout")
            .expect("recv");
        rx_bytes += n;
    }
    tx_task.await.expect("tx join");
    let elapsed_s = t0.elapsed().as_secs_f64();
    let mbps = (rx_bytes as f64 * 8.0) / (elapsed_s * 1_000_000.0);
    assert_eq!(rx_bytes, total_pkts * 1_200);
    assert!(
        mbps <= 8.05,
        "UdpImpairmentProxy must enforce 8 Mbps cap without 500ms backlog clamp (measured {mbps:.2} Mbps in {elapsed_s:.3}s)"
    );
    proxy.shutdown().await;
}
