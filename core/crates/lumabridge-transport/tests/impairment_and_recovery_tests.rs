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
        .insert_newly_paired(&r_id, PeerRole::Controller, "Rx", perms, now)
        .expect("s");
    r_store
        .insert_newly_paired(&s_id, PeerRole::Host, "Tx", perms, now)
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
        .insert_newly_paired(&r_id, PeerRole::Controller, "Rx", perms, now)
        .expect("s");
    r_store
        .insert_newly_paired(&s_id, PeerRole::Host, "Tx", perms, now)
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
        .insert_newly_paired(&r_id, PeerRole::Controller, "Rx", perms, now)
        .expect("s");
    r_store
        .insert_newly_paired(&s_id, PeerRole::Host, "Tx", perms, now)
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
