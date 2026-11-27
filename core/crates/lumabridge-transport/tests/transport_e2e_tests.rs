// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]

use lumabridge_protocol::control::{
    ActiveDisplayConfig, CaptureMode, CodecCapability, ColorFormat, ControlMessage,
    DisplayFrameCursor, DisplayMode, Heartbeat, InputBatch, InputCapabilities, InputEvent,
    NodeCapabilities, OsGraphicsPlatform, Permissions, RoleFlags, RotationDeg,
};
use lumabridge_protocol::media::fragmentation::FrameKind;
use lumabridge_protocol::media::header::VideoFlags;
use lumabridge_protocol::version::{CodecId, ALPN_OPERATIONAL_V1, ALPN_PAIRING_V1};
use lumabridge_security::certificate::{
    generate_self_signed_device_cert, GeneratedDeviceCertificate,
};
use lumabridge_security::identity::{DeviceId, IdentityKeyPair, PeerRole};
use lumabridge_security::secret::{CheckedOsCryptoRng, ResumeTokenSecret};
use lumabridge_security::session_token::{revoke_peer_and_sessions, SessionTokenManager};
use lumabridge_security::tls::{TlsPeerTrustPolicy, LUMABRIDGE_ALPN_V1, LUMABRIDGE_PAIR_ALPN_V1};
use lumabridge_security::trust_store::{InMemoryTrustStore, RevocationReason};
use lumabridge_transport::config::{TransportConfig, TransportKind};
use lumabridge_transport::connection::{
    connect_client_link, ConnectionRegistry, MediaRxEvent, OperationalConnection,
    PairingConnection, TransportServer,
};
use lumabridge_transport::discovery::{
    discover_peers, DiscoveryAdvertisement, DiscoveryResponder, ManualEndpoint,
};
use lumabridge_transport::error::TransportError;
use lumabridge_transport::queue::OutboundVideoFrame;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

struct NodeFixture {
    role: PeerRole,
    device_id: DeviceId,
    public_id: lumabridge_security::identity::PublicIdentity,
    cert: GeneratedDeviceCertificate,
}

fn make_node(role: PeerRole) -> NodeFixture {
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let kp = IdentityKeyPair::generate(&mut rng).expect("keygen");
    let now = now_unix();
    let cert = generate_self_signed_device_cert(&kp, now, now + 3600).expect("cert");
    let public_id = kp.public_identity().clone();
    NodeFixture {
        role,
        device_id: public_id.device_id(),
        public_id,
        cert,
    }
}

fn sample_caps() -> NodeCapabilities {
    NodeCapabilities {
        roles_mask: RoleFlags::CAN_RECEIVE_VIDEO
            .union(RoleFlags::CAN_EXTEND_SESSION)
            .union(RoleFlags::CAN_SEND_INPUT)
            .union(RoleFlags::CAN_RECEIVE_INPUT),
        platform: OsGraphicsPlatform::WindowsDwm,
        codecs: vec![CodecCapability {
            codec_id: CodecId::H264,
            can_encode: true,
            can_decode: true,
            hw_accelerated: true,
            max_width: 3840,
            max_height: 2160,
            max_fps_num: 120,
            max_fps_den: 1,
            max_b_frames: 0,
        }],
        max_virtual_displays: 4,
        supports_scale: true,
        supports_rotation: true,
        input_caps_mask: InputCapabilities::POINTER.union(InputCapabilities::KEYBOARD),
    }
}

fn setup_paired_stores(
    host: &NodeFixture,
    controller: &NodeFixture,
    base_perms: Permissions,
) -> (Arc<InMemoryTrustStore>, Arc<InMemoryTrustStore>) {
    let host_store = Arc::new(InMemoryTrustStore::new());
    let controller_store = Arc::new(InMemoryTrustStore::new());
    let now = now_unix();
    host_store
        .insert_newly_paired(
            &controller.public_id,
            controller.role,
            "Controller",
            base_perms,
            now,
        )
        .expect("insert controller");
    controller_store
        .insert_newly_paired(&host.public_id, host.role, "Host", base_perms, now)
        .expect("insert host");
    (host_store, controller_store)
}

async fn run_mode_e2e_smoke(kind: TransportKind) {
    let host = make_node(PeerRole::Host);
    let controller = make_node(PeerRole::Controller);
    let base_perms = Permissions::EXTEND_DISPLAY;
    let session_perms = Permissions::EXTEND_DISPLAY.union(Permissions::INPUT_POINTER);
    let (host_store, controller_store) = setup_paired_stores(&host, &controller, base_perms);

    let mut cfg = TransportConfig {
        kind,
        ..TransportConfig::default()
    };
    cfg.handshake_timeout_ms = 5_000;
    let now = now_unix();

    let srv_policy = TlsPeerTrustPolicy::PinnedPeer {
        trust_store: controller_store.clone(),
        expected_role: PeerRole::Host,
        expected_device_id: host.device_id,
    };
    let server = TransportServer::bind(
        kind,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &controller.cert,
        srv_policy,
        cfg.clone(),
    )
    .await
    .expect("bind server");
    let addr = server.local_addr().expect("addr");

    let cli_policy = TlsPeerTrustPolicy::PinnedPeer {
        trust_store: host_store.clone(),
        expected_role: PeerRole::Controller,
        expected_device_id: controller.device_id,
    };

    let srv_task = tokio::spawn({
        let c_id = controller.device_id;
        let rs = controller_store.clone();
        let scfg = cfg.clone();
        async move {
            let link = server
                .accept_link(LUMABRIDGE_ALPN_V1, now)
                .await
                .expect("accept");
            let mut conn =
                OperationalConnection::from_link(link, scfg, false, None).expect("srv conn");
            let info = conn
                .handshake_acceptor(c_id, rs.as_ref(), PeerRole::Host, sample_caps())
                .await
                .expect("srv hs");
            assert_eq!(info.peer_device_id, host.device_id);
            conn.set_active_session(77, session_perms);

            let hb = conn.recv_feedback_message().await.expect("hb");
            assert!(matches!(hb, ControlMessage::Heartbeat(_)));

            let inp = conn.recv_input_message().await.expect("input");
            assert!(matches!(inp, ControlMessage::InputBatch(_)));

            let mut received_frames = 0usize;
            for _ in 0..8 {
                if let Some(MediaRxEvent::Frame(f)) = conn
                    .recv_media_event(Duration::from_millis(500))
                    .await
                    .expect("rx")
                {
                    assert!(!f.payload.is_empty());
                    received_frames += 1;
                    if received_frames == 2 {
                        break;
                    }
                }
            }
            assert_eq!(received_frames, 2);
            server.close();
        }
    });

    let cli_link = connect_client_link(
        kind,
        addr,
        &host.cert,
        cli_policy,
        controller.device_id,
        LUMABRIDGE_ALPN_V1,
        now,
        &cfg,
    )
    .await
    .expect("connect client");
    let mut cli_conn =
        OperationalConnection::from_link(cli_link, cfg, true, None).expect("cli conn");
    let info = cli_conn
        .handshake_initiator(
            host.device_id,
            host_store.as_ref(),
            PeerRole::Controller,
            "0.1.0",
            sample_caps(),
        )
        .await
        .expect("cli hs");
    assert_eq!(info.peer_device_id, controller.device_id);
    cli_conn.set_active_session(77, session_perms);

    cli_conn
        .send_feedback_message(&ControlMessage::Heartbeat(Heartbeat {
            session_id: Some(77),
            seq: 1,
            uptime_ms: 100,
        }))
        .await
        .expect("send hb");

    cli_conn
        .send_input_message(&ControlMessage::InputBatch(InputBatch {
            session_id: 77,
            display_id: 0,
            input_seq: 1,
            events: vec![InputEvent::PointerMoveAbs {
                x_norm: 32_768,
                y_norm: 16_384,
            }],
        }))
        .await
        .expect("send input");

    for (idx, is_idr) in [(1u32, true), (2u32, false)] {
        let out = cli_conn
            .send_video_frame(OutboundVideoFrame {
                session_id: 77,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: idx,
                gop_id: 1,
                capture_ts_us: u64::from(idx) * 16_000,
                encode_done_ts_us: u64::from(idx) * 16_000 + 2_000,
                kind: if is_idr {
                    FrameKind::Keyframe { chain_reset: true }
                } else {
                    FrameKind::InterFrame
                },
                has_codec_config: is_idr,
                mirror_source: false,
                payload: vec![0xABu8; 4096],
            })
            .await
            .expect("send video");
        assert!(out.admitted);
    }

    srv_task.await.expect("srv join");
}

#[tokio::test]
async fn quic_datagram_quic_stream_and_tcp_tls_e2e_all_succeed() {
    run_mode_e2e_smoke(TransportKind::QuicDatagram).await;
    run_mode_e2e_smoke(TransportKind::QuicStream).await;
    run_mode_e2e_smoke(TransportKind::TcpTls).await;
}

#[tokio::test]
async fn alpn_isolation_mitm_and_untrusted_peer_rejected_at_handshake() {
    for kind in [TransportKind::QuicDatagram, TransportKind::TcpTls] {
        let host = make_node(PeerRole::Host);
        let controller = make_node(PeerRole::Controller);
        let attacker = make_node(PeerRole::Host);
        let perms = Permissions::VIEW_MIRROR;
        let (host_store, controller_store) = setup_paired_stores(&host, &controller, perms);
        let cfg = TransportConfig {
            kind,
            handshake_timeout_ms: 1500,
            ..TransportConfig::default()
        };
        let now = now_unix();

        let srv = TransportServer::bind(
            kind,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            &controller.cert,
            TlsPeerTrustPolicy::Trusted {
                trust_store: controller_store.clone(),
                expected_role: PeerRole::Host,
            },
            cfg.clone(),
        )
        .await
        .expect("bind");
        let addr = srv.local_addr().expect("addr");

        let srv_accept = tokio::spawn({
            let s = srv;
            async move {
                for _ in 0..2 {
                    let _ = s.accept_link(LUMABRIDGE_ALPN_V1, now).await;
                }
                s.close();
            }
        });

        // 1. Operational server rejects pairing ALPN (`lumabridge-pair/1`).
        let pair_alpn_err = connect_client_link(
            kind,
            addr,
            &host.cert,
            TlsPeerTrustPolicy::Pairing {
                trust_store: host_store.clone(),
            },
            controller.device_id,
            ALPN_PAIRING_V1.as_bytes(),
            now,
            &cfg,
        )
        .await;
        assert!(pair_alpn_err.is_err());

        // 2. Untrusted attacker (not in controller TrustStore) rejected at TLS mTLS handshake.
        let untrusted_err = connect_client_link(
            kind,
            addr,
            &attacker.cert,
            TlsPeerTrustPolicy::Pairing {
                trust_store: host_store.clone(),
            },
            controller.device_id,
            ALPN_OPERATIONAL_V1.as_bytes(),
            now,
            &cfg,
        )
        .await;
        assert!(untrusted_err.is_err());

        let _ = tokio::time::timeout(Duration::from_millis(500), srv_accept).await;

        // 3. Dedicated pairing endpoint accepts `lumabridge-pair/1` only and rejects operational msgs.
        let pair_srv = TransportServer::bind(
            kind,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            &controller.cert,
            TlsPeerTrustPolicy::Pairing {
                trust_store: controller_store,
            },
            cfg.clone(),
        )
        .await
        .expect("pair bind");
        let p_addr = pair_srv.local_addr().expect("p_addr");
        let p_srv_task = tokio::spawn(async move {
            let link = pair_srv
                .accept_link(LUMABRIDGE_PAIR_ALPN_V1, now)
                .await
                .expect("pair accept");
            let pair_conn = PairingConnection::from_link(link, cfg.clone(), false).expect("pair");
            pair_conn.close();
            pair_srv.close();
        });
        let p_cli_link = connect_client_link(
            kind,
            p_addr,
            &host.cert,
            TlsPeerTrustPolicy::Pairing {
                trust_store: host_store,
            },
            controller.device_id,
            LUMABRIDGE_PAIR_ALPN_V1,
            now,
            &TransportConfig {
                kind,
                ..TransportConfig::default()
            },
        )
        .await
        .expect("pair connect");
        let pair_cli =
            PairingConnection::from_link(p_cli_link, TransportConfig::default(), true).expect("pc");
        assert!(pair_cli
            .send_pairing_message(&ControlMessage::Heartbeat(Heartbeat {
                session_id: Some(1),
                seq: 1,
                uptime_ms: 1,
            }))
            .await
            .is_err());
        pair_cli.close();
        p_srv_task.await.expect("p join");
    }
}

#[tokio::test]
async fn live_revocation_disconnects_sessions_and_channel_bound_resume_rotates_and_rejects_replay()
{
    let host = make_node(PeerRole::Host);
    let controller = make_node(PeerRole::Controller);
    let perms = Permissions::VIEW_MIRROR;
    let (host_store, controller_store) = setup_paired_stores(&host, &controller, perms);
    let session_mgr = Arc::new(SessionTokenManager::new());
    let registry = ConnectionRegistry::new(16);
    let now = now_unix();
    let cfg = TransportConfig {
        kind: TransportKind::QuicDatagram,
        heartbeat_timeout_ms: 3_000,
        ..TransportConfig::default()
    };

    let srv = TransportServer::bind(
        TransportKind::QuicDatagram,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &controller.cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: controller_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("srv");
    let addr = srv.local_addr().expect("addr");

    let srv_reg = registry.clone();
    let srv_store = controller_store.clone();
    let srv_mgr = session_mgr.clone();
    let replay_verified = Arc::new(tokio::sync::Notify::new());
    let replay_verified_srv = replay_verified.clone();
    let srv_task = tokio::spawn({
        let c_id = controller.device_id;
        let scfg = cfg.clone();
        async move {
            let link1 = srv.accept_link(LUMABRIDGE_ALPN_V1, now).await.expect("a1");
            let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
            let issued = srv_mgr
                .issue_session(
                    &mut rng,
                    srv_store.as_ref(),
                    link1.tls_session(),
                    PeerRole::Host,
                    perms,
                    now,
                    3600,
                    600,
                )
                .expect("issue");
            let sid = issued.session_id;
            let resume_tok = issued.resume_token.clone();
            let mut c1 =
                OperationalConnection::from_link(link1, scfg.clone(), false, Some(srv_reg.clone()))
                    .expect("c1");
            c1.handshake_acceptor(c_id, srv_store.as_ref(), PeerRole::Host, sample_caps())
                .await
                .expect("hs1");
            c1.send_control_message(&ControlMessage::SessionOpenResponse(
                lumabridge_protocol::control::SessionOpenResponse {
                    status: lumabridge_protocol::control::SessionOpenStatus::Accepted,
                    session_id: sid,
                    resume_token: Some(resume_tok.expose_secret().to_vec()),
                    active_displays: vec![ActiveDisplayConfig {
                        display_id: 0,
                        mode: DisplayMode::Extend,
                        width: 1920,
                        height: 1080,
                        fps_num: 60,
                        fps_den: 1,
                        scale_milli: 1000,
                        rotation_deg: RotationDeg::Deg0,
                        codec_id: CodecId::H264,
                        color_format: ColorFormat::Nv12_8Bit,
                        initial_bitrate_bps: 12_000_000,
                        capture_mode: CaptureMode::WindowsIddVirtualMonitor,
                    }],
                    granted_perms: perms,
                },
            ))
            .await
            .expect("send open resp");
            drop(c1);

            // Second connection: handle channel-bound resume & rotate token using live-verified registration.
            let link2 = srv.accept_link(LUMABRIDGE_ALPN_V1, now).await.expect("a2");
            let mut c2 = OperationalConnection::from_link_verified(
                link2,
                scfg.clone(),
                false,
                srv_reg.clone(),
                srv_store.as_ref(),
                PeerRole::Host,
            )
            .expect("c2");
            c2.handshake_acceptor(c_id, srv_store.as_ref(), PeerRole::Host, sample_caps())
                .await
                .expect("hs2");
            let msg = c2.recv_control_message().await.expect("recv resume");
            let ControlMessage::SessionResumeRequest(req) = msg else {
                panic!("expected SessionResumeRequest");
            };
            let res = c2
                .handle_session_resume(
                    &mut rng,
                    srv_store.as_ref(),
                    &srv_mgr,
                    PeerRole::Host,
                    &req,
                    vec![ActiveDisplayConfig {
                        display_id: 0,
                        mode: DisplayMode::Extend,
                        width: 1920,
                        height: 1080,
                        fps_num: 60,
                        fps_den: 1,
                        scale_milli: 1000,
                        rotation_deg: RotationDeg::Deg0,
                        codec_id: CodecId::H264,
                        color_format: ColorFormat::Nv12_8Bit,
                        initial_bitrate_bps: 12_000_000,
                        capture_mode: CaptureMode::WindowsIddVirtualMonitor,
                    }],
                    vec![0],
                    now,
                    600,
                )
                .await
                .expect("handle resume");
            assert!(res.is_some());

            // Third connection: replay of consumed initial resume token MUST be rejected (`Ok(None)`).
            let link3 = srv.accept_link(LUMABRIDGE_ALPN_V1, now).await.expect("a3");
            let mut c3 =
                OperationalConnection::from_link(link3, scfg, false, Some(srv_reg.clone()))
                    .expect("c3");
            c3.handshake_acceptor(c_id, srv_store.as_ref(), PeerRole::Host, sample_caps())
                .await
                .expect("hs3");
            let msg3 = c3.recv_control_message().await.expect("recv replay");
            let ControlMessage::SessionResumeRequest(req3) = msg3 else {
                panic!("expected replay SessionResumeRequest");
            };
            let replay_res = c3
                .handle_session_resume(
                    &mut rng,
                    srv_store.as_ref(),
                    &srv_mgr,
                    PeerRole::Host,
                    &req3,
                    Vec::new(),
                    Vec::new(),
                    now,
                    600,
                )
                .await
                .expect("handle replay");
            assert!(replay_res.is_none());
            replay_verified_srv.notified().await;
            drop(c3);

            assert_eq!(srv_reg.active_count(), 1);
            // Revoke host live and verify registry disconnects active transport handle immediately.
            let outcome = revoke_peer_and_sessions(
                srv_store.as_ref(),
                &srv_mgr,
                host.device_id,
                RevocationReason::SuspectedCompromise,
                now,
            )
            .expect("revoke");
            let closed = srv_reg.apply_security_action(&outcome.actions[0]);
            assert_eq!(closed, 1);
            assert_eq!(srv_reg.active_count(), 0);
            srv.close();
        }
    });

    let cli_policy = TlsPeerTrustPolicy::PinnedPeer {
        trust_store: host_store.clone(),
        expected_role: PeerRole::Controller,
        expected_device_id: controller.device_id,
    };

    let l1 = connect_client_link(
        TransportKind::QuicDatagram,
        addr,
        &host.cert,
        cli_policy.clone(),
        controller.device_id,
        LUMABRIDGE_ALPN_V1,
        now,
        &cfg,
    )
    .await
    .expect("c1");
    let mut cli1 = OperationalConnection::from_link(l1, cfg.clone(), true, None).expect("cli1");
    cli1.handshake_initiator(
        host.device_id,
        host_store.as_ref(),
        PeerRole::Controller,
        "0.1.0",
        sample_caps(),
    )
    .await
    .expect("hs1");
    let ControlMessage::SessionOpenResponse(open_resp) =
        cli1.recv_control_message().await.expect("open resp")
    else {
        panic!("expected SessionOpenResponse");
    };
    let initial_tok = ResumeTokenSecret::from_slice(open_resp.resume_token.as_ref().expect("tok"))
        .expect("tok secret");
    let sid = open_resp.session_id;
    drop(cli1);

    // Reconnect and execute channel-bound resume!
    let l2 = connect_client_link(
        TransportKind::QuicDatagram,
        addr,
        &host.cert,
        cli_policy.clone(),
        controller.device_id,
        LUMABRIDGE_ALPN_V1,
        now,
        &cfg,
    )
    .await
    .expect("c2");
    let mut cli2 = OperationalConnection::from_link(l2, cfg.clone(), true, None).expect("cli2");
    cli2.handshake_initiator(
        host.device_id,
        host_store.as_ref(),
        PeerRole::Controller,
        "0.1.0",
        sample_caps(),
    )
    .await
    .expect("hs2");
    let resume_resp = cli2
        .resume_session_as_client(
            host.device_id,
            sid,
            1,
            &initial_tok,
            vec![DisplayFrameCursor {
                display_id: 0,
                last_good_frame_id: 42,
            }],
        )
        .await
        .expect("resume");
    assert!(resume_resp.accepted);
    let rotated = resume_resp.rotated_resume_token.expect("rotated token");
    assert_eq!(rotated.len(), 32);
    assert_ne!(rotated.as_slice(), initial_tok.expose_secret());

    // Third connection attempts to replay initial_tok on a new connection (must be denied).
    let l3 = connect_client_link(
        TransportKind::QuicDatagram,
        addr,
        &host.cert,
        cli_policy.clone(),
        controller.device_id,
        LUMABRIDGE_ALPN_V1,
        now,
        &cfg,
    )
    .await
    .expect("c3");
    let mut cli3 = OperationalConnection::from_link(l3, cfg.clone(), true, None).expect("cli3");
    cli3.handshake_initiator(
        host.device_id,
        host_store.as_ref(),
        PeerRole::Controller,
        "0.1.0",
        sample_caps(),
    )
    .await
    .expect("hs3");
    let replay_resp = cli3
        .resume_session_as_client(
            host.device_id,
            sid,
            1,
            &initial_tok,
            vec![DisplayFrameCursor {
                display_id: 0,
                last_good_frame_id: 42,
            }],
        )
        .await
        .expect("replay resp");
    assert!(!replay_resp.accepted);
    assert!(replay_resp.rotated_resume_token.is_none());
    drop(cli3);
    replay_verified.notify_one();

    srv_task.await.expect("srv");

    // Reconnecting after revocation MUST fail!
    let post_revoke = connect_client_link(
        TransportKind::QuicDatagram,
        addr,
        &host.cert,
        cli_policy,
        controller.device_id,
        LUMABRIDGE_ALPN_V1,
        now,
        &cfg,
    )
    .await;
    assert!(post_revoke.is_err());
    drop(cli2);
}

#[tokio::test]
async fn silent_peer_triggers_heartbeat_timeout() {
    let host = make_node(PeerRole::Host);
    let controller = make_node(PeerRole::Controller);
    let perms = Permissions::VIEW_MIRROR;
    let (h_store, c_store) = setup_paired_stores(&host, &controller, perms);
    let cfg = TransportConfig {
        heartbeat_interval_ms: 50,
        heartbeat_timeout_ms: 180,
        ..TransportConfig::default()
    };
    let now = now_unix();

    let srv = TransportServer::bind(
        TransportKind::QuicDatagram,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &controller.cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: c_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("srv");
    let addr = srv.local_addr().expect("addr");
    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            TransportKind::QuicDatagram,
            addr,
            &host.cert,
            TlsPeerTrustPolicy::PinnedPeer {
                trust_store: h_store.clone(),
                expected_role: PeerRole::Controller,
                expected_device_id: controller.device_id,
            },
            controller.device_id,
            LUMABRIDGE_ALPN_V1,
            now,
            &cfg,
        ),
        srv.accept_link(LUMABRIDGE_ALPN_V1, now),
    );
    let cli_link = cli_res.expect("cli");
    let srv_link = srv_res.expect("acc");
    let mut cli_c = OperationalConnection::from_link(cli_link, cfg.clone(), true, None).expect("c");
    let mut srv_c = OperationalConnection::from_link(srv_link, cfg, false, None).expect("s");

    let t = tokio::spawn(async move {
        cli_c
            .handshake_initiator(
                host.device_id,
                h_store.as_ref(),
                PeerRole::Controller,
                "0.1.0",
                sample_caps(),
            )
            .await
            .expect("hi");
        // Go silent deliberately past heartbeat_timeout_ms.
        tokio::time::sleep(Duration::from_millis(300)).await;
    });

    srv_c
        .handshake_acceptor(
            controller.device_id,
            c_store.as_ref(),
            PeerRole::Host,
            sample_caps(),
        )
        .await
        .expect("ha");
    let err = srv_c
        .recv_control_message()
        .await
        .expect_err("must timeout");
    assert!(matches!(err, TransportError::Timeout(_)));
    t.await.expect("t");
    srv.close();
}

#[tokio::test]
async fn lan_mdns_discovery_and_manual_fallback_return_hints() {
    let responder = DiscoveryResponder::bind(
        SocketAddr::from(([127, 0, 0, 1], 0)),
        DiscoveryAdvertisement {
            short_device_id_hex: "0123456789abcdef".to_owned(),
            friendly_name: "Linux Display".to_owned(),
            host_ip: Ipv4Addr::LOCALHOST,
            quic_port: 49_200,
            tcp_port: Some(49_201),
        },
        false,
    )
    .await
    .expect("responder");
    let r_addr = responder.local_addr();

    let manual = ManualEndpoint {
        addr: SocketAddr::from(([192, 168, 1, 50], 49_200)),
        label: Some("Static LAN".to_owned()),
    };
    let hints = discover_peers(r_addr, Duration::from_millis(500), &[manual])
        .await
        .expect("discover");
    responder.shutdown().await;

    assert_eq!(hints.len(), 2);
    assert_eq!(hints[0].short_device_id_hex, "0123456789abcdef");
    assert_eq!(hints[0].friendly_name, "Linux Display");
    assert_eq!(
        hints[0].addrs,
        vec![SocketAddr::from(([127, 0, 0, 1], 49_200))]
    );
    assert_eq!(hints[0].tcp_port, Some(49_201));
    assert_eq!(hints[1].friendly_name, "Static LAN");
}

#[tokio::test]
async fn media_packet_flags_preserved_end_to_end() {
    let host = make_node(PeerRole::Host);
    let controller = make_node(PeerRole::Controller);
    let perms = Permissions::VIEW_MIRROR;
    let (h_store, c_store) = setup_paired_stores(&host, &controller, perms);
    let cfg = TransportConfig::default();
    let now = now_unix();
    let srv = TransportServer::bind(
        TransportKind::QuicDatagram,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &controller.cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: c_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("srv");
    let addr = srv.local_addr().expect("addr");
    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            TransportKind::QuicDatagram,
            addr,
            &host.cert,
            TlsPeerTrustPolicy::PinnedPeer {
                trust_store: h_store.clone(),
                expected_role: PeerRole::Controller,
                expected_device_id: controller.device_id,
            },
            controller.device_id,
            LUMABRIDGE_ALPN_V1,
            now,
            &cfg,
        ),
        srv.accept_link(LUMABRIDGE_ALPN_V1, now),
    );
    let cli_link = cli_res.expect("cli");
    let srv_link = srv_res.expect("acc");
    let mut cli_c =
        OperationalConnection::from_link(cli_link, cfg.clone(), true, None).expect("cc");
    let mut srv_c = OperationalConnection::from_link(srv_link, cfg, false, None).expect("sc");

    let done = Arc::new(tokio::sync::Notify::new());
    let done_tx = Arc::clone(&done);
    let t1 = tokio::spawn(async move {
        cli_c
            .handshake_initiator(
                host.device_id,
                h_store.as_ref(),
                PeerRole::Controller,
                "0.1.0",
                sample_caps(),
            )
            .await
            .expect("ci");
        cli_c.set_active_session(9, perms);
        cli_c
            .send_video_frame(OutboundVideoFrame {
                session_id: 9,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: 1,
                gop_id: 1,
                capture_ts_us: 1000,
                encode_done_ts_us: 1500,
                kind: FrameKind::Keyframe { chain_reset: true },
                has_codec_config: true,
                mirror_source: true,
                payload: vec![0xCDu8; 3_000],
            })
            .await
            .expect("send");
        let _ = tokio::time::timeout(Duration::from_secs(5), done_tx.notified()).await;
    });

    srv_c
        .handshake_acceptor(
            controller.device_id,
            c_store.as_ref(),
            PeerRole::Host,
            sample_caps(),
        )
        .await
        .expect("sa");
    srv_c.set_active_session(9, perms);
    let ev = srv_c
        .recv_media_event(Duration::from_millis(800))
        .await
        .expect("rx")
        .expect("some");
    done.notify_one();
    t1.await.expect("join");
    match ev {
        MediaRxEvent::Frame(f) => {
            assert!(f.flags.contains(VideoFlags::KEYFRAME));
            assert!(f.flags.contains(VideoFlags::MIRROR_SOURCE));
            assert_eq!(f.payload.len(), 3_000);
        }
        other => panic!("unexpected event: {other:?}"),
    }
    srv.close();
}

#[tokio::test]
async fn hello_ack_remote_perms_are_clamped_by_local_trust_store() {
    let host = make_node(PeerRole::Host);
    let controller = make_node(PeerRole::Controller);
    let now = now_unix();
    let host_store = Arc::new(InMemoryTrustStore::new());
    let controller_store = Arc::new(InMemoryTrustStore::new());
    host_store
        .insert_newly_paired(
            &controller.public_id,
            controller.role,
            "Controller",
            Permissions::VIEW_MIRROR,
            now,
        )
        .expect("host pair");
    controller_store
        .insert_newly_paired(
            &host.public_id,
            host.role,
            "Host",
            Permissions::VIEW_MIRROR.union(Permissions::EXTEND_DISPLAY),
            now,
        )
        .expect("controller pair");

    let cfg = TransportConfig::default();
    let srv = TransportServer::bind(
        TransportKind::QuicDatagram,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &controller.cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: controller_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("srv");
    let addr = srv.local_addr().expect("addr");
    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            TransportKind::QuicDatagram,
            addr,
            &host.cert,
            TlsPeerTrustPolicy::PinnedPeer {
                trust_store: host_store.clone(),
                expected_role: PeerRole::Controller,
                expected_device_id: controller.device_id,
            },
            controller.device_id,
            LUMABRIDGE_ALPN_V1,
            now,
            &cfg,
        ),
        srv.accept_link(LUMABRIDGE_ALPN_V1, now),
    );
    let mut cli_c =
        OperationalConnection::from_link(cli_res.expect("cli"), cfg.clone(), true, None)
            .expect("cc");
    let mut srv_c =
        OperationalConnection::from_link(srv_res.expect("acc"), cfg, false, None).expect("sc");

    let srv_task = tokio::spawn(async move {
        srv_c
            .handshake_acceptor(
                controller.device_id,
                controller_store.as_ref(),
                PeerRole::Host,
                sample_caps(),
            )
            .await
            .expect("sa")
    });
    let cli_info = cli_c
        .handshake_initiator(
            host.device_id,
            host_store.as_ref(),
            PeerRole::Controller,
            "0.1.0",
            sample_caps(),
        )
        .await
        .expect("ci");
    let srv_info = srv_task.await.expect("join");
    assert!(srv_info
        .granted_stored_perms
        .contains(Permissions::EXTEND_DISPLAY));
    assert_eq!(cli_info.granted_stored_perms, Permissions::VIEW_MIRROR);
    assert!(!cli_info
        .granted_stored_perms
        .contains(Permissions::EXTEND_DISPLAY));
    srv.close();
}

#[tokio::test]
async fn from_link_verified_rejects_live_revoked_peer_and_cleans_registry() {
    let host = make_node(PeerRole::Host);
    let controller = make_node(PeerRole::Controller);
    let (h_store, c_store) = setup_paired_stores(&host, &controller, Permissions::VIEW_MIRROR);
    let cfg = TransportConfig::default();
    let now = now_unix();
    let reg = ConnectionRegistry::new(4);
    let srv = TransportServer::bind(
        TransportKind::QuicDatagram,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &controller.cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: c_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("srv");
    let addr = srv.local_addr().expect("addr");
    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            TransportKind::QuicDatagram,
            addr,
            &host.cert,
            TlsPeerTrustPolicy::PinnedPeer {
                trust_store: h_store,
                expected_role: PeerRole::Controller,
                expected_device_id: controller.device_id,
            },
            controller.device_id,
            LUMABRIDGE_ALPN_V1,
            now,
            &cfg,
        ),
        srv.accept_link(LUMABRIDGE_ALPN_V1, now),
    );
    let _cli_link = cli_res.expect("cli");
    let srv_link = srv_res.expect("srv");

    // Simulate race: TLS handshake finished right before revocation commit took effect.
    let mgr = SessionTokenManager::new();
    let _ = revoke_peer_and_sessions(
        c_store.as_ref(),
        &mgr,
        host.device_id,
        RevocationReason::SuspectedCompromise,
        now + 1,
    )
    .expect("revoke");

    let err = OperationalConnection::from_link_verified(
        srv_link,
        cfg,
        false,
        reg.clone(),
        c_store.as_ref(),
        PeerRole::Host,
    );
    assert!(matches!(err, Err(TransportError::Revoked)));
    assert_eq!(reg.active_count(), 0);
    srv.close();
}

#[tokio::test]
async fn foreign_session_id_media_packets_are_dropped_before_reassembler() {
    let host = make_node(PeerRole::Host);
    let controller = make_node(PeerRole::Controller);
    let perms = Permissions::VIEW_MIRROR;
    let (h_store, c_store) = setup_paired_stores(&host, &controller, perms);
    let cfg = TransportConfig::default();
    let now = now_unix();
    let srv = TransportServer::bind(
        TransportKind::QuicDatagram,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        &controller.cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: c_store.clone(),
            expected_role: PeerRole::Host,
        },
        cfg.clone(),
    )
    .await
    .expect("srv");
    let addr = srv.local_addr().expect("addr");
    let (cli_res, srv_res) = tokio::join!(
        connect_client_link(
            TransportKind::QuicDatagram,
            addr,
            &host.cert,
            TlsPeerTrustPolicy::PinnedPeer {
                trust_store: h_store.clone(),
                expected_role: PeerRole::Controller,
                expected_device_id: controller.device_id,
            },
            controller.device_id,
            LUMABRIDGE_ALPN_V1,
            now,
            &cfg,
        ),
        srv.accept_link(LUMABRIDGE_ALPN_V1, now),
    );
    let mut cli_c =
        OperationalConnection::from_link(cli_res.expect("cli"), cfg.clone(), true, None)
            .expect("cc");
    let mut srv_c =
        OperationalConnection::from_link(srv_res.expect("acc"), cfg, false, None).expect("sc");

    let done = Arc::new(tokio::sync::Notify::new());
    let done_tx = Arc::clone(&done);
    let tx_task = tokio::spawn(async move {
        cli_c
            .handshake_initiator(
                host.device_id,
                h_store.as_ref(),
                PeerRole::Controller,
                "0.1.0",
                sample_caps(),
            )
            .await
            .expect("ci");
        cli_c.set_active_session(777, perms);
        // Inject foreign session_id (999 != 777) before valid session 777 frame.
        cli_c
            .send_video_frame(OutboundVideoFrame {
                session_id: 999,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: 1,
                gop_id: 1,
                capture_ts_us: 500,
                encode_done_ts_us: 700,
                kind: FrameKind::Keyframe { chain_reset: true },
                has_codec_config: true,
                mirror_source: false,
                payload: vec![0xAAu8; 2_500],
            })
            .await
            .expect("foreign");
        cli_c
            .send_video_frame(OutboundVideoFrame {
                session_id: 777,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: 2,
                gop_id: 2,
                capture_ts_us: 1000,
                encode_done_ts_us: 1200,
                kind: FrameKind::Keyframe { chain_reset: true },
                has_codec_config: true,
                mirror_source: false,
                payload: vec![0xBBu8; 2_500],
            })
            .await
            .expect("valid");
        let _ = tokio::time::timeout(Duration::from_secs(5), done_tx.notified()).await;
    });

    srv_c
        .handshake_acceptor(
            controller.device_id,
            c_store.as_ref(),
            PeerRole::Host,
            sample_caps(),
        )
        .await
        .expect("sa");
    srv_c.set_active_session(777, perms);
    let ev = srv_c
        .recv_media_event(Duration::from_millis(800))
        .await
        .expect("rx")
        .expect("some");
    done.notify_one();
    tx_task.await.expect("tx");
    match ev {
        MediaRxEvent::Frame(f) => {
            assert_eq!(f.session_id, 777);
            assert_eq!(f.frame_id, 2);
            assert_eq!(f.payload.len(), 2_500);
        }
        other => panic!("unexpected event for session 777: {other:?}"),
    }
    assert_eq!(srv_c.snapshot_congestion().idr_requests_emitted, 0);
    srv.close();
}
