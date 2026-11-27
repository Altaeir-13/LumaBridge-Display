// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_lines)]

use lumabridge_core::node::{
    LumaBridgeNode, NodeConfig, NodeError, NodeMediaEvent, NodeSignalEvent,
};
use lumabridge_protocol::control::{
    ActiveDisplayConfig, CaptureMode, CloseReasonCode, CodecCapability, ColorFormat,
    DisplayFrameCursor, DisplayMode, DisplayRequest, InputBatch, InputCapabilities, InputEvent,
    LatencyProfile, NodeCapabilities, OsGraphicsPlatform, PermissionUpgradeRequest, Permissions,
    RoleFlags, RotationDeg,
};
use lumabridge_protocol::media::fragmentation::FrameKind;
use lumabridge_protocol::version::CodecId;
use lumabridge_security::authorization::{AuthorizationPolicyContext, InputApprovalDecision};
use lumabridge_security::error::SecurityError;
use lumabridge_security::identity::PeerRole;
use lumabridge_security::pairing::{HumanApprovalDecision, PinPairingWindow, QrTokenStore};
use lumabridge_security::secret::{CheckedOsCryptoRng, PinSecret};
use lumabridge_security::tls::{LUMABRIDGE_ALPN_V1, LUMABRIDGE_PAIR_ALPN_V1};
use lumabridge_security::trust_store::{RevocationReason, TrustStore};
use lumabridge_transport::config::{TransportConfig, TransportKind};
use lumabridge_transport::impairment::{ImpairmentProfile, UdpImpairmentProxy};
use lumabridge_transport::queue::OutboundVideoFrame;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1_700_000_000, |d| d.as_secs())
}

fn caps() -> NodeCapabilities {
    NodeCapabilities {
        roles_mask: RoleFlags::CAN_RECEIVE_VIDEO
            .union(RoleFlags::CAN_EXTEND_SESSION)
            .union(RoleFlags::CAN_SEND_INPUT)
            .union(RoleFlags::CAN_RECEIVE_INPUT),
        platform: OsGraphicsPlatform::Other,
        codecs: vec![CodecCapability {
            codec_id: CodecId::H264,
            can_encode: true,
            can_decode: true,
            hw_accelerated: false,
            max_width: 1920,
            max_height: 1080,
            max_fps_num: 60,
            max_fps_den: 1,
            max_b_frames: 0,
        }],
        max_virtual_displays: 1,
        supports_scale: true,
        supports_rotation: true,
        input_caps_mask: InputCapabilities::POINTER.union(InputCapabilities::KEYBOARD),
    }
}

fn make_node(name: &str, role: PeerRole, kind: TransportKind) -> LumaBridgeNode {
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let now = now_unix();
    LumaBridgeNode::generate(
        NodeConfig {
            friendly_name: name.to_owned(),
            role,
            capabilities: caps(),
            transport_config: TransportConfig {
                kind,
                heartbeat_timeout_ms: 8_000,
                ..TransportConfig::default()
            },
            policy_ctx: AuthorizationPolicyContext::allow_all_v1(),
            session_ttl_secs: 3600,
            resume_ttl_secs: 600,
            max_connections: 16,
        },
        &mut rng,
        now,
        3600,
    )
    .expect("node generate")
}

fn sample_display_req() -> Vec<DisplayRequest> {
    vec![DisplayRequest {
        display_id: 0,
        mode: DisplayMode::Extend,
        width: 1920,
        height: 1080,
        fps_num: 60,
        fps_den: 1,
        scale_milli: 1000,
        rotation_deg: RotationDeg::Deg0,
        codec_pref: vec![CodecId::H264],
        max_bitrate_bps: 12_000_000,
        latency_profile: LatencyProfile::LowLatency,
    }]
}

fn build_active_displays(
    _req: &[DisplayRequest],
    _caps: &NodeCapabilities,
) -> Vec<ActiveDisplayConfig> {
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
    }]
}

#[tokio::test]
async fn spake2_pairing_3attempt_budget_input_authz_resume_and_revocation() {
    let host = make_node("M15Host", PeerRole::Host, TransportKind::QuicDatagram);
    let rx = make_node("M15Rx", PeerRole::Controller, TransportKind::QuicDatagram);
    let now = now_unix();
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");

    let pin_win = PinPairingWindow::new();
    let real_pin = pin_win.open_with_new_pin(&mut rng, now).expect("pin");
    let wrong_pin = PinSecret::new(if real_pin.expose_bytes() == b"99999999" {
        "11111111"
    } else {
        "99999999"
    })
    .expect("wrong pin");

    let pair_srv = rx
        .bind_server(
            TransportKind::QuicDatagram,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            true,
        )
        .await
        .expect("pair bind");
    let pair_addr = pair_srv.local_addr().expect("addr");

    // Exhaust atomic 3-attempt PIN budget with wrong PINs -> must destroy PIN at attempt 3.
    for attempt in 0..3u64 {
        let now_ms = 1_000_000 + attempt * 10_000;
        let accept_fut = async {
            let link = pair_srv
                .accept_link(LUMABRIDGE_PAIR_ALPN_V1, now)
                .await
                .expect("accept");
            rx.accept_pairing_over_link(link, Some(&pin_win), None, now, now_ms, |p| {
                HumanApprovalDecision::Approve {
                    pairing_attempt_id: p.pairing_attempt_id,
                    peer_device_id: p.peer_device_id,
                    granted_base_perms: Permissions::EXTEND_DISPLAY,
                }
            })
            .await
        };
        let init_fut = host.pair_with_pin(
            TransportKind::QuicDatagram,
            pair_addr,
            rx.device_id(),
            &wrong_pin,
            now,
            |p| HumanApprovalDecision::Approve {
                pairing_attempt_id: p.pairing_attempt_id,
                peer_device_id: p.peer_device_id,
                granted_base_perms: Permissions::EXTEND_DISPLAY,
            },
        );
        let (acc_res, init_res) = tokio::join!(accept_fut, init_fut);
        assert!(acc_res.is_err());
        assert!(init_res.is_err());
    }
    assert_eq!(pin_win.remaining_attempts(now), 0);

    // Open fresh PIN window and complete SPAKE2 pairing with local human consent.
    let fresh_pin = pin_win.open_with_new_pin(&mut rng, now).expect("fresh pin");
    let (acc_ok, init_ok) = tokio::join!(
        async {
            let link = pair_srv
                .accept_link(LUMABRIDGE_PAIR_ALPN_V1, now)
                .await
                .expect("accept");
            rx.accept_pairing_over_link(link, Some(&pin_win), None, now, 2_000_000, |p| {
                HumanApprovalDecision::Approve {
                    pairing_attempt_id: p.pairing_attempt_id,
                    peer_device_id: p.peer_device_id,
                    granted_base_perms: Permissions::EXTEND_DISPLAY,
                }
            })
            .await
        },
        host.pair_with_pin(
            TransportKind::QuicDatagram,
            pair_addr,
            rx.device_id(),
            &fresh_pin,
            now,
            |p| HumanApprovalDecision::Approve {
                pairing_attempt_id: p.pairing_attempt_id,
                peer_device_id: p.peer_device_id,
                granted_base_perms: Permissions::EXTEND_DISPLAY,
            }
        )
    );
    let rec_host = acc_ok.expect("acc pair");
    let rec_rx = init_ok.expect("init pair");
    assert!(!rec_host.base_permissions.has_any_input());
    assert!(!rec_rx.base_permissions.has_any_input());
    pair_srv.close();

    // Open Phase 2 mTLS operational session, test default-deny input vs local consent elevation,
    // ClockSync, media + ProtectedBlank, channel-bound SessionResume, and live revocation.
    let op_srv = rx
        .bind_server(
            TransportKind::QuicDatagram,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            false,
        )
        .await
        .expect("op bind");
    let op_addr = op_srv.local_addr().expect("op addr");

    let (r_sess_res, h_sess_res) = tokio::join!(
        async {
            let link = op_srv
                .accept_link(LUMABRIDGE_ALPN_V1, now)
                .await
                .expect("op accept");
            rx.accept_operational_session(link, build_active_displays, now)
                .await
        },
        host.connect_operational_session(
            TransportKind::QuicDatagram,
            op_addr,
            rx.device_id(),
            sample_display_req(),
            Permissions::EXTEND_DISPLAY,
            now,
        )
    );
    let mut rx_sess = r_sess_res.expect("rx sess");
    let mut host_sess = h_sess_res.expect("host sess");
    let sid = host_sess.session_id();
    let initial_tok = host_sess.resume_token().expect("resume tok").clone();

    // Remote input MUST be denied by default before explicit local consent elevation.
    let unauth_batch = InputBatch {
        session_id: sid,
        display_id: 0,
        input_seq: 1,
        events: vec![InputEvent::KeyEvent {
            hid_usage_page: 7,
            hid_usage_id: 4,
            pressed: true,
            modifiers_mask: 0,
        }],
    };
    assert!(rx_sess.send_input_batch(&unauth_batch, now).await.is_err());
    assert!(matches!(
        host_sess.evaluate_inbound_input(&unauth_batch, now),
        NodeSignalEvent::InputDenied { .. }
    ));
    assert_eq!(host_sess.telemetry_summary().unauthorized_input_drops, 1);

    // Spoofed PermissionUpdate from Controller MUST be rejected by Host without elevating rights.
    assert!(matches!(
        host_sess
            .handle_control_or_feedback(
                lumabridge_protocol::control::ControlMessage::PermissionUpdate(
                    lumabridge_protocol::control::PermissionUpdate {
                        session_id: sid,
                        update_seq: 99,
                        effective_perms: Permissions::EXTEND_DISPLAY
                            .union(Permissions::INPUT_KEYBOARD),
                    },
                ),
                1_550,
                now,
            )
            .await,
        Err(NodeError::Security(SecurityError::AuthorizationDenied(_)))
    ));
    assert!(matches!(
        host_sess.evaluate_inbound_input(&unauth_batch, now),
        NodeSignalEvent::InputDenied { .. }
    ));

    // Elevate via explicit local consent on host side and verify PermissionUpdate reaches controller.
    let upgrade_req = PermissionUpgradeRequest {
        session_id: sid,
        request_seq: 1,
        requested_perms: Permissions::INPUT_KEYBOARD,
        reason_text: String::from("Allow keyboard"),
    };
    let upgraded = host_sess
        .handle_permission_upgrade_request(&upgrade_req, now, |p| InputApprovalDecision::Approve {
            session_id: p.session_id,
            request_seq: p.request_seq,
            peer_device_id: p.peer_device_id,
            granted_input_perms: Permissions::INPUT_KEYBOARD,
        })
        .await
        .expect("elevate");
    assert!(upgraded.contains(Permissions::INPUT_KEYBOARD));
    let ctrl_msg = rx_sess.recv_control().await.expect("perm update");
    assert!(matches!(
        rx_sess
            .handle_control_or_feedback(ctrl_msg, 1_000, now)
            .await
            .expect("apply"),
        Some(NodeSignalEvent::PermissionUpdated(_))
    ));
    rx_sess
        .send_input_batch(&unauth_batch, now)
        .await
        .expect("authorized input send");
    let in_msg = host_sess.recv_input().await.expect("recv input");
    assert!(matches!(
        host_sess
            .handle_control_or_feedback(in_msg, 1_500, now)
            .await
            .expect("eval"),
        Some(NodeSignalEvent::InputAccepted {
            accepted_events: 1,
            ..
        })
    ));

    // ClockSyncPing / Pong RTT measurement + 1080p60 frame + ProtectedBlank.
    host_sess.send_clock_sync_ping(1, 500).await.expect("ping");
    let ping_msg = rx_sess.recv_feedback().await.expect("recv ping");
    assert!(matches!(
        rx_sess
            .handle_control_or_feedback(ping_msg, 700, now)
            .await
            .expect("pong tx"),
        Some(NodeSignalEvent::ClockSyncReplied { seq: 1 })
    ));
    let pong_msg = host_sess.recv_feedback().await.expect("recv pong");
    assert!(matches!(
        host_sess
            .handle_control_or_feedback(pong_msg, 1_200, now)
            .await
            .expect("clock sample"),
        Some(NodeSignalEvent::ClockSyncUpdated { .. })
    ));
    assert!(host_sess.telemetry_summary().clock_sync_rtt_us <= 700);

    host_sess
        .send_encoded_frame(OutboundVideoFrame {
            session_id: sid,
            display_id: 0,
            codec_id: CodecId::H264,
            frame_id: 1,
            gop_id: 1,
            capture_ts_us: 1000,
            encode_done_ts_us: 1300,
            kind: FrameKind::Keyframe { chain_reset: true },
            has_codec_config: true,
            mirror_source: false,
            payload: vec![0x65u8; 4_096],
        })
        .await
        .expect("frame 1");
    let rx_ev = rx_sess
        .poll_media_event(Duration::from_millis(500), 1_600)
        .await
        .expect("poll")
        .expect("frame");
    assert!(matches!(rx_ev, NodeMediaEvent::Frame(ref f) if f.frame_id == 1));

    host_sess
        .send_protected_blank(0, 2, 1, 2_000)
        .await
        .expect("blank");
    let blank_ev = rx_sess
        .poll_media_event(Duration::from_millis(500), 2_200)
        .await
        .expect("poll blank")
        .expect("blank");
    assert!(matches!(blank_ev, NodeMediaEvent::ProtectedBlank(_)));

    drop(host_sess);
    drop(rx_sess);

    // Channel-bound SessionResume rotation on a fresh operational connection.
    let (r_res_srv, h_res_cli) = tokio::join!(
        async {
            let link = op_srv
                .accept_link(LUMABRIDGE_ALPN_V1, now)
                .await
                .expect("accept resume");
            rx.accept_operational_session(link, build_active_displays, now)
                .await
        },
        host.resume_operational_session(
            TransportKind::QuicDatagram,
            op_addr,
            rx.device_id(),
            sid,
            &initial_tok,
            vec![DisplayFrameCursor {
                display_id: 0,
                last_good_frame_id: 1,
            }],
            now,
        )
    );
    let resumed_rx = r_res_srv.expect("resumed rx");
    let (resumed_host, resume_resp) = h_res_cli.expect("resume resp");
    assert!(resume_resp.accepted);
    assert!(resume_resp.rotated_resume_token.is_some());
    assert_eq!(resumed_host.session_id(), sid);

    // Live revocation removes peer trust + closes active registered sessions immediately.
    let (_outcome, closed) = rx
        .revoke_peer(
            host.device_id(),
            RevocationReason::UserRemovedDevice,
            now + 5,
        )
        .expect("revoke");
    assert_eq!(closed, 1);
    assert!(rx.trust_store().is_revoked(host.device_id()));
    assert_eq!(rx.connection_registry().active_count(), 0);
    drop(resumed_host);
    drop(resumed_rx);
    op_srv.close();
}

#[tokio::test]
async fn qr_pairing_spki_pin_mitm_rejection_and_single_use_replay() {
    let real_rx = make_node("RealRx", PeerRole::Controller, TransportKind::TcpTls);
    let mitm_srv_node = make_node("MitmNode", PeerRole::Controller, TransportKind::TcpTls);
    let host = make_node("RealHost", PeerRole::Host, TransportKind::TcpTls);
    let now = now_unix();
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");

    let qr_store = QrTokenStore::new();
    let ticket = qr_store
        .issue(
            &mut rng,
            real_rx.device_id(),
            PeerRole::Controller,
            now,
            120,
        )
        .expect("qr issue");

    // Attacker MITM intercepts pairing port with different certificate SPKI -> must abort before PairQrAuth!
    let mitm_srv = mitm_srv_node
        .bind_server(
            TransportKind::TcpTls,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            true,
        )
        .await
        .expect("mitm bind");
    let mitm_addr = mitm_srv.local_addr().expect("mitm addr");

    let (mitm_res, cli_mitm_res) = tokio::join!(
        async {
            let link = mitm_srv
                .accept_link(LUMABRIDGE_PAIR_ALPN_V1, now)
                .await
                .expect("accept");
            mitm_srv_node
                .accept_pairing_over_link(link, None, Some(&qr_store), now, 500, |p| {
                    HumanApprovalDecision::Approve {
                        pairing_attempt_id: p.pairing_attempt_id,
                        peer_device_id: p.peer_device_id,
                        granted_base_perms: Permissions::VIEW_MIRROR,
                    }
                })
                .await
        },
        host.pair_with_qr(TransportKind::TcpTls, mitm_addr, &ticket, now, |p| {
            HumanApprovalDecision::Approve {
                pairing_attempt_id: p.pairing_attempt_id,
                peer_device_id: p.peer_device_id,
                granted_base_perms: Permissions::VIEW_MIRROR,
            }
        })
    );
    assert!(mitm_res.is_err());
    assert!(matches!(
        cli_mitm_res,
        Err(NodeError::Security(SecurityError::IdentityMismatch(_)))
    ));
    mitm_srv.close();

    // Genuine receiver succeeds once; second replay of single-use ticket fails.
    let real_srv = real_rx
        .bind_server(
            TransportKind::TcpTls,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            true,
        )
        .await
        .expect("real bind");
    let real_addr = real_srv.local_addr().expect("real addr");

    let (ok_rx, ok_host) = tokio::join!(
        async {
            let link = real_srv
                .accept_link(LUMABRIDGE_PAIR_ALPN_V1, now)
                .await
                .expect("accept");
            real_rx
                .accept_pairing_over_link(link, None, Some(&qr_store), now, 600, |p| {
                    HumanApprovalDecision::Approve {
                        pairing_attempt_id: p.pairing_attempt_id,
                        peer_device_id: p.peer_device_id,
                        granted_base_perms: Permissions::VIEW_MIRROR,
                    }
                })
                .await
        },
        host.pair_with_qr(TransportKind::TcpTls, real_addr, &ticket, now, |p| {
            HumanApprovalDecision::Approve {
                pairing_attempt_id: p.pairing_attempt_id,
                peer_device_id: p.peer_device_id,
                granted_base_perms: Permissions::VIEW_MIRROR,
            }
        })
    );
    assert!(ok_rx.is_ok());
    assert!(ok_host.is_ok());

    let host2 = make_node("ReplayHost", PeerRole::Host, TransportKind::TcpTls);
    let now2 = now_unix();
    let (rep_rx, rep_host) = tokio::join!(
        async {
            let link = real_srv
                .accept_link(LUMABRIDGE_PAIR_ALPN_V1, now2)
                .await
                .expect("accept2");
            real_rx
                .accept_pairing_over_link(link, None, Some(&qr_store), now2, 700, |p| {
                    HumanApprovalDecision::Approve {
                        pairing_attempt_id: p.pairing_attempt_id,
                        peer_device_id: p.peer_device_id,
                        granted_base_perms: Permissions::VIEW_MIRROR,
                    }
                })
                .await
        },
        host2.pair_with_qr(TransportKind::TcpTls, real_addr, &ticket, now2, |p| {
            HumanApprovalDecision::Approve {
                pairing_attempt_id: p.pairing_attempt_id,
                peer_device_id: p.peer_device_id,
                granted_base_perms: Permissions::VIEW_MIRROR,
            }
        })
    );
    assert!(matches!(
        rep_rx,
        Err(NodeError::Security(SecurityError::QrTokenReusedOrUnknown))
    ));
    assert!(matches!(
        rep_host,
        Err(NodeError::Security(SecurityError::QrTokenReusedOrUnknown))
    ));
    real_srv.close();
}

#[tokio::test]
async fn pairing_error_and_closed_window_enforce_rate_limiter_and_clock_sync_clamps_extremes() {
    use lumabridge_core::telemetry::ClockSyncTracker;
    use lumabridge_protocol::control::ClockSyncPong;

    // 1. Regression test for ClockSyncTracker EWMA arithmetic under extreme u64 timestamps.
    let mut tracker = ClockSyncTracker::new();
    tracker.record_ping(1, 100);
    let s1 = tracker
        .process_pong(
            &ClockSyncPong {
                seq: 1,
                t1_client_mono_us: 100,
                t2_server_recv_us: 0,
                t3_server_send_us: 0,
            },
            2_000,
        )
        .expect("extreme negative offset");
    assert!(s1.clock_offset_us < 0);
    tracker.record_ping(2, 2_100);
    let s2 = tracker
        .process_pong(
            &ClockSyncPong {
                seq: 2,
                t1_client_mono_us: 2_100,
                t2_server_recv_us: u64::MAX,
                t3_server_send_us: u64::MAX,
            },
            2_500,
        )
        .expect("extreme positive offset without i64 subtraction overflow");
    assert_eq!(s2.clock_offset_us, i64::MAX);
    assert!(tracker.smoothed_offset_us().is_some());

    // 2. Regression test for AuthRateLimiter failure accounting on closed PIN window / protocol failure.
    let host = make_node("RateHost", PeerRole::Host, TransportKind::QuicDatagram);
    let rx = make_node("RateRx", PeerRole::Controller, TransportKind::QuicDatagram);
    let now = now_unix();
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let fake_pin = PinSecret::new("12345678").expect("pin");

    let pair_srv = rx
        .bind_server(
            TransportKind::QuicDatagram,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            true,
        )
        .await
        .expect("bind");
    let pair_addr = pair_srv.local_addr().expect("addr");

    // First failed attempt with PIN window = None records a failure -> triggers 1_000 ms backoff.
    let (acc1, init1) = tokio::join!(
        async {
            let link = pair_srv
                .accept_link(LUMABRIDGE_PAIR_ALPN_V1, now)
                .await
                .expect("accept1");
            rx.accept_pairing_over_link(link, None, None, now, 10_000, |_| {
                panic!("must not reach consent")
            })
            .await
        },
        host.pair_with_pin(
            TransportKind::QuicDatagram,
            pair_addr,
            rx.device_id(),
            &fake_pin,
            now,
            |p| HumanApprovalDecision::Approve {
                pairing_attempt_id: p.pairing_attempt_id,
                peer_device_id: p.peer_device_id,
                granted_base_perms: Permissions::EXTEND_DISPLAY,
            }
        )
    );
    assert!(acc1.is_err());
    assert!(init1.is_err());

    // Immediate retry at now_ms = 10_100 MUST be blocked with RateLimited!
    let (acc2, _init2) = tokio::join!(
        async {
            let link = pair_srv
                .accept_link(LUMABRIDGE_PAIR_ALPN_V1, now)
                .await
                .expect("accept2");
            rx.accept_pairing_over_link(link, None, None, now, 10_100, |_| {
                panic!("must not reach consent")
            })
            .await
        },
        host.pair_with_pin(
            TransportKind::QuicDatagram,
            pair_addr,
            rx.device_id(),
            &fake_pin,
            now,
            |p| HumanApprovalDecision::Approve {
                pairing_attempt_id: p.pairing_attempt_id,
                peer_device_id: p.peer_device_id,
                granted_base_perms: Permissions::EXTEND_DISPLAY,
            }
        )
    );
    assert!(matches!(
        acc2,
        Err(NodeError::Security(SecurityError::RateLimited { .. }))
    ));

    // After backoff expires and PIN succeeds, record_success clears backoff cleanly.
    let pin_win = PinPairingWindow::new();
    let real_pin = pin_win.open_with_new_pin(&mut rng, now).expect("pin");
    let (acc_ok, init_ok) = tokio::join!(
        async {
            let link = pair_srv
                .accept_link(LUMABRIDGE_PAIR_ALPN_V1, now)
                .await
                .expect("accept3");
            rx.accept_pairing_over_link(link, Some(&pin_win), None, now, 20_000, |p| {
                HumanApprovalDecision::Approve {
                    pairing_attempt_id: p.pairing_attempt_id,
                    peer_device_id: p.peer_device_id,
                    granted_base_perms: Permissions::EXTEND_DISPLAY,
                }
            })
            .await
        },
        host.pair_with_pin(
            TransportKind::QuicDatagram,
            pair_addr,
            rx.device_id(),
            &real_pin,
            now,
            |p| HumanApprovalDecision::Approve {
                pairing_attempt_id: p.pairing_attempt_id,
                peer_device_id: p.peer_device_id,
                granted_base_perms: Permissions::EXTEND_DISPLAY,
            }
        )
    );
    assert!(acc_ok.is_ok());
    assert!(init_ok.is_ok());
    pair_srv.close();
}

#[tokio::test]
async fn lossy_network_closed_loop_awaiting_idr_and_force_idr_recovery() {
    let mut cfg = TransportConfig {
        kind: TransportKind::QuicDatagram,
        heartbeat_timeout_ms: 8_000,
        ..TransportConfig::default()
    };
    cfg.reassembly_config.fragment_timeout_us = 150_000;
    cfg.recovery_config.idr_request_cooldown_us = 150_000;
    cfg.recovery_config.reorder_gap_timeout_us = 150_000;

    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let now = now_unix();
    let host = LumaBridgeNode::generate(
        NodeConfig {
            friendly_name: String::from("LossHost"),
            role: PeerRole::Host,
            capabilities: caps(),
            transport_config: cfg.clone(),
            policy_ctx: AuthorizationPolicyContext::allow_all_v1(),
            session_ttl_secs: 3600,
            resume_ttl_secs: 600,
            max_connections: 8,
        },
        &mut rng,
        now,
        3600,
    )
    .expect("host");
    let rx = LumaBridgeNode::generate(
        NodeConfig {
            friendly_name: String::from("LossRx"),
            role: PeerRole::Controller,
            capabilities: caps(),
            transport_config: cfg,
            policy_ctx: AuthorizationPolicyContext::allow_all_v1(),
            session_ttl_secs: 3600,
            resume_ttl_secs: 600,
            max_connections: 8,
        },
        &mut rng,
        now,
        3600,
    )
    .expect("rx");

    host.trust_store()
        .insert_newly_paired(
            rx.public_identity(),
            PeerRole::Controller,
            "LossRx",
            Permissions::EXTEND_DISPLAY,
            now,
        )
        .expect("pair1");
    rx.trust_store()
        .insert_newly_paired(
            host.public_identity(),
            PeerRole::Host,
            "LossHost",
            Permissions::EXTEND_DISPLAY,
            now,
        )
        .expect("pair2");

    let srv = rx
        .bind_server(
            TransportKind::QuicDatagram,
            SocketAddr::from(([127, 0, 0, 1], 0)),
            false,
        )
        .await
        .expect("srv");
    let proxy = UdpImpairmentProxy::start(
        srv.local_addr().expect("addr"),
        0x5151_A0A0,
        ImpairmentProfile {
            base_delay_ms: 8,
            jitter_ms: 6,
            drop_ppm: 80_000,
            duplicate_ppm: 40_000,
            reorder_ppm: 80_000,
            extra_reorder_delay_ms: 12,
            bandwidth_cap_bps: None,
            link_cut: false,
            min_drop_payload_bytes: 0,
        },
    )
    .await
    .expect("proxy");

    let (r_sess_res, h_sess_res) = tokio::join!(
        async {
            let link = srv
                .accept_link(LUMABRIDGE_ALPN_V1, now)
                .await
                .expect("accept");
            rx.accept_operational_session(link, build_active_displays, now)
                .await
        },
        host.connect_operational_session(
            TransportKind::QuicDatagram,
            proxy.listen_addr(),
            rx.device_id(),
            sample_display_req(),
            Permissions::EXTEND_DISPLAY,
            now,
        )
    );
    let mut rx_sess = r_sess_res.expect("rx sess");
    let mut host_sess = h_sess_res.expect("host sess");
    let sid = host_sess.session_id();
    let recovered = Arc::new(AtomicBool::new(false));
    let recovered_rx = Arc::clone(&recovered);

    let rx_task = tokio::spawn(async move {
        let start = Instant::now();
        let mut last_fid = 0u32;
        let mut saw_idr = false;
        let mut saw_req = false;
        let deadline = start + Duration::from_secs(7);
        while Instant::now() < deadline {
            let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
            if let Ok(Some(ev)) = rx_sess
                .poll_media_event(Duration::from_millis(60), now_us)
                .await
            {
                match ev {
                    NodeMediaEvent::Frame(f) => {
                        assert!(f.frame_id > last_fid);
                        last_fid = f.frame_id;
                        if f.gop_id >= 2
                            && f.flags
                                .contains(lumabridge_protocol::media::header::VideoFlags::KEYFRAME)
                        {
                            saw_idr = true;
                        }
                        if saw_idr
                            && (saw_req || rx_sess.telemetry_summary().idr_requests > 0)
                            && rx_sess.telemetry_summary().frames_delivered >= 3
                        {
                            recovered_rx.store(true, Ordering::Release);
                            break;
                        }
                    }
                    NodeMediaEvent::ForceIdrRequested(fb) => {
                        assert!(fb.request_idr);
                        saw_req = true;
                    }
                    _ => {}
                }
            }
        }
        let summary = rx_sess.telemetry_summary();
        assert!(saw_idr, "must recover with GOP>=2 IDR");
        assert!(summary.idr_requests > 0 || saw_req);
        assert!(summary.end_to_end.p50_us <= summary.end_to_end.p95_us);
        assert!(summary.end_to_end.p95_us <= summary.end_to_end.p99_us);
        rx_sess
    });

    for fid in 1u32..=12 {
        let is_idr = fid == 1;
        let _ = host_sess
            .send_encoded_frame(OutboundVideoFrame {
                session_id: sid,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: fid,
                gop_id: 1,
                capture_ts_us: u64::from(fid) * 16_000,
                encode_done_ts_us: u64::from(fid) * 16_000 + 500,
                kind: if is_idr {
                    FrameKind::Keyframe { chain_reset: true }
                } else {
                    FrameKind::InterFrame
                },
                has_codec_config: is_idr,
                mirror_source: false,
                payload: vec![0x44u8; 4_800],
            })
            .await;
        tokio::time::sleep(Duration::from_millis(12)).await;
    }

    let fb_deadline = tokio::time::Instant::now() + Duration::from_millis(350);
    let mut saw_remote_force_idr = false;
    while tokio::time::Instant::now() < fb_deadline && !saw_remote_force_idr {
        if let Ok(Ok(msg)) =
            tokio::time::timeout(Duration::from_millis(30), host_sess.recv_feedback()).await
        {
            if matches!(
                host_sess
                    .handle_control_or_feedback(msg, 200_000, now)
                    .await
                    .expect("ctrl"),
                Some(NodeSignalEvent::RemoteForceIdr { .. })
            ) {
                saw_remote_force_idr = true;
            }
        }
    }

    let mut next_fid = 13u32;
    for attempt in 0u16..10 {
        if recovered.load(Ordering::Acquire) {
            break;
        }
        let gop_id = 2 + attempt;
        let _ = host_sess
            .send_encoded_frame(OutboundVideoFrame {
                session_id: sid,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: next_fid,
                gop_id,
                capture_ts_us: u64::from(next_fid) * 16_000,
                encode_done_ts_us: u64::from(next_fid) * 16_000 + 500,
                kind: FrameKind::Keyframe { chain_reset: true },
                has_codec_config: true,
                mirror_source: false,
                payload: vec![0x88u8; 2_800],
            })
            .await;
        next_fid += 1;
        for _ in 0..3 {
            if recovered.load(Ordering::Acquire) {
                break;
            }
            let _ = host_sess
                .send_encoded_frame(OutboundVideoFrame {
                    session_id: sid,
                    display_id: 0,
                    codec_id: CodecId::H264,
                    frame_id: next_fid,
                    gop_id,
                    capture_ts_us: u64::from(next_fid) * 16_000,
                    encode_done_ts_us: u64::from(next_fid) * 16_000 + 500,
                    kind: FrameKind::InterFrame,
                    has_codec_config: false,
                    mirror_source: false,
                    payload: vec![0x22u8; 2_000],
                })
                .await;
            next_fid += 1;
            if let Ok(Ok(msg)) =
                tokio::time::timeout(Duration::from_millis(2), host_sess.recv_feedback()).await
            {
                if matches!(
                    host_sess
                        .handle_control_or_feedback(msg, 300_000, now)
                        .await
                        .expect("ctrl"),
                    Some(NodeSignalEvent::RemoteForceIdr { .. })
                ) {
                    saw_remote_force_idr = true;
                }
            }
            tokio::time::sleep(Duration::from_millis(16)).await;
        }
    }

    let rx_done = rx_task.await.expect("rx join");
    if !saw_remote_force_idr && host_sess.telemetry_summary().idr_requests == 0 {
        let drain_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        while tokio::time::Instant::now() < drain_deadline && !saw_remote_force_idr {
            if let Ok(Ok(msg)) =
                tokio::time::timeout(Duration::from_millis(30), host_sess.recv_feedback()).await
            {
                if matches!(
                    host_sess
                        .handle_control_or_feedback(msg, 350_000, now)
                        .await
                        .expect("ctrl"),
                    Some(NodeSignalEvent::RemoteForceIdr { .. })
                ) {
                    saw_remote_force_idr = true;
                }
            }
        }
    }
    assert!(saw_remote_force_idr || host_sess.telemetry_summary().idr_requests > 0);
    host_sess.close(CloseReasonCode::UserRequested).await;
    drop(rx_done);
    proxy.shutdown().await;
    srv.close();
}

#[test]
fn two_process_1080p60_synthetic_stream_quic_and_tcp() {
    let bin = env!("CARGO_BIN_EXE_lumabridge_node");
    let pid = std::process::id();
    for transport in ["quic-datagram", "tcp-tls"] {
        let dir = std::env::temp_dir().join(format!("lb-m15-two-proc-{transport}-{pid}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let rendezvous = dir.join("rendezvous.txt");
        let rx_json = dir.join("rx_report.json");
        let tx_json = dir.join("tx_report.json");

        let mut rx_child = Command::new(bin)
            .args([
                "--mode",
                "receiver",
                "--transport",
                transport,
                "--frames",
                "180",
                "--fps",
                "60",
                "--endpoint-out",
                rendezvous.to_str().expect("utf8"),
                "--json-report",
                rx_json.to_str().expect("utf8"),
            ])
            .spawn()
            .expect("spawn receiver");

        for _ in 0..100 {
            if rendezvous.exists()
                && std::fs::read_to_string(&rendezvous).is_ok_and(|s| s.split('|').count() == 4)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        let tx_status = Command::new(bin)
            .args([
                "--mode",
                "host",
                "--transport",
                transport,
                "--frames",
                "180",
                "--fps",
                "60",
                "--endpoint-out",
                rendezvous.to_str().expect("utf8"),
                "--json-report",
                tx_json.to_str().expect("utf8"),
            ])
            .status()
            .expect("run host");
        let rx_status = rx_child.wait().expect("wait receiver");
        assert!(tx_status.success(), "{transport} host exited non-zero");
        assert!(rx_status.success(), "{transport} receiver exited non-zero");

        let rx_raw = std::fs::read_to_string(&rx_json).expect("read rx json");
        let tx_raw = std::fs::read_to_string(&tx_json).expect("read tx json");
        assert!(tx_raw.contains("\"frames_sent\": 180"), "{tx_raw}");
        let delivered = rx_raw
            .lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix("\"frames_delivered\": ")
                    .and_then(|rest| rest.trim_end_matches(',').parse::<u64>().ok())
            })
            .expect("frames_delivered present");
        if transport == "tcp-tls" {
            assert_eq!(delivered, 180, "{rx_raw}");
        } else {
            assert!(
                delivered >= 160,
                "expected >=160 delivered over {transport}: {rx_raw}"
            );
        }
        assert!(
            rx_raw.contains("\"timestamp_measurement_errors\": 0"),
            "{rx_raw}"
        );
        assert!(!rx_raw.contains("BEGIN PRIVATE KEY"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
