// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;

use lumabridge_protocol::cbor::{
    CborDecodeMode, CborDecodeOptions, CborMapEncoder, UnknownFieldPolicy,
};
use lumabridge_protocol::control::{
    ActiveDisplayConfig, AuthMode, CaptureMode, ClockSyncPing, ClockSyncPong, CloseReasonCode,
    CodecCapability, ColorFormat, ControlMessage, DiagnosticsSummary, DisplayConfigAction,
    DisplayConfigUpdate, DisplayFrameCursor, DisplayMode, DisplayRequest, ErrorNotice, Heartbeat,
    Hello, HelloAck, HelloAckStatus, InputBatch, InputCapabilities, InputEvent, LatencyProfile,
    MediaFeedback, MsgType, NodeCapabilities, OsGraphicsPlatform, PairCancel, PairCancelReason,
    PairConfirm, PairHello, PairQrAuth, PairSpakeMsg, PermissionUpdate, PermissionUpgradeRequest,
    Permissions, RoleFlags, RotationDeg, SessionClose, SessionOpenRequest, SessionOpenResponse,
    SessionOpenStatus, SessionResumeRequest, SessionResumeResponse, SpakeStep, TouchPhase,
};
use lumabridge_protocol::error::{
    CborError, ErrorCode, FragmentationError, FrameError, ReassemblyError, VideoHeaderError,
};
use lumabridge_protocol::framing::{
    encode_stream_frame, ChannelId, DecodeStep, FrameFlags, FrameHeader, StreamBindingMode,
    StreamFrameDecoder,
};
use lumabridge_protocol::limits::{
    CborLimits, FramingLimits, ReassemblyConfig, RecoveryConfig, CHANNEL_0_MAX_PAYLOAD,
    CHANNEL_1_STREAM_MAX_PAYLOAD, CHANNEL_2_MAX_PAYLOAD, CHANNEL_3_MAX_PAYLOAD,
    DEFAULT_IDR_COOLDOWN_US, FRAME_ID_RENEWAL_THRESHOLD, MAX_FRAGMENTS_PER_FRAME, MAX_FRAME_BYTES,
    MSG_TYPE_MEDIA_VIDEO_FRAGMENT,
};
use lumabridge_protocol::media::fragmentation::{
    decode_media_stream_record, encode_media_stream_record, fragment_frame, FrameKind,
    FrameToFragment, MediaStreamRecordError, PacketBudget,
};
use lumabridge_protocol::media::header::{
    decode_video_packet, VideoFlags, VideoPacketHeader, VIDEO_PACKET_MAGIC,
};
use lumabridge_protocol::media::reassembly::{DiscardReason, Reassembler, ReassemblyOutcome};
use lumabridge_protocol::media::recovery::{GopRecoveryStateMachine, RecoveryState};
use lumabridge_protocol::validation::{
    validate_frame_context, validate_message_context, ConnectionPhase, Direction,
    FrameContextDecision, SequenceTracker, ValidationContext,
};
use lumabridge_protocol::version::{negotiate_version, Alpn, CodecId, ProtocolVersion};

fn sample_pairing_and_handshake_messages() -> Vec<ControlMessage> {
    let dev_a = [0xAAu8; 32];
    let dev_b = [0xBBu8; 32];
    vec![
        ControlMessage::PairHello(PairHello {
            protocol_major: 1,
            protocol_minor: 0,
            device_id: dev_a,
            friendly_name: "Pixel-Tablet".to_owned(),
            auth_mode: AuthMode::PinSpake2,
            spki_ed25519: vec![0x30u8; 44],
        }),
        ControlMessage::PairSpakeMsg(PairSpakeMsg {
            pairing_attempt_id: 42,
            step: SpakeStep::KeyConfirmation,
            spake_payload: vec![0x5Au8; 64],
            key_confirmation: Some(vec![0xC3u8; 32]),
        }),
        ControlMessage::PairQrAuth(PairQrAuth {
            pairing_attempt_id: 43,
            one_time_pairing_token: vec![0x11u8; 32],
            initiator_signature: vec![0x22u8; 64],
        }),
        ControlMessage::PairConfirm(PairConfirm {
            pairing_attempt_id: 42,
            accepted: true,
            granted_base_perms: Permissions::VIEW_MIRROR.union(Permissions::EXTEND_DISPLAY),
            confirm_signature: Some(vec![0x77u8; 64]),
        }),
        ControlMessage::PairCancel(PairCancel {
            pairing_attempt_id: Some(44),
            reason_code: PairCancelReason::UserCancelled,
            detail_ascii: Some("user cancelled dialog".to_owned()),
        }),
        ControlMessage::Hello(Hello {
            protocol_major: 1,
            protocol_minor: 0,
            device_id: dev_a,
            app_version: "1.2.0".to_owned(),
            max_control_bytes: 65_536,
            max_frame_bytes: 8_388_608,
            preferred_mtu: 1200,
        }),
        ControlMessage::HelloAck(HelloAck {
            negotiated_major: 1,
            negotiated_minor: 0,
            device_id: dev_b,
            granted_stored_perms: Permissions::VIEW_MIRROR.union(Permissions::INPUT_POINTER),
            status: HelloAckStatus::Accepted,
            max_control_bytes: 65_536,
            max_frame_bytes: 8_388_608,
            negotiated_mtu: 1200,
        }),
        ControlMessage::NodeCapabilities(NodeCapabilities {
            roles_mask: RoleFlags::CAN_RECEIVE_VIDEO.union(RoleFlags::CAN_SEND_INPUT),
            platform: OsGraphicsPlatform::Android,
            codecs: vec![CodecCapability {
                codec_id: CodecId::H264,
                can_encode: false,
                can_decode: true,
                hw_accelerated: true,
                max_width: 3840,
                max_height: 2160,
                max_fps_num: 120,
                max_fps_den: 1,
                max_b_frames: 0,
            }],
            max_virtual_displays: 2,
            supports_scale: true,
            supports_rotation: true,
            input_caps_mask: InputCapabilities::POINTER
                .union(InputCapabilities::TOUCH)
                .union(InputCapabilities::STYLUS),
        }),
    ]
}

fn sample_session_and_media_messages() -> Vec<ControlMessage> {
    let sid = 0x0102_0304_0506_0708;
    let active_display = ActiveDisplayConfig {
        display_id: 1,
        mode: DisplayMode::Extend,
        width: 2560,
        height: 1600,
        fps_num: 120,
        fps_den: 1,
        scale_milli: 1500,
        rotation_deg: RotationDeg::Deg0,
        codec_id: CodecId::H264,
        color_format: ColorFormat::Nv12_8Bit,
        initial_bitrate_bps: 25_000_000,
        capture_mode: CaptureMode::WindowsIddVirtualMonitor,
    };
    vec![
        ControlMessage::SessionOpenRequest(SessionOpenRequest {
            session_id: sid,
            displays: vec![DisplayRequest {
                display_id: 1,
                mode: DisplayMode::Extend,
                width: 2560,
                height: 1600,
                fps_num: 120,
                fps_den: 1,
                scale_milli: 1500,
                rotation_deg: RotationDeg::Deg0,
                codec_pref: vec![CodecId::H264, CodecId::Hevc],
                max_bitrate_bps: 35_000_000,
                latency_profile: LatencyProfile::LowLatency,
            }],
            requested_perms: Permissions::EXTEND_DISPLAY.union(Permissions::INPUT_POINTER),
        }),
        ControlMessage::SessionOpenResponse(SessionOpenResponse {
            status: SessionOpenStatus::Accepted,
            session_id: sid,
            resume_token: Some(vec![0x99u8; 32]),
            active_displays: vec![active_display.clone()],
            granted_perms: Permissions::EXTEND_DISPLAY.union(Permissions::INPUT_POINTER),
        }),
        ControlMessage::DisplayConfigUpdate(DisplayConfigUpdate {
            session_id: sid,
            update_seq: 1,
            display_id: 1,
            action: DisplayConfigAction::Reconfigure,
            mode: Some(DisplayMode::Mirror),
            width: Some(1920),
            height: Some(1080),
            fps_num: Some(60),
            fps_den: Some(1),
            scale_milli: Some(1000),
            rotation_deg: Some(RotationDeg::Deg90),
            pos_x: Some(-1920),
            pos_y: Some(0),
        }),
        ControlMessage::SessionResumeRequest(SessionResumeRequest {
            session_id: sid,
            resume_token: vec![0x99u8; 32],
            last_good_frames: vec![DisplayFrameCursor {
                display_id: 1,
                last_good_frame_id: 777,
            }],
        }),
        ControlMessage::SessionResumeResponse(SessionResumeResponse {
            accepted: true,
            session_id: sid,
            preserved_displays: vec![active_display],
            idr_requested_displays: vec![1],
        }),
        ControlMessage::SessionClose(SessionClose {
            session_id: sid,
            reason_code: CloseReasonCode::UserRequested,
            teardown_virtual_displays: true,
        }),
        ControlMessage::PermissionUpgradeRequest(PermissionUpgradeRequest {
            session_id: sid,
            request_seq: 1,
            requested_perms: Permissions::INPUT_KEYBOARD.union(Permissions::INPUT_TOUCH),
            reason_text: "enable stylus and touch".to_owned(),
        }),
        ControlMessage::PermissionUpdate(PermissionUpdate {
            session_id: sid,
            update_seq: 2,
            effective_perms: Permissions::EXTEND_DISPLAY
                .union(Permissions::INPUT_POINTER)
                .union(Permissions::INPUT_TOUCH),
        }),
    ]
}

fn sample_feedback_input_and_error_messages() -> Vec<ControlMessage> {
    let sid = 0x0102_0304_0506_0708;
    vec![
        ControlMessage::MediaFeedback(MediaFeedback {
            session_id: sid,
            display_id: 1,
            last_complete_frame_id: 900,
            last_displayed_frame_id: 899,
            broken_gop_id: Some(12),
            request_idr: true,
            decode_p50_us: 1400,
            decode_p95_us: 2800,
            present_p95_us: 3500,
            rx_fps_milli: 120_000,
            packet_loss_ppm: 250,
            jitter_us: 600,
            suggested_bitrate_bps: 18_000_000,
        }),
        ControlMessage::ClockSyncPing(ClockSyncPing {
            seq: 11,
            t1_client_mono_us: 123_456_789,
        }),
        ControlMessage::ClockSyncPong(ClockSyncPong {
            seq: 11,
            t1_client_mono_us: 123_456_789,
            t2_server_recv_us: 123_458_000,
            t3_server_send_us: 123_458_040,
        }),
        ControlMessage::Heartbeat(Heartbeat {
            session_id: Some(sid),
            seq: 5,
            uptime_ms: 99_000,
        }),
        ControlMessage::DiagnosticsSummary(DiagnosticsSummary {
            session_id: sid,
            window_ms: 1000,
            e2e_p50_us: 6500,
            e2e_p95_us: 11_000,
            e2e_p99_us: 14_500,
            cpu_usage_bps: 1250,
            gpu_usage_bps: 2100,
            ram_rss_kib: 131_072,
            backpressure_drops: 0,
            hw_accel_active: true,
        }),
        ControlMessage::InputBatch(InputBatch {
            session_id: sid,
            display_id: 1,
            input_seq: 9,
            events: vec![
                InputEvent::PointerMoveAbs {
                    x_norm: 32_768,
                    y_norm: 16_384,
                },
                InputEvent::PointerButton {
                    button_id: 1,
                    pressed: true,
                },
                InputEvent::PointerScroll {
                    delta_x_milli: 0,
                    delta_y_milli: -120,
                },
                InputEvent::KeyEvent {
                    hid_usage_page: 0x07,
                    hid_usage_id: 0x04,
                    pressed: true,
                    modifiers_mask: 0x02,
                },
                InputEvent::TouchContact {
                    contact_id: 0,
                    phase: TouchPhase::Down,
                    x_norm: 1000,
                    y_norm: 2000,
                    pressure_norm: 500,
                },
                InputEvent::StylusEvent {
                    x_norm: 4000,
                    y_norm: 5000,
                    pressure_norm: 30_000,
                    tilt_x_deg: -15,
                    tilt_y_deg: 25,
                    buttons_mask: 1,
                },
            ],
        }),
        ControlMessage::ErrorNotice(ErrorNotice {
            code: ErrorCode::PermissionDenied,
            fatal: false,
            related_msg_type: MsgType::InputBatch.as_u16(),
            context_ascii: "missing keyboard permission".to_owned(),
        }),
    ]
}

fn sample_all_23_messages() -> Vec<ControlMessage> {
    let mut all = sample_pairing_and_handshake_messages();
    all.extend(sample_session_and_media_messages());
    all.extend(sample_feedback_input_and_error_messages());
    all
}

#[test]
fn all_23_control_messages_roundtrip_and_deterministic_encoding() {
    let msgs = sample_all_23_messages();
    assert_eq!(msgs.len(), 23);

    let mut scratch = Vec::with_capacity(512);
    for msg in &msgs {
        let encoded_a = msg.encode_cbor().expect("canonical CBOR encode");
        scratch.clear();
        msg.encode_cbor_into(&mut scratch).expect("into encode");
        assert_eq!(encoded_a, scratch);

        let decoded =
            ControlMessage::decode_cbor(msg.msg_type(), &encoded_a, CborDecodeOptions::default())
                .expect("round-trip decode");
        assert_eq!(&decoded, msg);

        let encoded_b = decoded.encode_cbor().expect("re-encode deterministic");
        assert_eq!(
            encoded_a,
            encoded_b,
            "non-deterministic {:?}",
            msg.msg_type()
        );
    }
}

#[test]
fn control_message_semantic_and_privacy_invariants() {
    // PairConfirm MUST never grant remote input permissions.
    let bad_confirm = ControlMessage::PairConfirm(PairConfirm {
        pairing_attempt_id: 1,
        accepted: true,
        granted_base_perms: Permissions::VIEW_MIRROR.union(Permissions::INPUT_POINTER),
        confirm_signature: Some(vec![0xAA; 64]),
    });
    assert!(matches!(
        bad_confirm.encode_cbor(),
        Err(CborError::ValueOutOfRange(_))
    ));

    // ErrorNotice forbids non-printable ASCII.
    let bad_err = ControlMessage::ErrorNotice(ErrorNotice {
        code: ErrorCode::InvalidFraming,
        fatal: true,
        related_msg_type: 0x0200,
        context_ascii: "bad\nline".to_owned(),
    });
    assert!(matches!(
        bad_err.encode_cbor(),
        Err(CborError::ValueOutOfRange(_))
    ));

    // MediaFeedback enforces last_displayed_frame_id <= last_complete_frame_id.
    let bad_feedback = ControlMessage::MediaFeedback(MediaFeedback {
        session_id: 1,
        display_id: 1,
        last_complete_frame_id: 10,
        last_displayed_frame_id: 11,
        broken_gop_id: None,
        request_idr: false,
        decode_p50_us: 100,
        decode_p95_us: 200,
        present_p95_us: 300,
        rx_fps_milli: 60_000,
        packet_loss_ppm: 0,
        jitter_us: 10,
        suggested_bitrate_bps: 1_000_000,
    });
    assert!(matches!(
        bad_feedback.encode_cbor(),
        Err(CborError::ValueOutOfRange(_))
    ));

    // Privacy-redacted Debug MUST NOT expose secrets or coordinates/keycodes.
    let mut all_debug = String::new();
    for m in &sample_all_23_messages() {
        let _ = writeln!(all_debug, "{m:?}");
    }
    assert!(all_debug.contains("[REDACTED]"));
    assert!(!all_debug.contains("32768"));
    assert!(!all_debug.contains("hid_usage_id"));
    assert!(!all_debug.contains("153, 153"));
}

#[test]
fn restricted_cbor_rejects_forbidden_types_duplicates_limits_and_modes() {
    let opts = CborDecodeOptions::default();

    // 1. Float in map: {1: 1.5, 2: 10}
    let float_cbor = [0xA2, 0x01, 0xF9, 0x3E, 0x00, 0x02, 0x0A];
    assert_eq!(
        ControlMessage::decode_cbor(MsgType::ClockSyncPing, &float_cbor, opts),
        Err(CborError::ForbiddenType("CBOR float"))
    );

    // 2. Semantic tag wrapping map: 0xC6 (tag 6) + {1: 1, 2: 10}
    let tag_cbor = [0xC6, 0xA2, 0x01, 0x01, 0x02, 0x0A];
    assert_eq!(
        ControlMessage::decode_cbor(MsgType::ClockSyncPing, &tag_cbor, opts),
        Err(CborError::ForbiddenType("CBOR tag"))
    );

    // 3. Duplicate map key: {1: 1, 1: 2, 2: 10}
    let dup_key_cbor = [0xA3, 0x01, 0x01, 0x01, 0x02, 0x02, 0x0A];
    assert_eq!(
        ControlMessage::decode_cbor(MsgType::ClockSyncPing, &dup_key_cbor, opts),
        Err(CborError::DuplicateMapKey)
    );
    let relaxed = CborDecodeOptions {
        mode: CborDecodeMode::RelaxedOrderAndWidth,
        unknown_fields: UnknownFieldPolicy::SkipBounded,
        limits: CborLimits::default(),
    };
    assert_eq!(
        ControlMessage::decode_cbor(MsgType::ClockSyncPing, &dup_key_cbor, relaxed),
        Err(CborError::DuplicateMapKey)
    );

    // 4. Indefinite map and 5. Negative map key
    let indef_cbor = [0xBF, 0x01, 0x01, 0x02, 0x0A, 0xFF];
    assert_eq!(
        ControlMessage::decode_cbor(MsgType::ClockSyncPing, &indef_cbor, opts),
        Err(CborError::IndefiniteLengthForbidden)
    );
    let neg_key = [0xA2, 0x20, 0x01, 0x02, 0x0A];
    assert!(ControlMessage::decode_cbor(MsgType::ClockSyncPing, &neg_key, opts).is_err());

    // 6. Invalid UTF-8 in ErrorNotice context_ascii (keys 1..=4)
    let bad_utf8 = [
        0xA4, 0x01, 0x02, 0x02, 0xF4, 0x03, 0x19, 0x07, 0x00, 0x04, 0x61, 0xFF,
    ];
    assert_eq!(
        ControlMessage::decode_cbor(MsgType::ErrorNotice, &bad_utf8, opts),
        Err(CborError::InvalidUtf8)
    );

    // 7. UnknownFieldPolicy::Reject vs SkipBounded overflow (> max_unknown_fields_per_map)
    let mut buf = Vec::new();
    let mut enc = CborMapEncoder::start(&mut buf, 5).expect("start map");
    enc.put_u64(1, 99).expect("k1");
    enc.put_u64(2, 500).expect("k2");
    enc.put_u64(10, 1).expect("u1");
    enc.put_u64(11, 2).expect("u2");
    enc.put_u64(12, 3).expect("u3");
    enc.finish().expect("finish map");

    assert_eq!(
        ControlMessage::decode_cbor(
            MsgType::ClockSyncPing,
            &buf,
            CborDecodeOptions {
                unknown_fields: UnknownFieldPolicy::Reject,
                ..opts
            }
        ),
        Err(CborError::TypeMismatch("unknown map field rejected"))
    );
    let tight_unknown = CborDecodeOptions {
        limits: CborLimits {
            max_unknown_fields_per_map: 2,
            ..CborLimits::default()
        },
        ..opts
    };
    assert_eq!(
        ControlMessage::decode_cbor(MsgType::ClockSyncPing, &buf, tight_unknown),
        Err(CborError::LimitExceeded(
            "max_unknown_fields_per_map exceeded"
        ))
    );

    // 8. Exceeding max_depth via deeply nested unknown array under key 99
    let mut deep_unknown = vec![0xA3, 0x01, 0x01, 0x02, 0x02, 0x18, 0x63];
    deep_unknown.extend(std::iter::repeat_n(0x81, 12));
    deep_unknown.push(0x00);
    assert_eq!(
        ControlMessage::decode_cbor(MsgType::ClockSyncPing, &deep_unknown, opts),
        Err(CborError::DepthExceeded)
    );
}

#[test]
fn stream_framing_limits_reject_before_allocation() {
    let limits = FramingLimits::default();
    let ceilings = [
        (ChannelId::Control, 0x0200, CHANNEL_0_MAX_PAYLOAD),
        (
            ChannelId::Media,
            MSG_TYPE_MEDIA_VIDEO_FRAGMENT,
            CHANNEL_1_STREAM_MAX_PAYLOAD,
        ),
        (ChannelId::Feedback, 0x0503, CHANNEL_2_MAX_PAYLOAD),
        (ChannelId::Input, 0x0600, CHANNEL_3_MAX_PAYLOAD),
    ];

    for (ch, msg_type, max_len) in ceilings {
        let hdr_ok = FrameHeader {
            frame_len: u32::try_from(max_len).expect("fits u32"),
            channel_id: ch,
            msg_type,
            flags: FrameFlags::NONE,
        };
        assert_eq!(
            FrameHeader::decode(&hdr_ok.encode(), &limits).expect("exact limit"),
            hdr_ok
        );

        let hdr_over = FrameHeader {
            frame_len: u32::try_from(max_len + 1).expect("fits u32"),
            channel_id: ch,
            msg_type,
            flags: FrameFlags::NONE,
        };
        let mut dec = StreamFrameDecoder::new(limits, StreamBindingMode::Multiplexed).expect("dec");
        let err = dec.step_slice(&hdr_over.encode()).expect_err("must reject");
        assert!(matches!(err, FrameError::FrameTooLarge { .. }));
        assert_eq!(dec.buffered_bytes(), 0);
        assert!(dec.is_poisoned());
    }

    let small_ch1 = FrameHeader {
        frame_len: 43,
        channel_id: ChannelId::Media,
        msg_type: MSG_TYPE_MEDIA_VIDEO_FRAGMENT,
        flags: FrameFlags::NONE,
    };
    assert_eq!(
        FrameHeader::decode(&small_ch1.encode(), &limits),
        Err(FrameError::MediaStreamRecordTooSmall(43))
    );

    let wrong_ch1_ty = FrameHeader {
        frame_len: 48,
        channel_id: ChannelId::Media,
        msg_type: MsgType::Hello.as_u16(),
        flags: FrameFlags::NONE,
    };
    assert_eq!(
        FrameHeader::decode(&wrong_ch1_ty.encode(), &limits),
        Err(FrameError::InvalidMediaStreamMsgType(
            MsgType::Hello.as_u16()
        ))
    );
}

#[test]
fn stream_framing_incremental_eof_and_channel_isolation() {
    let limits = FramingLimits::default();
    let frame_a = encode_stream_frame(
        ChannelId::Control,
        MsgType::Hello.as_u16(),
        FrameFlags::MUST_UNDERSTAND,
        b"alpha-ctrl",
        &limits,
    )
    .expect("encode A");
    let frame_b = encode_stream_frame(
        ChannelId::Feedback,
        MsgType::Heartbeat.as_u16(),
        FrameFlags::NONE,
        b"beta-hb",
        &limits,
    )
    .expect("encode B");
    let mut wire = Vec::new();
    wire.extend_from_slice(&frame_a);
    wire.extend_from_slice(&frame_b);

    for chunk_size in [1usize, 3] {
        let mut dec = StreamFrameDecoder::new(limits, StreamBindingMode::Multiplexed).expect("dec");
        let mut out = Vec::new();
        for ch in wire.chunks(chunk_size) {
            dec.feed(ch).expect("feed");
            while let Some(f) = dec.next_frame().expect("next") {
                out.push(f);
            }
        }
        dec.finish_eof().expect("clean EOF");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].payload, b"alpha-ctrl");
        assert_eq!(out[1].payload, b"beta-hb");
    }

    let mut eof_dec = StreamFrameDecoder::new(limits, StreamBindingMode::Multiplexed).expect("dec");
    eof_dec.feed(&frame_a[..frame_a.len() - 1]).expect("feed");
    assert!(eof_dec.next_frame().expect("need more").is_none());
    assert_eq!(
        eof_dec.finish_eof(),
        Err(FrameError::UnexpectedEofInPayload)
    );

    let mut bound =
        StreamFrameDecoder::new(limits, StreamBindingMode::UnboundSingleChannel).expect("dec");
    let step = bound.step_slice(&frame_a).expect("first binds Ch0");
    assert!(matches!(step, DecodeStep::Frame { .. }));
    assert_eq!(
        bound.binding_mode(),
        StreamBindingMode::BoundSingleChannel(ChannelId::Control)
    );
    assert_eq!(
        bound.step_slice(&frame_b),
        Err(FrameError::ChannelSwitchForbidden {
            bound: 0,
            observed: 2
        })
    );
}

#[test]
fn media_stream_record_encode_and_decode() {
    let limits = FramingLimits::default();
    let budget = PacketBudget::for_media_stream(&limits).expect("stream budget");
    let frame = FrameToFragment {
        session_id: 55,
        display_id: 2,
        codec_id: CodecId::Hevc,
        frame_id: 101,
        gop_id: 4,
        capture_ts_us: 10_000,
        encode_done_ts_us: 10_500,
        kind: FrameKind::Keyframe { chain_reset: true },
        has_codec_config: true,
        mirror_source: false,
        payload: &[0x42u8; 256],
    };
    let packets = fragment_frame(&frame, budget).expect("fragment fits 16 KiB");
    assert_eq!(packets.len(), 1);

    let wire =
        encode_media_stream_record(&packets[0], FrameFlags::NONE, &limits).expect("wrap 8B header");
    let mut dec = StreamFrameDecoder::new(
        limits,
        StreamBindingMode::BoundSingleChannel(ChannelId::Media),
    )
    .expect("dec");
    dec.feed(&wire).expect("feed");
    let raw = dec.next_frame().expect("ok").expect("complete");
    let (hdr, body) = decode_media_stream_record(&raw, &limits).expect("valid media record");
    assert_eq!(hdr.frame_id, 101);
    assert_eq!(body, &[0x42u8; 256]);

    let wrong = encode_stream_frame(
        ChannelId::Control,
        MsgType::Hello.as_u16(),
        FrameFlags::NONE,
        &[1, 2, 3],
        &limits,
    )
    .expect("ctrl");
    let mut dec2 = StreamFrameDecoder::new(limits, StreamBindingMode::Multiplexed).expect("d2");
    dec2.feed(&wrong).expect("f");
    let raw_ctrl = dec2.next_frame().expect("ok").expect("c");
    assert_eq!(
        decode_media_stream_record(&raw_ctrl, &limits),
        Err(MediaStreamRecordError::Framing(
            FrameError::InvalidChannelId(0)
        ))
    );
}

#[test]
fn contextual_validation_enforces_alpn_and_unknown_extension_isolation() {
    let pair_ctx = ValidationContext {
        alpn: Alpn::Pairing,
        channel: ChannelId::Control,
        direction: Direction::InitiatorToAcceptor,
        phase: ConnectionPhase::PairingOpen,
        effective_perms: Permissions::NONE,
        active_session_id: None,
    };
    let pair_hello_hdr = FrameHeader {
        frame_len: 12,
        channel_id: ChannelId::Control,
        msg_type: MsgType::PairHello.as_u16(),
        flags: FrameFlags::MUST_UNDERSTAND,
    };
    assert_eq!(
        validate_frame_context(&pair_ctx, pair_hello_hdr),
        FrameContextDecision::AllowKnown(MsgType::PairHello)
    );

    let hello_hdr = FrameHeader {
        frame_len: 12,
        channel_id: ChannelId::Control,
        msg_type: MsgType::Hello.as_u16(),
        flags: FrameFlags::NONE,
    };
    assert!(matches!(
        validate_frame_context(&pair_ctx, hello_hdr),
        FrameContextDecision::Reject(e) if e.code == ErrorCode::InvalidFraming
    ));

    // Unknown msg WITHOUT MUST_UNDERSTAND MUST still be rejected on pairing ALPN!
    let unknown_opt = FrameHeader {
        frame_len: 12,
        channel_id: ChannelId::Control,
        msg_type: 0x7FFF,
        flags: FrameFlags::NONE,
    };
    assert!(matches!(
        validate_frame_context(&pair_ctx, unknown_opt),
        FrameContextDecision::Reject(e) if e.code == ErrorCode::InvalidFraming
    ));

    let mut op_ctx = ValidationContext {
        alpn: Alpn::Operational,
        channel: ChannelId::Input,
        direction: Direction::InitiatorToAcceptor,
        phase: ConnectionPhase::OperationalAuthenticated,
        effective_perms: Permissions::EXTEND_DISPLAY,
        active_session_id: None,
    };
    let ch3_unknown_opt = FrameHeader {
        frame_len: 16,
        channel_id: ChannelId::Input,
        msg_type: 0x7FFF,
        flags: FrameFlags::NONE,
    };
    assert!(matches!(
        validate_frame_context(&op_ctx, ch3_unknown_opt),
        FrameContextDecision::Reject(_)
    ));

    op_ctx.phase = ConnectionPhase::OperationalSessionActive;
    op_ctx.active_session_id = Some(9);
    op_ctx.effective_perms = Permissions::INPUT_POINTER;
    assert_eq!(
        validate_frame_context(&op_ctx, ch3_unknown_opt),
        FrameContextDecision::IgnoreUnknownOptional
    );

    let ch3_unknown_must = FrameHeader {
        flags: FrameFlags::MUST_UNDERSTAND,
        ..ch3_unknown_opt
    };
    assert!(matches!(
        validate_frame_context(&op_ctx, ch3_unknown_must),
        FrameContextDecision::Reject(e) if e.code == ErrorCode::UnsupportedFeature
    ));
}

#[test]
fn contextual_validation_input_permissions_heartbeat_and_sequence_tracker() {
    let mut op_ctx = ValidationContext {
        alpn: Alpn::Operational,
        channel: ChannelId::Input,
        direction: Direction::InitiatorToAcceptor,
        phase: ConnectionPhase::OperationalSessionActive,
        effective_perms: Permissions::INPUT_POINTER,
        active_session_id: Some(9),
    };
    let batch = ControlMessage::InputBatch(InputBatch {
        session_id: 9,
        display_id: 1,
        input_seq: 1,
        events: vec![InputEvent::KeyEvent {
            hid_usage_page: 0x07,
            hid_usage_id: 0x04,
            pressed: true,
            modifiers_mask: 0,
        }],
    });
    assert!(matches!(
        validate_message_context(&op_ctx, &batch),
        Err(e) if e.code == ErrorCode::PermissionDenied
    ));

    op_ctx.effective_perms = Permissions::INPUT_KEYBOARD;
    assert!(validate_message_context(&op_ctx, &batch).is_ok());

    op_ctx.active_session_id = Some(10);
    assert!(matches!(
        validate_message_context(&op_ctx, &batch),
        Err(e) if e.code == ErrorCode::SessionNotFound
    ));

    let hb_ch0 = ValidationContext {
        channel: ChannelId::Control,
        ..op_ctx
    };
    let hb_hdr = FrameHeader {
        frame_len: 10,
        channel_id: ChannelId::Control,
        msg_type: MsgType::Heartbeat.as_u16(),
        flags: FrameFlags::NONE,
    };
    assert!(matches!(
        validate_frame_context(&hb_ch0, hb_hdr),
        FrameContextDecision::Reject(e) if e.code == ErrorCode::InvalidFraming
    ));

    let mut seq = SequenceTracker::new();
    assert!(seq.accept(0).is_err());
    seq.accept(1).expect("1");
    seq.accept(5).expect("5");
    assert_eq!(seq.last_accepted(), 5);
    assert!(seq.accept(5).is_err());
    assert!(seq.accept(4).is_err());
    seq.accept(u64::MAX).expect("max");
    assert!(seq.accept(u64::MAX).is_err());
}

#[test]
fn version_negotiation_separates_major_mismatch() {
    let local = ProtocolVersion { major: 1, minor: 2 };
    let remote = ProtocolVersion { major: 1, minor: 0 };
    assert_eq!(
        negotiate_version(local, remote),
        Ok(ProtocolVersion { major: 1, minor: 0 })
    );
    assert_eq!(
        negotiate_version(local, ProtocolVersion { major: 2, minor: 0 }),
        Err(ErrorCode::UnsupportedVersion)
    );
}

#[test]
fn video_header_validation_mtu_budget_and_fragmentation_limits() {
    assert_eq!(
        PacketBudget::new(44, 1500),
        Err(FragmentationError::InvalidBudget(44))
    );

    let budget = PacketBudget::new(1136, 1500).expect("1136 - 44 = 1092");
    assert_eq!(budget.max_fragment_payload, 1092);
    assert_eq!(
        budget.max_representable_frame_bytes,
        usize::from(MAX_FRAGMENTS_PER_FRAME) * 1092
    );

    let large_budget = PacketBudget::new(4096, 8192).expect("4052 payload");
    assert_eq!(large_budget.max_representable_frame_bytes, MAX_FRAME_BYTES);

    let tiny_budget = PacketBudget::new(200, 1500).expect("156 payload");
    let too_big_payload = vec![0x55u8; tiny_budget.max_representable_frame_bytes + 1];
    let frame = FrameToFragment {
        session_id: 1,
        display_id: 0,
        codec_id: CodecId::Av1,
        frame_id: 1,
        gop_id: 0,
        capture_ts_us: 100,
        encode_done_ts_us: 200,
        kind: FrameKind::InterFrame,
        has_codec_config: false,
        mirror_source: false,
        payload: &too_big_payload,
    };
    assert!(matches!(
        fragment_frame(&frame, tiny_budget),
        Err(FragmentationError::FrameNotRepresentable { .. })
    ));

    let valid_hdr = VideoPacketHeader {
        flags: VideoFlags::KEYFRAME.union(VideoFlags::END_OF_FRAME),
        session_id: 1,
        display_id: 0,
        codec_id: CodecId::H264,
        frame_id: 1,
        gop_id: 0,
        frag_index: 0,
        frag_count: 1,
        payload_len: 10,
        capture_ts_us: 500,
        encode_done_ts_us: 500,
    };
    assert_eq!(
        u16::from_be_bytes([valid_hdr.encode()[0], valid_hdr.encode()[1]]),
        VIDEO_PACKET_MAGIC
    );

    let mut hdr_no_eof = valid_hdr;
    hdr_no_eof.flags = VideoFlags::KEYFRAME;
    assert_eq!(
        hdr_no_eof.validate(100),
        Err(VideoHeaderError::EndOfFrameFlagMismatch)
    );

    let mut hdr_chain = valid_hdr;
    hdr_chain.flags = VideoFlags::CHAIN_RESET.union(VideoFlags::END_OF_FRAME);
    assert_eq!(
        hdr_chain.validate(100),
        Err(VideoHeaderError::ChainResetWithoutKeyframe)
    );

    let mut hdr_blank_key = valid_hdr;
    hdr_blank_key.flags = VideoFlags::PROTECTED_BLANK
        .union(VideoFlags::KEYFRAME)
        .union(VideoFlags::END_OF_FRAME);
    hdr_blank_key.payload_len = 0;
    assert!(matches!(
        hdr_blank_key.validate(100),
        Err(VideoHeaderError::ProtectedBlankInvalidFlags(_))
    ));

    let mut hdr_ts = valid_hdr;
    hdr_ts.encode_done_ts_us = 499;
    assert_eq!(
        hdr_ts.validate(100),
        Err(VideoHeaderError::TimestampRegression)
    );

    let mut pkt = valid_hdr.encode().to_vec();
    pkt.extend_from_slice(&[1, 2, 3]);
    assert!(matches!(
        decode_video_packet(&pkt, 1024),
        Err(VideoHeaderError::PayloadLenMismatch { .. })
    ));
}

#[test]
fn reassembly_ordering_duplicates_conflicts_and_cleanup() {
    let cfg = ReassemblyConfig {
        max_frame_bytes: 64 * 1024,
        max_display_bytes: 128 * 1024,
        max_session_bytes: 256 * 1024,
        max_global_bytes: 512 * 1024,
        max_total_displays: 4,
        max_pending_frames: 8,
        ..ReassemblyConfig::default()
    };
    cfg.validate().expect("valid cfg");
    let mut reasm = Reassembler::new(cfg).expect("init");
    let budget = PacketBudget::new(1044, 1500).expect("1000B fragments");

    let payload: Vec<u8> = (0..2500u32).map(|i| (i % 251) as u8).collect();
    let pkts = fragment_frame(
        &FrameToFragment {
            session_id: 1,
            display_id: 0,
            codec_id: CodecId::H264,
            frame_id: 10,
            gop_id: 1,
            capture_ts_us: 1000,
            encode_done_ts_us: 1200,
            kind: FrameKind::Keyframe { chain_reset: true },
            has_codec_config: true,
            mirror_source: false,
            payload: &payload,
        },
        budget,
    )
    .expect("3 fragments");
    assert_eq!(pkts.len(), 3);

    let rep2 = reasm
        .ingest_packet(&pkts[2], budget.effective_lbwp_packet_budget, 10_000)
        .expect("pkt2");
    assert!(matches!(
        rep2.outcome,
        ReassemblyOutcome::Incomplete {
            received_fragments: 1,
            total_fragments: 3,
            ..
        }
    ));
    let bytes_after_one = reasm.stats().global_total_bytes();
    assert!(bytes_after_one > 0 && bytes_after_one < 2000);

    let rep2_dup = reasm
        .ingest_packet(&pkts[2], budget.effective_lbwp_packet_budget, 10_100)
        .expect("dup");
    assert_eq!(
        rep2_dup.outcome,
        ReassemblyOutcome::DuplicateIgnored { frame_id: 10 }
    );
    assert_eq!(reasm.stats().global_total_bytes(), bytes_after_one);

    let p11 = fragment_frame(
        &FrameToFragment {
            session_id: 1,
            display_id: 0,
            codec_id: CodecId::H264,
            frame_id: 11,
            gop_id: 1,
            capture_ts_us: 2000,
            encode_done_ts_us: 2200,
            kind: FrameKind::InterFrame,
            has_codec_config: false,
            mirror_source: false,
            payload: &[0xAAu8; 2000],
        },
        budget,
    )
    .expect("2 frags");
    reasm.ingest_packet(&p11[0], 1044, 10_200).expect("f11-0");
    let mut conflicting = p11[0].clone();
    *conflicting.last_mut().expect("nonempty") ^= 0xFF;
    let rep_conf = reasm
        .ingest_packet(&conflicting, 1044, 10_300)
        .expect("conf");
    assert!(matches!(rep_conf.outcome, ReassemblyOutcome::Rejected(_)));
    assert_eq!(rep_conf.discarded.len(), 1);
    assert_eq!(
        rep_conf.discarded[0].reason,
        DiscardReason::ConflictingPayload
    );
    let rep_stale = reasm.ingest_packet(&p11[1], 1044, 10_400).expect("stale");
    assert_eq!(
        rep_stale.outcome,
        ReassemblyOutcome::StaleIgnored { frame_id: 11 }
    );

    reasm.ingest_packet(&pkts[0], 1044, 10_500).expect("f10-0");
    let done = reasm.ingest_packet(&pkts[1], 1044, 10_600).expect("f10-1");
    match done.outcome {
        ReassemblyOutcome::Completed(f) => {
            assert_eq!(f.payload, payload);
            assert!(f.flags.contains(VideoFlags::HAS_CODEC_CONFIG));
            assert!(f.flags.contains(VideoFlags::KEYFRAME));
        }
        other => panic!("expected Completed, got {other:?}"),
    }
    assert_eq!(reasm.stats().global_total_bytes(), 0);
}

#[test]
fn reassembly_window_near_cap_stress_and_expiry_release_all_memory() {
    let cfg = ReassemblyConfig {
        max_incomplete_frames_per_display: 4,
        max_frame_bytes: 8 * 1024 * 1024,
        max_display_bytes: 8 * 1024 * 1024,
        max_session_bytes: 8 * 1024 * 1024,
        max_global_bytes: 8 * 1024 * 1024,
        max_total_displays: 4,
        max_pending_frames: 6,
        metadata_overhead_per_fragment_bytes: 64,
        fragment_timeout_us: 150_000,
    };
    cfg.validate().expect("ok");
    let mut reasm = Reassembler::new(cfg).expect("init");

    // Claiming frag_count=4096 with 100B fragment must NOT preallocate 8 MiB!
    let spoof_hdr = VideoPacketHeader {
        flags: VideoFlags::NONE,
        session_id: 1,
        display_id: 0,
        codec_id: CodecId::H264,
        frame_id: 1,
        gop_id: 1,
        frag_index: 0,
        frag_count: 4096,
        payload_len: 100,
        capture_ts_us: 100,
        encode_done_ts_us: 100,
    };
    reasm.ingest_decoded(spoof_hdr, &[0x11; 100], 1_000);
    assert_eq!(reasm.stats().global_payload_bytes, 100);
    assert_eq!(reasm.stats().global_metadata_bytes, 64);

    for fid in 2..=5u32 {
        let mut h = spoof_hdr;
        h.frame_id = fid;
        h.frag_count = 2;
        let rep = reasm.ingest_decoded(h, &[0x22; 100], 2_000);
        if fid == 5 {
            assert_eq!(rep.discarded.len(), 1);
            assert_eq!(rep.discarded[0].frame_id, 1);
            assert_eq!(rep.discarded[0].reason, DiscardReason::EvictedByWindow);
        }
    }
    assert_eq!(reasm.stats().total_pending_frames, 4);

    let expired = reasm.expire(2_000 + 150_000);
    assert_eq!(expired.len(), 4);
    assert_eq!(reasm.stats().global_total_bytes(), 0);

    // Near-capacity 7.5 MB frame reassembly under 8 MiB budget + second session budget cap check.
    let big_budget = PacketBudget::new(8192, 8192).expect("8148 payload");
    let near_max = 7_500_000usize;
    let big_payload = vec![0x7Du8; near_max];
    let pkts = fragment_frame(
        &FrameToFragment {
            session_id: 9,
            display_id: 0,
            codec_id: CodecId::H264,
            frame_id: 100,
            gop_id: 1,
            capture_ts_us: 5000,
            encode_done_ts_us: 6000,
            kind: FrameKind::Keyframe { chain_reset: false },
            has_codec_config: false,
            mirror_source: false,
            payload: &big_payload,
        },
        big_budget,
    )
    .expect("fragments");

    for p in &pkts[..pkts.len() - 1] {
        let r = reasm.ingest_packet(p, 8192, 50_000).expect("ingest");
        assert!(matches!(r.outcome, ReassemblyOutcome::Incomplete { .. }));
    }
    assert!(reasm.stats().global_total_bytes() > 7_000_000);

    let mut hit_global_cap = false;
    for idx in 0..20u16 {
        let h = VideoPacketHeader {
            flags: VideoFlags::NONE,
            session_id: 10,
            display_id: 0,
            codec_id: CodecId::H264,
            frame_id: 1,
            gop_id: 1,
            frag_index: idx,
            frag_count: 25,
            payload_len: u16::MAX,
            capture_ts_us: 100,
            encode_done_ts_us: 100,
        };
        let chunk = vec![0x33u8; u16::MAX as usize];
        let rep = reasm.ingest_decoded(h, &chunk, 51_000);
        if let ReassemblyOutcome::Rejected(err) = rep.outcome {
            assert!(matches!(err, ReassemblyError::GlobalBudgetExceeded));
            hit_global_cap = true;
            break;
        }
        assert!(reasm.stats().global_total_bytes() <= cfg.max_global_bytes);
    }
    assert!(hit_global_cap);

    reasm.remove_session(10);
    let final_rep = reasm
        .ingest_packet(pkts.last().expect("last"), 8192, 52_000)
        .expect("complete");
    match final_rep.outcome {
        ReassemblyOutcome::Completed(done) => assert_eq!(done.payload.len(), near_max),
        other => panic!("expected completion, got {other:?}"),
    }
    assert_eq!(reasm.stats().global_total_bytes(), 0);
}

fn test_frame(
    frame_id: u32,
    gop_id: u16,
    keyframe: bool,
) -> lumabridge_protocol::media::reassembly::ReassembledFrame {
    lumabridge_protocol::media::reassembly::ReassembledFrame {
        session_id: 1,
        display_id: 0,
        codec_id: CodecId::H264,
        frame_id,
        gop_id,
        flags: if keyframe {
            VideoFlags::KEYFRAME
        } else {
            VideoFlags::NONE
        },
        capture_ts_us: u64::from(frame_id) * 1000,
        encode_done_ts_us: u64::from(frame_id) * 1000 + 100,
        payload: vec![u8::try_from(frame_id % 256).expect("mod 256"); 8],
    }
}

#[test]
fn gop_recovery_reorder_cooldown_and_wraparound() {
    let mut sm = GopRecoveryStateMachine::new(1, 0, RecoveryConfig::default()).expect("sm");
    assert_eq!(sm.state(), RecoveryState::InitialAwaitingIdr);

    let a0 = sm.on_frame_completed(test_frame(1, 65_535, false), 1_000_000, false);
    assert_eq!(a0.dropped_dependent_frames, 1);
    assert!(a0.request_idr);

    let a1 = sm.on_frame_completed(test_frame(2, 65_535, true), 1_005_000, false);
    assert_eq!(a1.deliver_frames.len(), 1);
    assert!(matches!(
        sm.state(),
        RecoveryState::Healthy {
            active_gop_id: 65_535,
            last_delivered_frame_id: 2
        }
    ));

    // Reordered frame 4 while 3 in-flight buffers without breaking GOP; then 3 drains both.
    let a2 = sm.on_frame_completed(test_frame(4, 65_535, false), 1_010_000, true);
    assert!(a2.deliver_frames.is_empty());
    assert!(!a2.request_idr);
    assert_eq!(sm.queued_reorder_len(), 1);

    let a3 = sm.on_frame_completed(test_frame(3, 65_535, false), 1_012_000, false);
    let ids: Vec<u32> = a3.deliver_frames.iter().map(|f| f.frame_id).collect();
    assert_eq!(ids, vec![3, 4]);

    // Loss at 1_020_000 (20 ms after initial IDR request at 1_000_000) enters AwaitingIdr
    // while persistent cooldown rate-limits the immediate IDR request!
    let a4_cd = sm.on_frame_lost(1, 0, 5, 65_535, 1_020_000);
    assert!(!a4_cd.request_idr);
    assert!(matches!(
        sm.state(),
        RecoveryState::AwaitingIdr {
            broken_gop_id: 65_535,
            last_good_frame_id: 4,
        }
    ));

    // Once persistent cooldown from 1_000_000 expires at 1_220_000, IDR request is allowed.
    let a4 = sm.on_frame_lost(1, 0, 5, 65_535, 1_220_000);
    assert!(a4.request_idr);

    let drop_p = sm.on_frame_completed(test_frame(6, 65_535, false), 1_225_000, false);
    assert_eq!(drop_p.dropped_dependent_frames, 1);
    assert!(!drop_p.request_idr);

    let within_cd = sm.on_frame_lost(1, 0, 6, 65_535, 1_220_000 + DEFAULT_IDR_COOLDOWN_US - 1);
    assert!(!within_cd.request_idr);

    let past_cd = sm.on_frame_lost(1, 0, 7, 65_535, 1_220_000 + DEFAULT_IDR_COOLDOWN_US);
    assert!(past_cd.request_idr);

    // Modular gop_id wraparound 65_535 -> 0 on clean IDR recovers Healthy.
    let a7 = sm.on_frame_completed(test_frame(8, 0, true), 1_450_000, false);
    assert_eq!(a7.deliver_frames.len(), 1);
    assert!(matches!(
        sm.state(),
        RecoveryState::Healthy {
            active_gop_id: 0,
            last_delivered_frame_id: 8
        }
    ));
}

#[test]
fn gop_recovery_reorder_timeout_protected_blank_and_renewal() {
    let reasm = Reassembler::new(ReassemblyConfig::default()).expect("reasm");
    let mut sm = GopRecoveryStateMachine::new(1, 0, RecoveryConfig::default()).expect("sm");
    let _ = sm.on_frame_completed(test_frame(1, 1, true), 10_000, false);

    // Buffer frame 3 with gap (2 missing), then expire reorder timeout.
    let _ = sm.on_frame_completed(test_frame(3, 1, false), 20_000, true);
    assert_eq!(sm.queued_reorder_len(), 1);
    let timed_out =
        sm.poll_reorder_timeout(20_000 + RecoveryConfig::default().reorder_gap_timeout_us);
    assert!(timed_out.request_idr);
    assert_eq!(timed_out.dropped_dependent_frames, 1);
    assert_eq!(sm.queued_reorder_len(), 0);

    let mut r_blank = Reassembler::new(ReassemblyConfig::default()).expect("r");
    let pkt_budget = PacketBudget::new(1024, 1500).expect("b");
    let older_pkts = fragment_frame(
        &FrameToFragment {
            session_id: 1,
            display_id: 0,
            codec_id: CodecId::H264,
            frame_id: 8,
            gop_id: 1,
            capture_ts_us: 8000,
            encode_done_ts_us: 8000,
            kind: FrameKind::InterFrame,
            has_codec_config: false,
            mirror_source: false,
            payload: &[0x55u8; 1500],
        },
        pkt_budget,
    )
    .expect("2 frags");
    let _ = r_blank
        .ingest_packet(&older_pkts[0], 1024, 1_255_000)
        .expect("old frag0");

    let blank_pkt = fragment_frame(
        &FrameToFragment {
            session_id: 1,
            display_id: 0,
            codec_id: CodecId::H264,
            frame_id: 9,
            gop_id: 1,
            capture_ts_us: 9000,
            encode_done_ts_us: 9000,
            kind: FrameKind::ProtectedBlank,
            has_codec_config: false,
            mirror_source: false,
            payload: &[],
        },
        pkt_budget,
    )
    .expect("blank");
    let rep_b = r_blank
        .ingest_packet(&blank_pkt[0], 1024, 1_260_000)
        .expect("ok");
    assert_eq!(rep_b.discarded.len(), 1);
    assert_eq!(
        rep_b.discarded[0].reason,
        DiscardReason::EvictedByProtectedBlank
    );
    let blank_actions = sm.on_reassembly_report(rep_b, 1_260_000, &reasm);
    assert!(blank_actions.hide_content_for_protected_blank);
    assert!(matches!(
        sm.state(),
        RecoveryState::ProtectedBlanked {
            last_blank_frame_id: 9
        }
    ));

    // Late delayed fragment from frame 8 MUST be StaleIgnored and cannot re-present prior content.
    let late_rep = r_blank
        .ingest_packet(&older_pkts[1], 1024, 1_265_000)
        .expect("late ignored");
    assert_eq!(
        late_rep.outcome,
        ReassemblyOutcome::StaleIgnored { frame_id: 8 }
    );
    assert_eq!(r_blank.stats().global_total_bytes(), 0);
    let late_actions = sm.on_reassembly_report(late_rep, 1_265_000, &r_blank);
    assert!(late_actions.deliver_frames.is_empty());

    // Orphan P-frame 10 remains suppressed while ProtectedBlanked until clean IDR.
    let p_after_blank = sm.on_frame_completed(test_frame(10, 1, false), 1_270_000, false);
    assert!(p_after_blank.deliver_frames.is_empty());
    assert_eq!(p_after_blank.dropped_dependent_frames, 1);
    assert!(matches!(
        sm.state(),
        RecoveryState::ProtectedBlanked {
            last_blank_frame_id: 9
        }
    ));

    let renewal = sm.on_frame_completed(
        test_frame(FRAME_ID_RENEWAL_THRESHOLD, 2, true),
        1_300_000,
        false,
    );
    assert!(renewal.session_renewal_required);
}
