// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use lumabridge_protocol::cbor::{CborDecodeMode, CborDecodeOptions, UnknownFieldPolicy};
use lumabridge_protocol::control::{
    ClockSyncPing, ClockSyncPong, ControlMessage, ErrorNotice, Heartbeat, InputBatch, InputEvent,
    MsgType, PairCancel, PairCancelReason, PermissionUpdate, Permissions,
};
use lumabridge_protocol::error::{CborError, ErrorCode};
use lumabridge_protocol::framing::{
    ChannelId, FrameFlags, FrameHeader, StreamBindingMode, StreamFrameDecoder,
};
use lumabridge_protocol::limits::{CborLimits, FramingLimits, FRAME_HEADER_LEN, VIDEO_HEADER_LEN};
use lumabridge_protocol::media::header::{VideoFlags, VideoPacketHeader};
use lumabridge_protocol::version::CodecId;

fn decode_hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    assert_eq!(clean.len() % 2, 0, "hex length must be even");
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

fn load_golden_vectors() -> BTreeMap<&'static str, Vec<u8>> {
    let raw = include_str!("corpus/golden_vectors.hex");
    let mut map = BTreeMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (name, hex) = trimmed.split_once('|').expect("pipe separator");
        map.insert(name.trim(), decode_hex(hex));
    }
    map
}

#[test]
fn golden_frame_headers_exact_bytes_and_truncations() {
    let vectors = load_golden_vectors();
    let limits = FramingLimits::default();

    let cases = [
        (
            "FRAME_HEADER_CH0_HELLO",
            FrameHeader {
                frame_len: 66,
                channel_id: ChannelId::Control,
                msg_type: MsgType::Hello.as_u16(),
                flags: FrameFlags::MUST_UNDERSTAND,
            },
        ),
        (
            "FRAME_HEADER_CH1_MEDIA_STREAM",
            FrameHeader {
                frame_len: 48,
                channel_id: ChannelId::Media,
                msg_type: 0x0800,
                flags: FrameFlags::NONE,
            },
        ),
        (
            "FRAME_HEADER_CH2_HEARTBEAT",
            FrameHeader {
                frame_len: 10,
                channel_id: ChannelId::Feedback,
                msg_type: MsgType::Heartbeat.as_u16(),
                flags: FrameFlags::NONE,
            },
        ),
        (
            "FRAME_HEADER_CH3_INPUT_BATCH",
            FrameHeader {
                frame_len: 24,
                channel_id: ChannelId::Input,
                msg_type: MsgType::InputBatch.as_u16(),
                flags: FrameFlags::NONE,
            },
        ),
    ];

    for (name, expected) in cases {
        let wire = &vectors[name];
        assert_eq!(wire.len(), FRAME_HEADER_LEN);
        let arr: [u8; FRAME_HEADER_LEN] = wire.as_slice().try_into().expect("8B slice");
        let decoded = FrameHeader::decode(&arr, &limits).expect("golden header decodes");
        assert_eq!(decoded, expected);
        assert_eq!(expected.encode().as_slice(), wire.as_slice());

        // Exhaustive truncation check at every offset 1..FRAME_HEADER_LEN.
        for cut in 1..FRAME_HEADER_LEN {
            let mut dec = StreamFrameDecoder::new(limits, StreamBindingMode::Multiplexed)
                .expect("decoder init");
            dec.feed(&wire[..cut]).expect("feed prefix");
            assert!(dec.next_frame().expect("no error yet").is_none());
            assert!(dec.finish_eof().is_err(), "cut={cut} must reject EOF");
        }
    }
}

#[test]
fn golden_video_headers_exact_bytes_and_truncations() {
    let vectors = load_golden_vectors();

    let idr_expected = VideoPacketHeader {
        flags: VideoFlags::KEYFRAME
            .union(VideoFlags::HAS_CODEC_CONFIG)
            .union(VideoFlags::CHAIN_RESET),
        session_id: 0x0102_0304_0506_0708,
        display_id: 0,
        codec_id: CodecId::H264,
        frame_id: 1,
        gop_id: 1,
        frag_index: 0,
        frag_count: 2,
        payload_len: 1156,
        capture_ts_us: 1_000_000,
        encode_done_ts_us: 1_002_500,
    };

    let pframe_expected = VideoPacketHeader {
        flags: VideoFlags::END_OF_FRAME.union(VideoFlags::MIRROR_SOURCE),
        session_id: 0x1122_3344_5566_7788,
        display_id: 2,
        codec_id: CodecId::Hevc,
        frame_id: 256,
        gop_id: 65535,
        frag_index: 2,
        frag_count: 3,
        payload_len: 256,
        capture_ts_us: 0x0020_0000,
        encode_done_ts_us: 0x0020_0500,
    };

    let blank_expected = VideoPacketHeader {
        flags: VideoFlags::PROTECTED_BLANK.union(VideoFlags::END_OF_FRAME),
        session_id: 0x0102_0304_0506_0708,
        display_id: 1,
        codec_id: CodecId::H264,
        frame_id: 42,
        gop_id: 3,
        frag_index: 0,
        frag_count: 1,
        payload_len: 0,
        capture_ts_us: 2_000_000,
        encode_done_ts_us: 2_000_100,
    };

    for (name, expected, max_frag) in [
        ("VIDEO_HEADER_IDR_FRAG0", idr_expected, 1200usize),
        ("VIDEO_HEADER_PFRAME_LAST_MIRROR", pframe_expected, 1200),
        ("VIDEO_HEADER_PROTECTED_BLANK", blank_expected, 1200),
    ] {
        let wire = &vectors[name];
        assert_eq!(wire.len(), VIDEO_HEADER_LEN);
        let arr: [u8; VIDEO_HEADER_LEN] = wire.as_slice().try_into().expect("44B slice");
        let decoded = VideoPacketHeader::decode(&arr, max_frag).expect("golden video hdr decodes");
        assert_eq!(decoded, expected);
        assert_eq!(expected.encode().as_slice(), wire.as_slice());

        for cut in 0..VIDEO_HEADER_LEN {
            let err = lumabridge_protocol::media::header::decode_video_packet(&wire[..cut], 1600)
                .unwrap_err();
            assert_eq!(
                err,
                lumabridge_protocol::error::VideoHeaderError::PacketTooShort(cut)
            );
        }
    }
}

#[test]
fn golden_canonical_cbor_vectors_and_all_offset_truncations() {
    let vectors = load_golden_vectors();
    let opts = CborDecodeOptions::default();

    let cases: [(&str, ControlMessage); 7] = [
        (
            "CBOR_CLOCK_SYNC_PING",
            ControlMessage::ClockSyncPing(ClockSyncPing {
                seq: 1,
                t1_client_mono_us: 1000,
            }),
        ),
        (
            "CBOR_CLOCK_SYNC_PONG",
            ControlMessage::ClockSyncPong(ClockSyncPong {
                seq: 1,
                t1_client_mono_us: 1000,
                t2_server_recv_us: 1500,
                t3_server_send_us: 1520,
            }),
        ),
        (
            "CBOR_PAIR_CANCEL",
            ControlMessage::PairCancel(PairCancel {
                pairing_attempt_id: Some(7),
                reason_code: PairCancelReason::UserCancelled,
                detail_ascii: Some("timeout".to_owned()),
            }),
        ),
        (
            "CBOR_ERROR_NOTICE",
            ControlMessage::ErrorNotice(ErrorNotice {
                code: ErrorCode::InvalidFraming,
                fatal: true,
                related_msg_type: 0x0300,
                context_ascii: "bad_alpn".to_owned(),
            }),
        ),
        (
            "CBOR_HEARTBEAT_SESSION",
            ControlMessage::Heartbeat(Heartbeat {
                session_id: Some(0x0102_0304_0506_0708),
                seq: 42,
                uptime_ms: 5000,
            }),
        ),
        (
            "CBOR_PERMISSION_UPDATE",
            ControlMessage::PermissionUpdate(PermissionUpdate {
                session_id: 99,
                update_seq: 5,
                effective_perms: Permissions::VIEW_MIRROR
                    .union(Permissions::EXTEND_DISPLAY)
                    .union(Permissions::INPUT_POINTER)
                    .union(Permissions::INPUT_KEYBOARD),
            }),
        ),
        (
            "CBOR_INPUT_BATCH_SCROLL_AND_KEY",
            ControlMessage::InputBatch(InputBatch {
                session_id: 55,
                display_id: 0,
                input_seq: 12,
                events: vec![
                    InputEvent::PointerScroll {
                        delta_x_milli: -120,
                        delta_y_milli: 240,
                    },
                    InputEvent::KeyEvent {
                        hid_usage_page: 7,
                        hid_usage_id: 4,
                        pressed: true,
                        modifiers_mask: 2,
                    },
                ],
            }),
        ),
    ];

    for (name, expected_msg) in cases {
        let wire = &vectors[name];
        let encoded = expected_msg.encode_cbor().expect("encode canonical");
        assert_eq!(encoded, *wire, "encoding mismatch for {name}");
        let decoded = ControlMessage::decode_cbor(expected_msg.msg_type(), wire, opts)
            .expect("decode golden");
        assert_eq!(decoded, expected_msg, "decoded mismatch for {name}");

        // Truncate at EVERY byte offset 0..wire.len()
        for cut in 0..wire.len() {
            assert!(
                ControlMessage::decode_cbor(expected_msg.msg_type(), &wire[..cut], opts).is_err(),
                "truncated {name} at cut={cut} unexpectedly succeeded"
            );
        }
    }
}

#[test]
fn malformed_corpus_deterministically_rejected() {
    let raw = include_str!("corpus/malformed_corpus.hex");
    let frame_limits = FramingLimits::default();
    let cbor_opts = CborDecodeOptions::default();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('|').map(str::trim).collect();
        assert_eq!(parts.len(), 3, "malformed corpus line: {trimmed}");
        let domain = parts[0];
        let label = parts[1];
        let bytes = decode_hex(parts[2]);

        match domain {
            "FRAME" => {
                let arr: [u8; FRAME_HEADER_LEN] = bytes.as_slice().try_into().expect("8B header");
                assert!(
                    FrameHeader::decode(&arr, &frame_limits).is_err(),
                    "FRAME {label} should fail"
                );
            }
            "CBOR_PING" => {
                assert!(
                    ControlMessage::decode_cbor(MsgType::ClockSyncPing, &bytes, cbor_opts).is_err(),
                    "CBOR_PING {label} should fail"
                );
            }
            "CBOR_ERR" => {
                assert!(
                    ControlMessage::decode_cbor(MsgType::ErrorNotice, &bytes, cbor_opts).is_err(),
                    "CBOR_ERR {label} should fail"
                );
            }
            "VIDEO" => {
                let arr: [u8; VIDEO_HEADER_LEN] = bytes.as_slice().try_into().expect("44B header");
                assert!(
                    VideoPacketHeader::decode(&arr, 1200).is_err(),
                    "VIDEO {label} should fail"
                );
            }
            other => panic!("unknown domain {other}"),
        }
    }
}

#[test]
fn cbor_distinguishes_representation_vs_semantic_errors_and_handles_unknown_fields() {
    let strict = CborDecodeOptions::default();
    let relaxed = CborDecodeOptions {
        limits: CborLimits::default(),
        mode: CborDecodeMode::RelaxedOrderAndWidth,
        unknown_fields: UnknownFieldPolicy::SkipBounded,
    };

    // Unsorted map keys {2: 1000, 1: 1}: semantically valid under relaxed mode, rejected in strict mode.
    let unsorted = decode_hex("A2021903E80101");
    let err = ControlMessage::decode_cbor(MsgType::ClockSyncPing, &unsorted, strict).unwrap_err();
    assert_eq!(err, CborError::UnsortedMapKeys);
    assert!(err.is_representation_error());
    assert!(ControlMessage::decode_cbor(MsgType::ClockSyncPing, &unsorted, relaxed).is_ok());

    // Non-minimal integer width {1: 1 (2 bytes 18 01), 2: 1000}: representation fault only.
    let non_minimal = decode_hex("A2011801021903E8");
    let err =
        ControlMessage::decode_cbor(MsgType::ClockSyncPing, &non_minimal, strict).unwrap_err();
    assert_eq!(err, CborError::NonMinimalInteger);
    assert!(err.is_representation_error());
    assert!(ControlMessage::decode_cbor(MsgType::ClockSyncPing, &non_minimal, relaxed).is_ok());

    // Duplicate map key {1: 1, 1: 2}: semantic/structural error in BOTH modes.
    let dup = decode_hex("A201010102");
    for opts in [strict, relaxed] {
        let err = ControlMessage::decode_cbor(MsgType::ClockSyncPing, &dup, opts).unwrap_err();
        assert_eq!(err, CborError::DuplicateMapKey);
        assert!(!err.is_representation_error());
    }

    // Unknown optional field 99 with valid deterministic nested array/text is skipped cleanly.
    let with_unknown = decode_hex("A30101021903E8186382626F6B05");
    let msg = ControlMessage::decode_cbor(MsgType::ClockSyncPing, &with_unknown, strict)
        .expect("bounded unknown field skipped");
    assert_eq!(
        msg,
        ControlMessage::ClockSyncPing(ClockSyncPing {
            seq: 1,
            t1_client_mono_us: 1000
        })
    );

    // Same unknown field rejected when UnknownFieldPolicy::Reject is selected.
    let reject_unknown = CborDecodeOptions {
        unknown_fields: UnknownFieldPolicy::Reject,
        ..strict
    };
    assert!(
        ControlMessage::decode_cbor(MsgType::ClockSyncPing, &with_unknown, reject_unknown).is_err()
    );

    // Unknown optional field carrying a forbidden CBOR float is REJECTED even when skipping.
    let unknown_float = decode_hex("A30101021903E81863F93C00");
    assert_eq!(
        ControlMessage::decode_cbor(MsgType::ClockSyncPing, &unknown_float, strict).unwrap_err(),
        CborError::ForbiddenType("CBOR float")
    );

    // Depth exceeding limit (nested array depth 9 inside unknown field 99) rejected.
    let too_deep = decode_hex("A30101021903E8186381818181818181818100");
    assert_eq!(
        ControlMessage::decode_cbor(MsgType::ClockSyncPing, &too_deep, strict).unwrap_err(),
        CborError::DepthExceeded
    );
}
