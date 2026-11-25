// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

use lumabridge_protocol::cbor::{CborDecodeMode, CborDecodeOptions, UnknownFieldPolicy};
use lumabridge_protocol::control::{
    ClockSyncPing, ControlMessage, ErrorNotice, Heartbeat, InputBatch, InputEvent, MsgType,
    TouchPhase,
};
use lumabridge_protocol::error::ErrorCode;
use lumabridge_protocol::framing::{
    encode_stream_frame, ChannelId, FrameFlags, FrameHeader, StreamBindingMode, StreamFrameDecoder,
};
use lumabridge_protocol::limits::{
    CborLimits, FramingLimits, ReassemblyConfig, MSG_TYPE_MEDIA_VIDEO_FRAGMENT, VIDEO_HEADER_LEN,
};
use lumabridge_protocol::media::fragmentation::{
    fragment_frame, FrameKind, FrameToFragment, PacketBudget,
};
use lumabridge_protocol::media::header::{decode_video_packet, VideoFlags, VideoPacketHeader};
use lumabridge_protocol::media::reassembly::{Reassembler, ReassemblyOutcome};
use lumabridge_protocol::version::CodecId;
use proptest::prelude::*;

fn arb_codec() -> impl Strategy<Value = CodecId> {
    prop_oneof![Just(CodecId::H264), Just(CodecId::Hevc), Just(CodecId::Av1),]
}

fn arb_input_event() -> impl Strategy<Value = InputEvent> {
    prop_oneof![
        (any::<u16>(), any::<u16>())
            .prop_map(|(x_norm, y_norm)| { InputEvent::PointerMoveAbs { x_norm, y_norm } }),
        (0u8..=31u8, any::<bool>())
            .prop_map(|(button_id, pressed)| { InputEvent::PointerButton { button_id, pressed } }),
        (-1_000_000i32..=1_000_000i32, -1_000_000i32..=1_000_000i32).prop_map(
            |(delta_x_milli, delta_y_milli)| InputEvent::PointerScroll {
                delta_x_milli,
                delta_y_milli,
            }
        ),
        (any::<u16>(), any::<u16>(), any::<bool>(), any::<u8>()).prop_map(
            |(hid_usage_page, hid_usage_id, pressed, modifiers_mask)| InputEvent::KeyEvent {
                hid_usage_page,
                hid_usage_id,
                pressed,
                modifiers_mask,
            }
        ),
        (
            any::<u8>(),
            prop_oneof![
                Just(TouchPhase::Down),
                Just(TouchPhase::Move),
                Just(TouchPhase::Up),
                Just(TouchPhase::Cancel),
            ],
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
        )
            .prop_map(|(contact_id, phase, x_norm, y_norm, pressure_norm)| {
                InputEvent::TouchContact {
                    contact_id,
                    phase,
                    x_norm,
                    y_norm,
                    pressure_norm,
                }
            }),
        (
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            -90i8..=90i8,
            -90i8..=90i8,
            0u8..=15u8,
        )
            .prop_map(
                |(x_norm, y_norm, pressure_norm, tilt_x_deg, tilt_y_deg, buttons_mask)| {
                    InputEvent::StylusEvent {
                        x_norm,
                        y_norm,
                        pressure_norm,
                        tilt_x_deg,
                        tilt_y_deg,
                        buttons_mask,
                    }
                }
            ),
    ]
}

fn arb_frame_spec() -> impl Strategy<Value = (ChannelId, u16, FrameFlags, Vec<u8>)> {
    let flags_strat = prop_oneof![Just(FrameFlags::NONE), Just(FrameFlags::MUST_UNDERSTAND)];
    prop_oneof![
        (
            flags_strat.clone(),
            proptest::collection::vec(any::<u8>(), 0..=2048),
        )
            .prop_map(|(flags, payload)| {
                (ChannelId::Control, MsgType::Hello.as_u16(), flags, payload)
            }),
        (
            flags_strat.clone(),
            proptest::collection::vec(any::<u8>(), 44..=2048),
        )
            .prop_map(|(flags, payload)| {
                (
                    ChannelId::Media,
                    MSG_TYPE_MEDIA_VIDEO_FRAGMENT,
                    flags,
                    payload,
                )
            }),
        (
            flags_strat.clone(),
            proptest::collection::vec(any::<u8>(), 0..=1024),
        )
            .prop_map(|(flags, payload)| {
                (
                    ChannelId::Feedback,
                    MsgType::Heartbeat.as_u16(),
                    flags,
                    payload,
                )
            }),
        (flags_strat, proptest::collection::vec(any::<u8>(), 0..=512),).prop_map(
            |(flags, payload)| {
                (
                    ChannelId::Input,
                    MsgType::InputBatch.as_u16(),
                    flags,
                    payload,
                )
            }
        ),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_stream_framing_handles_arbitrary_chunk_boundaries(
        specs in proptest::collection::vec(arb_frame_spec(), 1..=6),
        chunk_sizes in proptest::collection::vec(1usize..=128usize, 1..=64),
    ) {
        let limits = FramingLimits::default();
        let mut wire = Vec::new();
        for (ch, msg_ty, flags, payload) in &specs {
            let encoded = encode_stream_frame(*ch, *msg_ty, *flags, payload, &limits)
                .expect("valid stream frame");
            wire.extend_from_slice(&encoded);
        }

        let mut dec = StreamFrameDecoder::new(limits, StreamBindingMode::Multiplexed)
            .expect("decoder init");
        let mut decoded = Vec::new();
        let mut offset = 0usize;
        let mut idx = 0usize;
        while offset < wire.len() {
            let step = chunk_sizes[idx % chunk_sizes.len()];
            let end = offset.saturating_add(step).min(wire.len());
            dec.feed(&wire[offset..end]).expect("feed");
            while let Some(frame) = dec.next_frame().expect("next_frame") {
                decoded.push(frame);
            }
            offset = end;
            idx += 1;
        }
        dec.finish_eof().expect("clean EOF");

        prop_assert_eq!(decoded.len(), specs.len());
        for (raw, (ch, msg_ty, flags, payload)) in decoded.iter().zip(specs.iter()) {
            prop_assert_eq!(raw.header.channel_id, *ch);
            prop_assert_eq!(raw.header.msg_type, *msg_ty);
            prop_assert_eq!(raw.header.flags, *flags);
            prop_assert_eq!(&raw.payload, payload);
        }
    }

    #[test]
    fn prop_cbor_roundtrip_and_canonical_determinism(
        seq in 1u64..=u64::MAX,
        t1 in any::<u64>(),
        sid in prop::option::of(1u64..=u64::MAX),
        uptime in any::<u64>(),
        err_fatal in any::<bool>(),
        err_ascii in proptest::collection::vec(0x20u8..=0x7Eu8, 0..=128),
        display_id in 0u16..=0xFFFEu16,
        input_events in proptest::collection::vec(arb_input_event(), 1..=8),
    ) {
        let ascii = String::from_utf8(err_ascii).expect("ASCII is UTF-8");
        let messages = [
            ControlMessage::ClockSyncPing(ClockSyncPing {
                seq,
                t1_client_mono_us: t1,
            }),
            ControlMessage::Heartbeat(Heartbeat {
                session_id: sid,
                seq,
                uptime_ms: uptime,
            }),
            ControlMessage::ErrorNotice(ErrorNotice {
                code: ErrorCode::PermissionDenied,
                fatal: err_fatal,
                related_msg_type: MsgType::InputBatch.as_u16(),
                context_ascii: ascii,
            }),
            ControlMessage::InputBatch(InputBatch {
                session_id: 42,
                display_id,
                input_seq: seq,
                events: input_events,
            }),
        ];

        let opts = CborDecodeOptions::default();
        for msg in &messages {
            let wire_a = msg.encode_cbor().expect("canonical encode");
            let decoded = ControlMessage::decode_cbor(msg.msg_type(), &wire_a, opts)
                .expect("strict deterministic decode");
            prop_assert_eq!(&decoded, msg);
            let wire_b = decoded.encode_cbor().expect("re-encode");
            prop_assert_eq!(wire_a, wire_b);
        }
    }

    #[test]
    fn prop_video_header_roundtrip(
        session_id in 1u64..=u64::MAX,
        display_id in 0u16..=0xFFFEu16,
        codec_id in arb_codec(),
        frame_id in 1u32..=u32::MAX,
        gop_id in any::<u16>(),
        frag_count in 1u16..=4096u16,
        frag_index_seed in 0u16..=4095u16,
        payload_len in 1u16..=1400u16,
        capture_ts_us in any::<u64>(),
        delta_us in 0u64..=100_000u64,
        is_keyframe in any::<bool>(),
        chain_reset in any::<bool>(),
        has_codec_config in any::<bool>(),
        mirror_source in any::<bool>(),
    ) {
        let frag_index = frag_index_seed % frag_count;
        let mut flags = VideoFlags::NONE;
        if is_keyframe {
            flags = flags.union(VideoFlags::KEYFRAME);
            if chain_reset {
                flags = flags.union(VideoFlags::CHAIN_RESET);
            }
        }
        if has_codec_config {
            flags = flags.union(VideoFlags::HAS_CODEC_CONFIG);
        }
        if mirror_source {
            flags = flags.union(VideoFlags::MIRROR_SOURCE);
        }
        if frag_index == frag_count - 1 {
            flags = flags.union(VideoFlags::END_OF_FRAME);
        }

        let hdr = VideoPacketHeader {
            flags,
            session_id,
            display_id,
            codec_id,
            frame_id,
            gop_id,
            frag_index,
            frag_count,
            payload_len,
            capture_ts_us,
            encode_done_ts_us: capture_ts_us.saturating_add(delta_us),
        };
        let wire = hdr.encode();
        let decoded = VideoPacketHeader::decode(&wire, 1400).expect("valid header");
        prop_assert_eq!(decoded, hdr);
    }

    #[test]
    fn prop_fragmentation_and_permuted_reassembly_conserves_payload(
        budget_bytes in 128usize..=4096usize,
        payload_seed in proptest::collection::vec(any::<u8>(), 1..=16_384usize),
        is_keyframe in any::<bool>(),
        shuffle_seeds in proptest::collection::vec(any::<usize>(), 1..=128usize),
        dup_picks in proptest::collection::vec(any::<usize>(), 0..=8usize),
    ) {
        let budget = PacketBudget::new(budget_bytes, 65_535).expect("valid budget");
        let max_len = budget.max_representable_frame_bytes.min(payload_seed.len());
        let payload = &payload_seed[..max_len];

        let packets = fragment_frame(
            &FrameToFragment {
                session_id: 7,
                display_id: 1,
                codec_id: CodecId::H264,
                frame_id: 12,
                gop_id: 3,
                capture_ts_us: 1_000,
                encode_done_ts_us: 1_500,
                kind: if is_keyframe {
                    FrameKind::Keyframe { chain_reset: false }
                } else {
                    FrameKind::InterFrame
                },
                has_codec_config: is_keyframe,
                mirror_source: true,
                payload,
            },
            budget,
        )
        .expect("fragment_frame");

        // Deterministic permutation + optional duplicates.
        let mut order: Vec<usize> = (0..packets.len()).collect();
        for (step, &seed) in shuffle_seeds.iter().enumerate() {
            let a = step % order.len();
            let b = seed % order.len();
            order.swap(a, b);
        }
        for &pick in &dup_picks {
            order.push(pick % packets.len());
        }

        let mut reasm = Reassembler::new(ReassemblyConfig::default()).expect("reasm");
        let mut completed_payload = None;
        for (tick, &idx) in order.iter().enumerate() {
            let report = reasm
                .ingest_packet(
                    &packets[idx],
                    budget.effective_lbwp_packet_budget,
                    10_000 + tick as u64,
                )
                .expect("valid packet");
            match report.outcome {
                ReassemblyOutcome::Completed(frame) => {
                    prop_assert!(completed_payload.is_none());
                    completed_payload = Some(frame.payload);
                }
                ReassemblyOutcome::Incomplete { .. } => {
                    prop_assert!(completed_payload.is_none());
                }
                ReassemblyOutcome::StaleIgnored { .. } | ReassemblyOutcome::DuplicateIgnored { .. } => {}
                other => prop_assert!(false, "unexpected outcome: {other:?}"),
            }
        }

        let got = completed_payload.expect("frame completes");
        prop_assert_eq!(got.as_slice(), payload);
        prop_assert_eq!(reasm.stats().global_total_bytes(), 0);
    }

    #[test]
    fn prop_arbitrary_untrusted_bytes_never_panic(
        raw in proptest::collection::vec(any::<u8>(), 0..=512),
        chunk_step in 1usize..=64usize,
    ) {
        let flimits = FramingLimits::default();
        if raw.len() >= 8 {
            let arr: [u8; 8] = raw[..8].try_into().expect("8B");
            let _ = FrameHeader::decode(&arr, &flimits);
        }

        let mut dec = StreamFrameDecoder::new(flimits, StreamBindingMode::Multiplexed)
            .expect("decoder init");
        for c in raw.chunks(chunk_step) {
            if dec.feed(c).is_err() {
                break;
            }
            while matches!(dec.next_frame(), Ok(Some(_))) {}
        }
        let _ = dec.finish_eof();

        for msg_ty in [
            MsgType::PairHello,
            MsgType::Hello,
            MsgType::SessionOpenRequest,
            MsgType::MediaFeedback,
            MsgType::InputBatch,
            MsgType::ErrorNotice,
        ] {
            let strict = CborDecodeOptions::default();
            let relaxed = CborDecodeOptions {
                mode: CborDecodeMode::RelaxedOrderAndWidth,
                unknown_fields: UnknownFieldPolicy::SkipBounded,
                limits: CborLimits::default(),
            };
            let _ = ControlMessage::decode_cbor(msg_ty, &raw, strict);
            let _ = ControlMessage::decode_cbor(msg_ty, &raw, relaxed);
        }

        let _ = decode_video_packet(&raw, flimits.max_media_stream_bytes);

        let cfg = ReassemblyConfig::default();
        let mut reasm = Reassembler::new(cfg).expect("reasm");
        if raw.len() >= VIDEO_HEADER_LEN {
            let _ = reasm.ingest_packet(&raw, flimits.max_media_stream_bytes, 1_000);
        }
        prop_assert!(reasm.stats().global_total_bytes() <= cfg.max_global_bytes);
    }
}
