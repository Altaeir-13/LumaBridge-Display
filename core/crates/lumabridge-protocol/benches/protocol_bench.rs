// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::hint::black_box;
use std::time::Instant;

use lumabridge_protocol::cbor::CborDecodeOptions;
use lumabridge_protocol::control::{
    ControlMessage, Hello, InputBatch, InputEvent, MediaFeedback, MsgType,
};
use lumabridge_protocol::framing::{
    encode_stream_frame, ChannelId, FrameFlags, StreamBindingMode, StreamFrameDecoder,
};
use lumabridge_protocol::limits::{FramingLimits, ReassemblyConfig};
use lumabridge_protocol::media::fragmentation::{
    fragment_frame, FrameKind, FrameToFragment, PacketBudget,
};
use lumabridge_protocol::media::header::{decode_video_packet, VideoFlags, VideoPacketHeader};
use lumabridge_protocol::media::reassembly::{Reassembler, ReassemblyOutcome};
use lumabridge_protocol::version::CodecId;

struct StatsSummary {
    avg_ns: f64,
    p50_ns: u128,
    p95_ns: u128,
    p99_ns: u128,
    max_ns: u128,
}

fn summarize(samples: &mut [u128]) -> StatsSummary {
    samples.sort_unstable();
    let len = samples.len();
    let sum: u128 = samples.iter().copied().sum();
    let idx = |pct: usize| -> usize { ((len.saturating_sub(1)) * pct) / 100 };
    StatsSummary {
        avg_ns: (sum as f64) / (len as f64),
        p50_ns: samples[idx(50)],
        p95_ns: samples[idx(95)],
        p99_ns: samples[idx(99)],
        max_ns: samples[len.saturating_sub(1)],
    }
}

fn measure<F>(warmup: usize, iters: usize, mut op: F) -> StatsSummary
where
    F: FnMut(usize),
{
    for i in 0..warmup {
        op(i);
    }
    let mut samples = Vec::with_capacity(iters);
    for i in 0..iters {
        let start = Instant::now();
        op(i);
        samples.push(start.elapsed().as_nanos());
    }
    summarize(&mut samples)
}

fn bench_framing_and_headers() {
    let limits = FramingLimits::default();
    let payload = [0x5Au8; 256];
    let mut scratch = Vec::with_capacity(512);

    let enc_stats = measure(200, 2_000, |_| {
        scratch.clear();
        let frame = encode_stream_frame(
            ChannelId::Control,
            MsgType::Hello.as_u16(),
            FrameFlags::MUST_UNDERSTAND,
            black_box(&payload),
            &limits,
        )
        .expect("encode frame");
        scratch.extend_from_slice(&frame);
        black_box(&scratch);
    });

    let wire = encode_stream_frame(
        ChannelId::Control,
        MsgType::Hello.as_u16(),
        FrameFlags::MUST_UNDERSTAND,
        &payload,
        &limits,
    )
    .expect("wire");
    let dec_stats = measure(200, 2_000, |_| {
        let mut dec = StreamFrameDecoder::new(limits, StreamBindingMode::Multiplexed).expect("dec");
        dec.feed(black_box(&wire)).expect("feed");
        let raw = dec.next_frame().expect("ok").expect("frame");
        dec.finish_eof().expect("eof");
        black_box(raw);
    });

    let vhdr = VideoPacketHeader {
        flags: VideoFlags::KEYFRAME.union(VideoFlags::END_OF_FRAME),
        session_id: 1,
        display_id: 0,
        codec_id: CodecId::H264,
        frame_id: 1,
        gop_id: 0,
        frag_index: 0,
        frag_count: 1,
        payload_len: 1092,
        capture_ts_us: 10_000,
        encode_done_ts_us: 10_500,
    };
    let mut pkt = vhdr.encode().to_vec();
    pkt.extend_from_slice(&[0xABu8; 1092]);

    let vhdr_stats = measure(200, 2_000, |_| {
        let encoded = black_box(vhdr).encode();
        let (decoded, body) = decode_video_packet(black_box(&pkt), 1500).expect("decode vhdr");
        black_box((encoded, decoded, body.len()));
    });

    println!(
        "stream_frame_encode_256b: avg={:.1}ns p50={}ns p95={}ns p99={}ns max={}ns",
        enc_stats.avg_ns, enc_stats.p50_ns, enc_stats.p95_ns, enc_stats.p99_ns, enc_stats.max_ns
    );
    println!(
        "stream_frame_decode_256b: avg={:.1}ns p50={}ns p95={}ns p99={}ns max={}ns",
        dec_stats.avg_ns, dec_stats.p50_ns, dec_stats.p95_ns, dec_stats.p99_ns, dec_stats.max_ns
    );
    println!(
        "video_header_44b_roundtrip: avg={:.1}ns p50={}ns p95={}ns p99={}ns max={}ns",
        vhdr_stats.avg_ns,
        vhdr_stats.p50_ns,
        vhdr_stats.p95_ns,
        vhdr_stats.p99_ns,
        vhdr_stats.max_ns
    );
}

fn bench_cbor_messages() {
    let opts = CborDecodeOptions::default();
    let samples = [
        (
            "Hello",
            ControlMessage::Hello(Hello {
                protocol_major: 1,
                protocol_minor: 0,
                device_id: [0x11u8; 32],
                app_version: "1.2.0".to_owned(),
                max_control_bytes: 65_536,
                max_frame_bytes: 8_388_608,
                preferred_mtu: 1200,
            }),
        ),
        (
            "MediaFeedback",
            ControlMessage::MediaFeedback(MediaFeedback {
                session_id: 9,
                display_id: 0,
                last_complete_frame_id: 120,
                last_displayed_frame_id: 119,
                broken_gop_id: None,
                request_idr: false,
                decode_p50_us: 1200,
                decode_p95_us: 2400,
                present_p95_us: 3200,
                rx_fps_milli: 120_000,
                packet_loss_ppm: 0,
                jitter_us: 300,
                suggested_bitrate_bps: 20_000_000,
            }),
        ),
        (
            "InputBatch_4events",
            ControlMessage::InputBatch(InputBatch {
                session_id: 9,
                display_id: 0,
                input_seq: 42,
                events: vec![
                    InputEvent::PointerMoveAbs {
                        x_norm: 1000,
                        y_norm: 2000,
                    },
                    InputEvent::PointerButton {
                        button_id: 1,
                        pressed: true,
                    },
                    InputEvent::KeyEvent {
                        hid_usage_page: 0x07,
                        hid_usage_id: 0x04,
                        pressed: true,
                        modifiers_mask: 0,
                    },
                    InputEvent::PointerScroll {
                        delta_x_milli: 0,
                        delta_y_milli: -120,
                    },
                ],
            }),
        ),
    ];

    for (name, msg) in &samples {
        let encoded = msg.encode_cbor().expect("encode");
        let mut scratch = Vec::with_capacity(encoded.len());
        let enc_s = measure(200, 2_000, |_| {
            scratch.clear();
            msg.encode_cbor_into(&mut scratch).expect("enc");
            black_box(&scratch);
        });
        let dec_s = measure(200, 2_000, |_| {
            let d = ControlMessage::decode_cbor(msg.msg_type(), black_box(&encoded), opts)
                .expect("dec");
            black_box(d);
        });
        println!(
            "cbor_{name}_encode ({}B): avg={:.1}ns p50={}ns p95={}ns p99={}ns max={}ns",
            encoded.len(),
            enc_s.avg_ns,
            enc_s.p50_ns,
            enc_s.p95_ns,
            enc_s.p99_ns,
            enc_s.max_ns
        );
        println!(
            "cbor_{name}_decode ({}B): avg={:.1}ns p50={}ns p95={}ns p99={}ns max={}ns",
            encoded.len(),
            dec_s.avg_ns,
            dec_s.p50_ns,
            dec_s.p95_ns,
            dec_s.p99_ns,
            dec_s.max_ns
        );
    }
}

fn bench_media_pipeline_sizes() {
    let budget = PacketBudget::new(1136, 1500).expect("1092B fragment payload");
    let cfg = ReassemblyConfig::default();

    for &size_kib in &[30usize, 80, 150] {
        let size_bytes = size_kib * 1024;
        let payload: Vec<u8> = (0..size_bytes).map(|i| (i % 251) as u8).collect();
        let frag_s = measure(30, 300, |iter| {
            let pkts = fragment_frame(
                &FrameToFragment {
                    session_id: 1,
                    display_id: 0,
                    codec_id: CodecId::H264,
                    frame_id: (iter as u32) + 1,
                    gop_id: 1,
                    capture_ts_us: 1000,
                    encode_done_ts_us: 1200,
                    kind: FrameKind::InterFrame,
                    has_codec_config: false,
                    mirror_source: false,
                    payload: black_box(&payload),
                },
                budget,
            )
            .expect("fragment");
            black_box(pkts);
        });

        let packets = fragment_frame(
            &FrameToFragment {
                session_id: 1,
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: 1,
                gop_id: 1,
                capture_ts_us: 1000,
                encode_done_ts_us: 1200,
                kind: FrameKind::InterFrame,
                has_codec_config: false,
                mirror_source: false,
                payload: &payload,
            },
            budget,
        )
        .expect("pkts");

        let mut reasm = Reassembler::new(cfg).expect("reasm");
        let reasm_s = measure(30, 300, |iter| {
            reasm.clear();
            let fid = (iter as u32) + 100;
            for (idx, pkt) in packets.iter().enumerate() {
                let (mut hdr, body) = decode_video_packet(pkt, 1136).expect("hdr");
                hdr.frame_id = fid;
                let rep = reasm
                    .ingest_decoded(hdr, body, 10_000 + (idx as u64))
                    .expect("validated decoded packet");
                if idx == packets.len() - 1 {
                    assert!(matches!(rep.outcome, ReassemblyOutcome::Completed(_)));
                }
            }
            black_box(reasm.stats());
        });

        let wire_overhead = packets.len() * 44;
        let meta_overhead = packets.len() * cfg.metadata_overhead_per_fragment_bytes;
        let mib_s_frag =
            ((size_bytes as f64) / (1024.0 * 1024.0)) / (frag_s.avg_ns / 1_000_000_000.0);
        let mib_s_reasm =
            ((size_bytes as f64) / (1024.0 * 1024.0)) / (reasm_s.avg_ns / 1_000_000_000.0);
        println!(
            "media_frag_{size_kib}KiB (frags={}, wire_hdr={}B): avg={:.2}us p50={:.2}us p95={:.2}us p99={:.2}us max={:.2}us ({:.1} MiB/s)",
            packets.len(),
            wire_overhead,
            frag_s.avg_ns / 1_000.0,
            (frag_s.p50_ns as f64) / 1_000.0,
            (frag_s.p95_ns as f64) / 1_000.0,
            (frag_s.p99_ns as f64) / 1_000.0,
            (frag_s.max_ns as f64) / 1_000.0,
            mib_s_frag
        );
        println!(
            "media_reasm_{size_kib}KiB (meta_hdr={}B): avg={:.2}us p50={:.2}us p95={:.2}us p99={:.2}us max={:.2}us ({:.1} MiB/s)",
            meta_overhead,
            reasm_s.avg_ns / 1_000.0,
            (reasm_s.p50_ns as f64) / 1_000.0,
            (reasm_s.p95_ns as f64) / 1_000.0,
            (reasm_s.p99_ns as f64) / 1_000.0,
            (reasm_s.max_ns as f64) / 1_000.0,
            mib_s_reasm
        );
    }
}

fn main() {
    println!("=== lumabridge-protocol synthetic benchmark (INFORMATIVE ONLY) ===");
    bench_framing_and_headers();
    bench_cbor_messages();
    bench_media_pipeline_sizes();
}
