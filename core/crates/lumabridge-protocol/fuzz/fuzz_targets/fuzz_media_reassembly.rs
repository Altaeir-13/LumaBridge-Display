// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use lumabridge_protocol::limits::{ReassemblyConfig, RecoveryConfig};
use lumabridge_protocol::media::header::{VideoFlags, VideoPacketHeader};
use lumabridge_protocol::media::reassembly::{Reassembler, ReassemblyOutcome};
use lumabridge_protocol::media::recovery::GopRecoveryStateMachine;
use lumabridge_protocol::version::CodecId;

fuzz_target!(|data: &[u8]| {
    let cfg = ReassemblyConfig {
        max_incomplete_frames_per_display: 4,
        max_frame_bytes: 256 * 1024,
        max_display_bytes: 512 * 1024,
        max_session_bytes: 512 * 1024,
        max_global_bytes: 1024 * 1024,
        max_total_displays: 4,
        max_pending_frames: 8,
        metadata_overhead_per_fragment_bytes: 64,
        fragment_timeout_us: 150_000,
    };
    let rec_cfg = RecoveryConfig {
        max_reorder_bytes: 128 * 1024,
        ..RecoveryConfig::default()
    };

    let Ok(mut reasm) = Reassembler::new(cfg) else {
        return;
    };
    let Ok(mut rec_s1_d0) = GopRecoveryStateMachine::new(1, 0, rec_cfg) else {
        return;
    };
    let Ok(mut rec_s2_d0) = GopRecoveryStateMachine::new(2, 0, rec_cfg) else {
        return;
    };

    let mut cursor = 0usize;
    let mut now_us = 1_000_000u64;
    let mut ops = 0usize;

    while cursor < data.len() && ops < 64 {
        ops += 1;
        let op = data[cursor];
        cursor += 1;
        now_us = now_us.saturating_add(u64::from(op & 0x0F) * 20_000);

        match op & 0xE0 {
            0xE0 => {
                let notices = reasm.expire(now_us);
                let _ = rec_s1_d0.on_discarded_notices(&notices, now_us);
                let _ = rec_s2_d0.on_discarded_notices(&notices, now_us);
            }
            0xC0 => {
                let _ = rec_s1_d0.poll_timers(now_us);
                let _ = rec_s2_d0.poll_timers(now_us);
            }
            0xA0 => {
                if (op & 0x01) == 0 {
                    reasm.remove_display(u64::from((op & 0x03) + 1), u16::from((op >> 2) & 0x03));
                } else {
                    reasm.remove_session(u64::from((op & 0x03) + 1));
                }
            }
            0x80 => {
                if cursor + 10 > data.len() {
                    break;
                }
                let sid = u64::from((data[cursor] & 0x01) + 1);
                let did = u16::from(data[cursor + 1] & 0x01);
                let fid = u32::from((data[cursor + 2] & 0x1F) + 1);
                let gop = u16::from(data[cursor + 3] & 0x07);
                let frag_count = u16::from((data[cursor + 4] & 0x07) + 1);
                let frag_index = u16::from(data[cursor + 5]) % frag_count;
                let codec_id = match data[cursor + 6] % 3 {
                    0 => CodecId::H264,
                    1 => CodecId::Hevc,
                    _ => CodecId::Av1,
                };
                let mut raw_flags = u16::from(data[cursor + 7]) & VideoFlags::VALID_MASK;
                if frag_index == frag_count - 1 {
                    raw_flags |= VideoFlags::END_OF_FRAME.raw();
                } else {
                    raw_flags &= !VideoFlags::END_OF_FRAME.raw();
                }
                let mut plen = usize::from(data[cursor + 8]).min(data.len() - (cursor + 10));
                if (raw_flags & VideoFlags::PROTECTED_BLANK.raw()) != 0 {
                    plen = 0;
                }
                let flags = VideoFlags::from_wire(raw_flags).unwrap_or(VideoFlags::NONE);
                let cts = 1_000 + u64::from(data[cursor + 9]);
                cursor += 10;
                let chunk = &data[cursor..cursor + plen];
                cursor += plen;

                let hdr = VideoPacketHeader {
                    flags,
                    session_id: sid,
                    display_id: did,
                    codec_id,
                    frame_id: fid,
                    gop_id: gop,
                    frag_index,
                    frag_count,
                    payload_len: u16::try_from(chunk.len()).unwrap_or(u16::MAX),
                    capture_ts_us: cts,
                    encode_done_ts_us: cts + 50,
                };
                // Exercise untrusted-style ingest_decoded directly without pre-validating hdr.
                if let Ok(report) = reasm.ingest_decoded(hdr, chunk, now_us) {
                    if let ReassemblyOutcome::Completed(ref f) = report.outcome {
                        assert!(f.payload.len() <= cfg.max_frame_bytes);
                    }
                    let a1 = rec_s1_d0.on_reassembly_report(report.clone(), now_us, &reasm);
                    let a2 = rec_s2_d0.on_reassembly_report(report, now_us, &reasm);
                    if sid == 2 || did != 0 {
                        assert!(a1.deliver_frames.is_empty());
                    }
                    if sid == 1 || did != 0 {
                        assert!(a2.deliver_frames.is_empty());
                    }
                }
            }
            _ => {
                if cursor + 2 > data.len() {
                    break;
                }
                let raw_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
                cursor += 2;
                let take = usize::from(raw_len).min(data.len() - cursor).min(2048);
                let pkt = &data[cursor..cursor + take];
                cursor += take;

                if let Ok(report) = reasm.ingest_packet(pkt, 2048, now_us) {
                    let _ = rec_s1_d0.on_reassembly_report(report.clone(), now_us, &reasm);
                    let _ = rec_s2_d0.on_reassembly_report(report, now_us, &reasm);
                }
            }
        }

        let stats = reasm.stats();
        assert!(stats.global_total_bytes() <= cfg.max_global_bytes);
        assert!(stats.total_pending_frames <= cfg.max_pending_frames);
        assert!(stats.total_displays <= cfg.max_total_displays);
        assert!(rec_s1_d0.queued_reorder_bytes() <= rec_cfg.max_reorder_bytes);
        assert!(rec_s2_d0.queued_reorder_bytes() <= rec_cfg.max_reorder_bytes);
    }

    reasm.clear();
    assert_eq!(reasm.stats().global_total_bytes(), 0);
});
