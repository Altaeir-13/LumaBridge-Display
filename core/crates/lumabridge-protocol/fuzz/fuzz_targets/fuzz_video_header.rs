// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use lumabridge_protocol::framing::{FrameFlags, StreamBindingMode, StreamFrameDecoder};
use lumabridge_protocol::limits::FramingLimits;
use lumabridge_protocol::media::fragmentation::{
    decode_media_stream_record, encode_media_stream_record,
};
use lumabridge_protocol::media::header::decode_video_packet;

fuzz_target!(|data: &[u8]| {
    let raw_budget = match (data.first().copied(), data.get(1).copied()) {
        (Some(a), Some(b)) => u16::from_be_bytes([a, b]),
        _ => 1500,
    };
    let budget = match raw_budget % 4 {
        0 => usize::from(raw_budget & 0x003F),
        1 => usize::from(raw_budget).clamp(44, 1500),
        _ => usize::from(raw_budget).clamp(44, 16_384),
    };

    let packet = if data.len() >= 2 && (data[0] & 0x80) == 0 {
        &data[2..]
    } else {
        data
    };

    if let Ok((hdr, body)) = decode_video_packet(packet, budget) {
        assert_eq!(usize::from(hdr.payload_len), body.len());
        let mut rebuilt = Vec::with_capacity(44 + body.len());
        rebuilt.extend_from_slice(&hdr.encode());
        rebuilt.extend_from_slice(body);
        let (hdr2, body2) = decode_video_packet(&rebuilt, budget)
            .expect("re-encoded valid video packet must decode");
        assert_eq!(hdr, hdr2);
        assert_eq!(body, body2);

        let limits = FramingLimits::default();
        if rebuilt.len() <= limits.max_media_stream_bytes {
            let framed = encode_media_stream_record(&rebuilt, FrameFlags::NONE, &limits)
                .expect("stream record within Channel 1 ceiling must encode");
            let mut dec = StreamFrameDecoder::new(limits, StreamBindingMode::Multiplexed)
                .expect("valid limits");
            dec.feed(&framed).expect("feed record");
            let raw = dec
                .next_frame()
                .expect("decode ok")
                .expect("complete frame");
            dec.finish_eof().expect("eof");
            let (hdr3, body3) =
                decode_media_stream_record(&raw, &limits).expect("media record roundtrip");
            assert_eq!(hdr, hdr3);
            assert_eq!(body, body3);
        }
    }
});
