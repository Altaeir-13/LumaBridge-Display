// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use lumabridge_protocol::framing::{ChannelId, DecodeStep, StreamBindingMode, StreamFrameDecoder};
use lumabridge_protocol::limits::FramingLimits;

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or(0);
    let binding = match selector % 6 {
        0 => StreamBindingMode::UnboundSingleChannel,
        1 => StreamBindingMode::BoundSingleChannel(ChannelId::Control),
        2 => StreamBindingMode::BoundSingleChannel(ChannelId::Media),
        3 => StreamBindingMode::BoundSingleChannel(ChannelId::Feedback),
        4 => StreamBindingMode::BoundSingleChannel(ChannelId::Input),
        _ => StreamBindingMode::Multiplexed,
    };
    let chunk_step = data.get(1).map_or(1, |&b| usize::from((b & 0x3F).max(1)));
    let expected_single = match binding {
        StreamBindingMode::BoundSingleChannel(ch) => Some(ch),
        _ => None,
    };
    let payload = data.get(2..).unwrap_or(data);
    let limits = FramingLimits::default();

    // Path 1: buffered feed() + next_frame() + finish_eof()
    if let Ok(mut decoder) = StreamFrameDecoder::new(limits, binding) {
        let mut poisoned = false;
        for chunk in payload.chunks(chunk_step) {
            if decoder.feed(chunk).is_err() {
                assert!(decoder.is_poisoned());
                poisoned = true;
                break;
            }
            loop {
                match decoder.next_frame() {
                    Ok(Some(frame)) => {
                        if let Some(ch) = expected_single {
                            assert_eq!(frame.header.channel_id, ch);
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        assert!(decoder.is_poisoned());
                        poisoned = true;
                        break;
                    }
                }
            }
            if poisoned {
                break;
            }
        }
        if !poisoned {
            let _ = decoder.finish_eof();
        }
    }

    // Path 2: zero-copy incremental step_slice() on direct chunks
    if let Ok(mut direct) = StreamFrameDecoder::new(limits, binding) {
        for chunk in payload.chunks(chunk_step) {
            let mut slice = chunk;
            while !slice.is_empty() {
                match direct.step_slice(slice) {
                    Ok(DecodeStep::Frame { frame, consumed }) => {
                        if let Some(ch) = expected_single {
                            assert_eq!(frame.header.channel_id, ch);
                        }
                        if consumed == 0 {
                            break;
                        }
                        slice = &slice[consumed..];
                    }
                    Ok(DecodeStep::NeedMoreData { consumed }) => {
                        if consumed == 0 {
                            break;
                        }
                        slice = &slice[consumed..];
                    }
                    Err(_) => {
                        assert!(direct.is_poisoned());
                        return;
                    }
                }
            }
        }
        let _ = direct.finish_eof();
    }
});
