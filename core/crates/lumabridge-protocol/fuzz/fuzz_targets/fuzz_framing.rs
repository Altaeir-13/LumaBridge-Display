// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use lumabridge_protocol::error::FrameError;
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

    // Path 1: buffered feed() + premature finish_eof() check + next_frame() drain + finish_eof()
    if let Ok(mut decoder) = StreamFrameDecoder::new(limits, binding) {
        let mut poisoned = false;
        let dbg_str = format!("{decoder:?}");
        assert!(!dbg_str.contains("buf:"));

        for (idx, chunk) in payload.chunks(chunk_step).enumerate() {
            if decoder.feed(chunk).is_err() {
                assert!(decoder.is_poisoned());
                poisoned = true;
                break;
            }
            if !chunk.is_empty() && (idx & 1) == 0 {
                // Calling finish_eof() while unread bytes remain MUST fail non-destructively.
                let eof_early = decoder.finish_eof();
                assert!(matches!(
                    eof_early,
                    Err(FrameError::PendingBufferedInput { .. })
                ));
                assert!(!decoder.is_poisoned());
                assert!(matches!(
                    decoder.step_slice(&[0u8]),
                    Err(FrameError::PendingBufferedInput { .. })
                ));
            }
            loop {
                match decoder.next_frame() {
                    Ok(Some(frame)) => {
                        if let Some(ch) = expected_single {
                            assert_eq!(frame.header.channel_id, ch);
                        }
                        let frame_dbg = format!("{frame:?}");
                        assert!(frame_dbg.contains("payload_len"));
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
        if !poisoned && decoder.finish_eof().is_ok() {
            assert!(decoder.is_eof());
            assert!(decoder.finish_eof().is_ok());
            assert_eq!(decoder.feed(&[1]), Err(FrameError::StreamClosed));
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
