// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use lumabridge_protocol::cbor::{CborDecodeOptions, UnknownFieldPolicy};
use lumabridge_protocol::control::{ControlMessage, MsgType, Permissions};
use lumabridge_protocol::framing::{ChannelId, FrameFlags, FrameHeader};
use lumabridge_protocol::limits::FramingLimits;
use lumabridge_protocol::validation::{
    ConnectionPhase, Direction, FrameContextDecision, SequenceTracker, ValidationContext,
    validate_frame_context, validate_message_context,
};
use lumabridge_protocol::version::Alpn;

const ALL_MSG_CODES: [u16; 24] = [
    MsgType::PairHello.as_u16(),
    MsgType::PairSpakeMsg.as_u16(),
    MsgType::PairQrAuth.as_u16(),
    MsgType::PairConfirm.as_u16(),
    MsgType::PairCancel.as_u16(),
    MsgType::Hello.as_u16(),
    MsgType::HelloAck.as_u16(),
    MsgType::NodeCapabilities.as_u16(),
    MsgType::SessionOpenRequest.as_u16(),
    MsgType::SessionOpenResponse.as_u16(),
    MsgType::DisplayConfigUpdate.as_u16(),
    MsgType::SessionResumeRequest.as_u16(),
    MsgType::SessionResumeResponse.as_u16(),
    MsgType::SessionClose.as_u16(),
    MsgType::PermissionUpgradeRequest.as_u16(),
    MsgType::PermissionUpdate.as_u16(),
    MsgType::MediaFeedback.as_u16(),
    MsgType::ClockSyncPing.as_u16(),
    MsgType::ClockSyncPong.as_u16(),
    MsgType::Heartbeat.as_u16(),
    MsgType::DiagnosticsSummary.as_u16(),
    MsgType::InputBatch.as_u16(),
    MsgType::ErrorNotice.as_u16(),
    0x0800,
];

fn verify_decision(ctx: &ValidationContext, header: FrameHeader, payload: &[u8]) {
    let decision = validate_frame_context(ctx, header);
    if ctx.alpn == Alpn::Pairing {
        match decision {
            FrameContextDecision::AllowKnown(m) => {
                assert!(m.is_pairing() || m == MsgType::ErrorNotice);
            }
            FrameContextDecision::Reject(_) => {}
            other => panic!("unexpected pairing ALPN decision: {other:?}"),
        }
    }
    if header.flags.must_understand()
        && MsgType::from_raw(header.msg_type).is_none()
        && header.channel_id != ChannelId::Media
    {
        assert!(matches!(decision, FrameContextDecision::Reject(_)));
    }
    if let FrameContextDecision::AllowKnown(msg_type) = decision {
        if let Ok(msg) = ControlMessage::decode_cbor(
            msg_type,
            payload,
            CborDecodeOptions {
                unknown_fields: UnknownFieldPolicy::SkipBounded,
                ..CborDecodeOptions::default()
            },
        ) {
            let res = validate_message_context(ctx, &msg);
            if let ControlMessage::InputBatch(ref batch) = msg {
                let all_allowed = batch
                    .events
                    .iter()
                    .all(|ev| ctx.effective_perms.contains(ev.required_permission()));
                if ctx.active_session_id.is_none() || !all_allowed {
                    assert!(res.is_err());
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let b0 = data.first().copied().unwrap_or(0);
    let b1 = data.get(1).copied().unwrap_or(0);
    let b2 = data.get(2).copied().unwrap_or(0);

    let ctx = ValidationContext {
        alpn: if (b0 & 1) == 0 {
            Alpn::Pairing
        } else {
            Alpn::Operational
        },
        channel: match (b0 >> 1) & 0x03 {
            0 => ChannelId::Control,
            1 => ChannelId::Media,
            2 => ChannelId::Feedback,
            _ => ChannelId::Input,
        },
        direction: if (b0 & 0x08) == 0 {
            Direction::InitiatorToAcceptor
        } else {
            Direction::AcceptorToInitiator
        },
        phase: match (b0 >> 4) & 0x03 {
            0 => ConnectionPhase::PairingOpen,
            1 => ConnectionPhase::OperationalHandshake,
            2 => ConnectionPhase::OperationalAuthenticated,
            _ => ConnectionPhase::OperationalSessionActive,
        },
        effective_perms: Permissions::from_raw(u32::from(b1 & 0x7F)).unwrap_or(Permissions::NONE),
        active_session_id: if b2 == 0 { None } else { Some(u64::from(b2)) },
    };

    // Path 1: raw bytes as FrameHeader
    if data.len() >= 11 {
        let mut hdr_bytes: [u8; 8] = data[3..11].try_into().expect("8B slice");
        hdr_bytes[7] &= 0x01;
        if let Ok(header) = FrameHeader::decode(&hdr_bytes, &FramingLimits::default()) {
            verify_decision(&ctx, header, &data[11..]);
        }
    }

    // Path 2: structured known/unknown MsgType header against arbitrary context
    let msg_code = if (b0 & 0x80) == 0 {
        ALL_MSG_CODES[usize::from(b1) % ALL_MSG_CODES.len()]
    } else {
        u16::from_be_bytes([b1, b2])
    };
    let flags = if (b2 & 1) == 0 {
        FrameFlags::NONE
    } else {
        FrameFlags::MUST_UNDERSTAND
    };
    let synthetic = FrameHeader {
        frame_len: 64,
        channel_id: ctx.channel,
        msg_type: msg_code,
        flags,
    };
    verify_decision(&ctx, synthetic, data.get(3..).unwrap_or(&[]));

    // Path 3: monotonic sequence tracker invariant
    let mut tracker = SequenceTracker::new();
    for &b in data.get(3..).unwrap_or(data) {
        let seq = u64::from(b);
        let prev = tracker.last_accepted();
        let res = tracker.accept(seq);
        if seq == 0 || seq <= prev {
            assert!(res.is_err());
        } else {
            assert!(res.is_ok());
        }
    }
});
