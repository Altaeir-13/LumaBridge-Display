// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use lumabridge_protocol::cbor::{CborDecodeMode, CborDecodeOptions, UnknownFieldPolicy};
use lumabridge_protocol::control::{ControlMessage, MsgType};
use lumabridge_protocol::limits::CborLimits;

const ALL_MSG_TYPES: [MsgType; 23] = [
    MsgType::PairHello,
    MsgType::PairSpakeMsg,
    MsgType::PairQrAuth,
    MsgType::PairConfirm,
    MsgType::PairCancel,
    MsgType::Hello,
    MsgType::HelloAck,
    MsgType::NodeCapabilities,
    MsgType::SessionOpenRequest,
    MsgType::SessionOpenResponse,
    MsgType::DisplayConfigUpdate,
    MsgType::SessionResumeRequest,
    MsgType::SessionResumeResponse,
    MsgType::SessionClose,
    MsgType::PermissionUpgradeRequest,
    MsgType::PermissionUpdate,
    MsgType::MediaFeedback,
    MsgType::ClockSyncPing,
    MsgType::ClockSyncPong,
    MsgType::Heartbeat,
    MsgType::DiagnosticsSummary,
    MsgType::InputBatch,
    MsgType::ErrorNotice,
];

fuzz_target!(|data: &[u8]| {
    let idx = usize::from(data.first().copied().unwrap_or(0)) % ALL_MSG_TYPES.len();
    let msg_type = ALL_MSG_TYPES[idx];
    let flags = data.get(1).copied().unwrap_or(0);
    let body = data.get(2..).unwrap_or(data);

    let opts = CborDecodeOptions {
        mode: if (flags & 1) == 0 {
            CborDecodeMode::StrictDeterministic
        } else {
            CborDecodeMode::RelaxedOrderAndWidth
        },
        unknown_fields: if (flags & 2) == 0 {
            UnknownFieldPolicy::Reject
        } else {
            UnknownFieldPolicy::SkipBounded
        },
        limits: CborLimits::default(),
    };

    if let Ok(decoded) = ControlMessage::decode_cbor(msg_type, body, opts) {
        let canonical = decoded
            .encode_cbor()
            .expect("decoded validated control message must encode deterministically");
        let reparsed =
            ControlMessage::decode_cbor(msg_type, &canonical, CborDecodeOptions::default())
                .expect("re-encoded canonical CBOR must always decode strictly");
        assert_eq!(decoded, reparsed);
        let canonical_2 = reparsed
            .encode_cbor()
            .expect("canonical re-encode must be idempotent");
        assert_eq!(canonical, canonical_2);
    }
});
