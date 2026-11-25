// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pure, stateless contextual validation policy and monotonic sequence verification.
//!
//! This module does NOT grant trust, verify cryptography, or manage authentication state;
//! the caller (`lumabridge-security` / `lumabridge-transport` in `M1.3+`) supplies the
//! externally authenticated [`ValidationContext`].

use crate::control::{ControlMessage, MsgType, Permissions};
use crate::error::{ErrorClass, ErrorCode, ValidationError};
use crate::framing::{ChannelId, FrameHeader};
use crate::limits::MSG_TYPE_MEDIA_VIDEO_FRAGMENT;
use crate::version::Alpn;

/// Peer communication direction relative to the TLS/QUIC initiator and acceptor roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    InitiatorToAcceptor,
    AcceptorToInitiator,
}

/// Externally supplied connection phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPhase {
    /// Pairing ALPN window open (`UnverifiedPeer` until pairing completes).
    PairingOpen,
    /// Operational mTLS authenticated by transport; exchanging `Hello` / `HelloAck` / `NodeCapabilities`.
    OperationalHandshake,
    /// Operational handshake completed; ready for session open/resume.
    OperationalAuthenticated,
    /// Active media/input display session established.
    OperationalSessionActive,
}

/// Externally provided trust, channel, direction, and authorization context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationContext {
    pub alpn: Alpn,
    pub channel: ChannelId,
    pub direction: Direction,
    pub phase: ConnectionPhase,
    pub effective_perms: Permissions,
    pub active_session_id: Option<u64>,
}

/// Outcome of validating a stream frame header before CBOR payload decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameContextDecision {
    /// Known control/feedback/input message permitted in this context; proceed to CBOR decode.
    AllowKnown(MsgType),
    /// Binary `MediaVideoFragment` (`0x0800`) permitted on `Channel 1`.
    AllowMediaFragment,
    /// Unknown `msg_type` without `MUST_UNDERSTAND` safely ignored in authorized operational context.
    IgnoreUnknownOptional,
    /// Message violates ALPN, channel, direction, phase, or feature policy.
    Reject(ValidationError),
}

const fn reject_fatal(code: ErrorCode, reason: &'static str) -> ValidationError {
    ValidationError {
        code,
        fatal: true,
        class: ErrorClass::FatalStream,
        reason,
    }
}

const fn reject_contextual(code: ErrorCode, reason: &'static str) -> ValidationError {
    ValidationError {
        code,
        fatal: false,
        class: ErrorClass::ContextualError,
        reason,
    }
}

/// Validate a stream [`FrameHeader`] against the current ALPN, channel, direction, and phase.
#[must_use]
pub fn validate_frame_context(
    ctx: &ValidationContext,
    header: FrameHeader,
) -> FrameContextDecision {
    if ctx.channel != header.channel_id {
        return FrameContextDecision::Reject(reject_fatal(
            ErrorCode::InvalidFraming,
            "frame header channel_id mismatches bound context channel",
        ));
    }

    match ctx.alpn {
        Alpn::Pairing => validate_pairing_frame_context(ctx, header),
        Alpn::Operational => validate_operational_frame_context(ctx, header),
    }
}

fn validate_pairing_frame_context(
    ctx: &ValidationContext,
    header: FrameHeader,
) -> FrameContextDecision {
    if ctx.phase != ConnectionPhase::PairingOpen {
        return FrameContextDecision::Reject(reject_fatal(
            ErrorCode::InvalidFraming,
            "pairing ALPN requires PairingOpen phase",
        ));
    }
    if ctx.channel != ChannelId::Control {
        return FrameContextDecision::Reject(reject_fatal(
            ErrorCode::InvalidFraming,
            "pairing ALPN allows Channel 0 only",
        ));
    }
    let Some(msg_type) = MsgType::from_raw(header.msg_type) else {
        // Pairing ALPN rejects ALL unknown msg_types even without MUST_UNDERSTAND.
        return FrameContextDecision::Reject(reject_fatal(
            ErrorCode::InvalidFraming,
            "unknown msg_type forbidden in pairing ALPN",
        ));
    };
    if !msg_type.is_pairing() && msg_type != MsgType::ErrorNotice {
        return FrameContextDecision::Reject(reject_fatal(
            ErrorCode::InvalidFraming,
            "non-pairing message forbidden in pairing ALPN",
        ));
    }
    if let Err(err) = check_direction(msg_type, ctx.direction) {
        return FrameContextDecision::Reject(err);
    }
    FrameContextDecision::AllowKnown(msg_type)
}

fn validate_operational_frame_context(
    ctx: &ValidationContext,
    header: FrameHeader,
) -> FrameContextDecision {
    if ctx.phase == ConnectionPhase::PairingOpen {
        return FrameContextDecision::Reject(reject_fatal(
            ErrorCode::InvalidFraming,
            "PairingOpen phase invalid on operational ALPN",
        ));
    }

    if ctx.channel == ChannelId::Media {
        if header.msg_type != MSG_TYPE_MEDIA_VIDEO_FRAGMENT {
            return FrameContextDecision::Reject(reject_fatal(
                ErrorCode::InvalidFraming,
                "only MediaVideoFragment (0x0800) permitted on Channel 1",
            ));
        }
        if ctx.phase != ConnectionPhase::OperationalSessionActive || ctx.active_session_id.is_none()
        {
            return FrameContextDecision::Reject(reject_fatal(
                ErrorCode::InvalidFraming,
                "media frames require active session",
            ));
        }
        return FrameContextDecision::AllowMediaFragment;
    }

    let Some(msg_type) = MsgType::from_raw(header.msg_type) else {
        if header.flags.must_understand() {
            return FrameContextDecision::Reject(reject_fatal(
                ErrorCode::UnsupportedFeature,
                "unknown msg_type with MUST_UNDERSTAND",
            ));
        }
        if !matches!(
            ctx.phase,
            ConnectionPhase::OperationalAuthenticated | ConnectionPhase::OperationalSessionActive
        ) {
            return FrameContextDecision::Reject(reject_fatal(
                ErrorCode::InvalidFraming,
                "unknown optional message rejected before handshake completion",
            ));
        }
        if ctx.channel == ChannelId::Input
            && (ctx.phase != ConnectionPhase::OperationalSessionActive
                || !ctx.effective_perms.has_any_input())
        {
            return FrameContextDecision::Reject(reject_contextual(
                ErrorCode::PermissionDenied,
                "unknown optional input-channel message rejected without active input permission",
            ));
        }
        return FrameContextDecision::IgnoreUnknownOptional;
    };

    if msg_type.is_pairing() {
        return FrameContextDecision::Reject(reject_fatal(
            ErrorCode::InvalidFraming,
            "pairing messages forbidden on operational ALPN",
        ));
    }
    if msg_type.expected_channel() != ctx.channel {
        return FrameContextDecision::Reject(reject_fatal(
            ErrorCode::InvalidFraming,
            "message received on disallowed logical channel",
        ));
    }
    if let Err(err) = check_direction(msg_type, ctx.direction) {
        return FrameContextDecision::Reject(err);
    }
    if let Err(err) = check_operational_phase(msg_type, ctx.phase, ctx.active_session_id) {
        return FrameContextDecision::Reject(err);
    }
    FrameContextDecision::AllowKnown(msg_type)
}

const fn check_direction(msg_type: MsgType, dir: Direction) -> Result<(), ValidationError> {
    match (msg_type, dir) {
        (
            MsgType::PairQrAuth | MsgType::Hello | MsgType::SessionResumeRequest,
            Direction::AcceptorToInitiator,
        )
        | (
            MsgType::PairConfirm | MsgType::HelloAck | MsgType::SessionResumeResponse,
            Direction::InitiatorToAcceptor,
        ) => Err(reject_fatal(
            ErrorCode::InvalidFraming,
            "message direction violates protocol role",
        )),
        _ => Ok(()),
    }
}

const fn check_operational_phase(
    msg_type: MsgType,
    phase: ConnectionPhase,
    active_session_id: Option<u64>,
) -> Result<(), ValidationError> {
    match phase {
        ConnectionPhase::PairingOpen => Err(reject_fatal(
            ErrorCode::InvalidFraming,
            "invalid pairing phase on operational ALPN",
        )),
        ConnectionPhase::OperationalHandshake => match msg_type {
            MsgType::Hello
            | MsgType::HelloAck
            | MsgType::NodeCapabilities
            | MsgType::ClockSyncPing
            | MsgType::ClockSyncPong
            | MsgType::Heartbeat
            | MsgType::ErrorNotice => Ok(()),
            _ => Err(reject_fatal(
                ErrorCode::InvalidFraming,
                "message forbidden before handshake completion",
            )),
        },
        ConnectionPhase::OperationalAuthenticated => match msg_type {
            MsgType::DisplayConfigUpdate
            | MsgType::MediaFeedback
            | MsgType::DiagnosticsSummary
            | MsgType::InputBatch => Err(reject_contextual(
                ErrorCode::SessionNotFound,
                "message requires an active session",
            )),
            _ => Ok(()),
        },
        ConnectionPhase::OperationalSessionActive => {
            if active_session_id.is_none() {
                return Err(reject_contextual(
                    ErrorCode::SessionNotFound,
                    "active session ID missing in OperationalSessionActive",
                ));
            }
            Ok(())
        }
    }
}

/// Validate a decoded [`ControlMessage`] against the full [`ValidationContext`], including
/// `session_id` correlation and strict per-event remote input permissions (`deny-by-default`).
pub fn validate_message_context(
    ctx: &ValidationContext,
    msg: &ControlMessage,
) -> Result<(), ValidationError> {
    let synthetic_header = FrameHeader {
        frame_len: 0,
        channel_id: ctx.channel,
        msg_type: msg.msg_type().as_u16(),
        flags: crate::framing::FrameFlags::NONE,
    };
    match validate_frame_context(ctx, synthetic_header) {
        FrameContextDecision::AllowKnown(_) => {}
        FrameContextDecision::Reject(err) => return Err(err),
        FrameContextDecision::AllowMediaFragment | FrameContextDecision::IgnoreUnknownOptional => {
            return Err(reject_fatal(
                ErrorCode::InvalidFraming,
                "unexpected context decision for decoded control message",
            ));
        }
    }

    if let (Some(expected_sid), Some(msg_sid)) = (ctx.active_session_id, msg.session_id()) {
        if expected_sid != msg_sid {
            return Err(reject_contextual(
                ErrorCode::SessionNotFound,
                "message session_id does not match active session",
            ));
        }
    }

    if let ControlMessage::InputBatch(batch) = msg {
        if ctx.active_session_id.is_none() {
            return Err(reject_contextual(
                ErrorCode::SessionNotFound,
                "InputBatch requires active session",
            ));
        }
        for ev in &batch.events {
            let req_perm = ev.required_permission();
            if !ctx.effective_perms.contains(req_perm) {
                return Err(reject_contextual(
                    ErrorCode::PermissionDenied,
                    "InputEvent rejected: required input permission not granted",
                ));
            }
        }
    }

    Ok(())
}

/// Strictly monotonic `u64` sequence tracker rejecting `0`, replay/regression (`seq <= last`),
/// and counter exhaustion (`u64::MAX` overflow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceTracker {
    next_expected_min: Option<u64>,
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SequenceTracker {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_expected_min: Some(1),
        }
    }

    /// Return the last accepted sequence number (`0` before any accepted counter).
    #[must_use]
    pub const fn last_accepted(&self) -> u64 {
        match self.next_expected_min {
            Some(next) => next - 1,
            None => u64::MAX,
        }
    }

    /// Accept a strictly increasing sequence number (`>= 1`), returning an error on `0`,
    /// regression/replay, or domain exhaustion.
    pub fn accept(&mut self, seq: u64) -> Result<(), ValidationError> {
        let Some(min_allowed) = self.next_expected_min else {
            return Err(reject_fatal(
                ErrorCode::InvalidFraming,
                "sequence counter domain exhausted",
            ));
        };
        if seq == 0 {
            return Err(reject_fatal(
                ErrorCode::InvalidFraming,
                "sequence counter must be >= 1",
            ));
        }
        if seq < min_allowed {
            return Err(reject_fatal(
                ErrorCode::InvalidFraming,
                "sequence counter regression or replay detected",
            ));
        }
        self.next_expected_min = seq.checked_add(1);
        Ok(())
    }
}
