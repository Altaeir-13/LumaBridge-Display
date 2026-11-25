// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sanitized, typed protocol errors and operational error classification.

use core::fmt;

/// Numeric `ErrorNotice` wire codes defined in LBWP v1 §5.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ErrorCode {
    UnsupportedVersion = 1,
    InvalidFraming = 2,
    FrameTooLarge = 3,
    UnsupportedFeature = 4,
    UnauthorizedPeer = 5,
    PairingClosed = 6,
    PairingFailed = 7,
    PermissionDenied = 8,
    SessionNotFound = 9,
    DisplayUnavailable = 10,
    CodecNegotiationFailed = 11,
    RateLimited = 12,
}

impl ErrorCode {
    /// Decode a numeric `ErrorCode` strictly from its wire integer representation.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::UnsupportedVersion),
            2 => Some(Self::InvalidFraming),
            3 => Some(Self::FrameTooLarge),
            4 => Some(Self::UnsupportedFeature),
            5 => Some(Self::UnauthorizedPeer),
            6 => Some(Self::PairingClosed),
            7 => Some(Self::PairingFailed),
            8 => Some(Self::PermissionDenied),
            9 => Some(Self::SessionNotFound),
            10 => Some(Self::DisplayUnavailable),
            11 => Some(Self::CodecNegotiationFailed),
            12 => Some(Self::RateLimited),
            _ => None,
        }
    }

    /// Return the stable numeric wire code (`1..=12`).
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Action class separating fatal stream errors, silent datagram drops, frame rejections,
/// and non-fatal contextual errors (anti-amplification policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Fatal error on a byte-oriented stream; terminate stream/connection and optionally emit `ErrorNotice(fatal = true)`.
    FatalStream,
    /// Malformed or unauthorized media datagram; drop silently without per-packet reply to prevent amplification.
    DropDatagram,
    /// Incomplete or conflicting frame; free reassembly budget immediately and drive GOP recovery.
    RejectFrame,
    /// Context or permission violation on an otherwise well-framed message; emit non-fatal `ErrorNotice` when allowed.
    ContextualError,
}

/// Invalid limit configuration error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitConfigError {
    InvalidValue(&'static str),
}

impl fmt::Display for LimitConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue(msg) => write!(f, "invalid limit configuration: {msg}"),
        }
    }
}

impl std::error::Error for LimitConfigError {}

/// Stream framing encoder/decoder errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    InvalidChannelId(u8),
    FrameTooLarge {
        channel: u8,
        frame_len: u32,
        max_allowed: usize,
    },
    MediaStreamRecordTooSmall(u32),
    InvalidMediaStreamMsgType(u16),
    ReservedFlagsNonZero(u8),
    ChannelSwitchForbidden {
        bound: u8,
        observed: u8,
    },
    UnexpectedEofInHeader,
    UnexpectedEofInPayload,
    StreamPoisoned,
}

impl FrameError {
    /// Classify into protocol action class and wire error code.
    #[must_use]
    pub const fn wire_error_code(self) -> ErrorCode {
        match self {
            Self::FrameTooLarge { .. } => ErrorCode::FrameTooLarge,
            _ => ErrorCode::InvalidFraming,
        }
    }

    #[must_use]
    pub const fn error_class(self) -> ErrorClass {
        ErrorClass::FatalStream
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChannelId(ch) => write!(f, "invalid channel_id: {ch}"),
            Self::FrameTooLarge {
                channel,
                frame_len,
                max_allowed,
            } => write!(
                f,
                "frame_len {frame_len} exceeds max {max_allowed} on channel {channel}"
            ),
            Self::MediaStreamRecordTooSmall(len) => {
                write!(
                    f,
                    "media stream record len {len} < 44-byte VideoPacketHeader"
                )
            }
            Self::InvalidMediaStreamMsgType(ty) => {
                write!(f, "invalid Channel 1 stream msg_type 0x{ty:04X}")
            }
            Self::ReservedFlagsNonZero(flags) => {
                write!(f, "non-zero reserved framing flags: 0x{flags:02X}")
            }
            Self::ChannelSwitchForbidden { bound, observed } => write!(
                f,
                "mid-stream channel switch forbidden (bound {bound}, observed {observed})"
            ),
            Self::UnexpectedEofInHeader => write!(f, "unexpected EOF inside 8-byte frame header"),
            Self::UnexpectedEofInPayload => write!(f, "unexpected EOF inside frame payload"),
            Self::StreamPoisoned => write!(f, "stream decoder poisoned after fatal framing error"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Restricted CBOR codec errors distinguishing deterministic representation faults
/// from semantic/structural violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborError {
    // --- Deterministic representation errors (RFC 8949 §4.2.1) ---
    NonMinimalInteger,
    UnsortedMapKeys,
    IndefiniteLengthForbidden,
    // --- Structural / security / semantic errors ---
    DuplicateMapKey,
    ForbiddenType(&'static str),
    InvalidUtf8,
    Truncated,
    TrailingBytes,
    DepthExceeded,
    LimitExceeded(&'static str),
    MissingRequiredField(&'static str),
    TypeMismatch(&'static str),
    ValueOutOfRange(&'static str),
    EncodeBufferError,
}

impl CborError {
    /// Returns `true` when the payload failed solely deterministic representation requirements
    /// (`NonMinimalInteger`, `UnsortedMapKeys`, `IndefiniteLengthForbidden`).
    #[must_use]
    pub const fn is_representation_error(self) -> bool {
        matches!(
            self,
            Self::NonMinimalInteger | Self::UnsortedMapKeys | Self::IndefiniteLengthForbidden
        )
    }

    #[must_use]
    pub const fn wire_error_code(self) -> ErrorCode {
        match self {
            Self::LimitExceeded(_) => ErrorCode::FrameTooLarge,
            _ => ErrorCode::InvalidFraming,
        }
    }
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonMinimalInteger => write!(f, "non-minimal CBOR integer encoding"),
            Self::UnsortedMapKeys => write!(f, "CBOR map keys are not strictly ascending"),
            Self::IndefiniteLengthForbidden => {
                write!(f, "indefinite-length CBOR item or break is forbidden")
            }
            Self::DuplicateMapKey => write!(f, "duplicate CBOR map key"),
            Self::ForbiddenType(ty) => write!(f, "forbidden CBOR type: {ty}"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in CBOR text string"),
            Self::Truncated => write!(f, "truncated CBOR input"),
            Self::TrailingBytes => write!(f, "trailing bytes after CBOR root map"),
            Self::DepthExceeded => write!(f, "CBOR nesting depth exceeded"),
            Self::LimitExceeded(detail) => write!(f, "CBOR profile limit exceeded: {detail}"),
            Self::MissingRequiredField(field) => write!(f, "missing required CBOR field: {field}"),
            Self::TypeMismatch(field) => write!(f, "CBOR field type mismatch: {field}"),
            Self::ValueOutOfRange(field) => write!(f, "CBOR field value out of range: {field}"),
            Self::EncodeBufferError => write!(f, "CBOR encoding output buffer failure"),
        }
    }
}

impl std::error::Error for CborError {}

/// Binary `VideoPacketHeader` validation and decoding errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoHeaderError {
    PacketTooShort(usize),
    PacketTooLarge { actual: usize, max_allowed: usize },
    InvalidMagic(u16),
    ReservedFlagsNonZero(u16),
    ReservedByteNonZero(u8),
    InvalidSessionIdZero,
    InvalidDisplayId(u16),
    UnknownCodecId(u8),
    InvalidFrameIdZero,
    InvalidFragCount(u16),
    FragIndexOutOfBounds { frag_index: u16, frag_count: u16 },
    EndOfFrameFlagMismatch,
    ChainResetWithoutKeyframe,
    ProtectedBlankInvalidFlags(u16),
    ProtectedBlankInvalidGeometry,
    EmptyPayloadWithoutProtectedBlank,
    PayloadLenMismatch { header_len: u16, actual_len: usize },
    TimestampRegression,
}

impl VideoHeaderError {
    #[must_use]
    pub const fn error_class(self) -> ErrorClass {
        ErrorClass::DropDatagram
    }
}

impl fmt::Display for VideoHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort(len) => write!(f, "video packet shorter than 44 B ({len} B)"),
            Self::PacketTooLarge {
                actual,
                max_allowed,
            } => write!(
                f,
                "video packet {actual} B exceeds negotiated max {max_allowed} B"
            ),
            Self::InvalidMagic(m) => write!(f, "invalid VideoPacketHeader magic 0x{m:04X}"),
            Self::ReservedFlagsNonZero(flags) => {
                write!(f, "unknown/reserved video flags 0x{flags:04X}")
            }
            Self::ReservedByteNonZero(val) => {
                write!(f, "non-zero VideoPacketHeader reserved byte: {val}")
            }
            Self::InvalidSessionIdZero => write!(f, "video packet session_id must be non-zero"),
            Self::InvalidDisplayId(id) => write!(f, "invalid reserved display_id 0x{id:04X}"),
            Self::UnknownCodecId(c) => write!(f, "unknown codec_id {c}"),
            Self::InvalidFrameIdZero => write!(f, "video packet frame_id must be >= 1"),
            Self::InvalidFragCount(c) => write!(f, "invalid frag_count {c} (must be 1..=4096)"),
            Self::FragIndexOutOfBounds {
                frag_index,
                frag_count,
            } => write!(f, "frag_index {frag_index} >= frag_count {frag_count}"),
            Self::EndOfFrameFlagMismatch => {
                write!(f, "FLAG_END_OF_FRAME mismatch vs frag_index/frag_count")
            }
            Self::ChainResetWithoutKeyframe => {
                write!(f, "FLAG_CHAIN_RESET requires FLAG_KEYFRAME")
            }
            Self::ProtectedBlankInvalidFlags(flags) => write!(
                f,
                "FLAG_PROTECTED_BLANK combined with incompatible flags 0x{flags:04X}"
            ),
            Self::ProtectedBlankInvalidGeometry => write!(
                f,
                "FLAG_PROTECTED_BLANK requires frag_count=1, frag_index=0, payload_len=0"
            ),
            Self::EmptyPayloadWithoutProtectedBlank => {
                write!(
                    f,
                    "empty media payload disallowed without FLAG_PROTECTED_BLANK"
                )
            }
            Self::PayloadLenMismatch {
                header_len,
                actual_len,
            } => write!(
                f,
                "VideoPacketHeader payload_len {header_len} != actual {actual_len}"
            ),
            Self::TimestampRegression => {
                write!(f, "encode_done_ts_us < capture_ts_us")
            }
        }
    }
}

impl std::error::Error for VideoHeaderError {}

/// Checked MTU budgeting and frame fragmentation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentationError {
    InvalidBudget(usize),
    EmptyFrameWithoutProtectedBlank,
    ProtectedBlankWithNonEmptyPayload,
    InvalidHeaderMetadata(&'static str),
    FrameNotRepresentable {
        frame_bytes: usize,
        max_representable: usize,
    },
    ArithmeticOverflow,
}

impl fmt::Display for FragmentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBudget(b) => write!(f, "effective LBWP packet budget {b} B too small"),
            Self::EmptyFrameWithoutProtectedBlank => {
                write!(f, "cannot fragment empty frame without protected blank")
            }
            Self::ProtectedBlankWithNonEmptyPayload => {
                write!(f, "protected blank frame must carry empty payload")
            }
            Self::InvalidHeaderMetadata(msg) => write!(f, "invalid frame metadata: {msg}"),
            Self::FrameNotRepresentable {
                frame_bytes,
                max_representable,
            } => write!(
                f,
                "frame size {frame_bytes} B exceeds representable ceiling {max_representable} B"
            ),
            Self::ArithmeticOverflow => {
                write!(f, "checked arithmetic overflow during fragmentation")
            }
        }
    }
}

impl std::error::Error for FragmentationError {}

/// Bounded video reassembly errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyError {
    ConflictingFragmentMetadata {
        frame_id: u32,
    },
    ConflictingFragmentPayload {
        frame_id: u32,
        frag_index: u16,
    },
    FrameExceedsMaxBytes {
        frame_id: u32,
        attempted: usize,
        max: usize,
    },
    DisplayBudgetExceeded {
        display_id: u16,
    },
    SessionBudgetExceeded {
        session_id: u64,
    },
    GlobalBudgetExceeded,
    TooManyDisplays,
    TooManyPendingFrames,
}

impl ReassemblyError {
    #[must_use]
    pub const fn error_class(self) -> ErrorClass {
        ErrorClass::RejectFrame
    }
}

impl fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictingFragmentMetadata { frame_id } => {
                write!(
                    f,
                    "conflicting metadata across fragments for frame {frame_id}"
                )
            }
            Self::ConflictingFragmentPayload {
                frame_id,
                frag_index,
            } => write!(
                f,
                "conflicting duplicate fragment payload for frame {frame_id} frag {frag_index}"
            ),
            Self::FrameExceedsMaxBytes {
                frame_id,
                attempted,
                max,
            } => write!(
                f,
                "reassembled frame {frame_id} ({attempted} B) exceeds limit {max} B"
            ),
            Self::DisplayBudgetExceeded { display_id } => {
                write!(f, "display {display_id} reassembly byte budget exceeded")
            }
            Self::SessionBudgetExceeded { session_id } => {
                write!(f, "session {session_id} reassembly byte budget exceeded")
            }
            Self::GlobalBudgetExceeded => write!(f, "global reassembly byte budget exceeded"),
            Self::TooManyDisplays => write!(f, "maximum tracked displays exceeded"),
            Self::TooManyPendingFrames => write!(f, "maximum pending incomplete frames exceeded"),
        }
    }
}

impl std::error::Error for ReassemblyError {}

/// Contextual policy, sequence, and authorization enforcement errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationError {
    pub code: ErrorCode,
    pub fatal: bool,
    pub class: ErrorClass,
    pub reason: &'static str,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "validation error ({:?}, fatal={}): {}",
            self.code, self.fatal, self.reason
        )
    }
}

impl std::error::Error for ValidationError {}

/// Unified protocol crate error wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    Limit(LimitConfigError),
    Framing(FrameError),
    Cbor(CborError),
    VideoHeader(VideoHeaderError),
    Fragmentation(FragmentationError),
    Reassembly(ReassemblyError),
    Validation(ValidationError),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(e) => fmt::Display::fmt(e, f),
            Self::Framing(e) => fmt::Display::fmt(e, f),
            Self::Cbor(e) => fmt::Display::fmt(e, f),
            Self::VideoHeader(e) => fmt::Display::fmt(e, f),
            Self::Fragmentation(e) => fmt::Display::fmt(e, f),
            Self::Reassembly(e) => fmt::Display::fmt(e, f),
            Self::Validation(e) => fmt::Display::fmt(e, f),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<LimitConfigError> for ProtocolError {
    fn from(e: LimitConfigError) -> Self {
        Self::Limit(e)
    }
}
impl From<FrameError> for ProtocolError {
    fn from(e: FrameError) -> Self {
        Self::Framing(e)
    }
}
impl From<CborError> for ProtocolError {
    fn from(e: CborError) -> Self {
        Self::Cbor(e)
    }
}
impl From<VideoHeaderError> for ProtocolError {
    fn from(e: VideoHeaderError) -> Self {
        Self::VideoHeader(e)
    }
}
impl From<FragmentationError> for ProtocolError {
    fn from(e: FragmentationError) -> Self {
        Self::Fragmentation(e)
    }
}
impl From<ReassemblyError> for ProtocolError {
    fn from(e: ReassemblyError) -> Self {
        Self::Reassembly(e)
    }
}
impl From<ValidationError> for ProtocolError {
    fn from(e: ValidationError) -> Self {
        Self::Validation(e)
    }
}
