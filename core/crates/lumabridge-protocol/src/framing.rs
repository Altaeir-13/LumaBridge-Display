// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Transport-independent Big-Endian 8-byte framing and bounded incremental stream decoder.

use core::fmt;
use std::collections::VecDeque;

use crate::error::FrameError;
use crate::limits::{
    FramingLimits, FRAME_HEADER_LEN, MSG_TYPE_MEDIA_VIDEO_FRAGMENT, VIDEO_HEADER_LEN,
};

/// Logical LBWP channel identifier (`0..=3`), independent of QUIC stream IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ChannelId {
    /// Channel 0: reliable control, pairing, session, capabilities, permissions, diagnostics, errors.
    Control = 0,
    /// Channel 1: media video (QUIC datagrams or bounded 16 KiB stream fallback records).
    Media = 1,
    /// Channel 2: reliable media feedback, clock synchronization, and heartbeat.
    Feedback = 2,
    /// Channel 3: reliable ordered remote input batches.
    Input = 3,
}

impl ChannelId {
    /// Parse a raw wire `channel_id` byte strictly.
    pub const fn from_raw(raw: u8) -> Result<Self, FrameError> {
        match raw {
            0 => Ok(Self::Control),
            1 => Ok(Self::Media),
            2 => Ok(Self::Feedback),
            3 => Ok(Self::Input),
            _ => Err(FrameError::InvalidChannelId(raw)),
        }
    }

    /// Return the configured maximum payload length in bytes for this channel.
    #[must_use]
    pub const fn max_payload_len(self, limits: &FramingLimits) -> usize {
        match self {
            Self::Control => limits.max_control_bytes,
            Self::Media => limits.max_media_stream_bytes,
            Self::Feedback => limits.max_feedback_bytes,
            Self::Input => limits.max_input_bytes,
        }
    }
}

/// Bitmask for the 1-byte `flags` field of the 8-byte stream framing header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameFlags(u8);

impl FrameFlags {
    /// No flags set.
    pub const NONE: Self = Self(0x00);
    /// Unknown `msg_type` with this bit MUST be rejected (`ERR_UNSUPPORTED_FEATURE`).
    pub const MUST_UNDERSTAND: Self = Self(0x01);
    /// Bits `1..=7` are reserved in LBWP v1.0 and must be `0`.
    pub const RESERVED_MASK: u8 = 0xFE;

    /// Construct validated `FrameFlags` from wire byte, rejecting non-zero reserved bits.
    pub const fn from_wire(raw: u8) -> Result<Self, FrameError> {
        if (raw & Self::RESERVED_MASK) != 0 {
            return Err(FrameError::ReservedFlagsNonZero(raw));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn must_understand(self) -> bool {
        (self.0 & Self::MUST_UNDERSTAND.0) != 0
    }
}

/// Fixed 8-byte Big-Endian stream frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub frame_len: u32,
    pub channel_id: ChannelId,
    pub msg_type: u16,
    pub flags: FrameFlags,
}

impl FrameHeader {
    /// Encode into an exact 8-byte Big-Endian wire array.
    #[must_use]
    pub const fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        let len_be = self.frame_len.to_be_bytes();
        let ty_be = self.msg_type.to_be_bytes();
        [
            len_be[0],
            len_be[1],
            len_be[2],
            len_be[3],
            self.channel_id as u8,
            ty_be[0],
            ty_be[1],
            self.flags.raw(),
        ]
    }

    /// Decode and validate header bounds, channel ID, reserved flags, and Channel 1 stream rules
    /// BEFORE any payload buffer is allocated.
    pub fn decode(
        bytes: &[u8; FRAME_HEADER_LEN],
        limits: &FramingLimits,
    ) -> Result<Self, FrameError> {
        let frame_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let channel_id = ChannelId::from_raw(bytes[4])?;
        let msg_type = u16::from_be_bytes([bytes[5], bytes[6]]);
        let flags = FrameFlags::from_wire(bytes[7])?;

        let max_allowed = channel_id.max_payload_len(limits);
        if (frame_len as usize) > max_allowed {
            return Err(FrameError::FrameTooLarge {
                channel: channel_id as u8,
                frame_len,
                max_allowed,
            });
        }

        if channel_id == ChannelId::Media {
            if msg_type != MSG_TYPE_MEDIA_VIDEO_FRAGMENT {
                return Err(FrameError::InvalidMediaStreamMsgType(msg_type));
            }
            if (frame_len as usize) < VIDEO_HEADER_LEN {
                return Err(FrameError::MediaStreamRecordTooSmall(frame_len));
            }
        }

        Ok(Self {
            frame_len,
            channel_id,
            msg_type,
            flags,
        })
    }
}

/// Decoded raw frame returned by [`StreamFrameDecoder`] with privacy-redacted [`fmt::Debug`].
#[derive(Clone, PartialEq, Eq)]
pub struct RawStreamFrame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

impl fmt::Debug for RawStreamFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawStreamFrame")
            .field("header", &self.header)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Stream-to-channel binding policy enforcing channel isolation on dedicated QUIC streams
/// vs explicit multiplexing on TCP/TLS fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamBindingMode {
    /// Dedicated single-channel stream not yet bound; binds on the first valid header.
    UnboundSingleChannel,
    /// Dedicated single-channel stream permanently bound to one logical `ChannelId`.
    BoundSingleChannel(ChannelId),
    /// Multiplexed byte stream (e.g. TCP/TLS 1.3) allowing interleaved logical channels.
    Multiplexed,
}

/// Result of stepping the incremental decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeStep {
    /// A complete frame was decoded; `consumed` bytes were consumed from the caller slice.
    Frame {
        frame: RawStreamFrame,
        consumed: usize,
    },
    /// More bytes are required; `consumed` bytes were consumed from the caller slice.
    NeedMoreData { consumed: usize },
}

#[derive(Clone)]
enum DecoderState {
    ReadingHeader {
        buf: [u8; FRAME_HEADER_LEN],
        filled: usize,
    },
    ReadingPayload {
        header: FrameHeader,
        payload: Vec<u8>,
    },
    Poisoned(FrameError),
}

impl fmt::Debug for DecoderState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadingHeader { filled, .. } => f
                .debug_struct("ReadingHeader")
                .field("filled", filled)
                .finish(),
            Self::ReadingPayload { header, payload } => f
                .debug_struct("ReadingPayload")
                .field("header", header)
                .field("received_bytes", &payload.len())
                .finish(),
            Self::Poisoned(err) => f.debug_tuple("Poisoned").field(err).finish(),
        }
    }
}

#[derive(Clone)]
struct StreamDecoderCore {
    limits: FramingLimits,
    binding: StreamBindingMode,
    state: DecoderState,
}

impl fmt::Debug for StreamDecoderCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamDecoderCore")
            .field("limits", &self.limits)
            .field("binding", &self.binding)
            .field("state", &self.state)
            .finish()
    }
}

impl StreamDecoderCore {
    fn step_slice(&mut self, chunk: &[u8]) -> Result<DecodeStep, FrameError> {
        let mut cursor = 0usize;

        loop {
            match &mut self.state {
                DecoderState::Poisoned(err) => return Err(*err),
                DecoderState::ReadingHeader { buf, filled } => {
                    if *filled < FRAME_HEADER_LEN {
                        let need = FRAME_HEADER_LEN - *filled;
                        let avail = chunk.len() - cursor;
                        if avail == 0 {
                            return Ok(DecodeStep::NeedMoreData { consumed: cursor });
                        }
                        let take = need.min(avail);
                        buf[*filled..*filled + take].copy_from_slice(&chunk[cursor..cursor + take]);
                        *filled += take;
                        cursor += take;
                    }

                    if *filled == FRAME_HEADER_LEN {
                        let header = match FrameHeader::decode(buf, &self.limits) {
                            Ok(h) => h,
                            Err(err) => {
                                self.state = DecoderState::Poisoned(err);
                                return Err(err);
                            }
                        };

                        match self.binding {
                            StreamBindingMode::UnboundSingleChannel => {
                                self.binding =
                                    StreamBindingMode::BoundSingleChannel(header.channel_id);
                            }
                            StreamBindingMode::BoundSingleChannel(expected) => {
                                if header.channel_id != expected {
                                    let err = FrameError::ChannelSwitchForbidden {
                                        bound: expected as u8,
                                        observed: header.channel_id as u8,
                                    };
                                    self.state = DecoderState::Poisoned(err);
                                    return Err(err);
                                }
                            }
                            StreamBindingMode::Multiplexed => {}
                        }

                        let target_len = header.frame_len as usize;
                        if target_len == 0 {
                            self.state = DecoderState::ReadingHeader {
                                buf: [0u8; FRAME_HEADER_LEN],
                                filled: 0,
                            };
                            return Ok(DecodeStep::Frame {
                                frame: RawStreamFrame {
                                    header,
                                    payload: Vec::new(),
                                },
                                consumed: cursor,
                            });
                        }

                        // Pre-checked against channel limit before any heap allocation.
                        self.state = DecoderState::ReadingPayload {
                            header,
                            payload: Vec::with_capacity(target_len),
                        };
                    }
                }
                DecoderState::ReadingPayload { header, payload } => {
                    let target_len = header.frame_len as usize;
                    let remaining = target_len - payload.len();
                    let avail = chunk.len() - cursor;
                    if avail == 0 && remaining > 0 {
                        return Ok(DecodeStep::NeedMoreData { consumed: cursor });
                    }
                    let take = remaining.min(avail);
                    payload.extend_from_slice(&chunk[cursor..cursor + take]);
                    cursor += take;

                    if payload.len() == target_len {
                        let hdr = *header;
                        let completed_payload = core::mem::take(payload);
                        self.state = DecoderState::ReadingHeader {
                            buf: [0u8; FRAME_HEADER_LEN],
                            filled: 0,
                        };
                        return Ok(DecodeStep::Frame {
                            frame: RawStreamFrame {
                                header: hdr,
                                payload: completed_payload,
                            },
                            consumed: cursor,
                        });
                    }
                }
            }
        }
    }
}

/// Incremental, bounded byte-stream frame decoder supporting partial headers, partial payloads,
/// multiple records per read chunk, exact byte consumption reporting, and mid-record EOF detection.
///
/// Never allocates the payload buffer until the 8-byte header has passed all size, channel,
/// and reserved-flag validations.
#[derive(Clone)]
pub struct StreamFrameDecoder {
    core: StreamDecoderCore,
    buffered_input: VecDeque<u8>,
    eof_closed: bool,
}

impl fmt::Debug for StreamFrameDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamFrameDecoder")
            .field("core", &self.core)
            .field("buffered_input_len", &self.buffered_input.len())
            .field("eof_closed", &self.eof_closed)
            .finish()
    }
}

impl StreamFrameDecoder {
    /// Hard backlog limit for unread bytes queued via `feed()` (4 MiB).
    pub const MAX_FEED_BACKLOG_BYTES: usize = 4 * 1024 * 1024;

    /// Create a new incremental decoder with validated limits and stream binding mode.
    pub fn new(limits: FramingLimits, binding: StreamBindingMode) -> Result<Self, FrameError> {
        limits.validate().map_err(|_| FrameError::StreamPoisoned)?;
        Ok(Self {
            core: StreamDecoderCore {
                limits,
                binding,
                state: DecoderState::ReadingHeader {
                    buf: [0u8; FRAME_HEADER_LEN],
                    filled: 0,
                },
            },
            buffered_input: VecDeque::new(),
            eof_closed: false,
        })
    }

    /// Return current stream binding mode (reflects first-frame binding when `UnboundSingleChannel`).
    #[must_use]
    pub const fn binding_mode(&self) -> StreamBindingMode {
        self.core.binding
    }

    /// Return `true` if the decoder entered a fatal poisoned error state.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        matches!(self.core.state, DecoderState::Poisoned(_))
    }

    /// Return `true` if [`Self::finish_eof`] cleanly closed the stream at a frame boundary.
    #[must_use]
    pub const fn is_eof(&self) -> bool {
        self.eof_closed
    }

    /// Return total bytes currently retained across partial headers, partial payloads, and unread queue.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        let state_bytes = match &self.core.state {
            DecoderState::ReadingHeader { filled, .. } => *filled,
            DecoderState::ReadingPayload { payload, .. } => payload.len(),
            DecoderState::Poisoned(_) => 0,
        };
        state_bytes.saturating_add(self.buffered_input.len())
    }

    /// Consume bytes directly from `chunk` until either one complete frame is decoded, `chunk` is
    /// exhausted (`NeedMoreData`), or a fatal framing error poisons the stream.
    ///
    /// Returns [`FrameError::PendingBufferedInput`] (without poisoning) if unread bytes remain
    /// queued from [`Self::feed`], preventing out-of-order byte consumption between the two APIs.
    /// Returns [`FrameError::StreamClosed`] after a clean [`Self::finish_eof`].
    pub fn step_slice(&mut self, chunk: &[u8]) -> Result<DecodeStep, FrameError> {
        if let DecoderState::Poisoned(err) = self.core.state {
            return Err(err);
        }
        if self.eof_closed {
            return Err(FrameError::StreamClosed);
        }
        if !self.buffered_input.is_empty() {
            return Err(FrameError::PendingBufferedInput {
                buffered_bytes: self.buffered_input.len(),
            });
        }
        self.core.step_slice(chunk)
    }

    /// Append a read chunk into the bounded internal queue for draining via [`Self::next_frame`].
    ///
    /// Returns [`FrameError::StreamClosed`] after a clean [`Self::finish_eof`].
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), FrameError> {
        if let DecoderState::Poisoned(err) = self.core.state {
            return Err(err);
        }
        if self.eof_closed {
            return Err(FrameError::StreamClosed);
        }
        if self.buffered_input.len().saturating_add(chunk.len()) > Self::MAX_FEED_BACKLOG_BYTES {
            let err = FrameError::FrameTooLarge {
                channel: 0,
                frame_len: u32::try_from(chunk.len()).unwrap_or(u32::MAX),
                max_allowed: Self::MAX_FEED_BACKLOG_BYTES,
            };
            self.core.state = DecoderState::Poisoned(err);
            return Err(err);
        }
        self.buffered_input.extend(chunk);
        Ok(())
    }

    /// Pull the next complete frame from buffered input, returning `Ok(None)` when more bytes are needed.
    pub fn next_frame(&mut self) -> Result<Option<RawStreamFrame>, FrameError> {
        if let DecoderState::Poisoned(err) = self.core.state {
            return Err(err);
        }
        if self.buffered_input.is_empty() {
            return Ok(None);
        }
        let contiguous = self.buffered_input.make_contiguous();
        let step = self.core.step_slice(contiguous)?;
        match step {
            DecodeStep::Frame { frame, consumed } => {
                self.buffered_input.drain(..consumed);
                Ok(Some(frame))
            }
            DecodeStep::NeedMoreData { consumed } => {
                self.buffered_input.drain(..consumed);
                Ok(None)
            }
        }
    }

    /// Finalize the stream at transport EOF.
    ///
    /// Requires any bytes queued via [`Self::feed`] to be drained via [`Self::next_frame`] first:
    /// if unread queue bytes remain, returns [`FrameError::PendingBufferedInput`] non-destructively
    /// (without consuming records or poisoning the decoder). Once the queue is empty, verifies that
    /// no truncated header or payload remains buffered, marking the decoder EOF-closed or poisoning
    /// with [`FrameError::UnexpectedEofInHeader`] / [`FrameError::UnexpectedEofInPayload`].
    pub fn finish_eof(&mut self) -> Result<(), FrameError> {
        if let DecoderState::Poisoned(err) = self.core.state {
            return Err(err);
        }
        if self.eof_closed {
            return Ok(());
        }
        if !self.buffered_input.is_empty() {
            return Err(FrameError::PendingBufferedInput {
                buffered_bytes: self.buffered_input.len(),
            });
        }
        match &self.core.state {
            DecoderState::ReadingHeader { filled: 0, .. } => {
                self.eof_closed = true;
                Ok(())
            }
            DecoderState::ReadingHeader { .. } => {
                let err = FrameError::UnexpectedEofInHeader;
                self.core.state = DecoderState::Poisoned(err);
                Err(err)
            }
            DecoderState::ReadingPayload { .. } => {
                let err = FrameError::UnexpectedEofInPayload;
                self.core.state = DecoderState::Poisoned(err);
                Err(err)
            }
            DecoderState::Poisoned(err) => Err(*err),
        }
    }
}

/// Encode a validated stream frame (`8-byte header + payload`) into `out`.
pub fn encode_stream_frame_into(
    channel_id: ChannelId,
    msg_type: u16,
    flags: FrameFlags,
    payload: &[u8],
    limits: &FramingLimits,
    out: &mut Vec<u8>,
) -> Result<(), FrameError> {
    let max_allowed = channel_id.max_payload_len(limits);
    if payload.len() > max_allowed {
        return Err(FrameError::FrameTooLarge {
            channel: channel_id as u8,
            frame_len: u32::try_from(payload.len()).unwrap_or(u32::MAX),
            max_allowed,
        });
    }
    if channel_id == ChannelId::Media {
        if msg_type != MSG_TYPE_MEDIA_VIDEO_FRAGMENT {
            return Err(FrameError::InvalidMediaStreamMsgType(msg_type));
        }
        if payload.len() < VIDEO_HEADER_LEN {
            return Err(FrameError::MediaStreamRecordTooSmall(
                u32::try_from(payload.len()).unwrap_or(0),
            ));
        }
    }
    let frame_len = u32::try_from(payload.len()).map_err(|_| FrameError::FrameTooLarge {
        channel: channel_id as u8,
        frame_len: u32::MAX,
        max_allowed,
    })?;
    let hdr = FrameHeader {
        frame_len,
        channel_id,
        msg_type,
        flags,
    };
    out.reserve(FRAME_HEADER_LEN.saturating_add(payload.len()));
    out.extend_from_slice(&hdr.encode());
    out.extend_from_slice(payload);
    Ok(())
}

/// Encode a validated stream frame into a freshly allocated `Vec<u8>`.
pub fn encode_stream_frame(
    channel_id: ChannelId,
    msg_type: u16,
    flags: FrameFlags,
    payload: &[u8],
    limits: &FramingLimits,
) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN.saturating_add(payload.len()));
    encode_stream_frame_into(channel_id, msg_type, flags, payload, limits, &mut out)?;
    Ok(out)
}
