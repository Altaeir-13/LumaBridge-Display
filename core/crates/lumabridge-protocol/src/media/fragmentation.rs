// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Checked MTU budgeting, frame fragmentation, and `Channel 1` stream record helpers.

use crate::error::{FragmentationError, FrameError, VideoHeaderError};
use crate::framing::{encode_stream_frame, ChannelId, FrameFlags, FrameHeader, RawStreamFrame};
use crate::limits::{
    FramingLimits, MAX_FRAGMENTS_PER_FRAME, MAX_FRAME_BYTES, MAX_VALID_DISPLAY_ID,
    MSG_TYPE_MEDIA_VIDEO_FRAGMENT, VIDEO_HEADER_LEN,
};
use crate::media::header::{decode_video_packet, VideoFlags, VideoPacketHeader};
use crate::version::CodecId;

/// Transport-supplied effective packet budget governing LBWP media fragmentation.
///
/// Reflects the strict distinction between IP MTU, UDP payload, QUIC packet, QUIC `DATAGRAM`
/// frame overhead, and effective LBWP application bytes (`effective_lbwp_packet_budget`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketBudget {
    pub effective_lbwp_packet_budget: usize,
    pub max_fragment_payload: usize,
    pub max_representable_frame_bytes: usize,
}

impl PacketBudget {
    /// Compute checked fragmentation bounds from the transport-provided `effective_lbwp_packet_budget`
    /// and the negotiated session packet limit (`negotiated_max_packet_bytes`).
    pub fn new(
        effective_lbwp_packet_budget: usize,
        negotiated_max_packet_bytes: usize,
    ) -> Result<Self, FragmentationError> {
        let max_by_u16 = VIDEO_HEADER_LEN
            .checked_add(usize::from(u16::MAX))
            .ok_or(FragmentationError::ArithmeticOverflow)?;
        let capped_budget = effective_lbwp_packet_budget
            .min(negotiated_max_packet_bytes)
            .min(max_by_u16);

        let max_fragment_payload = capped_budget
            .checked_sub(VIDEO_HEADER_LEN)
            .filter(|&n| n >= 1)
            .ok_or(FragmentationError::InvalidBudget(capped_budget))?;

        let max_by_frags = usize::from(MAX_FRAGMENTS_PER_FRAME)
            .checked_mul(max_fragment_payload)
            .ok_or(FragmentationError::ArithmeticOverflow)?;

        let max_representable_frame_bytes = MAX_FRAME_BYTES.min(max_by_frags);

        Ok(Self {
            effective_lbwp_packet_budget: capped_budget,
            max_fragment_payload,
            max_representable_frame_bytes,
        })
    }

    /// Construct a budget matching `Channel 1` stream fallback framing (`16 KiB` default cap).
    pub fn for_media_stream(limits: &FramingLimits) -> Result<Self, FragmentationError> {
        Self::new(limits.max_media_stream_bytes, limits.max_media_stream_bytes)
    }
}

/// Semantic frame role carried by [`FrameToFragment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Inter-predicted frame (`P-frame`).
    InterFrame,
    /// Clean random-access IDR frame (`FLAG_KEYFRAME`), optionally resetting the prediction chain.
    Keyframe { chain_reset: bool },
    /// DRM/HDCP source protection event (`FLAG_PROTECTED_BLANK`, empty payload).
    ProtectedBlank,
}

/// Complete encoded frame (or `ProtectedBlank` marker) prepared for LBWP packetization.
#[derive(Clone, Copy)]
pub struct FrameToFragment<'a> {
    pub session_id: u64,
    pub display_id: u16,
    pub codec_id: CodecId,
    pub frame_id: u32,
    pub gop_id: u16,
    pub capture_ts_us: u64,
    pub encode_done_ts_us: u64,
    pub kind: FrameKind,
    pub has_codec_config: bool,
    pub mirror_source: bool,
    pub payload: &'a [u8],
}

impl core::fmt::Debug for FrameToFragment<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrameToFragment")
            .field("session_id", &self.session_id)
            .field("display_id", &self.display_id)
            .field("codec_id", &self.codec_id)
            .field("frame_id", &self.frame_id)
            .field("gop_id", &self.gop_id)
            .field("kind", &self.kind)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

fn validate_frame_input(input: &FrameToFragment<'_>) -> Result<(), FragmentationError> {
    if input.session_id == 0 {
        return Err(FragmentationError::InvalidHeaderMetadata(
            "session_id must be non-zero",
        ));
    }
    if input.display_id > MAX_VALID_DISPLAY_ID {
        return Err(FragmentationError::InvalidHeaderMetadata(
            "display_id 0xFFFF reserved",
        ));
    }
    if input.frame_id == 0 {
        return Err(FragmentationError::InvalidHeaderMetadata(
            "frame_id must be >= 1",
        ));
    }
    if input.encode_done_ts_us < input.capture_ts_us {
        return Err(FragmentationError::InvalidHeaderMetadata(
            "encode_done_ts_us < capture_ts_us",
        ));
    }
    if input.kind == FrameKind::ProtectedBlank {
        if !input.payload.is_empty() {
            return Err(FragmentationError::ProtectedBlankWithNonEmptyPayload);
        }
        if input.has_codec_config {
            return Err(FragmentationError::InvalidHeaderMetadata(
                "protected_blank forbids has_codec_config",
            ));
        }
    } else if input.payload.is_empty() {
        return Err(FragmentationError::EmptyFrameWithoutProtectedBlank);
    }
    Ok(())
}

/// Fragment an encoded frame into validated `[44 B VideoPacketHeader | fragment]` packets.
///
/// Rejects unrepresentable frames upfront using checked arithmetic and never truncates bitstreams.
pub fn fragment_frame(
    input: &FrameToFragment<'_>,
    budget: PacketBudget,
) -> Result<Vec<Vec<u8>>, FragmentationError> {
    validate_frame_input(input)?;

    if input.kind == FrameKind::ProtectedBlank {
        let mut flags = VideoFlags::PROTECTED_BLANK.union(VideoFlags::END_OF_FRAME);
        if input.mirror_source {
            flags = flags.union(VideoFlags::MIRROR_SOURCE);
        }
        let hdr = VideoPacketHeader {
            flags,
            session_id: input.session_id,
            display_id: input.display_id,
            codec_id: input.codec_id,
            frame_id: input.frame_id,
            gop_id: input.gop_id,
            frag_index: 0,
            frag_count: 1,
            payload_len: 0,
            capture_ts_us: input.capture_ts_us,
            encode_done_ts_us: input.encode_done_ts_us,
        };
        return Ok(vec![hdr.encode().to_vec()]);
    }

    if input.payload.len() > budget.max_representable_frame_bytes {
        return Err(FragmentationError::FrameNotRepresentable {
            frame_bytes: input.payload.len(),
            max_representable: budget.max_representable_frame_bytes,
        });
    }

    let frag_size = budget.max_fragment_payload;
    let total_frags_usize = input.payload.len().div_ceil(frag_size);
    let frag_count = u16::try_from(total_frags_usize).map_err(|_| {
        FragmentationError::FrameNotRepresentable {
            frame_bytes: input.payload.len(),
            max_representable: budget.max_representable_frame_bytes,
        }
    })?;
    if frag_count == 0 || frag_count > MAX_FRAGMENTS_PER_FRAME {
        return Err(FragmentationError::FrameNotRepresentable {
            frame_bytes: input.payload.len(),
            max_representable: budget.max_representable_frame_bytes,
        });
    }

    let mut base_flags = match input.kind {
        FrameKind::InterFrame => VideoFlags::NONE,
        FrameKind::Keyframe { chain_reset: false } => VideoFlags::KEYFRAME,
        FrameKind::Keyframe { chain_reset: true } => {
            VideoFlags::KEYFRAME.union(VideoFlags::CHAIN_RESET)
        }
        FrameKind::ProtectedBlank => unreachable!(),
    };
    if input.mirror_source {
        base_flags = base_flags.union(VideoFlags::MIRROR_SOURCE);
    }

    let mut packets = Vec::with_capacity(total_frags_usize);
    for (idx, chunk) in input.payload.chunks(frag_size).enumerate() {
        let frag_index = u16::try_from(idx).map_err(|_| FragmentationError::ArithmeticOverflow)?;
        let payload_len =
            u16::try_from(chunk.len()).map_err(|_| FragmentationError::ArithmeticOverflow)?;

        let mut flags = base_flags;
        if frag_index == 0 && input.has_codec_config {
            flags = flags.union(VideoFlags::HAS_CODEC_CONFIG);
        }
        if frag_index == frag_count - 1 {
            flags = flags.union(VideoFlags::END_OF_FRAME);
        }

        let hdr = VideoPacketHeader {
            flags,
            session_id: input.session_id,
            display_id: input.display_id,
            codec_id: input.codec_id,
            frame_id: input.frame_id,
            gop_id: input.gop_id,
            frag_index,
            frag_count,
            payload_len,
            capture_ts_us: input.capture_ts_us,
            encode_done_ts_us: input.encode_done_ts_us,
        };

        let mut pkt = Vec::with_capacity(VIDEO_HEADER_LEN.saturating_add(chunk.len()));
        pkt.extend_from_slice(&hdr.encode());
        pkt.extend_from_slice(chunk);
        packets.push(pkt);
    }

    Ok(packets)
}

/// Wrap an already-encoded media packet (`[44 B header | fragment]`) in an 8-byte `Channel 1`
/// stream record (`msg_type = 0x0800`).
pub fn encode_media_stream_record(
    media_packet: &[u8],
    flags: FrameFlags,
    limits: &FramingLimits,
) -> Result<Vec<u8>, FrameError> {
    encode_stream_frame(
        ChannelId::Media,
        MSG_TYPE_MEDIA_VIDEO_FRAGMENT,
        flags,
        media_packet,
        limits,
    )
}

/// Errors returned while extracting a `Channel 1` stream media record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaStreamRecordError {
    Framing(FrameError),
    VideoHeader(VideoHeaderError),
}

/// Validate a decoded [`RawStreamFrame`] from `Channel 1` and return its [`VideoPacketHeader`]
/// and fragment payload slice.
pub fn decode_media_stream_record<'a>(
    frame: &'a RawStreamFrame,
    limits: &FramingLimits,
) -> Result<(VideoPacketHeader, &'a [u8]), MediaStreamRecordError> {
    let FrameHeader {
        channel_id,
        msg_type,
        ..
    } = frame.header;
    if channel_id != ChannelId::Media {
        return Err(MediaStreamRecordError::Framing(
            FrameError::InvalidChannelId(channel_id as u8),
        ));
    }
    if msg_type != MSG_TYPE_MEDIA_VIDEO_FRAGMENT {
        return Err(MediaStreamRecordError::Framing(
            FrameError::InvalidMediaStreamMsgType(msg_type),
        ));
    }
    decode_video_packet(&frame.payload, limits.max_media_stream_bytes)
        .map_err(MediaStreamRecordError::VideoHeader)
}
