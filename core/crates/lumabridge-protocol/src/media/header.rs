// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Explicit Big-Endian 44-byte `VideoPacketHeader` encoder/decoder (`LBWP v1` §6).

use crate::error::VideoHeaderError;
use crate::limits::{MAX_FRAGMENTS_PER_FRAME, MAX_VALID_DISPLAY_ID, VIDEO_HEADER_LEN};
use crate::version::CodecId;

/// Fixed 16-bit magic header `'LB'` (`0x4C42`) identifying LBWP media packets.
pub const VIDEO_PACKET_MAGIC: u16 = 0x4C42;

/// Validated 16-bit `VideoPacketHeader.flags` bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VideoFlags(u16);

impl VideoFlags {
    pub const NONE: Self = Self(0x0000);
    /// Frame is an IDR / clean random-access keyframe.
    pub const KEYFRAME: Self = Self(0x0001);
    /// Mandatory iff `frag_index == frag_count - 1`.
    pub const END_OF_FRAME: Self = Self(0x0002);
    /// Fragment carries inline SPS/PPS/VPS sequence parameter sets.
    pub const HAS_CODEC_CONFIG: Self = Self(0x0004);
    /// Semantic event indicating source DRM/HDCP protection (`payload_len == 0`).
    pub const PROTECTED_BLANK: Self = Self(0x0008);
    /// Current `gop_id` starts a clean recovery chain (requires `KEYFRAME`).
    pub const CHAIN_RESET: Self = Self(0x0010);
    /// Source is screen mirror (`1`) vs virtual desktop extension (`0`).
    pub const MIRROR_SOURCE: Self = Self(0x0020);

    /// Valid bits defined in LBWP v1.0 (`0x003F`).
    pub const VALID_MASK: u16 = 0x003F;

    /// Subset of flags that MUST remain invariant across all fragments of the same `frame_id`.
    pub const FRAME_INVARIANT_MASK: u16 =
        Self::KEYFRAME.0 | Self::PROTECTED_BLANK.0 | Self::CHAIN_RESET.0 | Self::MIRROR_SOURCE.0;

    /// Parse wire flags strictly, rejecting any non-zero reserved bits (`0xFFC0`).
    pub const fn from_wire(raw: u16) -> Result<Self, VideoHeaderError> {
        if (raw & !Self::VALID_MASK) != 0 {
            return Err(VideoHeaderError::ReservedFlagsNonZero(raw));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn invariant_bits(self) -> u16 {
        self.0 & Self::FRAME_INVARIANT_MASK
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self((self.0 | other.0) & Self::VALID_MASK)
    }

    #[must_use]
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }
}

/// Fixed 44-byte Big-Endian media fragment header (`LBWP v1` §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoPacketHeader {
    pub flags: VideoFlags,
    pub session_id: u64,
    pub display_id: u16,
    pub codec_id: CodecId,
    pub frame_id: u32,
    pub gop_id: u16,
    pub frag_index: u16,
    pub frag_count: u16,
    pub payload_len: u16,
    pub capture_ts_us: u64,
    pub encode_done_ts_us: u64,
}

impl VideoPacketHeader {
    /// Serialize into an exact 44-byte Big-Endian wire array without `unsafe` or struct packing.
    #[must_use]
    pub const fn encode(self) -> [u8; VIDEO_HEADER_LEN] {
        let magic = VIDEO_PACKET_MAGIC.to_be_bytes();
        let flags = self.flags.raw().to_be_bytes();
        let sid = self.session_id.to_be_bytes();
        let did = self.display_id.to_be_bytes();
        let fid = self.frame_id.to_be_bytes();
        let gop = self.gop_id.to_be_bytes();
        let fidx = self.frag_index.to_be_bytes();
        let fcnt = self.frag_count.to_be_bytes();
        let plen = self.payload_len.to_be_bytes();
        let cts = self.capture_ts_us.to_be_bytes();
        let ets = self.encode_done_ts_us.to_be_bytes();

        [
            magic[0],
            magic[1],
            flags[0],
            flags[1],
            sid[0],
            sid[1],
            sid[2],
            sid[3],
            sid[4],
            sid[5],
            sid[6],
            sid[7],
            did[0],
            did[1],
            self.codec_id.as_u8(),
            0, // reserved byte: always 0 in v1.0
            fid[0],
            fid[1],
            fid[2],
            fid[3],
            gop[0],
            gop[1],
            fidx[0],
            fidx[1],
            fcnt[0],
            fcnt[1],
            plen[0],
            plen[1],
            cts[0],
            cts[1],
            cts[2],
            cts[3],
            cts[4],
            cts[5],
            cts[6],
            cts[7],
            ets[0],
            ets[1],
            ets[2],
            ets[3],
            ets[4],
            ets[5],
            ets[6],
            ets[7],
        ]
    }

    /// Decode a 44-byte Big-Endian header slice and validate all structural, range,
    /// flag-combination, and timestamp invariants against `max_fragment_payload`.
    pub fn decode(
        bytes: &[u8; VIDEO_HEADER_LEN],
        max_fragment_payload: usize,
    ) -> Result<Self, VideoHeaderError> {
        let magic = u16::from_be_bytes([bytes[0], bytes[1]]);
        if magic != VIDEO_PACKET_MAGIC {
            return Err(VideoHeaderError::InvalidMagic(magic));
        }

        let flags = VideoFlags::from_wire(u16::from_be_bytes([bytes[2], bytes[3]]))?;
        let session_id = u64::from_be_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ]);
        let display_id = u16::from_be_bytes([bytes[12], bytes[13]]);
        let raw_codec = bytes[14];
        let reserved = bytes[15];
        if reserved != 0 {
            return Err(VideoHeaderError::ReservedByteNonZero(reserved));
        }
        let codec_id =
            CodecId::from_raw(raw_codec).ok_or(VideoHeaderError::UnknownCodecId(raw_codec))?;

        let frame_id = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let gop_id = u16::from_be_bytes([bytes[20], bytes[21]]);
        let frag_index = u16::from_be_bytes([bytes[22], bytes[23]]);
        let frag_count = u16::from_be_bytes([bytes[24], bytes[25]]);
        let payload_len = u16::from_be_bytes([bytes[26], bytes[27]]);

        let capture_ts_us = u64::from_be_bytes([
            bytes[28], bytes[29], bytes[30], bytes[31], bytes[32], bytes[33], bytes[34], bytes[35],
        ]);
        let encode_done_ts_us = u64::from_be_bytes([
            bytes[36], bytes[37], bytes[38], bytes[39], bytes[40], bytes[41], bytes[42], bytes[43],
        ]);

        let header = Self {
            flags,
            session_id,
            display_id,
            codec_id,
            frame_id,
            gop_id,
            frag_index,
            frag_count,
            payload_len,
            capture_ts_us,
            encode_done_ts_us,
        };
        header.validate(max_fragment_payload)?;
        Ok(header)
    }

    /// Validate all structural, range, flag, and timestamp invariants on `self`.
    pub fn validate(&self, max_fragment_payload: usize) -> Result<(), VideoHeaderError> {
        if self.session_id == 0 {
            return Err(VideoHeaderError::InvalidSessionIdZero);
        }
        if self.display_id > MAX_VALID_DISPLAY_ID {
            return Err(VideoHeaderError::InvalidDisplayId(self.display_id));
        }
        if self.frame_id == 0 {
            return Err(VideoHeaderError::InvalidFrameIdZero);
        }
        if self.frag_count == 0 || self.frag_count > MAX_FRAGMENTS_PER_FRAME {
            return Err(VideoHeaderError::InvalidFragCount(self.frag_count));
        }
        if self.frag_index >= self.frag_count {
            return Err(VideoHeaderError::FragIndexOutOfBounds {
                frag_index: self.frag_index,
                frag_count: self.frag_count,
            });
        }

        let is_last = self.frag_index == self.frag_count - 1;
        if self.flags.contains(VideoFlags::END_OF_FRAME) != is_last {
            return Err(VideoHeaderError::EndOfFrameFlagMismatch);
        }
        if self.flags.contains(VideoFlags::CHAIN_RESET)
            && !self.flags.contains(VideoFlags::KEYFRAME)
        {
            return Err(VideoHeaderError::ChainResetWithoutKeyframe);
        }

        if self.flags.contains(VideoFlags::PROTECTED_BLANK) {
            if self.flags.contains(VideoFlags::KEYFRAME)
                || self.flags.contains(VideoFlags::HAS_CODEC_CONFIG)
                || self.flags.contains(VideoFlags::CHAIN_RESET)
            {
                return Err(VideoHeaderError::ProtectedBlankInvalidFlags(
                    self.flags.raw(),
                ));
            }
            if self.frag_count != 1 || self.frag_index != 0 || self.payload_len != 0 {
                return Err(VideoHeaderError::ProtectedBlankInvalidGeometry);
            }
        } else if self.payload_len == 0 {
            return Err(VideoHeaderError::EmptyPayloadWithoutProtectedBlank);
        }

        if (self.payload_len as usize) > max_fragment_payload {
            return Err(VideoHeaderError::PacketTooLarge {
                actual: VIDEO_HEADER_LEN.saturating_add(self.payload_len as usize),
                max_allowed: VIDEO_HEADER_LEN.saturating_add(max_fragment_payload),
            });
        }

        if self.encode_done_ts_us < self.capture_ts_us {
            return Err(VideoHeaderError::TimestampRegression);
        }

        Ok(())
    }
}

/// Decode and validate a complete LBWP media packet (`44 B` header + opaque bitstream fragment)
/// against the transport-provided `max_packet_budget` (`>= 44 B`).
pub fn decode_video_packet(
    packet: &[u8],
    max_packet_budget: usize,
) -> Result<(VideoPacketHeader, &[u8]), VideoHeaderError> {
    if packet.len() < VIDEO_HEADER_LEN {
        return Err(VideoHeaderError::PacketTooShort(packet.len()));
    }
    if packet.len() > max_packet_budget {
        return Err(VideoHeaderError::PacketTooLarge {
            actual: packet.len(),
            max_allowed: max_packet_budget,
        });
    }
    let max_fragment_payload = max_packet_budget.saturating_sub(VIDEO_HEADER_LEN);
    let raw_hdr: &[u8; VIDEO_HEADER_LEN] = packet[..VIDEO_HEADER_LEN]
        .try_into()
        .map_err(|_| VideoHeaderError::PacketTooShort(packet.len()))?;
    let header = VideoPacketHeader::decode(raw_hdr, max_fragment_payload)?;

    let body = &packet[VIDEO_HEADER_LEN..];
    if body.len() != (header.payload_len as usize) {
        return Err(VideoHeaderError::PayloadLenMismatch {
            header_len: header.payload_len,
            actual_len: body.len(),
        });
    }
    Ok((header, body))
}
