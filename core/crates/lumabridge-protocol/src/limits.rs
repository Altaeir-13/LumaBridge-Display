// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Normative bounds, budgets, and configurable limits for LBWP v1.

use crate::error::LimitConfigError;

/// Fixed binary framing header size in bytes (Big-Endian).
pub const FRAME_HEADER_LEN: usize = 8;

/// Fixed binary media packet header size in bytes (Big-Endian).
pub const VIDEO_HEADER_LEN: usize = 44;

/// Reserved `msg_type` for `Channel 1` stream media fragments (`MediaVideoFragment`).
pub const MSG_TYPE_MEDIA_VIDEO_FRAGMENT: u16 = 0x0800;

/// Maximum payload length for `Channel 0` (Control & Session): 64 KiB.
pub const CHANNEL_0_MAX_PAYLOAD: usize = 65_536;

/// Maximum record payload length for `Channel 1` stream fallback (`MediaVideoFragment`): 16 KiB
/// including the 44-byte `VideoPacketHeader`.
pub const CHANNEL_1_STREAM_MAX_PAYLOAD: usize = 16_384;

/// Maximum payload length for `Channel 2` (Feedback, `ClockSync` & Heartbeat): 4 KiB.
pub const CHANNEL_2_MAX_PAYLOAD: usize = 4_096;

/// Maximum payload length for `Channel 3` (Remote Input): 1 KiB.
pub const CHANNEL_3_MAX_PAYLOAD: usize = 1_024;

/// Maximum reassembled video frame payload size: 8 MiB.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Maximum number of fragments allowed per video frame.
pub const MAX_FRAGMENTS_PER_FRAME: u16 = 4_096;

/// Maximum simultaneous incomplete frames retained per display.
pub const DEFAULT_MAX_INCOMPLETE_FRAMES_PER_DISPLAY: usize = 4;

/// Experimental default global reassembly budget: 64 MiB.
///
/// Sized to accommodate up to two peak sessions or multiple displays simultaneously without risking
/// OOM on mobile/embedded receivers; configurable by the runtime.
pub const DEFAULT_GLOBAL_REASSEMBLY_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Default per-session reassembly byte budget: 32 MiB.
pub const DEFAULT_SESSION_REASSEMBLY_BUDGET_BYTES: usize = 32 * 1024 * 1024;

/// Default per-display reassembly byte budget: 16 MiB.
pub const DEFAULT_DISPLAY_REASSEMBLY_BUDGET_BYTES: usize = 16 * 1024 * 1024;

/// Default maximum distinct displays tracked simultaneously in the reassembler.
pub const DEFAULT_MAX_TOTAL_DISPLAYS: usize = 16;

/// Default maximum total pending incomplete frames across all sessions/displays.
pub const DEFAULT_MAX_PENDING_FRAMES: usize = 64;

/// Conservative per-fragment metadata overhead accounted against reassembly budgets.
pub const DEFAULT_FRAGMENT_METADATA_OVERHEAD_BYTES: usize = 64;

/// Default incomplete-frame timeout in microseconds (150 ms).
pub const DEFAULT_FRAGMENT_TIMEOUT_US: u64 = 150_000;

/// Minimum allowed IDR request cooldown in microseconds (architectural 150 ms floor).
pub const MIN_IDR_COOLDOWN_US: u64 = 150_000;

/// Default IDR request cooldown in microseconds (200 ms, within 150-250 ms).
pub const DEFAULT_IDR_COOLDOWN_US: u64 = 200_000;

/// Maximum architectural IDR request cooldown in microseconds (250 ms).
pub const MAX_IDR_COOLDOWN_US: u64 = 250_000;

/// Maximum completed out-of-order frames held in the GOP reorder queue while an older
/// frame on the same display is still in flight.
pub const DEFAULT_MAX_REORDER_COMPLETED_FRAMES: usize = 3;

/// `frame_id` renewal threshold triggering controlled session renewal before exhausting `u32`.
pub const FRAME_ID_RENEWAL_THRESHOLD: u32 = u32::MAX - 10_000;

/// Maximum valid `display_id` (`0xFFFF` is reserved).
pub const MAX_VALID_DISPLAY_ID: u16 = 0xFFFE;

/// Default CBOR profile limits (`LBWP-CBOR-v1`).
pub const DEFAULT_CBOR_MAX_DEPTH: usize = 8;
pub const DEFAULT_CBOR_MAX_MAP_ENTRIES: usize = 64;
pub const DEFAULT_CBOR_MAX_ARRAY_ITEMS: usize = 64;
pub const DEFAULT_CBOR_MAX_TEXT_BYTES: usize = 256;
pub const DEFAULT_CBOR_MAX_BYTE_STRING_BYTES: usize = 1_024;
pub const DEFAULT_CBOR_MAX_UNKNOWN_FIELDS: usize = 16;
pub const DEFAULT_CBOR_MAX_TOTAL_ITEMS: usize = 512;

/// Configurable stream framing limits bounded by the architectural hard ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramingLimits {
    pub max_control_bytes: usize,
    pub max_media_stream_bytes: usize,
    pub max_feedback_bytes: usize,
    pub max_input_bytes: usize,
}

impl Default for FramingLimits {
    fn default() -> Self {
        Self {
            max_control_bytes: CHANNEL_0_MAX_PAYLOAD,
            max_media_stream_bytes: CHANNEL_1_STREAM_MAX_PAYLOAD,
            max_feedback_bytes: CHANNEL_2_MAX_PAYLOAD,
            max_input_bytes: CHANNEL_3_MAX_PAYLOAD,
        }
    }
}

impl FramingLimits {
    /// Validate that all framing limits stay non-zero (and at least 44 B for media stream records)
    /// and do not exceed LBWP v1.0 channel ceilings.
    pub fn validate(&self) -> Result<(), LimitConfigError> {
        if self.max_control_bytes == 0 || self.max_control_bytes > CHANNEL_0_MAX_PAYLOAD {
            return Err(LimitConfigError::InvalidValue(
                "max_control_bytes must be within 1..=65536",
            ));
        }
        if self.max_media_stream_bytes < VIDEO_HEADER_LEN
            || self.max_media_stream_bytes > CHANNEL_1_STREAM_MAX_PAYLOAD
        {
            return Err(LimitConfigError::InvalidValue(
                "max_media_stream_bytes must be within 44..=16384",
            ));
        }
        if self.max_feedback_bytes == 0 || self.max_feedback_bytes > CHANNEL_2_MAX_PAYLOAD {
            return Err(LimitConfigError::InvalidValue(
                "max_feedback_bytes must be within 1..=4096",
            ));
        }
        if self.max_input_bytes == 0 || self.max_input_bytes > CHANNEL_3_MAX_PAYLOAD {
            return Err(LimitConfigError::InvalidValue(
                "max_input_bytes must be within 1..=1024",
            ));
        }
        Ok(())
    }
}

/// Configurable bounds for the restricted `LBWP-CBOR-v1` parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborLimits {
    pub max_depth: usize,
    pub max_map_entries: usize,
    pub max_array_items: usize,
    pub max_text_bytes: usize,
    pub max_byte_string_bytes: usize,
    pub max_unknown_fields_per_map: usize,
    pub max_total_items: usize,
}

impl Default for CborLimits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_CBOR_MAX_DEPTH,
            max_map_entries: DEFAULT_CBOR_MAX_MAP_ENTRIES,
            max_array_items: DEFAULT_CBOR_MAX_ARRAY_ITEMS,
            max_text_bytes: DEFAULT_CBOR_MAX_TEXT_BYTES,
            max_byte_string_bytes: DEFAULT_CBOR_MAX_BYTE_STRING_BYTES,
            max_unknown_fields_per_map: DEFAULT_CBOR_MAX_UNKNOWN_FIELDS,
            max_total_items: DEFAULT_CBOR_MAX_TOTAL_ITEMS,
        }
    }
}

impl CborLimits {
    /// Validate CBOR parser limits are sane and bounded.
    pub fn validate(&self) -> Result<(), LimitConfigError> {
        if self.max_depth == 0 || self.max_depth > 32 {
            return Err(LimitConfigError::InvalidValue(
                "cbor max_depth must be within 1..=32",
            ));
        }
        if self.max_map_entries == 0 || self.max_map_entries > 256 {
            return Err(LimitConfigError::InvalidValue(
                "cbor max_map_entries must be within 1..=256",
            ));
        }
        if self.max_array_items == 0 || self.max_array_items > 256 {
            return Err(LimitConfigError::InvalidValue(
                "cbor max_array_items must be within 1..=256",
            ));
        }
        if self.max_text_bytes == 0 || self.max_text_bytes > CHANNEL_0_MAX_PAYLOAD {
            return Err(LimitConfigError::InvalidValue(
                "cbor max_text_bytes must be within 1..=65536",
            ));
        }
        if self.max_byte_string_bytes == 0 || self.max_byte_string_bytes > CHANNEL_0_MAX_PAYLOAD {
            return Err(LimitConfigError::InvalidValue(
                "cbor max_byte_string_bytes must be within 1..=65536",
            ));
        }
        if self.max_total_items == 0 || self.max_total_items > 4096 {
            return Err(LimitConfigError::InvalidValue(
                "cbor max_total_items must be within 1..=4096",
            ));
        }
        Ok(())
    }
}

/// Configurable budgets for bounded video frame reassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReassemblyConfig {
    pub max_incomplete_frames_per_display: usize,
    pub max_frame_bytes: usize,
    pub max_display_bytes: usize,
    pub max_session_bytes: usize,
    pub max_global_bytes: usize,
    pub max_total_displays: usize,
    pub max_pending_frames: usize,
    pub metadata_overhead_per_fragment_bytes: usize,
    pub fragment_timeout_us: u64,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            max_incomplete_frames_per_display: DEFAULT_MAX_INCOMPLETE_FRAMES_PER_DISPLAY,
            max_frame_bytes: MAX_FRAME_BYTES,
            max_display_bytes: DEFAULT_DISPLAY_REASSEMBLY_BUDGET_BYTES,
            max_session_bytes: DEFAULT_SESSION_REASSEMBLY_BUDGET_BYTES,
            max_global_bytes: DEFAULT_GLOBAL_REASSEMBLY_BUDGET_BYTES,
            max_total_displays: DEFAULT_MAX_TOTAL_DISPLAYS,
            max_pending_frames: DEFAULT_MAX_PENDING_FRAMES,
            metadata_overhead_per_fragment_bytes: DEFAULT_FRAGMENT_METADATA_OVERHEAD_BYTES,
            fragment_timeout_us: DEFAULT_FRAGMENT_TIMEOUT_US,
        }
    }
}

impl ReassemblyConfig {
    /// Validate internal consistency across hierarchical memory and count budgets.
    pub fn validate(&self) -> Result<(), LimitConfigError> {
        if self.max_incomplete_frames_per_display == 0
            || self.max_incomplete_frames_per_display > 16
        {
            return Err(LimitConfigError::InvalidValue(
                "max_incomplete_frames_per_display must be within 1..=16",
            ));
        }
        if self.max_frame_bytes == 0 || self.max_frame_bytes > MAX_FRAME_BYTES {
            return Err(LimitConfigError::InvalidValue(
                "max_frame_bytes must be within 1..=8 MiB",
            ));
        }
        if self.max_display_bytes < self.max_frame_bytes {
            return Err(LimitConfigError::InvalidValue(
                "max_display_bytes must be >= max_frame_bytes",
            ));
        }
        if self.max_session_bytes < self.max_display_bytes {
            return Err(LimitConfigError::InvalidValue(
                "max_session_bytes must be >= max_display_bytes",
            ));
        }
        if self.max_global_bytes < self.max_session_bytes {
            return Err(LimitConfigError::InvalidValue(
                "max_global_bytes must be >= max_session_bytes",
            ));
        }
        if self.max_total_displays == 0 || self.max_pending_frames == 0 {
            return Err(LimitConfigError::InvalidValue(
                "max_total_displays and max_pending_frames must be non-zero",
            ));
        }
        if self.fragment_timeout_us == 0 {
            return Err(LimitConfigError::InvalidValue(
                "fragment_timeout_us must be non-zero",
            ));
        }
        Ok(())
    }
}

/// Configurable parameters for the pure GOP recovery state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryConfig {
    pub idr_request_cooldown_us: u64,
    pub max_reorder_completed_frames: usize,
    pub reorder_gap_timeout_us: u64,
    pub frame_id_renewal_threshold: u32,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            idr_request_cooldown_us: DEFAULT_IDR_COOLDOWN_US,
            max_reorder_completed_frames: DEFAULT_MAX_REORDER_COMPLETED_FRAMES,
            reorder_gap_timeout_us: DEFAULT_FRAGMENT_TIMEOUT_US,
            frame_id_renewal_threshold: FRAME_ID_RENEWAL_THRESHOLD,
        }
    }
}

impl RecoveryConfig {
    /// Validate recovery configuration bounds.
    pub fn validate(&self) -> Result<(), LimitConfigError> {
        if self.idr_request_cooldown_us < MIN_IDR_COOLDOWN_US
            || self.idr_request_cooldown_us > MAX_IDR_COOLDOWN_US
        {
            return Err(LimitConfigError::InvalidValue(
                "idr_request_cooldown_us must be within 150_000..=250_000 us",
            ));
        }
        if self.max_reorder_completed_frames > 16 {
            return Err(LimitConfigError::InvalidValue(
                "max_reorder_completed_frames must be <= 16",
            ));
        }
        if self.reorder_gap_timeout_us == 0 {
            return Err(LimitConfigError::InvalidValue(
                "reorder_gap_timeout_us must be non-zero",
            ));
        }
        if self.frame_id_renewal_threshold == 0 {
            return Err(LimitConfigError::InvalidValue(
                "frame_id_renewal_threshold must be non-zero",
            ));
        }
        Ok(())
    }
}
