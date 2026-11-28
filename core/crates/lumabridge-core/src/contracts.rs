// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Graphics-API-agnostic contracts (`lumabridge-display`, `lumabridge-media`, `lumabridge-input`)
//! separating platform native adapters (`D3D11/IddCx`, `PipeWire/VA-API`, `MediaCodec`) from core
//! networking, protocol, and security logic (`universal-platform-architecture.md` §4).

use crate::CoreError;
use lumabridge_protocol::control::{
    CaptureMode, ColorFormat, DisplayMode, InputEvent, Permissions, RotationDeg,
};
use lumabridge_protocol::version::CodecId;

/// Logical pixel formats supported across platform adapters (never exposing GPU-specific enums).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Bgra8,
    Rgba8,
    Nv12,
    P010,
    I420,
}

impl From<PixelFormat> for ColorFormat {
    fn from(value: PixelFormat) -> Self {
        match value {
            PixelFormat::Bgra8 | PixelFormat::Rgba8 => Self::Bgra8,
            PixelFormat::Nv12 | PixelFormat::I420 => Self::Nv12_8Bit,
            PixelFormat::P010 => Self::P010_10Bit,
        }
    }
}

/// Color primaries advertised with native captured frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorPrimaries {
    Bt709,
    Bt601,
    Bt2020,
}

/// Color transfer characteristics advertised with native captured frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferFunction {
    Srgb,
    Bt709,
    Pq2084,
}

/// Quantization range for native frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorRange {
    Limited,
    Full,
}

/// Graphics-API-neutral colorimetry metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorMetadata {
    pub primaries: ColorPrimaries,
    pub transfer: TransferFunction,
    pub range: ColorRange,
}

impl Default for ColorMetadata {
    fn default() -> Self {
        Self {
            primaries: ColorPrimaries::Bt709,
            transfer: TransferFunction::Srgb,
            range: ColorRange::Limited,
        }
    }
}

/// Logical display orientation (`RotationDeg` wrapper).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayOrientation(pub RotationDeg);

/// Virtual/mirrored display placement and DPI scale metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayGeometry {
    pub display_id: u16,
    pub mode: DisplayMode,
    pub width: u16,
    pub height: u16,
    pub fps_num: u16,
    pub fps_den: u16,
    pub scale_milli: u16,
    pub orientation: RotationDeg,
    pub pos_x: i32,
    pub pos_y: i32,
}

/// Complete requested or active display profile including negotiated codec/capture mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayModeSpec {
    pub geometry: DisplayGeometry,
    pub codec: CodecId,
    pub color_format: ColorFormat,
    pub initial_bitrate_bps: u32,
    pub capture_mode: CaptureMode,
}

/// Graphics-API-agnostic frame metadata (raw GPU handles NEVER cross FFI or `core`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameDescriptor {
    pub display_id: u16,
    pub frame_id: u32,
    pub width: u16,
    pub height: u16,
    pub stride_bytes: u32,
    pub pixel_format: PixelFormat,
    pub color: ColorMetadata,
    pub orientation: RotationDeg,
    pub scale_milli: u16,
    pub capture_monotonic_us: u64,
    pub encode_start_us: u64,
    pub encode_done_us: u64,
    /// When `true`, content must NEVER be captured/transmitted; emit `ProtectedBlank` reliably.
    pub is_hw_protected: bool,
}

/// Capability report produced by a native hardware or diagnostic software video encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderCapabilities {
    pub codec: CodecId,
    pub hw_accelerated: bool,
    pub max_width: u16,
    pub max_height: u16,
    pub max_fps: u16,
    pub zero_cpu_readback: bool,
}

/// Capability report produced by a native hardware or diagnostic software video decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoderCapabilities {
    pub codec: CodecId,
    pub hw_accelerated: bool,
    pub max_width: u16,
    pub max_height: u16,
    pub max_fps: u16,
    pub zero_copy_present: bool,
}

/// Encoded frame slice ready for network packetization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedUnit {
    pub frame_id: u32,
    pub gop_id: u16,
    pub is_keyframe: bool,
    pub has_codec_config: bool,
    pub encode_done_us: u64,
    pub annex_b_bytes: Vec<u8>,
}

/// Outcome of validating an incoming input batch against live session authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputAuthorizationOutcome {
    pub accepted_events: usize,
    pub rejected_events: usize,
    pub effective_perms: Permissions,
}

/// Platform contract for virtual monitor creation (`IddCx`, `KWin/Mutter/wlroots`, etc.).
pub trait VirtualDisplayProvider: Send + Sync {
    fn create_or_update_display(&mut self, spec: DisplayGeometry) -> Result<(), CoreError>;
    fn destroy_display(&mut self, display_id: u16) -> Result<(), CoreError>;
}

/// Platform capture adapter contract (`IddCx`, `WGC`, `PipeWire`, `XShm`, `MediaProjection`).
pub trait VideoSource: Send {
    fn display_id(&self) -> u16;
    fn poll_next_frame_descriptor(&mut self) -> Result<Option<FrameDescriptor>, CoreError>;
}

/// Platform video encoder contract (`NVENC`, `AMF`, `QSV`, `VA-API`, `MediaCodec`).
pub trait VideoEncoder: Send {
    fn capabilities(&self) -> EncoderCapabilities;
    fn request_force_idr(&mut self) -> Result<(), CoreError>;
    fn reconfigure_bitrate(&mut self, target_bps: u32) -> Result<(), CoreError>;
    fn encode_synthetic_or_bound(
        &mut self,
        desc: &FrameDescriptor,
        synthetic_payload: Option<&[u8]>,
    ) -> Result<EncodedUnit, CoreError>;
}

/// Platform video decoder contract (`VA-API`, `D3D11VA`, `MediaCodec`).
pub trait VideoDecoder: Send {
    fn capabilities(&self) -> DecoderCapabilities;
    fn decode_unit(&mut self, unit: &EncodedUnit) -> Result<(), CoreError>;
}

/// Platform presentation surface contract (`Mailbox 1-slot` `VSync` presentation).
pub trait DisplayRenderer: Send {
    fn present_blank(&mut self, display_id: u16) -> Result<(), CoreError>;
    fn present_decoded(&mut self, display_id: u16, frame_id: u32) -> Result<(), CoreError>;
}

/// Platform remote input injection contract (`SendInput`, `libei`, `XTest`).
pub trait InputInjector: Send {
    fn inject_authorized_event(
        &mut self,
        display_id: u16,
        event: &InputEvent,
    ) -> Result<(), CoreError>;
}
