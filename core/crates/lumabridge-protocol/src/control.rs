// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Complete `LBWP v1` control, feedback, diagnostics, error, and input message catalog with
//! deterministic CBOR codecs (`LBWP-CBOR-v1`), strict semantic validation, and privacy-redacted `Debug`.

use core::fmt;
use std::collections::BTreeSet;

use crate::cbor::{CborArrayEncoder, CborDecodeOptions, CborMapEncoder, CborReader};
use crate::error::CborError;
use crate::error::ErrorCode;
use crate::framing::ChannelId;
use crate::limits::MAX_VALID_DISPLAY_ID;
use crate::version::CodecId;

/// Numeric CBOR message type identifiers (`0x0100..=0x0700`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum MsgType {
    PairHello = 0x0100,
    PairSpakeMsg = 0x0101,
    PairQrAuth = 0x0102,
    PairConfirm = 0x0103,
    PairCancel = 0x0104,
    Hello = 0x0200,
    HelloAck = 0x0201,
    NodeCapabilities = 0x0202,
    SessionOpenRequest = 0x0300,
    SessionOpenResponse = 0x0301,
    DisplayConfigUpdate = 0x0302,
    SessionResumeRequest = 0x0303,
    SessionResumeResponse = 0x0304,
    SessionClose = 0x0305,
    PermissionUpgradeRequest = 0x0400,
    PermissionUpdate = 0x0401,
    MediaFeedback = 0x0500,
    ClockSyncPing = 0x0501,
    ClockSyncPong = 0x0502,
    Heartbeat = 0x0503,
    DiagnosticsSummary = 0x0504,
    InputBatch = 0x0600,
    ErrorNotice = 0x0700,
}

impl MsgType {
    /// Parse a wire `u16` into a known control/feedback/input message type.
    #[must_use]
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            0x0100 => Some(Self::PairHello),
            0x0101 => Some(Self::PairSpakeMsg),
            0x0102 => Some(Self::PairQrAuth),
            0x0103 => Some(Self::PairConfirm),
            0x0104 => Some(Self::PairCancel),
            0x0200 => Some(Self::Hello),
            0x0201 => Some(Self::HelloAck),
            0x0202 => Some(Self::NodeCapabilities),
            0x0300 => Some(Self::SessionOpenRequest),
            0x0301 => Some(Self::SessionOpenResponse),
            0x0302 => Some(Self::DisplayConfigUpdate),
            0x0303 => Some(Self::SessionResumeRequest),
            0x0304 => Some(Self::SessionResumeResponse),
            0x0305 => Some(Self::SessionClose),
            0x0400 => Some(Self::PermissionUpgradeRequest),
            0x0401 => Some(Self::PermissionUpdate),
            0x0500 => Some(Self::MediaFeedback),
            0x0501 => Some(Self::ClockSyncPing),
            0x0502 => Some(Self::ClockSyncPong),
            0x0503 => Some(Self::Heartbeat),
            0x0504 => Some(Self::DiagnosticsSummary),
            0x0600 => Some(Self::InputBatch),
            0x0700 => Some(Self::ErrorNotice),
            _ => None,
        }
    }

    /// Return the stable wire numeric identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Return the sole logical channel permitted for this message in v1.0.
    #[must_use]
    pub const fn expected_channel(self) -> ChannelId {
        match self {
            Self::MediaFeedback | Self::ClockSyncPing | Self::ClockSyncPong | Self::Heartbeat => {
                ChannelId::Feedback
            }
            Self::InputBatch => ChannelId::Input,
            _ => ChannelId::Control,
        }
    }

    /// Returns `true` if this message is a pairing message (`0x0100..=0x0104`).
    #[must_use]
    pub const fn is_pairing(self) -> bool {
        matches!(
            self,
            Self::PairHello
                | Self::PairSpakeMsg
                | Self::PairQrAuth
                | Self::PairConfirm
                | Self::PairCancel
        )
    }
}

/// Orthogonal session/node permission bitmask (`ADR-0005` deny-by-default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Permissions(u32);

impl Permissions {
    pub const NONE: Self = Self(0);
    pub const VIEW_MIRROR: Self = Self(1 << 0);
    pub const EXTEND_DISPLAY: Self = Self(1 << 1);
    pub const CAPTURE_CONTROL: Self = Self(1 << 2);
    pub const INPUT_POINTER: Self = Self(1 << 3);
    pub const INPUT_KEYBOARD: Self = Self(1 << 4);
    pub const INPUT_TOUCH: Self = Self(1 << 5);
    pub const INPUT_STYLUS: Self = Self(1 << 6);

    pub const INPUT_MASK: u32 = (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6);
    pub const VALID_V1_MASK: u32 = 0x007F;

    /// Parse a wire bitmask rejecting any reserved bits outside `0..=6`.
    pub const fn from_raw(raw: u32) -> Result<Self, CborError> {
        if (raw & !Self::VALID_V1_MASK) != 0 {
            return Err(CborError::ValueOutOfRange(
                "reserved permission bits non-zero",
            ));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    #[must_use]
    pub const fn has_any_input(self) -> bool {
        (self.0 & Self::INPUT_MASK) != 0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self((self.0 | other.0) & Self::VALID_V1_MASK)
    }
}

/// Node capability role bitmask (`0..=0x1F`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoleFlags(u32);

impl RoleFlags {
    pub const CAN_RECEIVE_VIDEO: Self = Self(1 << 0);
    pub const CAN_MIRROR: Self = Self(1 << 1);
    pub const CAN_EXTEND_SESSION: Self = Self(1 << 2);
    pub const CAN_SEND_INPUT: Self = Self(1 << 3);
    pub const CAN_RECEIVE_INPUT: Self = Self(1 << 4);
    pub const VALID_V1_MASK: u32 = 0x001F;

    pub const fn from_raw(raw: u32) -> Result<Self, CborError> {
        if (raw & !Self::VALID_V1_MASK) != 0 {
            return Err(CborError::ValueOutOfRange(
                "reserved role_flags bits non-zero",
            ));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self((self.0 | other.0) & Self::VALID_V1_MASK)
    }
}

/// Supported input modalities bitmask (`0..=0x0F`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InputCapabilities(u32);

impl InputCapabilities {
    pub const POINTER: Self = Self(1 << 0);
    pub const KEYBOARD: Self = Self(1 << 1);
    pub const TOUCH: Self = Self(1 << 2);
    pub const STYLUS: Self = Self(1 << 3);
    pub const VALID_V1_MASK: u32 = 0x000F;

    pub const fn from_raw(raw: u32) -> Result<Self, CborError> {
        if (raw & !Self::VALID_V1_MASK) != 0 {
            return Err(CborError::ValueOutOfRange(
                "reserved input_caps_mask bits non-zero",
            ));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self((self.0 | other.0) & Self::VALID_V1_MASK)
    }
}

/// Pairing authentication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMode {
    PinSpake2 = 1,
    QrOutOfBand = 2,
}

impl AuthMode {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            1 => Ok(Self::PinSpake2),
            2 => Ok(Self::QrOutOfBand),
            _ => Err(CborError::ValueOutOfRange("auth_mode")),
        }
    }
}

/// SPAKE2 message exchange step (`[M1.3-PROVISIONAL]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpakeStep {
    KeyExchange = 1,
    KeyConfirmation = 2,
}

impl SpakeStep {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            1 => Ok(Self::KeyExchange),
            2 => Ok(Self::KeyConfirmation),
            _ => Err(CborError::ValueOutOfRange("spake step")),
        }
    }
}

/// Reason codes for `PairCancel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PairCancelReason {
    UserCancelled = 1,
    Timeout = 2,
    ProtocolError = 3,
    RateLimited = 4,
}

impl PairCancelReason {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            1 => Ok(Self::UserCancelled),
            2 => Ok(Self::Timeout),
            3 => Ok(Self::ProtocolError),
            4 => Ok(Self::RateLimited),
            _ => Err(CborError::ValueOutOfRange("pair cancel reason")),
        }
    }
}

/// Operational `HelloAck` status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HelloAckStatus {
    Accepted = 0,
    UnsupportedVersion = 1,
    UnauthorizedPeer = 2,
    Busy = 3,
}

impl HelloAckStatus {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::UnsupportedVersion),
            2 => Ok(Self::UnauthorizedPeer),
            3 => Ok(Self::Busy),
            _ => Err(CborError::ValueOutOfRange("hello ack status")),
        }
    }
}

/// Graphics / OS platform advertised in `NodeCapabilities`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OsGraphicsPlatform {
    WindowsDwm = 1,
    LinuxWaylandGnome = 2,
    LinuxWaylandKde = 3,
    LinuxWaylandWlroots = 4,
    LinuxWaylandHyprland = 5,
    LinuxWaylandOther = 6,
    LinuxX11 = 7,
    Android = 8,
    MacOs = 9,
    IosIpados = 10,
    Other = 11,
}

impl OsGraphicsPlatform {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            1 => Ok(Self::WindowsDwm),
            2 => Ok(Self::LinuxWaylandGnome),
            3 => Ok(Self::LinuxWaylandKde),
            4 => Ok(Self::LinuxWaylandWlroots),
            5 => Ok(Self::LinuxWaylandHyprland),
            6 => Ok(Self::LinuxWaylandOther),
            7 => Ok(Self::LinuxX11),
            8 => Ok(Self::Android),
            9 => Ok(Self::MacOs),
            10 => Ok(Self::IosIpados),
            11 => Ok(Self::Other),
            _ => Err(CborError::ValueOutOfRange("os_platform")),
        }
    }
}

/// Display operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DisplayMode {
    Mirror = 1,
    Extend = 2,
}

impl DisplayMode {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            1 => Ok(Self::Mirror),
            2 => Ok(Self::Extend),
            _ => Err(CborError::ValueOutOfRange("display mode")),
        }
    }
}

/// Clockwise rotation in degrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RotationDeg {
    Deg0 = 0,
    Deg90 = 90,
    Deg180 = 180,
    Deg270 = 270,
}

impl RotationDeg {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            0 => Ok(Self::Deg0),
            90 => Ok(Self::Deg90),
            180 => Ok(Self::Deg180),
            270 => Ok(Self::Deg270),
            _ => Err(CborError::ValueOutOfRange("rotation_deg")),
        }
    }
}

/// Stream latency vs visual quality preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LatencyProfile {
    LowLatency = 1,
    Balanced = 2,
    Quality = 3,
}

impl LatencyProfile {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            1 => Ok(Self::LowLatency),
            2 => Ok(Self::Balanced),
            3 => Ok(Self::Quality),
            _ => Err(CborError::ValueOutOfRange("latency_profile")),
        }
    }
}

/// Negotiated `SessionOpenResponse` status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionOpenStatus {
    Accepted = 0,
    PermissionDenied = 1,
    DisplayUnavailable = 2,
    CodecNegotiationFailed = 3,
    RateLimited = 4,
    InvalidConfig = 5,
}

impl SessionOpenStatus {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::PermissionDenied),
            2 => Ok(Self::DisplayUnavailable),
            3 => Ok(Self::CodecNegotiationFailed),
            4 => Ok(Self::RateLimited),
            5 => Ok(Self::InvalidConfig),
            _ => Err(CborError::ValueOutOfRange("session_open_status")),
        }
    }
}

/// Encoded pixel color format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ColorFormat {
    Nv12_8Bit = 1,
    Bgra8 = 2,
    P010_10Bit = 3,
}

impl ColorFormat {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            1 => Ok(Self::Nv12_8Bit),
            2 => Ok(Self::Bgra8),
            3 => Ok(Self::P010_10Bit),
            _ => Err(CborError::ValueOutOfRange("color_format")),
        }
    }
}

/// Effective capture source mechanism reported by sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CaptureMode {
    WindowsIddVirtualMonitor = 1,
    WindowsWgcMirror = 2,
    LinuxPipeWirePortal = 3,
    LinuxCompositorVirtualOutput = 4,
    LinuxX11Shm = 5,
    AndroidMediaProjection = 6,
    Synthetic = 7,
}

impl CaptureMode {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            1 => Ok(Self::WindowsIddVirtualMonitor),
            2 => Ok(Self::WindowsWgcMirror),
            3 => Ok(Self::LinuxPipeWirePortal),
            4 => Ok(Self::LinuxCompositorVirtualOutput),
            5 => Ok(Self::LinuxX11Shm),
            6 => Ok(Self::AndroidMediaProjection),
            7 => Ok(Self::Synthetic),
            _ => Err(CborError::ValueOutOfRange("capture_mode")),
        }
    }
}

/// Action kind for `DisplayConfigUpdate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DisplayConfigAction {
    Reconfigure = 1,
    Add = 2,
    Remove = 3,
}

impl DisplayConfigAction {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            1 => Ok(Self::Reconfigure),
            2 => Ok(Self::Add),
            3 => Ok(Self::Remove),
            _ => Err(CborError::ValueOutOfRange("display_config_action")),
        }
    }
}

/// Reason codes for `SessionClose`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseReasonCode {
    UserRequested = 1,
    IdleTimeout = 2,
    TransportLost = 3,
    PeerRevoked = 4,
    ProtocolError = 5,
    Shutdown = 6,
}

impl CloseReasonCode {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            1 => Ok(Self::UserRequested),
            2 => Ok(Self::IdleTimeout),
            3 => Ok(Self::TransportLost),
            4 => Ok(Self::PeerRevoked),
            5 => Ok(Self::ProtocolError),
            6 => Ok(Self::Shutdown),
            _ => Err(CborError::ValueOutOfRange("close_reason_code")),
        }
    }
}

/// Touch contact lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TouchPhase {
    Down = 1,
    Move = 2,
    Up = 3,
    Cancel = 4,
}

impl TouchPhase {
    pub const fn from_u64(v: u64) -> Result<Self, CborError> {
        match v {
            1 => Ok(Self::Down),
            2 => Ok(Self::Move),
            3 => Ok(Self::Up),
            4 => Ok(Self::Cancel),
            _ => Err(CborError::ValueOutOfRange("touch_phase")),
        }
    }
}

// ============================================================================
// Message Structs
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairHello {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub device_id: [u8; 32],
    pub friendly_name: String,
    /// `[M1.3-PROVISIONAL]` authentication mechanism choice.
    pub auth_mode: AuthMode,
    /// `[M1.3-PROVISIONAL]` Ed25519 SPKI/key envelope (`32..=128` B until M1.3 freezes SPKI DER).
    pub spki_ed25519: Vec<u8>,
}

/// `[M1.3-PROVISIONAL]` structural envelope for SPAKE2 exchange (`RFC 9382`).
#[derive(Clone, PartialEq, Eq)]
pub struct PairSpakeMsg {
    pub pairing_attempt_id: u64,
    pub step: SpakeStep,
    pub spake_payload: Vec<u8>,
    pub key_confirmation: Option<Vec<u8>>,
}

impl fmt::Debug for PairSpakeMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairSpakeMsg")
            .field("pairing_attempt_id", &self.pairing_attempt_id)
            .field("step", &self.step)
            .field("spake_payload", &"[REDACTED]")
            .field(
                "key_confirmation",
                &self.key_confirmation.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// `[M1.3-PROVISIONAL]` structural envelope for QR out-of-band authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct PairQrAuth {
    pub pairing_attempt_id: u64,
    pub one_time_pairing_token: Vec<u8>,
    pub initiator_signature: Vec<u8>,
}

impl fmt::Debug for PairQrAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairQrAuth")
            .field("pairing_attempt_id", &self.pairing_attempt_id)
            .field("one_time_pairing_token", &"[REDACTED]")
            .field("initiator_signature", &"[REDACTED]")
            .finish()
    }
}

/// Pairing confirmation (`Acc -> Init`); remote input permissions are strictly disallowed here.
#[derive(Clone, PartialEq, Eq)]
pub struct PairConfirm {
    pub pairing_attempt_id: u64,
    pub accepted: bool,
    pub granted_base_perms: Permissions,
    /// `[M1.3-PROVISIONAL]` confirmation signature.
    pub confirm_signature: Option<Vec<u8>>,
}

impl fmt::Debug for PairConfirm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairConfirm")
            .field("pairing_attempt_id", &self.pairing_attempt_id)
            .field("accepted", &self.accepted)
            .field("granted_base_perms", &self.granted_base_perms)
            .field(
                "confirm_signature",
                &self.confirm_signature.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairCancel {
    pub pairing_attempt_id: Option<u64>,
    pub reason_code: PairCancelReason,
    pub detail_ascii: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub device_id: [u8; 32],
    pub app_version: String,
    pub max_control_bytes: u32,
    pub max_frame_bytes: u32,
    pub preferred_mtu: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    pub negotiated_major: u16,
    pub negotiated_minor: u16,
    pub device_id: [u8; 32],
    pub granted_stored_perms: Permissions,
    pub status: HelloAckStatus,
    pub max_control_bytes: u32,
    pub max_frame_bytes: u32,
    pub negotiated_mtu: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecCapability {
    pub codec_id: CodecId,
    pub can_encode: bool,
    pub can_decode: bool,
    pub hw_accelerated: bool,
    pub max_width: u16,
    pub max_height: u16,
    pub max_fps_num: u16,
    pub max_fps_den: u16,
    pub max_b_frames: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCapabilities {
    pub roles_mask: RoleFlags,
    pub platform: OsGraphicsPlatform,
    pub codecs: Vec<CodecCapability>,
    pub max_virtual_displays: u8,
    pub supports_scale: bool,
    pub supports_rotation: bool,
    pub input_caps_mask: InputCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayRequest {
    pub display_id: u16,
    pub mode: DisplayMode,
    pub width: u16,
    pub height: u16,
    pub fps_num: u16,
    pub fps_den: u16,
    pub scale_milli: u16,
    pub rotation_deg: RotationDeg,
    pub codec_pref: Vec<CodecId>,
    pub max_bitrate_bps: u32,
    pub latency_profile: LatencyProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOpenRequest {
    pub session_id: u64,
    pub displays: Vec<DisplayRequest>,
    pub requested_perms: Permissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveDisplayConfig {
    pub display_id: u16,
    pub mode: DisplayMode,
    pub width: u16,
    pub height: u16,
    pub fps_num: u16,
    pub fps_den: u16,
    pub scale_milli: u16,
    pub rotation_deg: RotationDeg,
    pub codec_id: CodecId,
    pub color_format: ColorFormat,
    pub initial_bitrate_bps: u32,
    pub capture_mode: CaptureMode,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionOpenResponse {
    pub status: SessionOpenStatus,
    pub session_id: u64,
    /// `[M1.3-PROVISIONAL]` ephemeral session resume token.
    pub resume_token: Option<Vec<u8>>,
    pub active_displays: Vec<ActiveDisplayConfig>,
    pub granted_perms: Permissions,
}

impl fmt::Debug for SessionOpenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionOpenResponse")
            .field("status", &self.status)
            .field("session_id", &self.session_id)
            .field(
                "resume_token",
                &self.resume_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("active_displays", &self.active_displays)
            .field("granted_perms", &self.granted_perms)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayConfigUpdate {
    pub session_id: u64,
    pub update_seq: u64,
    pub display_id: u16,
    pub action: DisplayConfigAction,
    pub mode: Option<DisplayMode>,
    pub width: Option<u16>,
    pub height: Option<u16>,
    pub fps_num: Option<u16>,
    pub fps_den: Option<u16>,
    pub scale_milli: Option<u16>,
    pub rotation_deg: Option<RotationDeg>,
    pub pos_x: Option<i32>,
    pub pos_y: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayFrameCursor {
    pub display_id: u16,
    pub last_good_frame_id: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionResumeRequest {
    pub session_id: u64,
    pub resume_token: Vec<u8>,
    pub last_good_frames: Vec<DisplayFrameCursor>,
}

impl fmt::Debug for SessionResumeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionResumeRequest")
            .field("session_id", &self.session_id)
            .field("resume_token", &"[REDACTED]")
            .field("last_good_frames", &self.last_good_frames)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResumeResponse {
    pub accepted: bool,
    pub session_id: u64,
    pub preserved_displays: Vec<ActiveDisplayConfig>,
    pub idr_requested_displays: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClose {
    pub session_id: u64,
    pub reason_code: CloseReasonCode,
    pub teardown_virtual_displays: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionUpgradeRequest {
    pub session_id: u64,
    pub request_seq: u64,
    pub requested_perms: Permissions,
    pub reason_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionUpdate {
    pub session_id: u64,
    pub update_seq: u64,
    pub effective_perms: Permissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaFeedback {
    pub session_id: u64,
    pub display_id: u16,
    pub last_complete_frame_id: u32,
    pub last_displayed_frame_id: u32,
    pub broken_gop_id: Option<u16>,
    pub request_idr: bool,
    pub decode_p50_us: u32,
    pub decode_p95_us: u32,
    pub present_p95_us: u32,
    pub rx_fps_milli: u32,
    pub packet_loss_ppm: u32,
    pub jitter_us: u32,
    pub suggested_bitrate_bps: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockSyncPing {
    pub seq: u64,
    pub t1_client_mono_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockSyncPong {
    pub seq: u64,
    pub t1_client_mono_us: u64,
    pub t2_server_recv_us: u64,
    pub t3_server_send_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    pub session_id: Option<u64>,
    pub seq: u64,
    pub uptime_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticsSummary {
    pub session_id: u64,
    pub window_ms: u32,
    pub e2e_p50_us: u32,
    pub e2e_p95_us: u32,
    pub e2e_p99_us: u32,
    pub cpu_usage_bps: u16,
    pub gpu_usage_bps: u16,
    pub ram_rss_kib: u64,
    pub backpressure_drops: u64,
    pub hw_accel_active: bool,
}

/// Normalized input event variants with privacy-redacted `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    PointerMoveAbs {
        x_norm: u16,
        y_norm: u16,
    },
    PointerButton {
        button_id: u8,
        pressed: bool,
    },
    PointerScroll {
        delta_x_milli: i32,
        delta_y_milli: i32,
    },
    KeyEvent {
        hid_usage_page: u16,
        hid_usage_id: u16,
        pressed: bool,
        modifiers_mask: u8,
    },
    TouchContact {
        contact_id: u8,
        phase: TouchPhase,
        x_norm: u16,
        y_norm: u16,
        pressure_norm: u16,
    },
    StylusEvent {
        x_norm: u16,
        y_norm: u16,
        pressure_norm: u16,
        tilt_x_deg: i8,
        tilt_y_deg: i8,
        buttons_mask: u8,
    },
}

impl InputEvent {
    /// Permission bit strictly required before this event may leave protocol validation.
    #[must_use]
    pub const fn required_permission(self) -> Permissions {
        match self {
            Self::PointerMoveAbs { .. }
            | Self::PointerButton { .. }
            | Self::PointerScroll { .. } => Permissions::INPUT_POINTER,
            Self::KeyEvent { .. } => Permissions::INPUT_KEYBOARD,
            Self::TouchContact { .. } => Permissions::INPUT_TOUCH,
            Self::StylusEvent { .. } => Permissions::INPUT_STYLUS,
        }
    }
}

impl fmt::Debug for InputEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PointerMoveAbs { .. } => f.write_str("PointerMoveAbs([REDACTED])"),
            Self::PointerButton { .. } => f.write_str("PointerButton([REDACTED])"),
            Self::PointerScroll { .. } => f.write_str("PointerScroll([REDACTED])"),
            Self::KeyEvent { .. } => f.write_str("KeyEvent([REDACTED])"),
            Self::TouchContact { .. } => f.write_str("TouchContact([REDACTED])"),
            Self::StylusEvent { .. } => f.write_str("StylusEvent([REDACTED])"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct InputBatch {
    pub session_id: u64,
    pub display_id: u16,
    pub input_seq: u64,
    pub events: Vec<InputEvent>,
}

impl fmt::Debug for InputBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InputBatch")
            .field("session_id", &self.session_id)
            .field("display_id", &self.display_id)
            .field("input_seq", &self.input_seq)
            .field("events_count", &self.events.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorNotice {
    pub code: ErrorCode,
    pub fatal: bool,
    pub related_msg_type: u16,
    pub context_ascii: String,
}

/// Top-level enum encompassing all 23 CBOR-encoded LBWP v1 messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    PairHello(PairHello),
    PairSpakeMsg(PairSpakeMsg),
    PairQrAuth(PairQrAuth),
    PairConfirm(PairConfirm),
    PairCancel(PairCancel),
    Hello(Hello),
    HelloAck(HelloAck),
    NodeCapabilities(NodeCapabilities),
    SessionOpenRequest(SessionOpenRequest),
    SessionOpenResponse(SessionOpenResponse),
    DisplayConfigUpdate(DisplayConfigUpdate),
    SessionResumeRequest(SessionResumeRequest),
    SessionResumeResponse(SessionResumeResponse),
    SessionClose(SessionClose),
    PermissionUpgradeRequest(PermissionUpgradeRequest),
    PermissionUpdate(PermissionUpdate),
    MediaFeedback(MediaFeedback),
    ClockSyncPing(ClockSyncPing),
    ClockSyncPong(ClockSyncPong),
    Heartbeat(Heartbeat),
    DiagnosticsSummary(DiagnosticsSummary),
    InputBatch(InputBatch),
    ErrorNotice(ErrorNotice),
}

impl ControlMessage {
    #[must_use]
    pub const fn msg_type(&self) -> MsgType {
        match self {
            Self::PairHello(_) => MsgType::PairHello,
            Self::PairSpakeMsg(_) => MsgType::PairSpakeMsg,
            Self::PairQrAuth(_) => MsgType::PairQrAuth,
            Self::PairConfirm(_) => MsgType::PairConfirm,
            Self::PairCancel(_) => MsgType::PairCancel,
            Self::Hello(_) => MsgType::Hello,
            Self::HelloAck(_) => MsgType::HelloAck,
            Self::NodeCapabilities(_) => MsgType::NodeCapabilities,
            Self::SessionOpenRequest(_) => MsgType::SessionOpenRequest,
            Self::SessionOpenResponse(_) => MsgType::SessionOpenResponse,
            Self::DisplayConfigUpdate(_) => MsgType::DisplayConfigUpdate,
            Self::SessionResumeRequest(_) => MsgType::SessionResumeRequest,
            Self::SessionResumeResponse(_) => MsgType::SessionResumeResponse,
            Self::SessionClose(_) => MsgType::SessionClose,
            Self::PermissionUpgradeRequest(_) => MsgType::PermissionUpgradeRequest,
            Self::PermissionUpdate(_) => MsgType::PermissionUpdate,
            Self::MediaFeedback(_) => MsgType::MediaFeedback,
            Self::ClockSyncPing(_) => MsgType::ClockSyncPing,
            Self::ClockSyncPong(_) => MsgType::ClockSyncPong,
            Self::Heartbeat(_) => MsgType::Heartbeat,
            Self::DiagnosticsSummary(_) => MsgType::DiagnosticsSummary,
            Self::InputBatch(_) => MsgType::InputBatch,
            Self::ErrorNotice(_) => MsgType::ErrorNotice,
        }
    }

    /// Return the explicit `session_id` carried by this message when present.
    #[must_use]
    pub const fn session_id(&self) -> Option<u64> {
        match self {
            Self::SessionOpenRequest(m) => Some(m.session_id),
            Self::SessionOpenResponse(m) => Some(m.session_id),
            Self::DisplayConfigUpdate(m) => Some(m.session_id),
            Self::SessionResumeRequest(m) => Some(m.session_id),
            Self::SessionResumeResponse(m) => Some(m.session_id),
            Self::SessionClose(m) => Some(m.session_id),
            Self::PermissionUpgradeRequest(m) => Some(m.session_id),
            Self::PermissionUpdate(m) => Some(m.session_id),
            Self::MediaFeedback(m) => Some(m.session_id),
            Self::Heartbeat(m) => m.session_id,
            Self::DiagnosticsSummary(m) => Some(m.session_id),
            Self::InputBatch(m) => Some(m.session_id),
            _ => None,
        }
    }

    /// Validate message semantics and serialize deterministically into `out` (RFC 8949 §4.2.1).
    pub fn encode_cbor_into(&self, out: &mut Vec<u8>) -> Result<(), CborError> {
        self.validate()?;
        match self {
            Self::PairHello(m) => encode_pair_hello(m, out),
            Self::PairSpakeMsg(m) => encode_pair_spake_msg(m, out),
            Self::PairQrAuth(m) => encode_pair_qr_auth(m, out),
            Self::PairConfirm(m) => encode_pair_confirm(m, out),
            Self::PairCancel(m) => encode_pair_cancel(m, out),
            Self::Hello(m) => encode_hello(m, out),
            Self::HelloAck(m) => encode_hello_ack(m, out),
            Self::NodeCapabilities(m) => encode_node_capabilities(m, out),
            Self::SessionOpenRequest(m) => encode_session_open_request(m, out),
            Self::SessionOpenResponse(m) => encode_session_open_response(m, out),
            Self::DisplayConfigUpdate(m) => encode_display_config_update(m, out),
            Self::SessionResumeRequest(m) => encode_session_resume_request(m, out),
            Self::SessionResumeResponse(m) => encode_session_resume_response(m, out),
            Self::SessionClose(m) => encode_session_close(m, out),
            Self::PermissionUpgradeRequest(m) => encode_perm_upgrade_req(m, out),
            Self::PermissionUpdate(m) => encode_perm_update(m, out),
            Self::MediaFeedback(m) => encode_media_feedback(m, out),
            Self::ClockSyncPing(m) => encode_clock_sync_ping(m, out),
            Self::ClockSyncPong(m) => encode_clock_sync_pong(m, out),
            Self::Heartbeat(m) => encode_heartbeat(m, out),
            Self::DiagnosticsSummary(m) => encode_diagnostics_summary(m, out),
            Self::InputBatch(m) => encode_input_batch(m, out),
            Self::ErrorNotice(m) => encode_error_notice(m, out),
        }
    }

    /// Validate message semantics and return a newly allocated deterministic CBOR byte vector.
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CborError> {
        let mut out = Vec::with_capacity(64);
        self.encode_cbor_into(&mut out)?;
        Ok(out)
    }

    /// Decode a deterministic CBOR payload for `msg_type` enforcing `LBWP-CBOR-v1` and semantics.
    pub fn decode_cbor(
        msg_type: MsgType,
        input: &[u8],
        options: CborDecodeOptions,
    ) -> Result<Self, CborError> {
        let mut reader = CborReader::new(input, options)?;
        let msg = match msg_type {
            MsgType::PairHello => Self::PairHello(decode_pair_hello(&mut reader)?),
            MsgType::PairSpakeMsg => Self::PairSpakeMsg(decode_pair_spake_msg(&mut reader)?),
            MsgType::PairQrAuth => Self::PairQrAuth(decode_pair_qr_auth(&mut reader)?),
            MsgType::PairConfirm => Self::PairConfirm(decode_pair_confirm(&mut reader)?),
            MsgType::PairCancel => Self::PairCancel(decode_pair_cancel(&mut reader)?),
            MsgType::Hello => Self::Hello(decode_hello(&mut reader)?),
            MsgType::HelloAck => Self::HelloAck(decode_hello_ack(&mut reader)?),
            MsgType::NodeCapabilities => {
                Self::NodeCapabilities(decode_node_capabilities(&mut reader)?)
            }
            MsgType::SessionOpenRequest => {
                Self::SessionOpenRequest(decode_session_open_request(&mut reader)?)
            }
            MsgType::SessionOpenResponse => {
                Self::SessionOpenResponse(decode_session_open_response(&mut reader)?)
            }
            MsgType::DisplayConfigUpdate => {
                Self::DisplayConfigUpdate(decode_display_config_update(&mut reader)?)
            }
            MsgType::SessionResumeRequest => {
                Self::SessionResumeRequest(decode_session_resume_request(&mut reader)?)
            }
            MsgType::SessionResumeResponse => {
                Self::SessionResumeResponse(decode_session_resume_response(&mut reader)?)
            }
            MsgType::SessionClose => Self::SessionClose(decode_session_close(&mut reader)?),
            MsgType::PermissionUpgradeRequest => {
                Self::PermissionUpgradeRequest(decode_perm_upgrade_req(&mut reader)?)
            }
            MsgType::PermissionUpdate => Self::PermissionUpdate(decode_perm_update(&mut reader)?),
            MsgType::MediaFeedback => Self::MediaFeedback(decode_media_feedback(&mut reader)?),
            MsgType::ClockSyncPing => Self::ClockSyncPing(decode_clock_sync_ping(&mut reader)?),
            MsgType::ClockSyncPong => Self::ClockSyncPong(decode_clock_sync_pong(&mut reader)?),
            MsgType::Heartbeat => Self::Heartbeat(decode_heartbeat(&mut reader)?),
            MsgType::DiagnosticsSummary => {
                Self::DiagnosticsSummary(decode_diagnostics_summary(&mut reader)?)
            }
            MsgType::InputBatch => Self::InputBatch(decode_input_batch(&mut reader)?),
            MsgType::ErrorNotice => Self::ErrorNotice(decode_error_notice(&mut reader)?),
        };
        reader.finish_exact()?;
        msg.validate()?;
        Ok(msg)
    }

    /// Validate all structural ranges and cross-field semantic invariants.
    pub fn validate(&self) -> Result<(), CborError> {
        match self {
            Self::PairHello(m) => validate_pair_hello(m),
            Self::PairSpakeMsg(m) => validate_pair_spake_msg(m),
            Self::PairQrAuth(m) => validate_pair_qr_auth(m),
            Self::PairConfirm(m) => validate_pair_confirm(m),
            Self::PairCancel(m) => validate_pair_cancel(m),
            Self::Hello(m) => validate_hello(m),
            Self::HelloAck(m) => validate_hello_ack(m),
            Self::NodeCapabilities(m) => validate_node_capabilities(m),
            Self::SessionOpenRequest(m) => validate_session_open_request(m),
            Self::SessionOpenResponse(m) => validate_session_open_response(m),
            Self::DisplayConfigUpdate(m) => validate_display_config_update(m),
            Self::SessionResumeRequest(m) => validate_session_resume_request(m),
            Self::SessionResumeResponse(m) => validate_session_resume_response(m),
            Self::SessionClose(m) => require_nonzero(m.session_id, "session_id"),
            Self::PermissionUpgradeRequest(m) => validate_perm_upgrade_req(m),
            Self::PermissionUpdate(m) => {
                require_nonzero(m.session_id, "session_id")?;
                require_nonzero(m.update_seq, "update_seq")
            }
            Self::MediaFeedback(m) => validate_media_feedback(m),
            Self::ClockSyncPing(m) => require_nonzero(m.seq, "seq"),
            Self::ClockSyncPong(m) => {
                require_nonzero(m.seq, "seq")?;
                if m.t3_server_send_us < m.t2_server_recv_us {
                    return Err(CborError::ValueOutOfRange(
                        "t3_server_send_us < t2_server_recv_us",
                    ));
                }
                Ok(())
            }
            Self::Heartbeat(m) => {
                if let Some(sid) = m.session_id {
                    require_nonzero(sid, "session_id")?;
                }
                require_nonzero(m.seq, "seq")
            }
            Self::DiagnosticsSummary(m) => validate_diagnostics_summary(m),
            Self::InputBatch(m) => validate_input_batch(m),
            Self::ErrorNotice(m) => {
                validate_printable_ascii(&m.context_ascii, 128, "context_ascii")
            }
        }
    }
}

// ============================================================================
// Shared Validation Helpers
// ============================================================================

const fn require_nonzero(val: u64, field: &'static str) -> Result<(), CborError> {
    if val == 0 {
        return Err(CborError::ValueOutOfRange(field));
    }
    Ok(())
}

fn require_range_u64(val: u64, min: u64, max: u64, field: &'static str) -> Result<(), CborError> {
    if val < min || val > max {
        return Err(CborError::ValueOutOfRange(field));
    }
    Ok(())
}

fn require_range_i64(val: i64, min: i64, max: i64, field: &'static str) -> Result<(), CborError> {
    if val < min || val > max {
        return Err(CborError::ValueOutOfRange(field));
    }
    Ok(())
}

const fn require_display_id(id: u16) -> Result<(), CborError> {
    if id > MAX_VALID_DISPLAY_ID {
        return Err(CborError::ValueOutOfRange("display_id 0xFFFF reserved"));
    }
    Ok(())
}

fn validate_printable_ascii(s: &str, max_len: usize, field: &'static str) -> Result<(), CborError> {
    if s.len() > max_len {
        return Err(CborError::LimitExceeded(field));
    }
    if !s.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        return Err(CborError::ValueOutOfRange(field));
    }
    Ok(())
}

fn check_unique_display_ids<I: IntoIterator<Item = u16>>(iter: I) -> Result<(), CborError> {
    let mut seen = BTreeSet::new();
    for id in iter {
        require_display_id(id)?;
        if !seen.insert(id) {
            return Err(CborError::ValueOutOfRange("duplicate display_id"));
        }
    }
    Ok(())
}

fn req<T>(opt: Option<T>, field: &'static str) -> Result<T, CborError> {
    opt.ok_or(CborError::MissingRequiredField(field))
}

fn read_u16_bounded(
    r: &mut CborReader<'_>,
    min: u64,
    max: u64,
    field: &'static str,
) -> Result<u16, CborError> {
    let v = r.read_u64(field)?;
    require_range_u64(v, min, max, field)?;
    u16::try_from(v).map_err(|_| CborError::ValueOutOfRange(field))
}

fn read_u32_bounded(
    r: &mut CborReader<'_>,
    min: u64,
    max: u64,
    field: &'static str,
) -> Result<u32, CborError> {
    let v = r.read_u64(field)?;
    require_range_u64(v, min, max, field)?;
    u32::try_from(v).map_err(|_| CborError::ValueOutOfRange(field))
}

fn read_u8_bounded(
    r: &mut CborReader<'_>,
    min: u64,
    max: u64,
    field: &'static str,
) -> Result<u8, CborError> {
    let v = r.read_u64(field)?;
    require_range_u64(v, min, max, field)?;
    u8::try_from(v).map_err(|_| CborError::ValueOutOfRange(field))
}

fn read_device_id(r: &mut CborReader<'_>, field: &'static str) -> Result<[u8; 32], CborError> {
    let bytes = r.read_bytes(32, field)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| CborError::ValueOutOfRange(field))
}

// ============================================================================
// Per-Message Validation
// ============================================================================

fn validate_pair_hello(m: &PairHello) -> Result<(), CborError> {
    require_range_u64(u64::from(m.protocol_major), 1, 65535, "protocol_major")?;
    require_range_u64(m.friendly_name.len() as u64, 1, 48, "friendly_name")?;
    require_range_u64(m.spki_ed25519.len() as u64, 32, 128, "spki_ed25519")
}

fn validate_pair_spake_msg(m: &PairSpakeMsg) -> Result<(), CborError> {
    require_nonzero(m.pairing_attempt_id, "pairing_attempt_id")?;
    require_range_u64(m.spake_payload.len() as u64, 1, 256, "spake_payload")?;
    match (m.step, &m.key_confirmation) {
        (SpakeStep::KeyConfirmation, None) => {
            Err(CborError::MissingRequiredField("key_confirmation"))
        }
        (_, Some(kc)) => require_range_u64(kc.len() as u64, 16, 64, "key_confirmation"),
        (SpakeStep::KeyExchange, None) => Ok(()),
    }
}

fn validate_pair_qr_auth(m: &PairQrAuth) -> Result<(), CborError> {
    require_nonzero(m.pairing_attempt_id, "pairing_attempt_id")?;
    require_range_u64(
        m.one_time_pairing_token.len() as u64,
        16,
        64,
        "one_time_pairing_token",
    )?;
    require_range_u64(
        m.initiator_signature.len() as u64,
        64,
        128,
        "initiator_signature",
    )
}

fn validate_pair_confirm(m: &PairConfirm) -> Result<(), CborError> {
    require_nonzero(m.pairing_attempt_id, "pairing_attempt_id")?;
    if m.granted_base_perms.has_any_input() {
        return Err(CborError::ValueOutOfRange(
            "PairConfirm cannot grant input permissions",
        ));
    }
    if !m.accepted && m.granted_base_perms != Permissions::NONE {
        return Err(CborError::ValueOutOfRange(
            "rejected PairConfirm must grant zero permissions",
        ));
    }
    if m.accepted {
        let Some(sig) = &m.confirm_signature else {
            return Err(CborError::MissingRequiredField("confirm_signature"));
        };
        require_range_u64(sig.len() as u64, 64, 128, "confirm_signature")?;
    } else if let Some(sig) = &m.confirm_signature {
        require_range_u64(sig.len() as u64, 64, 128, "confirm_signature")?;
    }
    Ok(())
}

fn validate_pair_cancel(m: &PairCancel) -> Result<(), CborError> {
    if let Some(id) = m.pairing_attempt_id {
        require_nonzero(id, "pairing_attempt_id")?;
    }
    if let Some(detail) = &m.detail_ascii {
        validate_printable_ascii(detail, 128, "detail_ascii")?;
    }
    Ok(())
}

fn validate_hello(m: &Hello) -> Result<(), CborError> {
    require_range_u64(u64::from(m.protocol_major), 1, 65535, "protocol_major")?;
    require_range_u64(m.app_version.len() as u64, 1, 32, "app_version")?;
    require_range_u64(
        u64::from(m.max_control_bytes),
        1024,
        65536,
        "max_control_bytes",
    )?;
    require_range_u64(
        u64::from(m.max_frame_bytes),
        4096,
        8_388_608,
        "max_frame_bytes",
    )?;
    require_range_u64(u64::from(m.preferred_mtu), 512, 65535, "preferred_mtu")
}

fn validate_hello_ack(m: &HelloAck) -> Result<(), CborError> {
    require_range_u64(u64::from(m.negotiated_major), 1, 65535, "negotiated_major")?;
    if m.status != HelloAckStatus::Accepted && m.granted_stored_perms != Permissions::NONE {
        return Err(CborError::ValueOutOfRange(
            "non-accepted HelloAck must clear granted_stored_perms",
        ));
    }
    require_range_u64(
        u64::from(m.max_control_bytes),
        1024,
        65536,
        "max_control_bytes",
    )?;
    require_range_u64(
        u64::from(m.max_frame_bytes),
        4096,
        8_388_608,
        "max_frame_bytes",
    )?;
    require_range_u64(u64::from(m.negotiated_mtu), 512, 65535, "negotiated_mtu")
}

fn validate_codec_cap(c: &CodecCapability) -> Result<(), CborError> {
    require_range_u64(u64::from(c.max_width), 1, 16384, "max_width")?;
    require_range_u64(u64::from(c.max_height), 1, 16384, "max_height")?;
    require_range_u64(u64::from(c.max_fps_num), 1, 1000, "max_fps_num")?;
    require_range_u64(u64::from(c.max_fps_den), 1, 1000, "max_fps_den")?;
    require_range_u64(u64::from(c.max_b_frames), 0, 4, "max_b_frames")
}

fn validate_node_capabilities(m: &NodeCapabilities) -> Result<(), CborError> {
    require_range_u64(m.codecs.len() as u64, 1, 16, "codecs")?;
    require_range_u64(
        u64::from(m.max_virtual_displays),
        0,
        16,
        "max_virtual_displays",
    )?;
    for c in &m.codecs {
        validate_codec_cap(c)?;
    }
    Ok(())
}

fn validate_display_request(d: &DisplayRequest) -> Result<(), CborError> {
    require_display_id(d.display_id)?;
    require_range_u64(u64::from(d.width), 64, 16384, "width")?;
    require_range_u64(u64::from(d.height), 64, 16384, "height")?;
    require_range_u64(u64::from(d.fps_num), 1, 1000, "fps_num")?;
    require_range_u64(u64::from(d.fps_den), 1, 1000, "fps_den")?;
    require_range_u64(u64::from(d.scale_milli), 250, 4000, "scale_milli")?;
    require_range_u64(d.codec_pref.len() as u64, 1, 8, "codec_pref")?;
    require_range_u64(
        u64::from(d.max_bitrate_bps),
        100_000,
        1_000_000_000,
        "max_bitrate_bps",
    )
}

fn validate_active_display(d: &ActiveDisplayConfig) -> Result<(), CborError> {
    require_display_id(d.display_id)?;
    require_range_u64(u64::from(d.width), 64, 16384, "width")?;
    require_range_u64(u64::from(d.height), 64, 16384, "height")?;
    require_range_u64(u64::from(d.fps_num), 1, 1000, "fps_num")?;
    require_range_u64(u64::from(d.fps_den), 1, 1000, "fps_den")?;
    require_range_u64(u64::from(d.scale_milli), 250, 4000, "scale_milli")?;
    require_range_u64(
        u64::from(d.initial_bitrate_bps),
        100_000,
        1_000_000_000,
        "initial_bitrate_bps",
    )
}

fn validate_session_open_request(m: &SessionOpenRequest) -> Result<(), CborError> {
    require_nonzero(m.session_id, "session_id")?;
    require_range_u64(m.displays.len() as u64, 1, 16, "displays")?;
    check_unique_display_ids(m.displays.iter().map(|d| d.display_id))?;
    for d in &m.displays {
        validate_display_request(d)?;
    }
    Ok(())
}

fn validate_session_open_response(m: &SessionOpenResponse) -> Result<(), CborError> {
    require_nonzero(m.session_id, "session_id")?;
    require_range_u64(m.active_displays.len() as u64, 0, 16, "active_displays")?;
    check_unique_display_ids(m.active_displays.iter().map(|d| d.display_id))?;
    for d in &m.active_displays {
        validate_active_display(d)?;
    }
    if m.status == SessionOpenStatus::Accepted {
        let Some(tok) = &m.resume_token else {
            return Err(CborError::MissingRequiredField("resume_token"));
        };
        require_range_u64(tok.len() as u64, 16, 64, "resume_token")?;
        if m.active_displays.is_empty() {
            return Err(CborError::ValueOutOfRange(
                "accepted SessionOpenResponse requires >= 1 active display",
            ));
        }
    } else if m.resume_token.is_some()
        || !m.active_displays.is_empty()
        || m.granted_perms != Permissions::NONE
    {
        return Err(CborError::ValueOutOfRange(
            "rejected SessionOpenResponse must omit token, displays, and perms",
        ));
    }
    Ok(())
}

fn validate_display_config_update(m: &DisplayConfigUpdate) -> Result<(), CborError> {
    require_nonzero(m.session_id, "session_id")?;
    require_nonzero(m.update_seq, "update_seq")?;
    require_display_id(m.display_id)?;
    if m.fps_num.is_some() != m.fps_den.is_some() {
        return Err(CborError::ValueOutOfRange("fps_num and fps_den must pair"));
    }
    if m.pos_x.is_some() != m.pos_y.is_some() {
        return Err(CborError::ValueOutOfRange("pos_x and pos_y must pair"));
    }
    if let Some(w) = m.width {
        require_range_u64(u64::from(w), 64, 16384, "width")?;
    }
    if let Some(h) = m.height {
        require_range_u64(u64::from(h), 64, 16384, "height")?;
    }
    if let Some(n) = m.fps_num {
        require_range_u64(u64::from(n), 1, 1000, "fps_num")?;
    }
    if let Some(d) = m.fps_den {
        require_range_u64(u64::from(d), 1, 1000, "fps_den")?;
    }
    if let Some(s) = m.scale_milli {
        require_range_u64(u64::from(s), 250, 4000, "scale_milli")?;
    }
    if let Some(x) = m.pos_x {
        require_range_i64(i64::from(x), -65536, 65536, "pos_x")?;
    }
    if let Some(y) = m.pos_y {
        require_range_i64(i64::from(y), -65536, 65536, "pos_y")?;
    }
    match m.action {
        DisplayConfigAction::Add => {
            if m.mode.is_none()
                || m.width.is_none()
                || m.height.is_none()
                || m.fps_num.is_none()
                || m.fps_den.is_none()
            {
                return Err(CborError::MissingRequiredField(
                    "DisplayConfigUpdate::Add geometry",
                ));
            }
        }
        DisplayConfigAction::Remove => {
            if m.mode.is_some()
                || m.width.is_some()
                || m.height.is_some()
                || m.fps_num.is_some()
                || m.scale_milli.is_some()
                || m.rotation_deg.is_some()
                || m.pos_x.is_some()
            {
                return Err(CborError::ValueOutOfRange(
                    "DisplayConfigUpdate::Remove forbids geometry fields",
                ));
            }
        }
        DisplayConfigAction::Reconfigure => {}
    }
    Ok(())
}

fn validate_session_resume_request(m: &SessionResumeRequest) -> Result<(), CborError> {
    require_nonzero(m.session_id, "session_id")?;
    require_range_u64(m.resume_token.len() as u64, 16, 64, "resume_token")?;
    require_range_u64(m.last_good_frames.len() as u64, 0, 16, "last_good_frames")?;
    check_unique_display_ids(m.last_good_frames.iter().map(|c| c.display_id))
}

fn validate_session_resume_response(m: &SessionResumeResponse) -> Result<(), CborError> {
    require_nonzero(m.session_id, "session_id")?;
    require_range_u64(
        m.preserved_displays.len() as u64,
        0,
        16,
        "preserved_displays",
    )?;
    require_range_u64(
        m.idr_requested_displays.len() as u64,
        0,
        16,
        "idr_requested_displays",
    )?;
    check_unique_display_ids(m.preserved_displays.iter().map(|d| d.display_id))?;
    check_unique_display_ids(m.idr_requested_displays.iter().copied())?;
    for d in &m.preserved_displays {
        validate_active_display(d)?;
    }
    if m.accepted && m.preserved_displays.is_empty() {
        return Err(CborError::ValueOutOfRange(
            "accepted SessionResumeResponse requires >= 1 preserved display",
        ));
    }
    if !m.accepted && (!m.preserved_displays.is_empty() || !m.idr_requested_displays.is_empty()) {
        return Err(CborError::ValueOutOfRange(
            "rejected SessionResumeResponse must return empty display lists",
        ));
    }
    Ok(())
}

fn validate_perm_upgrade_req(m: &PermissionUpgradeRequest) -> Result<(), CborError> {
    require_nonzero(m.session_id, "session_id")?;
    require_nonzero(m.request_seq, "request_seq")?;
    if m.requested_perms == Permissions::NONE {
        return Err(CborError::ValueOutOfRange(
            "requested_perms must be non-zero",
        ));
    }
    require_range_u64(m.reason_text.len() as u64, 0, 128, "reason_text")
}

fn validate_media_feedback(m: &MediaFeedback) -> Result<(), CborError> {
    require_nonzero(m.session_id, "session_id")?;
    require_display_id(m.display_id)?;
    if m.last_displayed_frame_id > m.last_complete_frame_id {
        return Err(CborError::ValueOutOfRange(
            "last_displayed_frame_id > last_complete_frame_id",
        ));
    }
    require_range_u64(u64::from(m.decode_p50_us), 0, 10_000_000, "decode_p50_us")?;
    require_range_u64(u64::from(m.decode_p95_us), 0, 10_000_000, "decode_p95_us")?;
    if m.decode_p95_us < m.decode_p50_us {
        return Err(CborError::ValueOutOfRange("decode_p95_us < decode_p50_us"));
    }
    require_range_u64(u64::from(m.present_p95_us), 0, 10_000_000, "present_p95_us")?;
    require_range_u64(u64::from(m.rx_fps_milli), 0, 1_000_000, "rx_fps_milli")?;
    require_range_u64(
        u64::from(m.packet_loss_ppm),
        0,
        1_000_000,
        "packet_loss_ppm",
    )?;
    require_range_u64(u64::from(m.jitter_us), 0, 10_000_000, "jitter_us")?;
    require_range_u64(
        u64::from(m.suggested_bitrate_bps),
        0,
        1_000_000_000,
        "suggested_bitrate_bps",
    )
}

fn validate_diagnostics_summary(m: &DiagnosticsSummary) -> Result<(), CborError> {
    require_nonzero(m.session_id, "session_id")?;
    require_range_u64(u64::from(m.window_ms), 1, 3_600_000, "window_ms")?;
    require_range_u64(u64::from(m.e2e_p50_us), 0, 10_000_000, "e2e_p50_us")?;
    require_range_u64(u64::from(m.e2e_p95_us), 0, 10_000_000, "e2e_p95_us")?;
    require_range_u64(u64::from(m.e2e_p99_us), 0, 10_000_000, "e2e_p99_us")?;
    if m.e2e_p95_us < m.e2e_p50_us || m.e2e_p99_us < m.e2e_p95_us {
        return Err(CborError::ValueOutOfRange(
            "diagnostics percentiles not monotonic",
        ));
    }
    require_range_u64(u64::from(m.cpu_usage_bps), 0, 10_000, "cpu_usage_bps")?;
    require_range_u64(u64::from(m.gpu_usage_bps), 0, 10_000, "gpu_usage_bps")
}

fn validate_input_event(ev: InputEvent) -> Result<(), CborError> {
    match ev {
        InputEvent::PointerMoveAbs { .. }
        | InputEvent::KeyEvent { .. }
        | InputEvent::TouchContact { .. } => Ok(()),
        InputEvent::PointerButton { button_id, .. } => {
            require_range_u64(u64::from(button_id), 0, 31, "button_id")
        }
        InputEvent::PointerScroll {
            delta_x_milli,
            delta_y_milli,
        } => {
            require_range_i64(
                i64::from(delta_x_milli),
                -1_000_000,
                1_000_000,
                "delta_x_milli",
            )?;
            require_range_i64(
                i64::from(delta_y_milli),
                -1_000_000,
                1_000_000,
                "delta_y_milli",
            )
        }
        InputEvent::StylusEvent {
            tilt_x_deg,
            tilt_y_deg,
            buttons_mask,
            ..
        } => {
            require_range_i64(i64::from(tilt_x_deg), -90, 90, "tilt_x_deg")?;
            require_range_i64(i64::from(tilt_y_deg), -90, 90, "tilt_y_deg")?;
            require_range_u64(u64::from(buttons_mask), 0, 15, "buttons_mask")
        }
    }
}

fn validate_input_batch(m: &InputBatch) -> Result<(), CborError> {
    require_nonzero(m.session_id, "session_id")?;
    require_display_id(m.display_id)?;
    require_nonzero(m.input_seq, "input_seq")?;
    require_range_u64(m.events.len() as u64, 1, 32, "events")?;
    for ev in &m.events {
        validate_input_event(*ev)?;
    }
    Ok(())
}

// ============================================================================
// Encoders & Decoders (Per-Message, Explicit Integer Keys)
// ============================================================================

fn encode_pair_hello(m: &PairHello, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 6)?;
    map.put_u64(1, u64::from(m.protocol_major))?;
    map.put_u64(2, u64::from(m.protocol_minor))?;
    map.put_bytes(3, &m.device_id)?;
    map.put_text(4, &m.friendly_name)?;
    map.put_u64(5, u64::from(m.auth_mode as u8))?;
    map.put_bytes(6, &m.spki_ed25519)?;
    map.finish()
}

fn decode_pair_hello(r: &mut CborReader<'_>) -> Result<PairHello, CborError> {
    let (mut maj, mut min, mut did, mut name, mut mode, mut spki) =
        (None, None, None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => maj = Some(read_u16_bounded(r, 1, 65535, "protocol_major")?),
            2 => min = Some(read_u16_bounded(r, 0, 65535, "protocol_minor")?),
            3 => did = Some(read_device_id(r, "device_id")?),
            4 => name = Some(r.read_text(48, "friendly_name")?),
            5 => mode = Some(AuthMode::from_u64(r.read_u64("auth_mode")?)?),
            6 => spki = Some(r.read_bytes(128, "spki_ed25519")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(PairHello {
        protocol_major: req(maj, "protocol_major")?,
        protocol_minor: req(min, "protocol_minor")?,
        device_id: req(did, "device_id")?,
        friendly_name: req(name, "friendly_name")?,
        auth_mode: req(mode, "auth_mode")?,
        spki_ed25519: req(spki, "spki_ed25519")?,
    })
}

fn encode_pair_spake_msg(m: &PairSpakeMsg, out: &mut Vec<u8>) -> Result<(), CborError> {
    let count = 3 + usize::from(m.key_confirmation.is_some());
    let mut map = CborMapEncoder::start(out, count)?;
    map.put_u64(1, m.pairing_attempt_id)?;
    map.put_u64(2, u64::from(m.step as u8))?;
    map.put_bytes(3, &m.spake_payload)?;
    if let Some(kc) = &m.key_confirmation {
        map.put_bytes(4, kc)?;
    }
    map.finish()
}

fn decode_pair_spake_msg(r: &mut CborReader<'_>) -> Result<PairSpakeMsg, CborError> {
    let (mut id, mut step, mut payload, mut kc) = (None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => id = Some(r.read_u64("pairing_attempt_id")?),
            2 => step = Some(SpakeStep::from_u64(r.read_u64("step")?)?),
            3 => payload = Some(r.read_bytes(256, "spake_payload")?),
            4 => kc = Some(r.read_bytes(64, "key_confirmation")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(PairSpakeMsg {
        pairing_attempt_id: req(id, "pairing_attempt_id")?,
        step: req(step, "step")?,
        spake_payload: req(payload, "spake_payload")?,
        key_confirmation: kc,
    })
}

fn encode_pair_qr_auth(m: &PairQrAuth, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 3)?;
    map.put_u64(1, m.pairing_attempt_id)?;
    map.put_bytes(2, &m.one_time_pairing_token)?;
    map.put_bytes(3, &m.initiator_signature)?;
    map.finish()
}

fn decode_pair_qr_auth(r: &mut CborReader<'_>) -> Result<PairQrAuth, CborError> {
    let (mut id, mut tok, mut sig) = (None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => id = Some(r.read_u64("pairing_attempt_id")?),
            2 => tok = Some(r.read_bytes(64, "one_time_pairing_token")?),
            3 => sig = Some(r.read_bytes(128, "initiator_signature")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(PairQrAuth {
        pairing_attempt_id: req(id, "pairing_attempt_id")?,
        one_time_pairing_token: req(tok, "one_time_pairing_token")?,
        initiator_signature: req(sig, "initiator_signature")?,
    })
}

fn encode_pair_confirm(m: &PairConfirm, out: &mut Vec<u8>) -> Result<(), CborError> {
    let count = 3 + usize::from(m.confirm_signature.is_some());
    let mut map = CborMapEncoder::start(out, count)?;
    map.put_u64(1, m.pairing_attempt_id)?;
    map.put_bool(2, m.accepted)?;
    map.put_u64(3, u64::from(m.granted_base_perms.raw()))?;
    if let Some(sig) = &m.confirm_signature {
        map.put_bytes(4, sig)?;
    }
    map.finish()
}

fn decode_pair_confirm(r: &mut CborReader<'_>) -> Result<PairConfirm, CborError> {
    let (mut id, mut acc, mut perms, mut sig) = (None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => id = Some(r.read_u64("pairing_attempt_id")?),
            2 => acc = Some(r.read_bool("accepted")?),
            3 => perms = Some(Permissions::from_raw(r.read_u32("granted_base_perms")?)?),
            4 => sig = Some(r.read_bytes(128, "confirm_signature")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(PairConfirm {
        pairing_attempt_id: req(id, "pairing_attempt_id")?,
        accepted: req(acc, "accepted")?,
        granted_base_perms: req(perms, "granted_base_perms")?,
        confirm_signature: sig,
    })
}

fn encode_pair_cancel(m: &PairCancel, out: &mut Vec<u8>) -> Result<(), CborError> {
    let count =
        1 + usize::from(m.pairing_attempt_id.is_some()) + usize::from(m.detail_ascii.is_some());
    let mut map = CborMapEncoder::start(out, count)?;
    if let Some(id) = m.pairing_attempt_id {
        map.put_u64(1, id)?;
    }
    map.put_u64(2, u64::from(m.reason_code as u8))?;
    if let Some(detail) = &m.detail_ascii {
        map.put_text(3, detail)?;
    }
    map.finish()
}

fn decode_pair_cancel(r: &mut CborReader<'_>) -> Result<PairCancel, CborError> {
    let (mut id, mut reason, mut detail) = (None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => id = Some(r.read_u64("pairing_attempt_id")?),
            2 => reason = Some(PairCancelReason::from_u64(r.read_u64("reason_code")?)?),
            3 => detail = Some(r.read_text(128, "detail_ascii")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(PairCancel {
        pairing_attempt_id: id,
        reason_code: req(reason, "reason_code")?,
        detail_ascii: detail,
    })
}

fn encode_hello(m: &Hello, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 7)?;
    map.put_u64(1, u64::from(m.protocol_major))?;
    map.put_u64(2, u64::from(m.protocol_minor))?;
    map.put_bytes(3, &m.device_id)?;
    map.put_text(4, &m.app_version)?;
    map.put_u64(5, u64::from(m.max_control_bytes))?;
    map.put_u64(6, u64::from(m.max_frame_bytes))?;
    map.put_u64(7, u64::from(m.preferred_mtu))?;
    map.finish()
}

fn decode_hello(r: &mut CborReader<'_>) -> Result<Hello, CborError> {
    let (mut maj, mut min, mut did, mut ver, mut mc, mut mf, mut mtu) =
        (None, None, None, None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => maj = Some(read_u16_bounded(r, 1, 65535, "protocol_major")?),
            2 => min = Some(read_u16_bounded(r, 0, 65535, "protocol_minor")?),
            3 => did = Some(read_device_id(r, "device_id")?),
            4 => ver = Some(r.read_text(32, "app_version")?),
            5 => mc = Some(read_u32_bounded(r, 1024, 65536, "max_control_bytes")?),
            6 => mf = Some(read_u32_bounded(r, 4096, 8_388_608, "max_frame_bytes")?),
            7 => mtu = Some(read_u16_bounded(r, 512, 65535, "preferred_mtu")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(Hello {
        protocol_major: req(maj, "protocol_major")?,
        protocol_minor: req(min, "protocol_minor")?,
        device_id: req(did, "device_id")?,
        app_version: req(ver, "app_version")?,
        max_control_bytes: req(mc, "max_control_bytes")?,
        max_frame_bytes: req(mf, "max_frame_bytes")?,
        preferred_mtu: req(mtu, "preferred_mtu")?,
    })
}

fn encode_hello_ack(m: &HelloAck, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 8)?;
    map.put_u64(1, u64::from(m.negotiated_major))?;
    map.put_u64(2, u64::from(m.negotiated_minor))?;
    map.put_bytes(3, &m.device_id)?;
    map.put_u64(4, u64::from(m.granted_stored_perms.raw()))?;
    map.put_u64(5, u64::from(m.status as u8))?;
    map.put_u64(6, u64::from(m.max_control_bytes))?;
    map.put_u64(7, u64::from(m.max_frame_bytes))?;
    map.put_u64(8, u64::from(m.negotiated_mtu))?;
    map.finish()
}

fn decode_hello_ack(r: &mut CborReader<'_>) -> Result<HelloAck, CborError> {
    let (mut maj, mut min, mut did, mut perms, mut status, mut mc, mut mf, mut mtu) =
        (None, None, None, None, None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => maj = Some(read_u16_bounded(r, 1, 65535, "negotiated_major")?),
            2 => min = Some(read_u16_bounded(r, 0, 65535, "negotiated_minor")?),
            3 => did = Some(read_device_id(r, "device_id")?),
            4 => perms = Some(Permissions::from_raw(r.read_u32("granted_stored_perms")?)?),
            5 => status = Some(HelloAckStatus::from_u64(r.read_u64("status")?)?),
            6 => mc = Some(read_u32_bounded(r, 1024, 65536, "max_control_bytes")?),
            7 => mf = Some(read_u32_bounded(r, 4096, 8_388_608, "max_frame_bytes")?),
            8 => mtu = Some(read_u16_bounded(r, 512, 65535, "negotiated_mtu")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(HelloAck {
        negotiated_major: req(maj, "negotiated_major")?,
        negotiated_minor: req(min, "negotiated_minor")?,
        device_id: req(did, "device_id")?,
        granted_stored_perms: req(perms, "granted_stored_perms")?,
        status: req(status, "status")?,
        max_control_bytes: req(mc, "max_control_bytes")?,
        max_frame_bytes: req(mf, "max_frame_bytes")?,
        negotiated_mtu: req(mtu, "negotiated_mtu")?,
    })
}

fn encode_codec_cap(c: &CodecCapability, arr: &mut CborArrayEncoder<'_>) -> Result<(), CborError> {
    arr.push_map_with(9, |m| {
        m.put_u64(1, u64::from(c.codec_id.as_u8()))?;
        m.put_bool(2, c.can_encode)?;
        m.put_bool(3, c.can_decode)?;
        m.put_bool(4, c.hw_accelerated)?;
        m.put_u64(5, u64::from(c.max_width))?;
        m.put_u64(6, u64::from(c.max_height))?;
        m.put_u64(7, u64::from(c.max_fps_num))?;
        m.put_u64(8, u64::from(c.max_fps_den))?;
        m.put_u64(9, u64::from(c.max_b_frames))?;
        Ok(())
    })
}

fn decode_codec_cap(r: &mut CborReader<'_>) -> Result<CodecCapability, CborError> {
    let (mut id, mut enc, mut dec, mut hw, mut w, mut h, mut fn_, mut fd, mut bf) =
        (None, None, None, None, None, None, None, None, None);
    r.read_map(2, |r, k| {
        match k {
            1 => {
                let raw = read_u8_bounded(r, 1, 3, "codec_id")?;
                id = Some(CodecId::from_raw(raw).ok_or(CborError::ValueOutOfRange("codec_id"))?);
            }
            2 => enc = Some(r.read_bool("can_encode")?),
            3 => dec = Some(r.read_bool("can_decode")?),
            4 => hw = Some(r.read_bool("hw_accelerated")?),
            5 => w = Some(read_u16_bounded(r, 1, 16384, "max_width")?),
            6 => h = Some(read_u16_bounded(r, 1, 16384, "max_height")?),
            7 => fn_ = Some(read_u16_bounded(r, 1, 1000, "max_fps_num")?),
            8 => fd = Some(read_u16_bounded(r, 1, 1000, "max_fps_den")?),
            9 => bf = Some(read_u8_bounded(r, 0, 4, "max_b_frames")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(CodecCapability {
        codec_id: req(id, "codec_id")?,
        can_encode: req(enc, "can_encode")?,
        can_decode: req(dec, "can_decode")?,
        hw_accelerated: req(hw, "hw_accelerated")?,
        max_width: req(w, "max_width")?,
        max_height: req(h, "max_height")?,
        max_fps_num: req(fn_, "max_fps_num")?,
        max_fps_den: req(fd, "max_fps_den")?,
        max_b_frames: req(bf, "max_b_frames")?,
    })
}

fn encode_node_capabilities(m: &NodeCapabilities, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 7)?;
    map.put_u64(1, u64::from(m.roles_mask.raw()))?;
    map.put_u64(2, u64::from(m.platform as u8))?;
    map.put_array_with(3, m.codecs.len(), |arr| {
        for c in &m.codecs {
            encode_codec_cap(c, arr)?;
        }
        Ok(())
    })?;
    map.put_u64(4, u64::from(m.max_virtual_displays))?;
    map.put_bool(5, m.supports_scale)?;
    map.put_bool(6, m.supports_rotation)?;
    map.put_u64(7, u64::from(m.input_caps_mask.raw()))?;
    map.finish()
}

fn decode_node_capabilities(r: &mut CborReader<'_>) -> Result<NodeCapabilities, CborError> {
    let (mut roles, mut plat, mut codecs, mut max_vd, mut scale, mut rot, mut icaps) =
        (None, None, None, None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => roles = Some(RoleFlags::from_raw(r.read_u32("roles_mask")?)?),
            2 => plat = Some(OsGraphicsPlatform::from_u64(r.read_u64("platform")?)?),
            3 => {
                let mut list = Vec::new();
                r.read_array(1, 16, "codecs", |r, _| {
                    list.push(decode_codec_cap(r)?);
                    Ok(())
                })?;
                codecs = Some(list);
            }
            4 => max_vd = Some(read_u8_bounded(r, 0, 16, "max_virtual_displays")?),
            5 => scale = Some(r.read_bool("supports_scale")?),
            6 => rot = Some(r.read_bool("supports_rotation")?),
            7 => icaps = Some(InputCapabilities::from_raw(r.read_u32("input_caps_mask")?)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(NodeCapabilities {
        roles_mask: req(roles, "roles_mask")?,
        platform: req(plat, "platform")?,
        codecs: req(codecs, "codecs")?,
        max_virtual_displays: req(max_vd, "max_virtual_displays")?,
        supports_scale: req(scale, "supports_scale")?,
        supports_rotation: req(rot, "supports_rotation")?,
        input_caps_mask: req(icaps, "input_caps_mask")?,
    })
}

fn encode_display_req(d: &DisplayRequest, arr: &mut CborArrayEncoder<'_>) -> Result<(), CborError> {
    arr.push_map_with(11, |m| {
        m.put_u64(1, u64::from(d.display_id))?;
        m.put_u64(2, u64::from(d.mode as u8))?;
        m.put_u64(3, u64::from(d.width))?;
        m.put_u64(4, u64::from(d.height))?;
        m.put_u64(5, u64::from(d.fps_num))?;
        m.put_u64(6, u64::from(d.fps_den))?;
        m.put_u64(7, u64::from(d.scale_milli))?;
        m.put_u64(8, u64::from(d.rotation_deg as u16))?;
        m.put_array_with(9, d.codec_pref.len(), |c_arr| {
            for c in &d.codec_pref {
                c_arr.push_u64(u64::from(c.as_u8()))?;
            }
            Ok(())
        })?;
        m.put_u64(10, u64::from(d.max_bitrate_bps))?;
        m.put_u64(11, u64::from(d.latency_profile as u8))?;
        Ok(())
    })
}

fn decode_display_req(r: &mut CborReader<'_>) -> Result<DisplayRequest, CborError> {
    let (mut id, mut mode, mut w, mut h, mut fn_, mut fd, mut sc, mut rot, mut cp, mut br, mut lp) = (
        None, None, None, None, None, None, None, None, None, None, None,
    );
    r.read_map(2, |r, k| {
        match k {
            1 => {
                id = Some(read_u16_bounded(
                    r,
                    0,
                    u64::from(MAX_VALID_DISPLAY_ID),
                    "display_id",
                )?);
            }
            2 => mode = Some(DisplayMode::from_u64(r.read_u64("mode")?)?),
            3 => w = Some(read_u16_bounded(r, 64, 16384, "width")?),
            4 => h = Some(read_u16_bounded(r, 64, 16384, "height")?),
            5 => fn_ = Some(read_u16_bounded(r, 1, 1000, "fps_num")?),
            6 => fd = Some(read_u16_bounded(r, 1, 1000, "fps_den")?),
            7 => sc = Some(read_u16_bounded(r, 250, 4000, "scale_milli")?),
            8 => rot = Some(RotationDeg::from_u64(r.read_u64("rotation_deg")?)?),
            9 => {
                let mut prefs = Vec::new();
                r.read_array(3, 8, "codec_pref", |r, _| {
                    let raw = read_u8_bounded(r, 1, 3, "codec_id")?;
                    prefs.push(
                        CodecId::from_raw(raw).ok_or(CborError::ValueOutOfRange("codec_id"))?,
                    );
                    Ok(())
                })?;
                cp = Some(prefs);
            }
            10 => {
                br = Some(read_u32_bounded(
                    r,
                    100_000,
                    1_000_000_000,
                    "max_bitrate_bps",
                )?);
            }
            11 => lp = Some(LatencyProfile::from_u64(r.read_u64("latency_profile")?)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(DisplayRequest {
        display_id: req(id, "display_id")?,
        mode: req(mode, "mode")?,
        width: req(w, "width")?,
        height: req(h, "height")?,
        fps_num: req(fn_, "fps_num")?,
        fps_den: req(fd, "fps_den")?,
        scale_milli: req(sc, "scale_milli")?,
        rotation_deg: req(rot, "rotation_deg")?,
        codec_pref: req(cp, "codec_pref")?,
        max_bitrate_bps: req(br, "max_bitrate_bps")?,
        latency_profile: req(lp, "latency_profile")?,
    })
}

fn encode_session_open_request(m: &SessionOpenRequest, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 3)?;
    map.put_u64(1, m.session_id)?;
    map.put_array_with(2, m.displays.len(), |arr| {
        for d in &m.displays {
            encode_display_req(d, arr)?;
        }
        Ok(())
    })?;
    map.put_u64(3, u64::from(m.requested_perms.raw()))?;
    map.finish()
}

fn decode_session_open_request(r: &mut CborReader<'_>) -> Result<SessionOpenRequest, CborError> {
    let (mut sid, mut displays, mut perms) = (None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => sid = Some(r.read_u64("session_id")?),
            2 => {
                let mut list = Vec::new();
                r.read_array(1, 16, "displays", |r, _| {
                    list.push(decode_display_req(r)?);
                    Ok(())
                })?;
                displays = Some(list);
            }
            3 => perms = Some(Permissions::from_raw(r.read_u32("requested_perms")?)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(SessionOpenRequest {
        session_id: req(sid, "session_id")?,
        displays: req(displays, "displays")?,
        requested_perms: req(perms, "requested_perms")?,
    })
}

fn encode_active_display(
    d: &ActiveDisplayConfig,
    arr: &mut CborArrayEncoder<'_>,
) -> Result<(), CborError> {
    arr.push_map_with(12, |m| {
        m.put_u64(1, u64::from(d.display_id))?;
        m.put_u64(2, u64::from(d.mode as u8))?;
        m.put_u64(3, u64::from(d.width))?;
        m.put_u64(4, u64::from(d.height))?;
        m.put_u64(5, u64::from(d.fps_num))?;
        m.put_u64(6, u64::from(d.fps_den))?;
        m.put_u64(7, u64::from(d.scale_milli))?;
        m.put_u64(8, u64::from(d.rotation_deg as u16))?;
        m.put_u64(9, u64::from(d.codec_id.as_u8()))?;
        m.put_u64(10, u64::from(d.color_format as u8))?;
        m.put_u64(11, u64::from(d.initial_bitrate_bps))?;
        m.put_u64(12, u64::from(d.capture_mode as u8))?;
        Ok(())
    })
}

fn decode_active_display(r: &mut CborReader<'_>) -> Result<ActiveDisplayConfig, CborError> {
    let (
        mut id,
        mut mode,
        mut w,
        mut h,
        mut fn_,
        mut fd,
        mut sc,
        mut rot,
        mut cid,
        mut cf,
        mut br,
        mut cm,
    ) = (
        None, None, None, None, None, None, None, None, None, None, None, None,
    );
    r.read_map(2, |r, k| {
        match k {
            1 => {
                id = Some(read_u16_bounded(
                    r,
                    0,
                    u64::from(MAX_VALID_DISPLAY_ID),
                    "display_id",
                )?);
            }
            2 => mode = Some(DisplayMode::from_u64(r.read_u64("mode")?)?),
            3 => w = Some(read_u16_bounded(r, 64, 16384, "width")?),
            4 => h = Some(read_u16_bounded(r, 64, 16384, "height")?),
            5 => fn_ = Some(read_u16_bounded(r, 1, 1000, "fps_num")?),
            6 => fd = Some(read_u16_bounded(r, 1, 1000, "fps_den")?),
            7 => sc = Some(read_u16_bounded(r, 250, 4000, "scale_milli")?),
            8 => rot = Some(RotationDeg::from_u64(r.read_u64("rotation_deg")?)?),
            9 => {
                let raw = read_u8_bounded(r, 1, 3, "codec_id")?;
                cid = Some(CodecId::from_raw(raw).ok_or(CborError::ValueOutOfRange("codec_id"))?);
            }
            10 => cf = Some(ColorFormat::from_u64(r.read_u64("color_format")?)?),
            11 => {
                br = Some(read_u32_bounded(
                    r,
                    100_000,
                    1_000_000_000,
                    "initial_bitrate_bps",
                )?);
            }
            12 => cm = Some(CaptureMode::from_u64(r.read_u64("capture_mode")?)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(ActiveDisplayConfig {
        display_id: req(id, "display_id")?,
        mode: req(mode, "mode")?,
        width: req(w, "width")?,
        height: req(h, "height")?,
        fps_num: req(fn_, "fps_num")?,
        fps_den: req(fd, "fps_den")?,
        scale_milli: req(sc, "scale_milli")?,
        rotation_deg: req(rot, "rotation_deg")?,
        codec_id: req(cid, "codec_id")?,
        color_format: req(cf, "color_format")?,
        initial_bitrate_bps: req(br, "initial_bitrate_bps")?,
        capture_mode: req(cm, "capture_mode")?,
    })
}

fn encode_session_open_response(
    m: &SessionOpenResponse,
    out: &mut Vec<u8>,
) -> Result<(), CborError> {
    let count = 4 + usize::from(m.resume_token.is_some());
    let mut map = CborMapEncoder::start(out, count)?;
    map.put_u64(1, u64::from(m.status as u8))?;
    map.put_u64(2, m.session_id)?;
    if let Some(tok) = &m.resume_token {
        map.put_bytes(3, tok)?;
    }
    map.put_array_with(4, m.active_displays.len(), |arr| {
        for d in &m.active_displays {
            encode_active_display(d, arr)?;
        }
        Ok(())
    })?;
    map.put_u64(5, u64::from(m.granted_perms.raw()))?;
    map.finish()
}

fn decode_session_open_response(r: &mut CborReader<'_>) -> Result<SessionOpenResponse, CborError> {
    let (mut status, mut sid, mut tok, mut displays, mut perms) = (None, None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => status = Some(SessionOpenStatus::from_u64(r.read_u64("status")?)?),
            2 => sid = Some(r.read_u64("session_id")?),
            3 => tok = Some(r.read_bytes(64, "resume_token")?),
            4 => {
                let mut list = Vec::new();
                r.read_array(1, 16, "active_displays", |r, _| {
                    list.push(decode_active_display(r)?);
                    Ok(())
                })?;
                displays = Some(list);
            }
            5 => perms = Some(Permissions::from_raw(r.read_u32("granted_perms")?)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(SessionOpenResponse {
        status: req(status, "status")?,
        session_id: req(sid, "session_id")?,
        resume_token: tok,
        active_displays: req(displays, "active_displays")?,
        granted_perms: req(perms, "granted_perms")?,
    })
}

fn encode_display_config_update(
    m: &DisplayConfigUpdate,
    out: &mut Vec<u8>,
) -> Result<(), CborError> {
    let count = 4
        + usize::from(m.mode.is_some())
        + usize::from(m.width.is_some())
        + usize::from(m.height.is_some())
        + usize::from(m.fps_num.is_some())
        + usize::from(m.fps_den.is_some())
        + usize::from(m.scale_milli.is_some())
        + usize::from(m.rotation_deg.is_some())
        + usize::from(m.pos_x.is_some())
        + usize::from(m.pos_y.is_some());
    let mut map = CborMapEncoder::start(out, count)?;
    map.put_u64(1, m.session_id)?;
    map.put_u64(2, m.update_seq)?;
    map.put_u64(3, u64::from(m.display_id))?;
    map.put_u64(4, u64::from(m.action as u8))?;
    if let Some(v) = m.mode {
        map.put_u64(5, u64::from(v as u8))?;
    }
    if let Some(v) = m.width {
        map.put_u64(6, u64::from(v))?;
    }
    if let Some(v) = m.height {
        map.put_u64(7, u64::from(v))?;
    }
    if let Some(v) = m.fps_num {
        map.put_u64(8, u64::from(v))?;
    }
    if let Some(v) = m.fps_den {
        map.put_u64(9, u64::from(v))?;
    }
    if let Some(v) = m.scale_milli {
        map.put_u64(10, u64::from(v))?;
    }
    if let Some(v) = m.rotation_deg {
        map.put_u64(11, u64::from(v as u16))?;
    }
    if let Some(v) = m.pos_x {
        map.put_i64(12, i64::from(v))?;
    }
    if let Some(v) = m.pos_y {
        map.put_i64(13, i64::from(v))?;
    }
    map.finish()
}

fn decode_display_config_update(r: &mut CborReader<'_>) -> Result<DisplayConfigUpdate, CborError> {
    let (
        mut sid,
        mut seq,
        mut did,
        mut act,
        mut mode,
        mut w,
        mut h,
        mut fn_,
        mut fd,
        mut sc,
        mut rot,
        mut px,
        mut py,
    ) = (
        None, None, None, None, None, None, None, None, None, None, None, None, None,
    );
    r.read_map(0, |r, k| {
        match k {
            1 => sid = Some(r.read_u64("session_id")?),
            2 => seq = Some(r.read_u64("update_seq")?),
            3 => {
                did = Some(read_u16_bounded(
                    r,
                    0,
                    u64::from(MAX_VALID_DISPLAY_ID),
                    "display_id",
                )?);
            }
            4 => act = Some(DisplayConfigAction::from_u64(r.read_u64("action")?)?),
            5 => mode = Some(DisplayMode::from_u64(r.read_u64("mode")?)?),
            6 => w = Some(read_u16_bounded(r, 64, 16384, "width")?),
            7 => h = Some(read_u16_bounded(r, 64, 16384, "height")?),
            8 => fn_ = Some(read_u16_bounded(r, 1, 1000, "fps_num")?),
            9 => fd = Some(read_u16_bounded(r, 1, 1000, "fps_den")?),
            10 => sc = Some(read_u16_bounded(r, 250, 4000, "scale_milli")?),
            11 => rot = Some(RotationDeg::from_u64(r.read_u64("rotation_deg")?)?),
            12 => {
                let v = r.read_i64("pos_x")?;
                require_range_i64(v, -65536, 65536, "pos_x")?;
                px = Some(i32::try_from(v).map_err(|_| CborError::ValueOutOfRange("pos_x"))?);
            }
            13 => {
                let v = r.read_i64("pos_y")?;
                require_range_i64(v, -65536, 65536, "pos_y")?;
                py = Some(i32::try_from(v).map_err(|_| CborError::ValueOutOfRange("pos_y"))?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(DisplayConfigUpdate {
        session_id: req(sid, "session_id")?,
        update_seq: req(seq, "update_seq")?,
        display_id: req(did, "display_id")?,
        action: req(act, "action")?,
        mode,
        width: w,
        height: h,
        fps_num: fn_,
        fps_den: fd,
        scale_milli: sc,
        rotation_deg: rot,
        pos_x: px,
        pos_y: py,
    })
}

fn encode_session_resume_request(
    m: &SessionResumeRequest,
    out: &mut Vec<u8>,
) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 3)?;
    map.put_u64(1, m.session_id)?;
    map.put_bytes(2, &m.resume_token)?;
    map.put_array_with(3, m.last_good_frames.len(), |arr| {
        for cur in &m.last_good_frames {
            arr.push_map_with(2, |c| {
                c.put_u64(1, u64::from(cur.display_id))?;
                c.put_u64(2, u64::from(cur.last_good_frame_id))?;
                Ok(())
            })?;
        }
        Ok(())
    })?;
    map.finish()
}

fn decode_frame_cursor(r: &mut CborReader<'_>) -> Result<DisplayFrameCursor, CborError> {
    let (mut did, mut fid) = (None, None);
    r.read_map(2, |r, k| {
        match k {
            1 => {
                did = Some(read_u16_bounded(
                    r,
                    0,
                    u64::from(MAX_VALID_DISPLAY_ID),
                    "display_id",
                )?);
            }
            2 => fid = Some(r.read_u32("last_good_frame_id")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(DisplayFrameCursor {
        display_id: req(did, "display_id")?,
        last_good_frame_id: req(fid, "last_good_frame_id")?,
    })
}

fn decode_session_resume_request(
    r: &mut CborReader<'_>,
) -> Result<SessionResumeRequest, CborError> {
    let (mut sid, mut tok, mut cursors) = (None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => sid = Some(r.read_u64("session_id")?),
            2 => tok = Some(r.read_bytes(64, "resume_token")?),
            3 => {
                let mut list = Vec::new();
                r.read_array(1, 16, "last_good_frames", |r, _| {
                    list.push(decode_frame_cursor(r)?);
                    Ok(())
                })?;
                cursors = Some(list);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(SessionResumeRequest {
        session_id: req(sid, "session_id")?,
        resume_token: req(tok, "resume_token")?,
        last_good_frames: req(cursors, "last_good_frames")?,
    })
}

fn encode_session_resume_response(
    m: &SessionResumeResponse,
    out: &mut Vec<u8>,
) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 4)?;
    map.put_bool(1, m.accepted)?;
    map.put_u64(2, m.session_id)?;
    map.put_array_with(3, m.preserved_displays.len(), |arr| {
        for d in &m.preserved_displays {
            encode_active_display(d, arr)?;
        }
        Ok(())
    })?;
    map.put_array_with(4, m.idr_requested_displays.len(), |arr| {
        for &id in &m.idr_requested_displays {
            arr.push_u64(u64::from(id))?;
        }
        Ok(())
    })?;
    map.finish()
}

fn decode_session_resume_response(
    r: &mut CborReader<'_>,
) -> Result<SessionResumeResponse, CborError> {
    let (mut acc, mut sid, mut displays, mut idrs) = (None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => acc = Some(r.read_bool("accepted")?),
            2 => sid = Some(r.read_u64("session_id")?),
            3 => {
                let mut list = Vec::new();
                r.read_array(1, 16, "preserved_displays", |r, _| {
                    list.push(decode_active_display(r)?);
                    Ok(())
                })?;
                displays = Some(list);
            }
            4 => {
                let mut list = Vec::new();
                r.read_array(1, 16, "idr_requested_displays", |r, _| {
                    list.push(read_u16_bounded(
                        r,
                        0,
                        u64::from(MAX_VALID_DISPLAY_ID),
                        "display_id",
                    )?);
                    Ok(())
                })?;
                idrs = Some(list);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(SessionResumeResponse {
        accepted: req(acc, "accepted")?,
        session_id: req(sid, "session_id")?,
        preserved_displays: req(displays, "preserved_displays")?,
        idr_requested_displays: req(idrs, "idr_requested_displays")?,
    })
}

fn encode_session_close(m: &SessionClose, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 3)?;
    map.put_u64(1, m.session_id)?;
    map.put_u64(2, u64::from(m.reason_code as u8))?;
    map.put_bool(3, m.teardown_virtual_displays)?;
    map.finish()
}

fn decode_session_close(r: &mut CborReader<'_>) -> Result<SessionClose, CborError> {
    let (mut sid, mut rsn, mut td) = (None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => sid = Some(r.read_u64("session_id")?),
            2 => rsn = Some(CloseReasonCode::from_u64(r.read_u64("reason_code")?)?),
            3 => td = Some(r.read_bool("teardown_virtual_displays")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(SessionClose {
        session_id: req(sid, "session_id")?,
        reason_code: req(rsn, "reason_code")?,
        teardown_virtual_displays: req(td, "teardown_virtual_displays")?,
    })
}

fn encode_perm_upgrade_req(
    m: &PermissionUpgradeRequest,
    out: &mut Vec<u8>,
) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 4)?;
    map.put_u64(1, m.session_id)?;
    map.put_u64(2, m.request_seq)?;
    map.put_u64(3, u64::from(m.requested_perms.raw()))?;
    map.put_text(4, &m.reason_text)?;
    map.finish()
}

fn decode_perm_upgrade_req(r: &mut CborReader<'_>) -> Result<PermissionUpgradeRequest, CborError> {
    let (mut sid, mut seq, mut perms, mut text) = (None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => sid = Some(r.read_u64("session_id")?),
            2 => seq = Some(r.read_u64("request_seq")?),
            3 => perms = Some(Permissions::from_raw(r.read_u32("requested_perms")?)?),
            4 => text = Some(r.read_text(128, "reason_text")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(PermissionUpgradeRequest {
        session_id: req(sid, "session_id")?,
        request_seq: req(seq, "request_seq")?,
        requested_perms: req(perms, "requested_perms")?,
        reason_text: req(text, "reason_text")?,
    })
}

fn encode_perm_update(m: &PermissionUpdate, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 3)?;
    map.put_u64(1, m.session_id)?;
    map.put_u64(2, m.update_seq)?;
    map.put_u64(3, u64::from(m.effective_perms.raw()))?;
    map.finish()
}

fn decode_perm_update(r: &mut CborReader<'_>) -> Result<PermissionUpdate, CborError> {
    let (mut sid, mut seq, mut perms) = (None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => sid = Some(r.read_u64("session_id")?),
            2 => seq = Some(r.read_u64("update_seq")?),
            3 => perms = Some(Permissions::from_raw(r.read_u32("effective_perms")?)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(PermissionUpdate {
        session_id: req(sid, "session_id")?,
        update_seq: req(seq, "update_seq")?,
        effective_perms: req(perms, "effective_perms")?,
    })
}

fn encode_media_feedback(m: &MediaFeedback, out: &mut Vec<u8>) -> Result<(), CborError> {
    let count = 12 + usize::from(m.broken_gop_id.is_some());
    let mut map = CborMapEncoder::start(out, count)?;
    map.put_u64(1, m.session_id)?;
    map.put_u64(2, u64::from(m.display_id))?;
    map.put_u64(3, u64::from(m.last_complete_frame_id))?;
    map.put_u64(4, u64::from(m.last_displayed_frame_id))?;
    if let Some(gop) = m.broken_gop_id {
        map.put_u64(5, u64::from(gop))?;
    }
    map.put_bool(6, m.request_idr)?;
    map.put_u64(7, u64::from(m.decode_p50_us))?;
    map.put_u64(8, u64::from(m.decode_p95_us))?;
    map.put_u64(9, u64::from(m.present_p95_us))?;
    map.put_u64(10, u64::from(m.rx_fps_milli))?;
    map.put_u64(11, u64::from(m.packet_loss_ppm))?;
    map.put_u64(12, u64::from(m.jitter_us))?;
    map.put_u64(13, u64::from(m.suggested_bitrate_bps))?;
    map.finish()
}

fn decode_media_feedback(r: &mut CborReader<'_>) -> Result<MediaFeedback, CborError> {
    let (
        mut sid,
        mut did,
        mut lcf,
        mut ldf,
        mut gop,
        mut ridr,
        mut d50,
        mut d95,
        mut p95,
        mut fps,
        mut loss,
        mut jit,
        mut br,
    ) = (
        None, None, None, None, None, None, None, None, None, None, None, None, None,
    );
    r.read_map(0, |r, k| {
        match k {
            1 => sid = Some(r.read_u64("session_id")?),
            2 => {
                did = Some(read_u16_bounded(
                    r,
                    0,
                    u64::from(MAX_VALID_DISPLAY_ID),
                    "display_id",
                )?);
            }
            3 => lcf = Some(r.read_u32("last_complete_frame_id")?),
            4 => ldf = Some(r.read_u32("last_displayed_frame_id")?),
            5 => gop = Some(r.read_u16("broken_gop_id")?),
            6 => ridr = Some(r.read_bool("request_idr")?),
            7 => d50 = Some(read_u32_bounded(r, 0, 10_000_000, "decode_p50_us")?),
            8 => d95 = Some(read_u32_bounded(r, 0, 10_000_000, "decode_p95_us")?),
            9 => p95 = Some(read_u32_bounded(r, 0, 10_000_000, "present_p95_us")?),
            10 => fps = Some(read_u32_bounded(r, 0, 1_000_000, "rx_fps_milli")?),
            11 => loss = Some(read_u32_bounded(r, 0, 1_000_000, "packet_loss_ppm")?),
            12 => jit = Some(read_u32_bounded(r, 0, 10_000_000, "jitter_us")?),
            13 => {
                br = Some(read_u32_bounded(
                    r,
                    0,
                    1_000_000_000,
                    "suggested_bitrate_bps",
                )?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(MediaFeedback {
        session_id: req(sid, "session_id")?,
        display_id: req(did, "display_id")?,
        last_complete_frame_id: req(lcf, "last_complete_frame_id")?,
        last_displayed_frame_id: req(ldf, "last_displayed_frame_id")?,
        broken_gop_id: gop,
        request_idr: req(ridr, "request_idr")?,
        decode_p50_us: req(d50, "decode_p50_us")?,
        decode_p95_us: req(d95, "decode_p95_us")?,
        present_p95_us: req(p95, "present_p95_us")?,
        rx_fps_milli: req(fps, "rx_fps_milli")?,
        packet_loss_ppm: req(loss, "packet_loss_ppm")?,
        jitter_us: req(jit, "jitter_us")?,
        suggested_bitrate_bps: req(br, "suggested_bitrate_bps")?,
    })
}

fn encode_clock_sync_ping(m: &ClockSyncPing, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 2)?;
    map.put_u64(1, m.seq)?;
    map.put_u64(2, m.t1_client_mono_us)?;
    map.finish()
}

fn decode_clock_sync_ping(r: &mut CborReader<'_>) -> Result<ClockSyncPing, CborError> {
    let (mut seq, mut t1) = (None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => seq = Some(r.read_u64("seq")?),
            2 => t1 = Some(r.read_u64("t1_client_mono_us")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(ClockSyncPing {
        seq: req(seq, "seq")?,
        t1_client_mono_us: req(t1, "t1_client_mono_us")?,
    })
}

fn encode_clock_sync_pong(m: &ClockSyncPong, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 4)?;
    map.put_u64(1, m.seq)?;
    map.put_u64(2, m.t1_client_mono_us)?;
    map.put_u64(3, m.t2_server_recv_us)?;
    map.put_u64(4, m.t3_server_send_us)?;
    map.finish()
}

fn decode_clock_sync_pong(r: &mut CborReader<'_>) -> Result<ClockSyncPong, CborError> {
    let (mut seq, mut t1, mut t2, mut t3) = (None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => seq = Some(r.read_u64("seq")?),
            2 => t1 = Some(r.read_u64("t1_client_mono_us")?),
            3 => t2 = Some(r.read_u64("t2_server_recv_us")?),
            4 => t3 = Some(r.read_u64("t3_server_send_us")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(ClockSyncPong {
        seq: req(seq, "seq")?,
        t1_client_mono_us: req(t1, "t1_client_mono_us")?,
        t2_server_recv_us: req(t2, "t2_server_recv_us")?,
        t3_server_send_us: req(t3, "t3_server_send_us")?,
    })
}

fn encode_heartbeat(m: &Heartbeat, out: &mut Vec<u8>) -> Result<(), CborError> {
    let count = 2 + usize::from(m.session_id.is_some());
    let mut map = CborMapEncoder::start(out, count)?;
    if let Some(sid) = m.session_id {
        map.put_u64(1, sid)?;
    }
    map.put_u64(2, m.seq)?;
    map.put_u64(3, m.uptime_ms)?;
    map.finish()
}

fn decode_heartbeat(r: &mut CborReader<'_>) -> Result<Heartbeat, CborError> {
    let (mut sid, mut seq, mut up) = (None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => sid = Some(r.read_u64("session_id")?),
            2 => seq = Some(r.read_u64("seq")?),
            3 => up = Some(r.read_u64("uptime_ms")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(Heartbeat {
        session_id: sid,
        seq: req(seq, "seq")?,
        uptime_ms: req(up, "uptime_ms")?,
    })
}

fn encode_diagnostics_summary(m: &DiagnosticsSummary, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 10)?;
    map.put_u64(1, m.session_id)?;
    map.put_u64(2, u64::from(m.window_ms))?;
    map.put_u64(3, u64::from(m.e2e_p50_us))?;
    map.put_u64(4, u64::from(m.e2e_p95_us))?;
    map.put_u64(5, u64::from(m.e2e_p99_us))?;
    map.put_u64(6, u64::from(m.cpu_usage_bps))?;
    map.put_u64(7, u64::from(m.gpu_usage_bps))?;
    map.put_u64(8, m.ram_rss_kib)?;
    map.put_u64(9, m.backpressure_drops)?;
    map.put_bool(10, m.hw_accel_active)?;
    map.finish()
}

fn decode_diagnostics_summary(r: &mut CborReader<'_>) -> Result<DiagnosticsSummary, CborError> {
    let (mut sid, mut win, mut p50, mut p95, mut p99, mut cpu, mut gpu, mut ram, mut drops, mut hw) =
        (None, None, None, None, None, None, None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => sid = Some(r.read_u64("session_id")?),
            2 => win = Some(read_u32_bounded(r, 1, 3_600_000, "window_ms")?),
            3 => p50 = Some(read_u32_bounded(r, 0, 10_000_000, "e2e_p50_us")?),
            4 => p95 = Some(read_u32_bounded(r, 0, 10_000_000, "e2e_p95_us")?),
            5 => p99 = Some(read_u32_bounded(r, 0, 10_000_000, "e2e_p99_us")?),
            6 => cpu = Some(read_u16_bounded(r, 0, 10_000, "cpu_usage_bps")?),
            7 => gpu = Some(read_u16_bounded(r, 0, 10_000, "gpu_usage_bps")?),
            8 => ram = Some(r.read_u64("ram_rss_kib")?),
            9 => drops = Some(r.read_u64("backpressure_drops")?),
            10 => hw = Some(r.read_bool("hw_accel_active")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(DiagnosticsSummary {
        session_id: req(sid, "session_id")?,
        window_ms: req(win, "window_ms")?,
        e2e_p50_us: req(p50, "e2e_p50_us")?,
        e2e_p95_us: req(p95, "e2e_p95_us")?,
        e2e_p99_us: req(p99, "e2e_p99_us")?,
        cpu_usage_bps: req(cpu, "cpu_usage_bps")?,
        gpu_usage_bps: req(gpu, "gpu_usage_bps")?,
        ram_rss_kib: req(ram, "ram_rss_kib")?,
        backpressure_drops: req(drops, "backpressure_drops")?,
        hw_accel_active: req(hw, "hw_accel_active")?,
    })
}

fn encode_input_event(ev: InputEvent, arr: &mut CborArrayEncoder<'_>) -> Result<(), CborError> {
    match ev {
        InputEvent::PointerMoveAbs { x_norm, y_norm } => arr.push_map_with(3, |m| {
            m.put_u64(1, 1)?;
            m.put_u64(2, u64::from(x_norm))?;
            m.put_u64(3, u64::from(y_norm))
        }),
        InputEvent::PointerButton { button_id, pressed } => arr.push_map_with(3, |m| {
            m.put_u64(1, 2)?;
            m.put_u64(2, u64::from(button_id))?;
            m.put_bool(3, pressed)
        }),
        InputEvent::PointerScroll {
            delta_x_milli,
            delta_y_milli,
        } => arr.push_map_with(3, |m| {
            m.put_u64(1, 3)?;
            m.put_i64(2, i64::from(delta_x_milli))?;
            m.put_i64(3, i64::from(delta_y_milli))
        }),
        InputEvent::KeyEvent {
            hid_usage_page,
            hid_usage_id,
            pressed,
            modifiers_mask,
        } => arr.push_map_with(5, |m| {
            m.put_u64(1, 4)?;
            m.put_u64(2, u64::from(hid_usage_page))?;
            m.put_u64(3, u64::from(hid_usage_id))?;
            m.put_bool(4, pressed)?;
            m.put_u64(5, u64::from(modifiers_mask))
        }),
        InputEvent::TouchContact {
            contact_id,
            phase,
            x_norm,
            y_norm,
            pressure_norm,
        } => arr.push_map_with(6, |m| {
            m.put_u64(1, 5)?;
            m.put_u64(2, u64::from(contact_id))?;
            m.put_u64(3, u64::from(phase as u8))?;
            m.put_u64(4, u64::from(x_norm))?;
            m.put_u64(5, u64::from(y_norm))?;
            m.put_u64(6, u64::from(pressure_norm))
        }),
        InputEvent::StylusEvent {
            x_norm,
            y_norm,
            pressure_norm,
            tilt_x_deg,
            tilt_y_deg,
            buttons_mask,
        } => arr.push_map_with(7, |m| {
            m.put_u64(1, 6)?;
            m.put_u64(2, u64::from(x_norm))?;
            m.put_u64(3, u64::from(y_norm))?;
            m.put_u64(4, u64::from(pressure_norm))?;
            m.put_i64(5, i64::from(tilt_x_deg))?;
            m.put_i64(6, i64::from(tilt_y_deg))?;
            m.put_u64(7, u64::from(buttons_mask))
        }),
    }
}

fn decode_input_event(r: &mut CborReader<'_>) -> Result<InputEvent, CborError> {
    let mut kind: Option<u64> = None;
    let mut f2_u: Option<u64> = None;
    let mut f2_i: Option<i64> = None;
    let mut f3_u: Option<u64> = None;
    let mut f3_i: Option<i64> = None;
    let mut f3_b: Option<bool> = None;
    let mut f4_u: Option<u64> = None;
    let mut f4_b: Option<bool> = None;
    let mut f5_u: Option<u64> = None;
    let mut f5_i: Option<i64> = None;
    let mut f6_u: Option<u64> = None;
    let mut f6_i: Option<i64> = None;
    let mut f7_u: Option<u64> = None;

    r.read_map(2, |r, k| {
        if k == 1 {
            let v = r.read_u64("input_event_kind")?;
            require_range_u64(v, 1, 6, "input_event_kind")?;
            kind = Some(v);
            return Ok(true);
        }
        let Some(kval) = kind else {
            return Err(CborError::MissingRequiredField("input_event_kind"));
        };
        match (kval, k) {
            (1 | 2 | 4 | 5 | 6, 2) => f2_u = Some(r.read_u64("event_f2")?),
            (3, 2) => f2_i = Some(r.read_i64("event_f2")?),
            (1 | 4 | 5 | 6, 3) => f3_u = Some(r.read_u64("event_f3")?),
            (2, 3) => f3_b = Some(r.read_bool("pressed")?),
            (3, 3) => f3_i = Some(r.read_i64("event_f3")?),
            (4, 4) => f4_b = Some(r.read_bool("pressed")?),
            (5 | 6, 4) => f4_u = Some(r.read_u64("event_f4")?),
            (4 | 5, 5) => f5_u = Some(r.read_u64("event_f5")?),
            (6, 5) => f5_i = Some(r.read_i64("tilt_x_deg")?),
            (5, 6) => f6_u = Some(r.read_u64("pressure_norm")?),
            (6, 6) => f6_i = Some(r.read_i64("tilt_y_deg")?),
            (6, 7) => f7_u = Some(r.read_u64("buttons_mask")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;

    match req(kind, "input_event_kind")? {
        1 => Ok(InputEvent::PointerMoveAbs {
            x_norm: u16::try_from(req(f2_u, "x_norm")?)
                .map_err(|_| CborError::ValueOutOfRange("x_norm"))?,
            y_norm: u16::try_from(req(f3_u, "y_norm")?)
                .map_err(|_| CborError::ValueOutOfRange("y_norm"))?,
        }),
        2 => Ok(InputEvent::PointerButton {
            button_id: u8::try_from(req(f2_u, "button_id")?)
                .map_err(|_| CborError::ValueOutOfRange("button_id"))?,
            pressed: req(f3_b, "pressed")?,
        }),
        3 => Ok(InputEvent::PointerScroll {
            delta_x_milli: i32::try_from(req(f2_i, "delta_x_milli")?)
                .map_err(|_| CborError::ValueOutOfRange("delta_x_milli"))?,
            delta_y_milli: i32::try_from(req(f3_i, "delta_y_milli")?)
                .map_err(|_| CborError::ValueOutOfRange("delta_y_milli"))?,
        }),
        4 => Ok(InputEvent::KeyEvent {
            hid_usage_page: u16::try_from(req(f2_u, "hid_usage_page")?)
                .map_err(|_| CborError::ValueOutOfRange("hid_usage_page"))?,
            hid_usage_id: u16::try_from(req(f3_u, "hid_usage_id")?)
                .map_err(|_| CborError::ValueOutOfRange("hid_usage_id"))?,
            pressed: req(f4_b, "pressed")?,
            modifiers_mask: u8::try_from(req(f5_u, "modifiers_mask")?)
                .map_err(|_| CborError::ValueOutOfRange("modifiers_mask"))?,
        }),
        5 => Ok(InputEvent::TouchContact {
            contact_id: u8::try_from(req(f2_u, "contact_id")?)
                .map_err(|_| CborError::ValueOutOfRange("contact_id"))?,
            phase: TouchPhase::from_u64(req(f3_u, "phase")?)?,
            x_norm: u16::try_from(req(f4_u, "x_norm")?)
                .map_err(|_| CborError::ValueOutOfRange("x_norm"))?,
            y_norm: u16::try_from(req(f5_u, "y_norm")?)
                .map_err(|_| CborError::ValueOutOfRange("y_norm"))?,
            pressure_norm: u16::try_from(req(f6_u, "pressure_norm")?)
                .map_err(|_| CborError::ValueOutOfRange("pressure_norm"))?,
        }),
        6 => Ok(InputEvent::StylusEvent {
            x_norm: u16::try_from(req(f2_u, "x_norm")?)
                .map_err(|_| CborError::ValueOutOfRange("x_norm"))?,
            y_norm: u16::try_from(req(f3_u, "y_norm")?)
                .map_err(|_| CborError::ValueOutOfRange("y_norm"))?,
            pressure_norm: u16::try_from(req(f4_u, "pressure_norm")?)
                .map_err(|_| CborError::ValueOutOfRange("pressure_norm"))?,
            tilt_x_deg: i8::try_from(req(f5_i, "tilt_x_deg")?)
                .map_err(|_| CborError::ValueOutOfRange("tilt_x_deg"))?,
            tilt_y_deg: i8::try_from(req(f6_i, "tilt_y_deg")?)
                .map_err(|_| CborError::ValueOutOfRange("tilt_y_deg"))?,
            buttons_mask: u8::try_from(req(f7_u, "buttons_mask")?)
                .map_err(|_| CborError::ValueOutOfRange("buttons_mask"))?,
        }),
        _ => Err(CborError::ValueOutOfRange("input_event_kind")),
    }
}

fn encode_input_batch(m: &InputBatch, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 4)?;
    map.put_u64(1, m.session_id)?;
    map.put_u64(2, u64::from(m.display_id))?;
    map.put_u64(3, m.input_seq)?;
    map.put_array_with(4, m.events.len(), |arr| {
        for &ev in &m.events {
            encode_input_event(ev, arr)?;
        }
        Ok(())
    })?;
    map.finish()
}

fn decode_input_batch(r: &mut CborReader<'_>) -> Result<InputBatch, CborError> {
    let (mut sid, mut did, mut seq, mut evs) = (None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => sid = Some(r.read_u64("session_id")?),
            2 => {
                did = Some(read_u16_bounded(
                    r,
                    0,
                    u64::from(MAX_VALID_DISPLAY_ID),
                    "display_id",
                )?);
            }
            3 => seq = Some(r.read_u64("input_seq")?),
            4 => {
                let mut list = Vec::new();
                r.read_array(1, 32, "events", |r, _| {
                    list.push(decode_input_event(r)?);
                    Ok(())
                })?;
                evs = Some(list);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(InputBatch {
        session_id: req(sid, "session_id")?,
        display_id: req(did, "display_id")?,
        input_seq: req(seq, "input_seq")?,
        events: req(evs, "events")?,
    })
}

fn encode_error_notice(m: &ErrorNotice, out: &mut Vec<u8>) -> Result<(), CborError> {
    let mut map = CborMapEncoder::start(out, 4)?;
    map.put_u64(1, u64::from(m.code.as_u32()))?;
    map.put_bool(2, m.fatal)?;
    map.put_u64(3, u64::from(m.related_msg_type))?;
    map.put_text(4, &m.context_ascii)?;
    map.finish()
}

fn decode_error_notice(r: &mut CborReader<'_>) -> Result<ErrorNotice, CborError> {
    let (mut code, mut fatal, mut rel, mut ctx) = (None, None, None, None);
    r.read_map(0, |r, k| {
        match k {
            1 => {
                let raw = r.read_u32("code")?;
                code = Some(ErrorCode::from_raw(raw).ok_or(CborError::ValueOutOfRange("code"))?);
            }
            2 => fatal = Some(r.read_bool("fatal")?),
            3 => rel = Some(r.read_u16("related_msg_type")?),
            4 => ctx = Some(r.read_text(128, "context_ascii")?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(ErrorNotice {
        code: req(code, "code")?,
        fatal: req(fatal, "fatal")?,
        related_msg_type: req(rel, "related_msg_type")?,
        context_ascii: req(ctx, "context_ascii")?,
    })
}
