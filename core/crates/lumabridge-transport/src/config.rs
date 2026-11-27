// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Validated configuration for QUIC (`RFC 9000` + `RFC 9221`) and `TCP/TLS 1.3` transports.

use crate::error::TransportError;
use lumabridge_protocol::limits::{
    CborLimits, FramingLimits, ReassemblyConfig, RecoveryConfig, CHANNEL_0_MAX_PAYLOAD,
    MAX_FRAME_BYTES,
};

/// Minimum UDP payload ceiling required by RFC 9000 for QUIC Initials.
pub const QUIC_MIN_INITIAL_MTU: u16 = 1200;

/// Conservative upper DPLPMTUD probe MTU ceiling over LAN Ethernet/Wi-Fi.
pub const LAN_MAX_PROBE_MTU: u16 = 1460;

/// Hard maximum active connections tracked concurrently by one endpoint/registry.
pub const MAX_TRACKED_CONNECTIONS_CEILING: usize = 256;

/// Operational wire mode selected for media delivery and framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    /// Primary `ADR-0005` candidate: `QUIC` (`RFC 9000`) with unreliable datagrams (`RFC 9221`)
    /// for video fragments and dedicated reliable streams per control/feedback/input/ProtectedBlank.
    QuicDatagram,
    /// `QUIC` (`RFC 9000`) using a dedicated `Channel 1` unidirectional/bidirectional stream for media
    /// fragments instead of RFC 9221 datagrams.
    QuicStream,
    /// Mandatory fallback (`ADR-0005`): `TCP / TLS 1.3` with `TCP_NODELAY`, multiplexed 8-byte
    /// stream framing, and pre-socket queue drop on congestion.
    TcpTls,
}

/// Complete, validated transport configuration enforcing explicit bounds and timeouts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    pub kind: TransportKind,
    pub initial_mtu: u16,
    pub max_mtu: u16,
    pub dplpmtud_enabled: bool,
    pub handshake_timeout_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub heartbeat_timeout_ms: u64,
    pub max_media_queue_frames: usize,
    pub max_media_queue_bytes: usize,
    pub max_control_queue: usize,
    pub max_feedback_queue: usize,
    pub max_input_queue: usize,
    pub max_concurrent_connections: usize,
    pub max_packet_bytes: usize,
    pub max_frame_bytes: usize,
    pub tcp_nodelay: bool,
    pub initial_bitrate_bps: u64,
    pub min_bitrate_bps: u64,
    pub max_bitrate_bps: u64,
    pub pacing_target_bps: Option<u64>,
    pub framing_limits: FramingLimits,
    pub cbor_limits: CborLimits,
    pub reassembly_config: ReassemblyConfig,
    pub recovery_config: RecoveryConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            kind: TransportKind::QuicDatagram,
            initial_mtu: QUIC_MIN_INITIAL_MTU,
            max_mtu: LAN_MAX_PROBE_MTU,
            dplpmtud_enabled: true,
            handshake_timeout_ms: 5_000,
            heartbeat_interval_ms: 1_000,
            heartbeat_timeout_ms: 5_000,
            max_media_queue_frames: 4,
            max_media_queue_bytes: 8 * 1024 * 1024,
            max_control_queue: 64,
            max_feedback_queue: 64,
            max_input_queue: 128,
            max_concurrent_connections: 32,
            max_packet_bytes: CHANNEL_0_MAX_PAYLOAD,
            max_frame_bytes: MAX_FRAME_BYTES,
            tcp_nodelay: true,
            initial_bitrate_bps: 15_000_000,
            min_bitrate_bps: 1_500_000,
            max_bitrate_bps: 60_000_000,
            pacing_target_bps: None,
            framing_limits: FramingLimits::default(),
            cbor_limits: CborLimits::default(),
            reassembly_config: ReassemblyConfig::default(),
            recovery_config: RecoveryConfig::default(),
        }
    }
}

impl TransportConfig {
    /// Validate every queue bound, MTU invariant, bitrate range, and embedded protocol config.
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.initial_mtu < QUIC_MIN_INITIAL_MTU {
            return Err(TransportError::InvalidConfig(
                "initial_mtu must be >= 1200 (RFC 9000)",
            ));
        }
        if self.max_mtu < self.initial_mtu || self.max_mtu > 9_000 {
            return Err(TransportError::InvalidConfig(
                "max_mtu must be within initial_mtu..=9000",
            ));
        }
        if self.handshake_timeout_ms == 0 || self.heartbeat_interval_ms == 0 {
            return Err(TransportError::InvalidConfig(
                "handshake and heartbeat intervals must be non-zero",
            ));
        }
        if self.heartbeat_timeout_ms <= self.heartbeat_interval_ms {
            return Err(TransportError::InvalidConfig(
                "heartbeat_timeout_ms must exceed heartbeat_interval_ms",
            ));
        }
        if self.max_media_queue_frames == 0 || self.max_media_queue_frames > 16 {
            return Err(TransportError::InvalidConfig(
                "max_media_queue_frames must be within 1..=16",
            ));
        }
        if self.max_media_queue_bytes < 64 * 1024 || self.max_media_queue_bytes > 32 * 1024 * 1024 {
            return Err(TransportError::InvalidConfig(
                "max_media_queue_bytes must be within 64 KiB..=32 MiB",
            ));
        }
        if self.max_control_queue == 0 || self.max_feedback_queue == 0 || self.max_input_queue == 0
        {
            return Err(TransportError::InvalidConfig(
                "control/feedback/input queue capacities must be non-zero",
            ));
        }
        if self.max_concurrent_connections == 0
            || self.max_concurrent_connections > MAX_TRACKED_CONNECTIONS_CEILING
        {
            return Err(TransportError::InvalidConfig(
                "max_concurrent_connections must be within 1..=256",
            ));
        }
        if self.max_packet_bytes < 1200 || self.max_packet_bytes > CHANNEL_0_MAX_PAYLOAD {
            return Err(TransportError::InvalidConfig(
                "max_packet_bytes must be within 1200..=65536",
            ));
        }
        if self.max_frame_bytes < 4096 || self.max_frame_bytes > MAX_FRAME_BYTES {
            return Err(TransportError::InvalidConfig(
                "max_frame_bytes must be within 4096..=8 MiB",
            ));
        }
        if self.min_bitrate_bps == 0
            || self.initial_bitrate_bps < self.min_bitrate_bps
            || self.max_bitrate_bps < self.initial_bitrate_bps
        {
            return Err(TransportError::InvalidConfig(
                "bitrate bounds must satisfy 0 < min <= initial <= max",
            ));
        }
        if self.pacing_target_bps == Some(0) {
            return Err(TransportError::InvalidConfig(
                "pacing_target_bps must be non-zero when set",
            ));
        }
        self.framing_limits.validate()?;
        self.cbor_limits.validate()?;
        self.reassembly_config.validate()?;
        self.recovery_config.validate()?;
        Ok(())
    }
}
