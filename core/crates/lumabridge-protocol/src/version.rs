// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! LBWP protocol versioning, ALPN identifiers, and explicit version negotiation.

use crate::error::ErrorCode;

/// Current LBWP wire protocol major version.
pub const LBWP_PROTOCOL_MAJOR: u16 = 1;

/// Current LBWP wire protocol minor version.
pub const LBWP_PROTOCOL_MINOR: u16 = 0;

/// Pairing ALPN identifier (`ADR-0005`): strictly accepts `Pair*` and `ErrorNotice`.
pub const ALPN_PAIRING_V1: &str = "lumabridge-pair/1";

/// Operational mTLS ALPN identifier (`ADR-0005`).
pub const ALPN_OPERATIONAL_V1: &str = "lumabridge/1";

/// Protocol version pair negotiated at connection establishment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    /// Current protocol version implemented by this crate (`1.0`).
    pub const CURRENT: Self = Self {
        major: LBWP_PROTOCOL_MAJOR,
        minor: LBWP_PROTOCOL_MINOR,
    };

    /// Construct an explicit protocol version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

/// Application-Layer Protocol Negotiation (ALPN) trust surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alpn {
    /// `"lumabridge-pair/1"` — pairing window only.
    Pairing,
    /// `"lumabridge/1"` — operational session over mutually authenticated mTLS.
    Operational,
}

impl Alpn {
    /// Wire ALPN string token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pairing => ALPN_PAIRING_V1,
            Self::Operational => ALPN_OPERATIONAL_V1,
        }
    }

    /// Parse an ALPN identifier strictly.
    #[must_use]
    pub fn from_alpn_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes == ALPN_PAIRING_V1.as_bytes() {
            Some(Self::Pairing)
        } else if bytes == ALPN_OPERATIONAL_V1.as_bytes() {
            Some(Self::Operational)
        } else {
            None
        }
    }
}

/// Supported video codecs negotiated in `LBWP v1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CodecId {
    H264 = 1,
    Hevc = 2,
    Av1 = 3,
}

impl CodecId {
    /// Parse a wire codec identifier strictly.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::H264),
            2 => Some(Self::Hevc),
            3 => Some(Self::Av1),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Negotiate the effective LBWP version between `local` and `remote`.
///
/// Major versions MUST match (`!=` fails with [`ErrorCode::UnsupportedVersion`]);
/// minor versions negotiate to `min(local.minor, remote.minor)`.
pub const fn negotiate_version(
    local: ProtocolVersion,
    remote: ProtocolVersion,
) -> Result<ProtocolVersion, ErrorCode> {
    if local.major != remote.major || remote.major == 0 {
        return Err(ErrorCode::UnsupportedVersion);
    }
    let effective_minor = if local.minor < remote.minor {
        local.minor
    } else {
        remote.minor
    };
    Ok(ProtocolVersion {
        major: local.major,
        minor: effective_minor,
    })
}
