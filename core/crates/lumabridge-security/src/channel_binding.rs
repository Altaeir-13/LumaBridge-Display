// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! RFC 9266 `tls-exporter` channel bindings for TLS 1.3 (RFC 9846).

use crate::error::SecurityError;
use core::fmt;
use rustls::{ConnectionCommon, HandshakeKind, ProtocolVersion};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Exact RFC 9266 exporter label for `tls-exporter` channel bindings.
pub const TLS_EXPORTER_CHANNEL_BINDING_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// Exact byte length (32 bytes) exported by `tls-exporter` in `LumaBridge`.
pub const CHANNEL_BINDING_LEN: usize = 32;

/// Provenance of a [`ChannelBinding`], separating real TLS 1.3 exporters from test fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelBindingSource {
    /// Derived strictly from a completed non-resumed TLS 1.3 `EXPORTER-Channel-Binding`.
    Tls13Exporter,
    /// Synthetic test/fuzz fixture available only in unit tests or `test-utils` builds.
    #[cfg(any(test, feature = "test-utils"))]
    SyntheticTest,
}

/// 32-byte RFC 9266 `tls-exporter` channel binding tied to one active TLS 1.3 session.
///
/// Zeroized on drop and completely redacted in `Debug` output (zero prefix bytes leaked).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChannelBinding {
    bytes: [u8; CHANNEL_BINDING_LEN],
    #[zeroize(skip)]
    source: ChannelBindingSource,
}

impl ChannelBinding {
    /// Construct exclusively from a real TLS 1.3 RFC 9266 exporter inside this crate.
    #[must_use]
    pub(crate) const fn from_tls13_exporter(bytes: [u8; CHANNEL_BINDING_LEN]) -> Self {
        Self {
            bytes,
            source: ChannelBindingSource::Tls13Exporter,
        }
    }

    /// Construct a synthetic channel binding strictly for unit tests and fuzz targets.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub const fn synthetic_for_testing(bytes: [u8; CHANNEL_BINDING_LEN]) -> Self {
        Self {
            bytes,
            source: ChannelBindingSource::SyntheticTest,
        }
    }

    /// Provenance of this channel binding value.
    #[must_use]
    pub const fn source(&self) -> ChannelBindingSource {
        self.source
    }

    /// Borrow the 32-byte exporter digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CHANNEL_BINDING_LEN] {
        &self.bytes
    }
}

impl PartialEq for ChannelBinding {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.bytes.ct_eq(&other.bytes)) && self.source == other.source
    }
}

impl Eq for ChannelBinding {}

impl fmt::Debug for ChannelBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelBinding([REDACTED])")
    }
}

/// Extract RFC 9266 `tls-exporter` channel binding from a completed, non-resumed TLS 1.3 connection.
///
/// Rejects incomplete handshakes, resumed TLS sessions, and any protocol version other than TLS 1.3.
pub fn extract_tls13_channel_binding<D>(
    conn: &ConnectionCommon<D>,
) -> Result<ChannelBinding, SecurityError> {
    if conn.is_handshaking() {
        return Err(SecurityError::ChannelBindingMismatch);
    }
    if conn.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err(SecurityError::ChannelBindingMismatch);
    }
    if !matches!(
        conn.handshake_kind(),
        Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)
    ) {
        return Err(SecurityError::TlsHandshakeFailed(
            "TLS session must complete a full non-resumed handshake",
        ));
    }
    let out = conn
        .export_keying_material(
            [0u8; CHANNEL_BINDING_LEN],
            TLS_EXPORTER_CHANNEL_BINDING_LABEL,
            None,
        )
        .map_err(|_| SecurityError::ChannelBindingMismatch)?;
    Ok(ChannelBinding::from_tls13_exporter(out))
}
