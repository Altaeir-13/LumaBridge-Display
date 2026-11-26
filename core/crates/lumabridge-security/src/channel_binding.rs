// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! RFC 9266 `tls-exporter` channel bindings for TLS 1.3 (RFC 9846).

use crate::error::SecurityError;
use core::fmt;
use rustls::{ConnectionCommon, ProtocolVersion};
use subtle::ConstantTimeEq;

/// Exact RFC 9266 exporter label for `tls-exporter` channel bindings.
pub const TLS_EXPORTER_CHANNEL_BINDING_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// Exact byte length (32 bytes) exported by `tls-exporter` in `LumaBridge`.
pub const CHANNEL_BINDING_LEN: usize = 32;

/// 32-byte RFC 9266 `tls-exporter` channel binding tied to one active TLS 1.3 session.
#[derive(Clone, Copy)]
pub struct ChannelBinding([u8; CHANNEL_BINDING_LEN]);

impl ChannelBinding {
    /// Construct from a 32-byte exporter output.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CHANNEL_BINDING_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the 32-byte exporter digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CHANNEL_BINDING_LEN] {
        &self.0
    }
}

impl PartialEq for ChannelBinding {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for ChannelBinding {}

impl fmt::Debug for ChannelBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChannelBinding({:02x}{:02x}{:02x}{:02x}..)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// Extract RFC 9266 `tls-exporter` channel binding from a completed TLS 1.3 connection.
///
/// Rejects incomplete handshakes and any TLS protocol version other than TLS 1.3.
pub fn extract_tls13_channel_binding<D>(
    conn: &ConnectionCommon<D>,
) -> Result<ChannelBinding, SecurityError> {
    if conn.is_handshaking() {
        return Err(SecurityError::ChannelBindingMismatch);
    }
    if conn.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err(SecurityError::ChannelBindingMismatch);
    }
    let out = conn
        .export_keying_material(
            [0u8; CHANNEL_BINDING_LEN],
            TLS_EXPORTER_CHANNEL_BINDING_LABEL,
            None,
        )
        .map_err(|_| SecurityError::ChannelBindingMismatch)?;
    Ok(ChannelBinding::from_bytes(out))
}
