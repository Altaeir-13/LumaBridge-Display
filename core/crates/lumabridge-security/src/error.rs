// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sanitized, typed security errors without secret or key leakage.

use core::fmt;
use lumabridge_protocol::error::ErrorCode;

/// Typed errors returned by `lumabridge-security`.
///
/// `Display` and `Debug` representations are intentionally sanitized so PINs,
/// private keys, pairing secrets, raw session tokens, channel bindings, and QR tokens
/// are never formatted into logs or diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    /// OS cryptographic randomness failed or returned an error.
    RngUnavailable,
    /// Provided cryptographic key material or lengths were invalid.
    InvalidKeyMaterial(&'static str),
    /// Ed25519 SPKI DER envelope did not match canonical RFC 8410/9295 44-byte encoding.
    InvalidSpki(&'static str),
    /// Cryptographic signature was malformed or failed strict RFC 8032 verification.
    InvalidSignature,
    /// Self-signed X.509 certificate generation failed.
    CertificateGeneration(&'static str),
    /// Peer X.509 certificate failed structural, algorithm, or signature validation.
    CertificateValidation(&'static str),
    /// Peer X.509 certificate is not yet valid or has expired relative to current time.
    CertificateExpired,
    /// Device has been explicitly revoked in the trust store.
    RevokedDevice,
    /// Peer identity is not present in the trust store.
    UntrustedDevice,
    /// Peer certificate or wire message violated identity binding invariants.
    IdentityMismatch(&'static str),
    /// Peer attempted an operation reserved for the opposite protocol role.
    RoleConfusion,
    /// RFC 9266 TLS 1.3 channel binding was unavailable or differed between endpoints.
    ChannelBindingMismatch,
    /// TLS 1.3 configuration failed.
    TlsConfiguration(&'static str),
    /// TLS 1.3 mTLS handshake or peer authentication failed.
    TlsHandshakeFailed(&'static str),
    /// Negotiated ALPN did not match `lumabridge/1` or `lumabridge-pair/1`.
    AlpnMismatch,
    /// Invalid pairing state transition or mismatched pairing attempt context.
    PairingState(&'static str),
    /// Pairing window is closed or the active pairing PIN has expired.
    PairingWindowClosed,
    /// Active PIN exhausted its 3-attempt budget and was destroyed.
    PinAttemptsExhausted,
    /// Supplied pairing PIN was empty, malformed, or out of policy bounds.
    InvalidPinFormat(&'static str),
    /// SPAKE2 key exchange or key confirmation failed.
    Spake2Failed,
    /// QR pairing payload expired, failed domain signature, or was invalid.
    QrPairingInvalid(&'static str),
    /// One-time QR pairing token was already consumed or never issued.
    QrTokenReusedOrUnknown,
    /// Local user approval is required before committing pairing or elevated permissions.
    ApprovalRequired,
    /// Requested action, permission bit, or role transition is forbidden by policy.
    AuthorizationDenied(&'static str),
    /// Session or resume token was unknown, malformed, expired, or revoked.
    SessionTokenInvalid(&'static str),
    /// One-time resume token was already consumed.
    SessionTokenReused,
    /// Replay or monotonic sequence check failed.
    ReplayDetected,
    /// Pairing or authentication attempts exceeded rate-limiting thresholds.
    RateLimited { retry_after_ms: u64 },
    /// Bounded security state capacity was reached; fail closed.
    ResourceExhausted(&'static str),
    /// Input timestamp or validity window was invalid.
    InvalidTimestamp(&'static str),
    /// Underlying wire protocol rejected the frame or payload.
    ProtocolViolation(&'static str),
}

impl SecurityError {
    /// Map this security failure to the closest coarse LBWP `ErrorCode`.
    #[must_use]
    pub const fn to_wire_error_code(&self) -> ErrorCode {
        match self {
            Self::RevokedDevice
            | Self::UntrustedDevice
            | Self::IdentityMismatch(_)
            | Self::RoleConfusion
            | Self::CertificateValidation(_)
            | Self::CertificateExpired
            | Self::TlsHandshakeFailed(_)
            | Self::AlpnMismatch
            | Self::ChannelBindingMismatch
            | Self::InvalidSignature
            | Self::InvalidSpki(_) => ErrorCode::UnauthorizedPeer,
            Self::PairingState(_) | Self::PairingWindowClosed => ErrorCode::PairingClosed,
            Self::InvalidPinFormat(_)
            | Self::PinAttemptsExhausted
            | Self::Spake2Failed
            | Self::QrPairingInvalid(_)
            | Self::QrTokenReusedOrUnknown
            | Self::ApprovalRequired => ErrorCode::PairingFailed,
            Self::AuthorizationDenied(_) => ErrorCode::PermissionDenied,
            Self::SessionTokenInvalid(_) | Self::SessionTokenReused | Self::ReplayDetected => {
                ErrorCode::SessionNotFound
            }
            Self::RateLimited { .. } | Self::ResourceExhausted(_) => ErrorCode::RateLimited,
            Self::RngUnavailable
            | Self::InvalidKeyMaterial(_)
            | Self::CertificateGeneration(_)
            | Self::TlsConfiguration(_)
            | Self::InvalidTimestamp(_)
            | Self::ProtocolViolation(_) => ErrorCode::InvalidFraming,
        }
    }
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RngUnavailable => f.write_str("OS cryptographic randomness unavailable"),
            Self::InvalidKeyMaterial(msg) => write!(f, "invalid key material: {msg}"),
            Self::InvalidSpki(msg) => write!(f, "invalid Ed25519 SPKI envelope: {msg}"),
            Self::InvalidSignature => f.write_str("signature verification failed"),
            Self::CertificateGeneration(msg) => write!(f, "certificate generation failed: {msg}"),
            Self::CertificateValidation(msg) => write!(f, "certificate validation failed: {msg}"),
            Self::CertificateExpired => f.write_str("certificate expired or not yet valid"),
            Self::RevokedDevice => f.write_str("device trust has been revoked"),
            Self::UntrustedDevice => f.write_str("device is not trusted"),
            Self::IdentityMismatch(msg) => write!(f, "identity binding mismatch: {msg}"),
            Self::RoleConfusion => f.write_str("peer role does not match expected trust policy"),
            Self::ChannelBindingMismatch => {
                f.write_str("TLS 1.3 channel binding mismatch or unavailable")
            }
            Self::TlsConfiguration(msg) => write!(f, "TLS 1.3 configuration failed: {msg}"),
            Self::TlsHandshakeFailed(msg) => write!(f, "TLS 1.3 handshake failed: {msg}"),
            Self::AlpnMismatch => f.write_str("ALPN protocol mismatch"),
            Self::PairingState(msg) => write!(f, "invalid pairing state: {msg}"),
            Self::PairingWindowClosed => f.write_str("pairing window is closed or PIN expired"),
            Self::PinAttemptsExhausted => {
                f.write_str("pairing PIN invalidated after 3 failed attempts")
            }
            Self::InvalidPinFormat(msg) => write!(f, "invalid pairing PIN format: {msg}"),
            Self::Spake2Failed => f.write_str("SPAKE2 authentication or confirmation failed"),
            Self::QrPairingInvalid(msg) => write!(f, "QR pairing verification failed: {msg}"),
            Self::QrTokenReusedOrUnknown => {
                f.write_str("QR one-time pairing token unknown or already consumed")
            }
            Self::ApprovalRequired => f.write_str("explicit local human approval required"),
            Self::AuthorizationDenied(msg) => write!(f, "authorization denied: {msg}"),
            Self::SessionTokenInvalid(msg) => write!(f, "invalid or expired session token: {msg}"),
            Self::SessionTokenReused => f.write_str("resume token has already been consumed"),
            Self::ReplayDetected => f.write_str("replayed message or token rejected"),
            Self::RateLimited { retry_after_ms } => {
                write!(f, "rate limited; retry after {retry_after_ms} ms")
            }
            Self::ResourceExhausted(msg) => write!(f, "security state capacity reached: {msg}"),
            Self::InvalidTimestamp(msg) => write!(f, "invalid timestamp: {msg}"),
            Self::ProtocolViolation(msg) => write!(f, "wire protocol constraint violated: {msg}"),
        }
    }
}

impl std::error::Error for SecurityError {}
