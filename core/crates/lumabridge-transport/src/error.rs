// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sanitized error types for `lumabridge-transport` (zero secret/key/pixel leakage).

use core::fmt;
use lumabridge_protocol::error::{
    CborError, ErrorCode, FragmentationError, FrameError, LimitConfigError, ValidationError,
};
use lumabridge_security::error::SecurityError;

/// Typed, privacy-sanitized errors returned by `lumabridge-transport`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    InvalidConfig(&'static str),
    LimitConfig(LimitConfigError),
    Security(SecurityError),
    ProtocolFrame(FrameError),
    ProtocolCbor(CborError),
    ProtocolValidation(ValidationError),
    Fragmentation(FragmentationError),
    RemoteErrorNotice { code: ErrorCode, fatal: bool },
    HandshakeFailed(&'static str),
    Timeout(&'static str),
    ConnectionClosed(&'static str),
    QueueFull(&'static str),
    Revoked,
    LimitExceeded(&'static str),
    Discovery(&'static str),
    Io(&'static str),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid transport config: {msg}"),
            Self::LimitConfig(err) => write!(f, "invalid protocol limit config: {err}"),
            Self::Security(err) => write!(f, "security error: {err}"),
            Self::ProtocolFrame(err) => write!(f, "stream framing error: {err}"),
            Self::ProtocolCbor(err) => write!(f, "CBOR codec error: {err}"),
            Self::ProtocolValidation(err) => write!(f, "protocol context error: {}", err.reason),
            Self::Fragmentation(err) => write!(f, "media fragmentation error: {err}"),
            Self::RemoteErrorNotice { code, fatal } => {
                write!(f, "remote peer error notice: {code:?} (fatal={fatal})")
            }
            Self::HandshakeFailed(msg) => write!(f, "transport handshake failed: {msg}"),
            Self::Timeout(msg) => write!(f, "transport timeout: {msg}"),
            Self::ConnectionClosed(msg) => write!(f, "connection closed: {msg}"),
            Self::QueueFull(msg) => write!(f, "bounded queue full: {msg}"),
            Self::Revoked => f.write_str("peer trust revoked; connection terminated"),
            Self::LimitExceeded(msg) => write!(f, "transport resource limit exceeded: {msg}"),
            Self::Discovery(msg) => write!(f, "LAN discovery error: {msg}"),
            Self::Io(msg) => write!(f, "transport I/O failure: {msg}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<LimitConfigError> for TransportError {
    fn from(value: LimitConfigError) -> Self {
        Self::LimitConfig(value)
    }
}

impl From<SecurityError> for TransportError {
    fn from(value: SecurityError) -> Self {
        match value {
            SecurityError::RevokedDevice => Self::Revoked,
            other => Self::Security(other),
        }
    }
}

impl From<FrameError> for TransportError {
    fn from(value: FrameError) -> Self {
        Self::ProtocolFrame(value)
    }
}

impl From<CborError> for TransportError {
    fn from(value: CborError) -> Self {
        Self::ProtocolCbor(value)
    }
}

impl From<ValidationError> for TransportError {
    fn from(value: ValidationError) -> Self {
        Self::ProtocolValidation(value)
    }
}

impl From<FragmentationError> for TransportError {
    fn from(value: FragmentationError) -> Self {
        Self::Fragmentation(value)
    }
}

/// Convert `std::io::Error` into a fixed static category without leaking local host strings.
#[must_use]
pub fn map_io_error(err: &std::io::Error) -> TransportError {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::TimedOut => TransportError::Timeout("socket I/O timed out"),
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::UnexpectedEof
        | ErrorKind::BrokenPipe => TransportError::ConnectionClosed("socket reset or EOF"),
        ErrorKind::ConnectionRefused => TransportError::ConnectionClosed("connection refused"),
        ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable => {
            TransportError::Io("socket address unavailable")
        }
        ErrorKind::WouldBlock => TransportError::Io("socket would block"),
        _ => TransportError::Io("socket I/O error"),
    }
}
