// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Persistent runtime configuration (`key=value`) for M2+ host and receiver endpoints.

use crate::node::NodeError;
use core::fmt::Write as _;
use lumabridge_transport::config::TransportKind;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;

pub const MIN_CONFIG_WIDTH: u16 = 320;
pub const MAX_CONFIG_WIDTH: u16 = 7680;
pub const MIN_CONFIG_HEIGHT: u16 = 240;
pub const MAX_CONFIG_HEIGHT: u16 = 4320;
pub const MIN_CONFIG_FPS: u16 = 1;
pub const MAX_CONFIG_FPS: u16 = 240;
pub const MIN_CONFIG_BITRATE_BPS: u32 = 1_000_000;
pub const MAX_CONFIG_BITRATE_BPS: u32 = 100_000_000;

/// Operational role persisted in runtime configuration files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeRole {
    Host,
    Receiver,
}

impl RuntimeRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Receiver => "receiver",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, NodeError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "receiver" => Ok(Self::Receiver),
            _ => Err(NodeError::InvalidConfig(
                "config role must be 'host' or 'receiver'",
            )),
        }
    }
}

/// Persistent M2+ configuration shared across host and receiver endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct RuntimeSessionConfig {
    pub role: RuntimeRole,
    pub friendly_name: String,
    pub transport: TransportKind,
    pub bind_addr: SocketAddr,
    pub remote_pair_addr: Option<SocketAddr>,
    pub remote_op_addr: Option<SocketAddr>,
    pub peer_device_id_hex: Option<String>,
    pub width: u16,
    pub height: u16,
    pub fps: u16,
    pub bitrate_bps: u32,
    pub fullscreen: bool,
    pub overlay: bool,
    pub vsync: bool,
    pub allow_sw_decode_fallback: bool,
}

impl Default for RuntimeSessionConfig {
    fn default() -> Self {
        Self {
            role: RuntimeRole::Receiver,
            friendly_name: String::from("LumaBridge Endpoint"),
            transport: TransportKind::QuicDatagram,
            bind_addr: "0.0.0.0:0".parse().expect("valid loopback/any socket addr"),
            remote_pair_addr: None,
            remote_op_addr: None,
            peer_device_id_hex: None,
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_bps: 15_000_000,
            fullscreen: true,
            overlay: false,
            vsync: true,
            allow_sw_decode_fallback: false,
        }
    }
}

impl RuntimeSessionConfig {
    /// Validate invariants (non-empty 1..=48-byte UTF-8 name, valid dimensions, bitrate bounds,
    /// and 64-char hex device id when provided).
    pub fn validate(&self) -> Result<(), NodeError> {
        if self.friendly_name.is_empty()
            || self.friendly_name.len() > 48
            || self.friendly_name.contains('\n')
            || self.friendly_name.contains('\r')
        {
            return Err(NodeError::InvalidConfig(
                "friendly_name must be 1..=48 UTF-8 bytes without newlines",
            ));
        }
        if !(MIN_CONFIG_WIDTH..=MAX_CONFIG_WIDTH).contains(&self.width)
            || !(MIN_CONFIG_HEIGHT..=MAX_CONFIG_HEIGHT).contains(&self.height)
        {
            return Err(NodeError::InvalidConfig(
                "resolution outside supported bounds",
            ));
        }
        if !(MIN_CONFIG_FPS..=MAX_CONFIG_FPS).contains(&self.fps) {
            return Err(NodeError::InvalidConfig("fps outside 1..=240"));
        }
        if !(MIN_CONFIG_BITRATE_BPS..=MAX_CONFIG_BITRATE_BPS).contains(&self.bitrate_bps) {
            return Err(NodeError::InvalidConfig(
                "bitrate_bps outside 1_000_000..=100_000_000",
            ));
        }
        if let Some(ref hex) = self.peer_device_id_hex {
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(NodeError::InvalidConfig(
                    "peer_device_id_hex must be exactly 64 hex characters",
                ));
            }
        }
        Ok(())
    }

    /// Serialize to canonical deterministic `key=value` format (excluding secrets/PINs).
    pub fn to_key_value_string(&self) -> Result<String, NodeError> {
        self.validate()?;
        let transport_str = match self.transport {
            TransportKind::QuicDatagram => "quic-datagram",
            TransportKind::QuicStream => "quic-stream",
            TransportKind::TcpTls => "tcp-tls",
        };
        let mut out = String::new();
        let _ = writeln!(out, "role={}", self.role.as_str());
        let _ = writeln!(out, "friendly_name={}", self.friendly_name);
        let _ = writeln!(out, "transport={transport_str}");
        let _ = writeln!(out, "bind_addr={}", self.bind_addr);
        if let Some(addr) = self.remote_pair_addr {
            let _ = writeln!(out, "remote_pair_addr={addr}");
        }
        if let Some(addr) = self.remote_op_addr {
            let _ = writeln!(out, "remote_op_addr={addr}");
        }
        if let Some(ref hex) = self.peer_device_id_hex {
            let _ = writeln!(out, "peer_device_id_hex={hex}");
        }
        let _ = writeln!(out, "width={}", self.width);
        let _ = writeln!(out, "height={}", self.height);
        let _ = writeln!(out, "fps={}", self.fps);
        let _ = writeln!(out, "bitrate_bps={}", self.bitrate_bps);
        let _ = writeln!(out, "fullscreen={}", self.fullscreen);
        let _ = writeln!(out, "overlay={}", self.overlay);
        let _ = writeln!(out, "vsync={}", self.vsync);
        let _ = writeln!(
            out,
            "allow_sw_decode_fallback={}",
            self.allow_sw_decode_fallback
        );
        Ok(out)
    }

    /// Parse and validate from deterministic `key=value` text.
    pub fn parse_key_value_str(input: &str) -> Result<Self, NodeError> {
        let mut map = BTreeMap::<String, String>::new();
        for raw_line in input.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                return Err(NodeError::InvalidConfig(
                    "malformed config line without '='",
                ));
            };
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_owned();
            if map.insert(key, val).is_some() {
                return Err(NodeError::InvalidConfig("duplicate config key"));
            }
        }

        let mut cfg = Self::default();
        for (k, v) in map {
            match k.as_str() {
                "role" => cfg.role = RuntimeRole::parse(&v)?,
                "friendly_name" => cfg.friendly_name = v,
                "transport" => cfg.transport = parse_transport_kind(&v)?,
                "bind_addr" => {
                    cfg.bind_addr = v
                        .parse()
                        .map_err(|_| NodeError::InvalidConfig("invalid bind_addr SocketAddr"))?;
                }
                "remote_pair_addr" => {
                    cfg.remote_pair_addr = if v.is_empty() {
                        None
                    } else {
                        Some(v.parse().map_err(|_| {
                            NodeError::InvalidConfig("invalid remote_pair_addr SocketAddr")
                        })?)
                    };
                }
                "remote_op_addr" => {
                    cfg.remote_op_addr = if v.is_empty() {
                        None
                    } else {
                        Some(v.parse().map_err(|_| {
                            NodeError::InvalidConfig("invalid remote_op_addr SocketAddr")
                        })?)
                    };
                }
                "peer_device_id_hex" => {
                    cfg.peer_device_id_hex = if v.is_empty() { None } else { Some(v) };
                }
                "width" => {
                    cfg.width = v
                        .parse()
                        .map_err(|_| NodeError::InvalidConfig("invalid width u16"))?;
                }
                "height" => {
                    cfg.height = v
                        .parse()
                        .map_err(|_| NodeError::InvalidConfig("invalid height u16"))?;
                }
                "fps" => {
                    cfg.fps = v
                        .parse()
                        .map_err(|_| NodeError::InvalidConfig("invalid fps u16"))?;
                }
                "bitrate_bps" => {
                    cfg.bitrate_bps = v
                        .parse()
                        .map_err(|_| NodeError::InvalidConfig("invalid bitrate_bps u32"))?;
                }
                "fullscreen" => cfg.fullscreen = parse_bool(&v)?,
                "overlay" => cfg.overlay = parse_bool(&v)?,
                "vsync" => cfg.vsync = parse_bool(&v)?,
                "allow_sw_decode_fallback" => cfg.allow_sw_decode_fallback = parse_bool(&v)?,
                _ => {
                    return Err(NodeError::InvalidConfig("unknown config key"));
                }
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_file(path: &Path) -> Result<Self, NodeError> {
        let text = std::fs::read_to_string(path)
            .map_err(|_| NodeError::InvalidConfig("failed reading config file"))?;
        Self::parse_key_value_str(&text)
    }

    pub fn save_file(&self, path: &Path) -> Result<(), NodeError> {
        let serialized = self.to_key_value_string()?;
        let tmp = path.with_extension("cfg.tmp");
        std::fs::write(&tmp, serialized.as_bytes())
            .map_err(|_| NodeError::InvalidConfig("failed writing temp config file"))?;
        std::fs::rename(&tmp, path)
            .map_err(|_| NodeError::InvalidConfig("failed finalizing config file"))?;
        Ok(())
    }
}

fn parse_transport_kind(raw: &str) -> Result<TransportKind, NodeError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "quic-datagram" => Ok(TransportKind::QuicDatagram),
        "quic-stream" => Ok(TransportKind::QuicStream),
        "tcp-tls" => Ok(TransportKind::TcpTls),
        _ => Err(NodeError::InvalidConfig("unsupported transport value")),
    }
}

fn parse_bool(raw: &str) -> Result<bool, NodeError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(NodeError::InvalidConfig("invalid boolean config value")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrip_validation_and_persistence() {
        let cfg = RuntimeSessionConfig {
            role: RuntimeRole::Host,
            friendly_name: String::from("Win11 Host"),
            transport: TransportKind::QuicDatagram,
            bind_addr: "127.0.0.1:0".parse().expect("valid"),
            remote_pair_addr: Some("192.168.1.25:4242".parse().expect("valid")),
            remote_op_addr: Some("192.168.1.25:4243".parse().expect("valid")),
            peer_device_id_hex: Some("aa".repeat(32)),
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_bps: 18_000_000,
            fullscreen: true,
            overlay: true,
            vsync: false,
            allow_sw_decode_fallback: false,
        };
        let encoded = cfg.to_key_value_string().expect("serialize");
        let parsed = RuntimeSessionConfig::parse_key_value_str(&encoded).expect("parse");
        assert_eq!(parsed, cfg);

        let tmp = std::env::temp_dir().join("lb-runtime-cfg-test.conf");
        cfg.save_file(&tmp).expect("save");
        let loaded = RuntimeSessionConfig::load_file(&tmp).expect("load");
        assert_eq!(loaded, cfg);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn config_rejects_unknown_keys_duplicate_keys_and_bad_bounds() {
        assert!(RuntimeSessionConfig::parse_key_value_str("secret_pin=123456\n").is_err());
        assert!(RuntimeSessionConfig::parse_key_value_str("fps=60\nfps=120\n").is_err());
        assert!(RuntimeSessionConfig::parse_key_value_str("width=100\n").is_err());
        assert!(RuntimeSessionConfig::parse_key_value_str("bitrate_bps=100\n").is_err());
        assert!(RuntimeSessionConfig::parse_key_value_str("peer_device_id_hex=abcd\n").is_err());
    }
}
