// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Explicit 5-layer MTU and DPLPMTUD packet budgeting (`ADR-0005` §1.2, `LBWP` §7.2).

use crate::config::{TransportConfig, TransportKind};
use crate::error::TransportError;
use lumabridge_protocol::limits::VIDEO_HEADER_LEN;
use lumabridge_protocol::media::fragmentation::PacketBudget;
use std::time::Duration;

/// Conservative reserve for QUIC `DATAGRAM` frame header overhead (`type=0x30/0x31` + varint length).
pub const QUIC_DATAGRAM_FRAME_OVERHEAD_BYTES: usize = 8;

/// Conservative IPv4/UDP + QUIC short header overhead subtracted from raw path MTU when
/// converting IP path MTU to conservative UDP datagram guidance.
pub const IP_UDP_QUIC_OVERHEAD_BYTES: usize = 52;

/// Compute the effective LBWP packet budget separating IP MTU, QUIC `max_datagram_size`,
/// negotiated session ceiling, and stream-record fallback (`Channel 1`).
pub fn compute_packet_budget(
    kind: TransportKind,
    config: &TransportConfig,
    quic_max_datagram_size: Option<usize>,
    peer_negotiated_mtu: Option<u16>,
) -> Result<PacketBudget, TransportError> {
    let min_lbwp_budget = VIDEO_HEADER_LEN + 1;
    let effective_budget = match kind {
        TransportKind::QuicDatagram => {
            let negotiated_cap = peer_negotiated_mtu.map_or(usize::from(config.max_mtu), |m| {
                usize::from(m).min(usize::from(config.max_mtu))
            });
            if let Some(live_max) = quic_max_datagram_size {
                let effective = live_max
                    .min(negotiated_cap)
                    .saturating_sub(QUIC_DATAGRAM_FRAME_OVERHEAD_BYTES);
                if effective < min_lbwp_budget {
                    return Err(TransportError::InvalidConfig(
                        "peer QUIC max_datagram_size too small for LBWP video packet",
                    ));
                }
                effective
            } else {
                let conservative = usize::from(config.initial_mtu)
                    .min(negotiated_cap)
                    .saturating_sub(
                        IP_UDP_QUIC_OVERHEAD_BYTES + QUIC_DATAGRAM_FRAME_OVERHEAD_BYTES,
                    );
                if conservative < min_lbwp_budget {
                    return Err(TransportError::InvalidConfig(
                        "negotiated MTU too small for LBWP video packet",
                    ));
                }
                conservative
            }
        }
        TransportKind::QuicStream | TransportKind::TcpTls => {
            config.framing_limits.max_media_stream_bytes
        }
    };

    Ok(PacketBudget::new(
        effective_budget,
        config.max_packet_bytes,
    )?)
}

/// Build a `quinn::MtuDiscoveryConfig` respecting DPLPMTUD (`RFC 8899`) bounds in [`TransportConfig`].
#[must_use]
pub fn build_quic_mtu_discovery_config(
    config: &TransportConfig,
) -> Option<quinn::MtuDiscoveryConfig> {
    if !config.dplpmtud_enabled || config.max_mtu <= config.initial_mtu {
        return None;
    }
    let mut mtu_cfg = quinn::MtuDiscoveryConfig::default();
    mtu_cfg.upper_bound(config.max_mtu);
    mtu_cfg.interval(Duration::from_secs(10));
    Some(mtu_cfg)
}
