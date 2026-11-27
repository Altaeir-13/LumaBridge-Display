// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Live transport congestion snapshots and AIMD adaptive bitrate controller (`ADR-0005` §1.3).

/// Live metrics snapshot exposed by active `LumaBridge` transport connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CongestionSnapshot {
    pub rtt_us: u64,
    pub packet_loss_ppm: u32,
    pub cwnd_bytes: u64,
    pub pacing_rate_bps: u64,
    pub effective_lbwp_packet_budget: usize,
    pub tx_queue_frames: usize,
    pub tx_queue_bytes: usize,
    pub dropped_stale_frames: u64,
    pub dropped_broken_gop_frames: u64,
    pub idr_requests_emitted: u64,
    pub protected_blanks_sent: u64,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub stream_media_records_sent: u64,
    pub stream_media_records_received: u64,
}

/// AIMD congestion-driven target bitrate controller (`min_bps..=max_bps`).
#[derive(Debug, Clone)]
pub struct BitrateAdvisor {
    min_bps: u64,
    max_bps: u64,
    current_bps: u64,
    last_adjust_us: u64,
    min_adjust_interval_us: u64,
    clean_intervals: u32,
}

impl BitrateAdvisor {
    /// Construct a bitrate advisor bounded by `[min_bps, max_bps]` starting at `initial_bps`.
    #[must_use]
    pub const fn new(min_bps: u64, initial_bps: u64, max_bps: u64) -> Self {
        let clamped_init = if initial_bps < min_bps {
            min_bps
        } else if initial_bps > max_bps {
            max_bps
        } else {
            initial_bps
        };
        Self {
            min_bps,
            max_bps,
            current_bps: clamped_init,
            last_adjust_us: 0,
            min_adjust_interval_us: 100_000,
            clean_intervals: 0,
        }
    }

    #[must_use]
    pub const fn current_bitrate_bps(&self) -> u64 {
        self.current_bps
    }

    /// Update recommended bitrate from transport telemetry (`packet_loss_ppm`, RTT, TX queue depth,
    /// and any encoder/backpressure drops). Returns `Some(new_bps)` when a significant change occurs.
    pub fn update(&mut self, snap: &CongestionSnapshot, now_us: u64) -> Option<u64> {
        if self.last_adjust_us != 0
            && now_us.saturating_sub(self.last_adjust_us) < self.min_adjust_interval_us
        {
            return None;
        }
        let prev = self.current_bps;
        let heavy_congestion =
            snap.packet_loss_ppm >= 20_000 || snap.tx_queue_frames >= 3 || snap.rtt_us >= 80_000;
        let mild_congestion =
            snap.packet_loss_ppm >= 2_500 || snap.tx_queue_frames >= 2 || snap.rtt_us >= 45_000;

        if heavy_congestion {
            self.clean_intervals = 0;
            // Multiplicative decrease (0.70x)
            self.current_bps = (self.current_bps.saturating_mul(70) / 100).max(self.min_bps);
        } else if mild_congestion {
            self.clean_intervals = 0;
            // Multiplicative decrease (0.85x)
            self.current_bps = (self.current_bps.saturating_mul(85) / 100).max(self.min_bps);
        } else {
            self.clean_intervals = self.clean_intervals.saturating_add(1);
            if self.clean_intervals >= 3 {
                // Additive increase (+5% capped at +1.5 Mbps/step)
                let step = (self.current_bps / 20).clamp(250_000, 1_500_000);
                self.current_bps = self.current_bps.saturating_add(step).min(self.max_bps);
            }
        }

        if self.current_bps == prev {
            None
        } else {
            self.last_adjust_us = now_us;
            Some(self.current_bps)
        }
    }
}
