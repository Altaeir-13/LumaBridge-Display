// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Privacy-sanitized clock synchronization (`ClockSyncPing`/`Pong`) and bounded sliding
//! latency percentiles (`p50`/`p95`/`p99`) with zero private pixels, keys, or input data.

use lumabridge_protocol::control::ClockSyncPong;
use std::collections::{BTreeMap, VecDeque};

/// Hard cap on tracked in-flight `ClockSyncPing` timestamps.
pub const MAX_PENDING_CLOCK_PINGS: usize = 64;

/// Bounded sliding reservoir size for exact `p50`/`p95`/`p99` stage percentile evaluation.
pub const MAX_LATENCY_RESERVOIR_SAMPLES: usize = 4096;

/// Clock synchronization measurement computed from `ClockSyncPing` (`t1`) / `ClockSyncPong` (`t2`, `t3`, `t4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockSyncSample {
    pub seq: u64,
    pub rtt_us: u64,
    pub clock_offset_us: i64,
}

/// Bounded NTP-style monotonic clock-sync estimator.
#[derive(Debug, Default)]
pub struct ClockSyncTracker {
    pending_t1_us: BTreeMap<u64, u64>,
    last_sample: Option<ClockSyncSample>,
    smoothed_offset_us: Option<i64>,
    valid_samples: u64,
    rejected_samples: u64,
}

impl ClockSyncTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an outgoing `ClockSyncPing` sequence and local monotonic timestamp (`t1_us`).
    pub fn record_ping(&mut self, seq: u64, t1_us: u64) {
        if self.pending_t1_us.len() >= MAX_PENDING_CLOCK_PINGS {
            if let Some((&oldest_seq, _)) = self.pending_t1_us.iter().next() {
                self.pending_t1_us.remove(&oldest_seq);
            }
        }
        self.pending_t1_us.insert(seq, t1_us);
    }

    /// Process a received `ClockSyncPong` at local monotonic receive time `t4_us`.
    pub fn process_pong(&mut self, pong: &ClockSyncPong, t4_us: u64) -> Option<ClockSyncSample> {
        let Some(recorded_t1) = self.pending_t1_us.remove(&pong.seq) else {
            self.rejected_samples = self.rejected_samples.saturating_add(1);
            return None;
        };
        if pong.t1_client_mono_us != recorded_t1
            || t4_us < recorded_t1
            || pong.t3_server_send_us < pong.t2_server_recv_us
        {
            self.rejected_samples = self.rejected_samples.saturating_add(1);
            return None;
        }
        let server_dwell = pong
            .t3_server_send_us
            .saturating_sub(pong.t2_server_recv_us);
        let rtt_us = t4_us
            .saturating_sub(recorded_t1)
            .saturating_sub(server_dwell);

        let d1 = i128::from(pong.t2_server_recv_us) - i128::from(recorded_t1);
        let d2 = i128::from(pong.t3_server_send_us) - i128::from(t4_us);
        let offset_i128 = i128::midpoint(d1, d2);
        let clock_offset_us = i64::try_from(offset_i128).unwrap_or(if offset_i128.is_negative() {
            i64::MIN
        } else {
            i64::MAX
        });

        let sample = ClockSyncSample {
            seq: pong.seq,
            rtt_us,
            clock_offset_us,
        };
        self.smoothed_offset_us = Some(match self.smoothed_offset_us {
            Some(prev) => {
                let next = i128::from(prev) + (i128::from(clock_offset_us) - i128::from(prev)) / 4;
                i64::try_from(next).unwrap_or(if next.is_negative() {
                    i64::MIN
                } else {
                    i64::MAX
                })
            }
            None => clock_offset_us,
        });
        self.last_sample = Some(sample);
        self.valid_samples = self.valid_samples.saturating_add(1);
        Some(sample)
    }

    #[must_use]
    pub const fn last_sample(&self) -> Option<ClockSyncSample> {
        self.last_sample
    }

    #[must_use]
    pub const fn smoothed_offset_us(&self) -> Option<i64> {
        self.smoothed_offset_us
    }

    #[must_use]
    pub const fn valid_samples(&self) -> u64 {
        self.valid_samples
    }

    #[must_use]
    pub const fn rejected_samples(&self) -> u64 {
        self.rejected_samples
    }
}

/// Exact quantile breakdown (`p50`, `p95`, `p99`) in microseconds for one telemetry stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StagePercentiles {
    pub samples: usize,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
}

#[derive(Debug)]
struct BoundedSamples {
    values: VecDeque<u64>,
}

impl Default for BoundedSamples {
    fn default() -> Self {
        Self {
            values: VecDeque::with_capacity(256),
        }
    }
}

impl BoundedSamples {
    fn push(&mut self, value_us: u64) {
        if self.values.len() >= MAX_LATENCY_RESERVOIR_SAMPLES {
            self.values.pop_front();
        }
        self.values.push_back(value_us);
    }

    fn percentiles(&self) -> StagePercentiles {
        if self.values.is_empty() {
            return StagePercentiles::default();
        }
        let mut sorted: Vec<u64> = self.values.iter().copied().collect();
        sorted.sort_unstable();
        let n = sorted.len();
        let idx =
            |num: usize, den: usize| -> usize { ((n.saturating_sub(1)).saturating_mul(num)) / den };
        StagePercentiles {
            samples: n,
            p50_us: sorted[idx(50, 100)],
            p95_us: sorted[idx(95, 100)],
            p99_us: sorted[idx(99, 100)],
        }
    }
}

/// Sanitized telemetry snapshot safe to print to logs or JSON reports (`M1.5`/`M2`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionTelemetrySummary {
    pub transport_mode: String,
    pub capture: StagePercentiles,
    pub encode: StagePercentiles,
    pub network: StagePercentiles,
    pub decode: StagePercentiles,
    pub present: StagePercentiles,
    pub end_to_end: StagePercentiles,
    pub frames_sent: u64,
    pub frames_delivered: u64,
    pub dropped_frames: u64,
    pub idr_requests: u64,
    pub protected_blanks: u64,
    pub unauthorized_input_drops: u64,
    pub clock_sync_rtt_us: u64,
    pub timestamp_measurement_errors: u64,
}

impl SessionTelemetrySummary {
    /// Serialize strictly non-sensitive metrics to deterministic JSON.
    #[must_use]
    pub fn to_sanitized_json(&self) -> String {
        let escaped_mode = self
            .transport_mode
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        format!(
            concat!(
                "{{\n",
                "  \"transport_mode\": \"{}\",\n",
                "  \"frames_sent\": {},\n",
                "  \"frames_delivered\": {},\n",
                "  \"dropped_frames\": {},\n",
                "  \"idr_requests\": {},\n",
                "  \"protected_blanks\": {},\n",
                "  \"unauthorized_input_drops\": {},\n",
                "  \"clock_sync_rtt_us\": {},\n",
                "  \"timestamp_measurement_errors\": {},\n",
                "  \"stages_us\": {{\n",
                "    \"capture\": {{ \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }},\n",
                "    \"encode\": {{ \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }},\n",
                "    \"network\": {{ \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }},\n",
                "    \"decode\": {{ \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }},\n",
                "    \"present\": {{ \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }},\n",
                "    \"end_to_end\": {{ \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }}\n",
                "  }}\n",
                "}}\n"
            ),
            escaped_mode,
            self.frames_sent,
            self.frames_delivered,
            self.dropped_frames,
            self.idr_requests,
            self.protected_blanks,
            self.unauthorized_input_drops,
            self.clock_sync_rtt_us,
            self.timestamp_measurement_errors,
            self.capture.samples,
            self.capture.p50_us,
            self.capture.p95_us,
            self.capture.p99_us,
            self.encode.samples,
            self.encode.p50_us,
            self.encode.p95_us,
            self.encode.p99_us,
            self.network.samples,
            self.network.p50_us,
            self.network.p95_us,
            self.network.p99_us,
            self.decode.samples,
            self.decode.p50_us,
            self.decode.p95_us,
            self.decode.p99_us,
            self.present.samples,
            self.present.p50_us,
            self.present.p95_us,
            self.present.p99_us,
            self.end_to_end.samples,
            self.end_to_end.p50_us,
            self.end_to_end.p95_us,
            self.end_to_end.p99_us,
        )
    }
}

/// Multi-stage latency & health tracker used across `LumaBridgeNode` operational sessions.
#[derive(Debug)]
pub struct LatencyPercentileTracker {
    transport_mode: String,
    capture: BoundedSamples,
    encode: BoundedSamples,
    network: BoundedSamples,
    decode: BoundedSamples,
    present: BoundedSamples,
    end_to_end: BoundedSamples,
    pub frames_sent: u64,
    pub frames_delivered: u64,
    pub dropped_frames: u64,
    pub idr_requests: u64,
    pub protected_blanks: u64,
    pub unauthorized_input_drops: u64,
    pub last_clock_sync_rtt_us: u64,
    pub timestamp_measurement_errors: u64,
}

impl LatencyPercentileTracker {
    #[must_use]
    pub fn new(transport_mode: impl Into<String>) -> Self {
        Self {
            transport_mode: transport_mode.into(),
            capture: BoundedSamples::default(),
            encode: BoundedSamples::default(),
            network: BoundedSamples::default(),
            decode: BoundedSamples::default(),
            present: BoundedSamples::default(),
            end_to_end: BoundedSamples::default(),
            frames_sent: 0,
            frames_delivered: 0,
            dropped_frames: 0,
            idr_requests: 0,
            protected_blanks: 0,
            unauthorized_input_drops: 0,
            last_clock_sync_rtt_us: 0,
            timestamp_measurement_errors: 0,
        }
    }

    pub fn record_stage_latencies(
        &mut self,
        capture_us: u64,
        encode_us: u64,
        network_us: u64,
        decode_us: u64,
        present_us: u64,
    ) {
        self.capture.push(capture_us);
        self.encode.push(encode_us);
        self.network.push(network_us);
        self.decode.push(decode_us);
        self.present.push(present_us);
        let e2e = capture_us
            .saturating_add(encode_us)
            .saturating_add(network_us)
            .saturating_add(decode_us)
            .saturating_add(present_us);
        self.end_to_end.push(e2e);
    }

    /// Record receiver-observed upstream latencies before external hardware decode/present
    /// timing is reported via [`Self::record_rx_decode_present`].
    pub fn record_rx_transport_latencies(&mut self, encode_us: u64, network_us: u64) {
        self.capture.push(0);
        self.encode.push(encode_us);
        self.network.push(network_us);
        self.end_to_end.push(encode_us.saturating_add(network_us));
    }

    /// Record receiver-measured hardware decode and swapchain present durations without
    /// inserting synthetic zero samples into `capture`/`encode`/`network`/`end_to_end`.
    pub fn record_rx_decode_present(&mut self, decode_us: u64, present_us: u64) {
        self.decode.push(decode_us);
        self.present.push(present_us);
    }

    #[must_use]
    pub fn summary(&self) -> SessionTelemetrySummary {
        SessionTelemetrySummary {
            transport_mode: self.transport_mode.clone(),
            capture: self.capture.percentiles(),
            encode: self.encode.percentiles(),
            network: self.network.percentiles(),
            decode: self.decode.percentiles(),
            present: self.present.percentiles(),
            end_to_end: self.end_to_end.percentiles(),
            frames_sent: self.frames_sent,
            frames_delivered: self.frames_delivered,
            dropped_frames: self.dropped_frames,
            idr_requests: self.idr_requests,
            protected_blanks: self.protected_blanks,
            unauthorized_input_drops: self.unauthorized_input_drops,
            clock_sync_rtt_us: self.last_clock_sync_rtt_us,
            timestamp_measurement_errors: self.timestamp_measurement_errors,
        }
    }
}
