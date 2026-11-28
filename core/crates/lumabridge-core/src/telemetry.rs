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

/// Explicit methodology classification distinguishing measured, estimated, synthetic,
/// and unavailable telemetry values (`M2` telemetry audit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MeasurementOrigin {
    #[default]
    Unavailable,
    Measured,
    Estimated,
    Synthetic,
}

impl MeasurementOrigin {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Measured => "measured",
            Self::Estimated => "estimated",
            Self::Synthetic => "synthetic",
        }
    }
}

/// Exact quantile breakdown (`p50`, `p95`, `p99`) in microseconds for one telemetry stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StagePercentiles {
    pub origin: MeasurementOrigin,
    pub samples: usize,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
}

#[derive(Debug, Default)]
struct BoundedSamples {
    origin: MeasurementOrigin,
    values: VecDeque<u64>,
}

impl BoundedSamples {
    fn push_with_origin(&mut self, value_us: u64, origin: MeasurementOrigin) {
        if self.values.len() >= MAX_LATENCY_RESERVOIR_SAMPLES {
            self.values.pop_front();
        }
        self.origin = origin;
        self.values.push_back(value_us);
    }

    fn percentiles(&self) -> StagePercentiles {
        if self.values.is_empty() {
            return StagePercentiles {
                origin: MeasurementOrigin::Unavailable,
                samples: 0,
                p50_us: 0,
                p95_us: 0,
                p99_us: 0,
            };
        }
        let mut sorted: Vec<u64> = self.values.iter().copied().collect();
        sorted.sort_unstable();
        let n = sorted.len();
        let idx =
            |num: usize, den: usize| -> usize { ((n.saturating_sub(1)).saturating_mul(num)) / den };
        StagePercentiles {
            origin: self.origin,
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
    pub clock_sync_valid_samples: u64,
    pub clock_sync_origin: MeasurementOrigin,
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
                "  \"clock_sync_samples\": {},\n",
                "  \"clock_sync_origin\": \"{}\",\n",
                "  \"timestamp_measurement_errors\": {},\n",
                "  \"stages_us\": {{\n",
                "    \"capture\": {{ \"origin\": \"{}\", \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }},\n",
                "    \"encode\": {{ \"origin\": \"{}\", \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }},\n",
                "    \"network\": {{ \"origin\": \"{}\", \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }},\n",
                "    \"decode\": {{ \"origin\": \"{}\", \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }},\n",
                "    \"present\": {{ \"origin\": \"{}\", \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }},\n",
                "    \"end_to_end\": {{ \"origin\": \"{}\", \"samples\": {}, \"p50\": {}, \"p95\": {}, \"p99\": {} }}\n",
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
            self.clock_sync_valid_samples,
            self.clock_sync_origin.as_str(),
            self.timestamp_measurement_errors,
            self.capture.origin.as_str(),
            self.capture.samples,
            self.capture.p50_us,
            self.capture.p95_us,
            self.capture.p99_us,
            self.encode.origin.as_str(),
            self.encode.samples,
            self.encode.p50_us,
            self.encode.p95_us,
            self.encode.p99_us,
            self.network.origin.as_str(),
            self.network.samples,
            self.network.p50_us,
            self.network.p95_us,
            self.network.p99_us,
            self.decode.origin.as_str(),
            self.decode.samples,
            self.decode.p50_us,
            self.decode.p95_us,
            self.decode.p99_us,
            self.present.origin.as_str(),
            self.present.samples,
            self.present.p50_us,
            self.present.p95_us,
            self.present.p99_us,
            self.end_to_end.origin.as_str(),
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
    pub clock_sync_valid_samples: u64,
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
            clock_sync_valid_samples: 0,
            timestamp_measurement_errors: 0,
        }
    }

    /// Record real measured stage latencies across the full pipeline.
    pub fn record_stage_latencies(
        &mut self,
        capture_us: u64,
        encode_us: u64,
        network_us: u64,
        decode_us: u64,
        present_us: u64,
    ) {
        self.record_stage_latencies_with_origin(
            capture_us,
            encode_us,
            network_us,
            decode_us,
            present_us,
            MeasurementOrigin::Measured,
        );
    }

    /// Record synthetic stage latencies (e.g. FFmpeg/test fixtures) with explicit `Synthetic` provenance.
    pub fn record_synthetic_stage_latencies(
        &mut self,
        capture_us: u64,
        encode_us: u64,
        network_us: u64,
        decode_us: u64,
        present_us: u64,
    ) {
        self.record_stage_latencies_with_origin(
            capture_us,
            encode_us,
            network_us,
            decode_us,
            present_us,
            MeasurementOrigin::Synthetic,
        );
    }

    fn record_stage_latencies_with_origin(
        &mut self,
        capture_us: u64,
        encode_us: u64,
        network_us: u64,
        decode_us: u64,
        present_us: u64,
        origin: MeasurementOrigin,
    ) {
        self.capture.push_with_origin(capture_us, origin);
        self.encode.push_with_origin(encode_us, origin);
        self.network.push_with_origin(network_us, origin);
        self.decode.push_with_origin(decode_us, origin);
        self.present.push_with_origin(present_us, origin);
        let e2e = capture_us
            .saturating_add(encode_us)
            .saturating_add(network_us)
            .saturating_add(decode_us)
            .saturating_add(present_us);
        self.end_to_end.push_with_origin(e2e, origin);
    }

    /// Record receiver-observed upstream latencies without fabricating `capture` or uncalibrated `network`.
    pub fn record_rx_transport_latencies(
        &mut self,
        encode_us: u64,
        encode_origin: MeasurementOrigin,
        network_us: Option<u64>,
        clock_sync_valid_samples: u64,
    ) {
        self.clock_sync_valid_samples = self.clock_sync_valid_samples.max(clock_sync_valid_samples);
        self.encode.push_with_origin(encode_us, encode_origin);
        if let Some(net_us) = network_us {
            self.network
                .push_with_origin(net_us, MeasurementOrigin::Estimated);
            self.end_to_end.push_with_origin(
                encode_us.saturating_add(net_us),
                MeasurementOrigin::Estimated,
            );
        }
    }

    /// Record receiver-measured hardware decode and optional swapchain present durations without
    /// inserting synthetic placeholder values when presentation timing is unavailable (e.g. headless).
    pub fn record_rx_decode_present(&mut self, decode_us: u64, present_us: Option<u64>) {
        self.decode
            .push_with_origin(decode_us, MeasurementOrigin::Measured);
        if let Some(pres_us) = present_us {
            self.present
                .push_with_origin(pres_us, MeasurementOrigin::Measured);
        }
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
            clock_sync_valid_samples: self.clock_sync_valid_samples,
            clock_sync_origin: if self.clock_sync_valid_samples > 0 {
                MeasurementOrigin::Measured
            } else {
                MeasurementOrigin::Unavailable
            },
            timestamp_measurement_errors: self.timestamp_measurement_errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_tracks_all_four_measurement_origins_without_fabrication() {
        let mut rx_uncal = LatencyPercentileTracker::new("quic-datagram");
        rx_uncal.record_rx_transport_latencies(1_200, MeasurementOrigin::Measured, None, 0);
        rx_uncal.record_rx_decode_present(850, None);
        let s1 = rx_uncal.summary();
        assert_eq!(s1.capture.origin, MeasurementOrigin::Unavailable);
        assert_eq!(s1.capture.samples, 0);
        assert_eq!(s1.encode.origin, MeasurementOrigin::Measured);
        assert_eq!(s1.encode.samples, 1);
        assert_eq!(s1.network.origin, MeasurementOrigin::Unavailable);
        assert_eq!(s1.network.samples, 0);
        assert_eq!(s1.decode.origin, MeasurementOrigin::Measured);
        assert_eq!(s1.present.origin, MeasurementOrigin::Unavailable);
        assert_eq!(s1.present.samples, 0);
        assert_eq!(s1.end_to_end.origin, MeasurementOrigin::Unavailable);
        assert_eq!(s1.clock_sync_origin, MeasurementOrigin::Unavailable);

        let mut rx_cal = LatencyPercentileTracker::new("tcp-tls");
        rx_cal.record_rx_transport_latencies(900, MeasurementOrigin::Synthetic, Some(1_500), 2);
        rx_cal.record_rx_decode_present(700, Some(300));
        let s2 = rx_cal.summary();
        assert_eq!(s2.encode.origin, MeasurementOrigin::Synthetic);
        assert_eq!(s2.network.origin, MeasurementOrigin::Estimated);
        assert_eq!(s2.end_to_end.origin, MeasurementOrigin::Estimated);
        assert_eq!(s2.decode.origin, MeasurementOrigin::Measured);
        assert_eq!(s2.present.origin, MeasurementOrigin::Measured);
        assert_eq!(s2.clock_sync_origin, MeasurementOrigin::Measured);
        let json = s2.to_sanitized_json();
        assert!(json.contains("\"clock_sync_samples\": 2"), "{json}");
        assert!(
            json.contains("\"clock_sync_origin\": \"measured\""),
            "{json}"
        );
        assert!(json.contains("\"origin\": \"synthetic\""), "{json}");
        assert!(json.contains("\"origin\": \"estimated\""), "{json}");
        assert!(json.contains("\"origin\": \"unavailable\""), "{json}");
        assert!(json.contains("\"origin\": \"measured\""), "{json}");
    }
}
