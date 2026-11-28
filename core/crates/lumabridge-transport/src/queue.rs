// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bounded media TX scheduling, GOP dependency drop (`chain_broken`), and byte pacing (`ADR-0005`).

use crate::error::TransportError;
use lumabridge_protocol::media::fragmentation::{
    fragment_frame, FrameKind, FrameToFragment, PacketBudget,
};
use lumabridge_protocol::version::CodecId;
use std::collections::VecDeque;

/// Application video frame queued for paced transmission.
#[derive(Clone)]
pub struct OutboundVideoFrame {
    pub session_id: u64,
    pub display_id: u16,
    pub codec_id: CodecId,
    pub frame_id: u32,
    pub gop_id: u16,
    pub capture_ts_us: u64,
    pub encode_done_ts_us: u64,
    pub kind: FrameKind,
    pub has_codec_config: bool,
    pub mirror_source: bool,
    pub payload: Vec<u8>,
}

impl core::fmt::Debug for OutboundVideoFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutboundVideoFrame")
            .field("session_id", &self.session_id)
            .field("display_id", &self.display_id)
            .field("codec_id", &self.codec_id)
            .field("frame_id", &self.frame_id)
            .field("gop_id", &self.gop_id)
            .field("kind", &self.kind)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// Outcome of submitting a frame to [`MediaTxScheduler`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EnqueueOutcome {
    pub admitted: bool,
    pub dropped_stale_frames: usize,
    pub dropped_broken_gop_frames: usize,
    pub force_idr_required: bool,
}

/// Dispatched packetized unit returned by [`MediaTxScheduler::pop_ready`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedTxFrame {
    pub display_id: u16,
    pub frame_id: u32,
    pub gop_id: u16,
    pub is_protected_blank: bool,
    pub packets: Vec<Vec<u8>>,
    pub total_bytes: usize,
}

/// Bounded TX scheduler enforcing `ADR-0005` §1.4:
/// - Never lets stale P-frames pile up beyond `[max_frames, max_bytes]`.
/// - If any P-frame in an active GOP is dropped due to backpressure or remote `request_idr`,
///   sets `chain_broken = true`, suppresses dependent P-frames in that GOP, and signals
///   `force_idr_required` for the encoder.
/// - `ProtectedBlank` preempts queued media and routes via reliable signaling.
#[derive(Debug)]
pub struct MediaTxScheduler {
    max_frames: usize,
    max_bytes: usize,
    queue: VecDeque<OutboundVideoFrame>,
    queued_bytes: usize,
    active_gop_id: Option<u16>,
    chain_broken: bool,
    force_idr_pending: bool,
    total_dropped_stale: u64,
    total_dropped_broken_gop: u64,
}

impl MediaTxScheduler {
    /// Construct a bounded TX scheduler with strict frame and byte ceilings.
    pub fn new(max_frames: usize, max_bytes: usize) -> Result<Self, TransportError> {
        if max_frames == 0 || max_bytes == 0 {
            return Err(TransportError::InvalidConfig(
                "MediaTxScheduler capacities must be non-zero",
            ));
        }
        Ok(Self {
            max_frames,
            max_bytes,
            queue: VecDeque::with_capacity(max_frames),
            queued_bytes: 0,
            active_gop_id: None,
            chain_broken: false,
            force_idr_pending: false,
            total_dropped_stale: 0,
            total_dropped_broken_gop: 0,
        })
    }

    #[must_use]
    pub fn queued_frames(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    #[must_use]
    pub const fn is_chain_broken(&self) -> bool {
        self.chain_broken
    }

    #[must_use]
    pub const fn total_dropped_stale(&self) -> u64 {
        self.total_dropped_stale
    }

    #[must_use]
    pub const fn total_dropped_broken_gop(&self) -> u64 {
        self.total_dropped_broken_gop
    }

    /// Consume and reset the `force_idr_required` flag for encoder wiring.
    pub fn take_force_idr_request(&mut self) -> bool {
        let req = self.force_idr_pending;
        self.force_idr_pending = false;
        req
    }

    /// Mark the active GOP broken (e.g., on remote `MediaFeedback(request_idr = true)` or
    /// socket backpressure), purging queued P-frames of the broken chain.
    pub fn notify_chain_broken(&mut self, broken_gop_id: Option<u16>) -> usize {
        if let Some(broken) = broken_gop_id {
            if let Some(active) = self.active_gop_id {
                if active != broken && !self.chain_broken {
                    // Stale feedback from an older already-recovered GOP.
                    return 0;
                }
            }
        }
        self.chain_broken = true;
        self.force_idr_pending = true;
        let dropped = self.purge_interframes();
        self.total_dropped_broken_gop =
            self.total_dropped_broken_gop.saturating_add(dropped as u64);
        dropped
    }

    /// Admit an outbound frame under bounded capacity and `ADR-0005` §1.4 dependency rules.
    pub fn enqueue(&mut self, frame: OutboundVideoFrame) -> EnqueueOutcome {
        let mut outcome = EnqueueOutcome::default();

        match frame.kind {
            FrameKind::ProtectedBlank => {
                // Clear obsolete buffered media so blanking takes strict precedence.
                let purged = self.clear_all_queued();
                self.chain_broken = true;
                self.active_gop_id = Some(frame.gop_id);
                self.force_idr_pending = true;
                self.queued_bytes = self.queued_bytes.saturating_add(frame.payload.len());
                self.queue.push_back(frame);
                outcome.admitted = true;
                outcome.dropped_stale_frames = purged;
                self.total_dropped_stale = self.total_dropped_stale.saturating_add(purged as u64);
                return outcome;
            }
            FrameKind::Keyframe { chain_reset } => {
                // Evict stale non-blank frames, check capacity BEFORE resetting `chain_broken` or `active_gop_id`!
                let new_bytes = frame.payload.len();
                if new_bytes > self.max_bytes {
                    self.chain_broken = true;
                    self.force_idr_pending = true;
                    outcome.force_idr_required = true;
                    return outcome;
                }
                let mut purged = self.purge_non_blank_queued();
                while self.queue.len() >= self.max_frames
                    || self.queued_bytes.saturating_add(new_bytes) > self.max_bytes
                {
                    if self.pop_oldest_non_blank().is_none() {
                        self.chain_broken = true;
                        self.force_idr_pending = true;
                        outcome.force_idr_required = true;
                        outcome.dropped_stale_frames = purged;
                        self.total_dropped_stale =
                            self.total_dropped_stale.saturating_add(purged as u64);
                        return outcome;
                    }
                    purged += 1;
                }
                if chain_reset || self.active_gop_id != Some(frame.gop_id) {
                    self.chain_broken = false;
                    self.force_idr_pending = false;
                }
                self.active_gop_id = Some(frame.gop_id);
                outcome.dropped_stale_frames = purged;
                self.total_dropped_stale = self.total_dropped_stale.saturating_add(purged as u64);
                self.queued_bytes = self.queued_bytes.saturating_add(new_bytes);
                self.queue.push_back(frame);
                outcome.admitted = true;
                outcome.force_idr_required = self.force_idr_pending;
                return outcome;
            }
            FrameKind::InterFrame => {
                if self.chain_broken {
                    outcome.dropped_broken_gop_frames = 1;
                    outcome.force_idr_required = true;
                    self.total_dropped_broken_gop = self.total_dropped_broken_gop.saturating_add(1);
                    return outcome;
                }
                if let Some(active) = self.active_gop_id {
                    if frame.gop_id != active {
                        self.chain_broken = true;
                        self.force_idr_pending = true;
                        outcome.dropped_broken_gop_frames = 1;
                        outcome.force_idr_required = true;
                        self.total_dropped_broken_gop =
                            self.total_dropped_broken_gop.saturating_add(1);
                        return outcome;
                    }
                } else {
                    // Never transmit orphan P-frames before an initial IDR.
                    self.chain_broken = true;
                    self.force_idr_pending = true;
                    outcome.dropped_broken_gop_frames = 1;
                    outcome.force_idr_required = true;
                    self.total_dropped_broken_gop = self.total_dropped_broken_gop.saturating_add(1);
                    return outcome;
                }
            }
        }

        // Enforce byte and count bounds before pushing; never exceed ceiling.
        let new_bytes = frame.payload.len();
        if new_bytes > self.max_bytes {
            // Single oversized frame (cannot even fit queue alone): if InterFrame, break chain!
            if matches!(frame.kind, FrameKind::InterFrame) {
                self.chain_broken = true;
                self.force_idr_pending = true;
                outcome.dropped_broken_gop_frames = 1;
                outcome.force_idr_required = true;
                self.total_dropped_broken_gop = self.total_dropped_broken_gop.saturating_add(1);
            }
            return outcome;
        }

        if self.queue.len() >= self.max_frames
            || self.queued_bytes.saturating_add(new_bytes) > self.max_bytes
        {
            if matches!(frame.kind, FrameKind::InterFrame) {
                // Dropping a P-frame on congestion invalidates the GOP immediately.
                let purged = self.purge_interframes();
                self.chain_broken = true;
                self.force_idr_pending = true;
                outcome.dropped_stale_frames = outcome.dropped_stale_frames.saturating_add(purged);
                outcome.dropped_broken_gop_frames = 1;
                outcome.force_idr_required = true;
                self.total_dropped_stale = self.total_dropped_stale.saturating_add(purged as u64);
                self.total_dropped_broken_gop = self.total_dropped_broken_gop.saturating_add(1);
                return outcome;
            }
            // Keyframe: make room by evicting older non-blank items.
            while self.queue.len() >= self.max_frames
                || self.queued_bytes.saturating_add(new_bytes) > self.max_bytes
            {
                if self.pop_oldest_non_blank().is_none() {
                    return outcome;
                }
                outcome.dropped_stale_frames = outcome.dropped_stale_frames.saturating_add(1);
                self.total_dropped_stale = self.total_dropped_stale.saturating_add(1);
            }
        }

        self.queued_bytes = self.queued_bytes.saturating_add(new_bytes);
        self.queue.push_back(frame);
        outcome.admitted = true;
        outcome.force_idr_required = self.force_idr_pending;
        outcome
    }

    /// Pop the next ready frame and fragment it under `budget`.
    pub fn pop_ready(
        &mut self,
        budget: PacketBudget,
    ) -> Result<Option<PreparedTxFrame>, TransportError> {
        let Some(frame) = self.queue.pop_front() else {
            return Ok(None);
        };
        self.queued_bytes = self.queued_bytes.saturating_sub(frame.payload.len());

        let is_blank = frame.kind == FrameKind::ProtectedBlank;
        let packets = match fragment_frame(
            &FrameToFragment {
                session_id: frame.session_id,
                display_id: frame.display_id,
                codec_id: frame.codec_id,
                frame_id: frame.frame_id,
                gop_id: frame.gop_id,
                capture_ts_us: frame.capture_ts_us,
                encode_done_ts_us: frame.encode_done_ts_us,
                kind: frame.kind,
                has_codec_config: frame.has_codec_config,
                mirror_source: frame.mirror_source,
                payload: &frame.payload,
            },
            budget,
        ) {
            Ok(p) => p,
            Err(err) => {
                if !is_blank {
                    // Dropping any non-blank frame after dequeue breaks the active GOP chain.
                    self.chain_broken = true;
                    self.force_idr_pending = true;
                    self.total_dropped_broken_gop = self.total_dropped_broken_gop.saturating_add(1);
                }
                return Err(err.into());
            }
        };
        let total_bytes = packets.iter().map(Vec::len).sum();
        Ok(Some(PreparedTxFrame {
            display_id: frame.display_id,
            frame_id: frame.frame_id,
            gop_id: frame.gop_id,
            is_protected_blank: is_blank,
            packets,
            total_bytes,
        }))
    }

    fn clear_all_queued(&mut self) -> usize {
        let count = self.queue.len();
        self.queue.clear();
        self.queued_bytes = 0;
        count
    }

    fn purge_interframes(&mut self) -> usize {
        let mut dropped = 0usize;
        let mut kept = VecDeque::with_capacity(self.queue.len());
        let mut kept_bytes = 0usize;
        while let Some(item) = self.queue.pop_front() {
            if matches!(item.kind, FrameKind::InterFrame) {
                dropped += 1;
            } else {
                kept_bytes = kept_bytes.saturating_add(item.payload.len());
                kept.push_back(item);
            }
        }
        self.queue = kept;
        self.queued_bytes = kept_bytes;
        dropped
    }

    fn purge_non_blank_queued(&mut self) -> usize {
        let mut dropped = 0usize;
        let mut kept = VecDeque::with_capacity(self.queue.len());
        let mut kept_bytes = 0usize;
        while let Some(item) = self.queue.pop_front() {
            if item.kind == FrameKind::ProtectedBlank {
                kept_bytes = kept_bytes.saturating_add(item.payload.len());
                kept.push_back(item);
            } else {
                dropped += 1;
            }
        }
        self.queue = kept;
        self.queued_bytes = kept_bytes;
        dropped
    }

    fn pop_oldest_non_blank(&mut self) -> Option<OutboundVideoFrame> {
        let pos = self
            .queue
            .iter()
            .position(|f| f.kind != FrameKind::ProtectedBlank)?;
        let removed = self.queue.remove(pos)?;
        self.queued_bytes = self.queued_bytes.saturating_sub(removed.payload.len());
        Some(removed)
    }
}

/// Token-bucket pacer smoothing bursty intra/inter packets at a target byte rate.
#[derive(Debug, Clone)]
pub struct TokenBucketPacer {
    rate_bytes_per_sec: u64,
    burst_bytes: u64,
    tokens: f64,
    last_refill_us: Option<u64>,
}

impl TokenBucketPacer {
    /// Construct a pacer for `target_bps` with bounded `burst_bytes` (>= 4 KiB).
    #[must_use]
    pub fn new(target_bps: u64, burst_bytes: usize) -> Self {
        let rate_bytes_per_sec = (target_bps / 8).max(1_024);
        let cap = (burst_bytes as u64).max(4_096);
        Self {
            rate_bytes_per_sec,
            burst_bytes: cap,
            tokens: cap as f64,
            last_refill_us: None,
        }
    }

    pub fn set_target_bps(&mut self, target_bps: u64) {
        self.rate_bytes_per_sec = (target_bps / 8).max(1_024);
    }

    /// Consume `packet_bytes` tokens and return extra delay (`0` if sendable immediately).
    pub fn consume_or_delay(&mut self, packet_bytes: usize, now_us: u64) -> std::time::Duration {
        let cap = self.burst_bytes as f64;
        if let Some(prev) = self.last_refill_us {
            let elapsed_us = now_us.saturating_sub(prev);
            let refill = (elapsed_us as f64 / 1_000_000.0) * (self.rate_bytes_per_sec as f64);
            self.tokens = (self.tokens + refill).min(cap);
        }
        self.last_refill_us = Some(now_us);
        self.tokens -= packet_bytes as f64;
        if self.tokens >= 0.0 {
            return std::time::Duration::ZERO;
        }
        let deficit = -self.tokens;
        let secs = deficit / (self.rate_bytes_per_sec as f64);
        std::time::Duration::from_secs_f64(secs.clamp(0.0, 0.25))
    }
}
