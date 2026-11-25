// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pure, clock-driven GOP dependency and `AwaitingIdr` recovery state machine (`ADR-0005` §1.4).
//!
//! Operates strictly on frame sequence/GOP metadata (`frame_id`, `gop_id`, `VideoFlags`) without
//! invoking any codec decoder (`H.264`/`HEVC`/`AV1`) or sleeping internally.

use std::collections::BTreeMap;

use crate::error::LimitConfigError;
use crate::limits::RecoveryConfig;
use crate::media::header::VideoFlags;
use crate::media::reassembly::{
    DiscardedFrameNotice, ProtectedBlankEvent, ReassembledFrame, Reassembler, ReassemblyOutcome,
    ReassemblyReport,
};

/// Current operational state of the per-display GOP recovery state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    /// Waiting for the initial intact keyframe (`IDR`) before delivering any `P-frame`.
    InitialAwaitingIdr,
    /// Prediction chain intact; delivering frames in strictly increasing `frame_id` order.
    Healthy {
        active_gop_id: u16,
        last_delivered_frame_id: u32,
    },
    /// Active prediction chain broke; holding last displayed intact frame and dropping
    /// dependent `P-frames` until a fresh intact `IDR` arrives.
    AwaitingIdr {
        broken_gop_id: u16,
        last_good_frame_id: u32,
        last_idr_request_us: Option<u64>,
    },
    /// Source sent `FLAG_PROTECTED_BLANK`; receiver MUST hide previous content until a clean `IDR`.
    ProtectedBlanked { last_blank_frame_id: u32 },
}

/// Pure output actions produced by [`GopRecoveryStateMachine`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryActions {
    /// Intact frames ready for decoder submission in strictly ascending `frame_id` order.
    pub deliver_frames: Vec<ReassembledFrame>,
    /// Number of out-of-order/orphan `P-frames` dropped due to broken chain or blanking.
    pub dropped_dependent_frames: usize,
    /// Emit `MediaFeedback(request_idr = true)` respecting cooldown (`200 ms` default).
    pub request_idr: bool,
    /// Clear/hide any previously presented frame immediately (`FLAG_PROTECTED_BLANK`).
    pub hide_content_for_protected_blank: bool,
    /// `frame_id` reached `frame_id_renewal_threshold`; caller must rotate `session_id` rather
    /// than wrapping `u32`.
    pub session_renewal_required: bool,
}

impl RecoveryActions {
    fn merge(&mut self, mut other: Self) {
        self.deliver_frames.append(&mut other.deliver_frames);
        self.dropped_dependent_frames = self
            .dropped_dependent_frames
            .saturating_add(other.dropped_dependent_frames);
        self.request_idr |= other.request_idr;
        self.hide_content_for_protected_blank |= other.hide_content_for_protected_blank;
        self.session_renewal_required |= other.session_renewal_required;
    }
}

struct QueuedReorderFrame {
    queued_at_us: u64,
    frame: ReassembledFrame,
}

/// Pure per-display GOP dependency and recovery state machine driven by caller monotonic `now_us`.
pub struct GopRecoveryStateMachine {
    config: RecoveryConfig,
    state: RecoveryState,
    reorder_queue: BTreeMap<u32, QueuedReorderFrame>,
    highest_seen_frame_id: u32,
}

impl GopRecoveryStateMachine {
    /// Construct a new state machine starting in [`RecoveryState::InitialAwaitingIdr`].
    pub fn new(config: RecoveryConfig) -> Result<Self, LimitConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            state: RecoveryState::InitialAwaitingIdr,
            reorder_queue: BTreeMap::new(),
            highest_seen_frame_id: 0,
        })
    }

    #[must_use]
    pub const fn state(&self) -> RecoveryState {
        self.state
    }

    #[must_use]
    pub fn queued_reorder_len(&self) -> usize {
        self.reorder_queue.len()
    }

    /// Reset state machine back to `InitialAwaitingIdr`.
    pub fn reset(&mut self) {
        self.state = RecoveryState::InitialAwaitingIdr;
        self.reorder_queue.clear();
        self.highest_seen_frame_id = 0;
    }

    /// Process a [`ReassemblyReport`] returned by [`Reassembler::ingest_packet`] / `ingest_decoded`.
    pub fn on_reassembly_report(
        &mut self,
        report: ReassemblyReport,
        now_us: u64,
        reassembler: &Reassembler,
    ) -> RecoveryActions {
        let mut actions = RecoveryActions::default();

        for notice in report.discarded {
            actions.merge(self.on_frame_lost(notice.frame_id, notice.gop_id, now_us));
        }

        match report.outcome {
            ReassemblyOutcome::Completed(frame) => {
                let older_in_flight = reassembler.has_incomplete_older_frame(
                    frame.session_id,
                    frame.display_id,
                    frame.frame_id,
                );
                actions.merge(self.on_frame_completed(frame, now_us, older_in_flight));
            }
            ReassemblyOutcome::ProtectedBlank(ev) => {
                actions.merge(self.on_protected_blank(ev, now_us));
            }
            ReassemblyOutcome::Incomplete { .. }
            | ReassemblyOutcome::DuplicateIgnored { .. }
            | ReassemblyOutcome::StaleIgnored { .. }
            | ReassemblyOutcome::Rejected(_) => {}
        }

        actions
    }

    /// Process a newly reassembled video frame at caller clock `now_us`.
    pub fn on_frame_completed(
        &mut self,
        frame: ReassembledFrame,
        now_us: u64,
        older_in_flight: bool,
    ) -> RecoveryActions {
        let mut actions = RecoveryActions::default();
        if frame.frame_id >= self.config.frame_id_renewal_threshold {
            actions.session_renewal_required = true;
        }
        if frame.frame_id > self.highest_seen_frame_id {
            self.highest_seen_frame_id = frame.frame_id;
        }

        if frame.flags.contains(VideoFlags::KEYFRAME) {
            self.handle_completed_keyframe(frame, &mut actions);
        } else {
            self.handle_completed_interframe(frame, now_us, older_in_flight, &mut actions);
        }
        actions
    }

    fn handle_completed_keyframe(
        &mut self,
        frame: ReassembledFrame,
        actions: &mut RecoveryActions,
    ) {
        if let Some(last_delivered) = self.last_delivered_or_blank() {
            if frame.frame_id <= last_delivered {
                actions.dropped_dependent_frames += 1;
                return;
            }
        }
        let stale_count = self
            .reorder_queue
            .keys()
            .filter(|&&fid| fid < frame.frame_id)
            .count();
        self.reorder_queue.retain(|&fid, _| fid > frame.frame_id);
        actions.dropped_dependent_frames += stale_count;

        let fid = frame.frame_id;
        let gop = frame.gop_id;
        self.state = RecoveryState::Healthy {
            active_gop_id: gop,
            last_delivered_frame_id: fid,
        };
        actions.deliver_frames.push(frame);
        self.drain_contiguous_from_reorder(actions);
    }

    fn handle_completed_interframe(
        &mut self,
        frame: ReassembledFrame,
        now_us: u64,
        older_in_flight: bool,
        actions: &mut RecoveryActions,
    ) {
        match self.state {
            RecoveryState::InitialAwaitingIdr
            | RecoveryState::AwaitingIdr { .. }
            | RecoveryState::ProtectedBlanked { .. } => {
                actions.dropped_dependent_frames += 1;
                if matches!(self.state, RecoveryState::InitialAwaitingIdr) {
                    actions.request_idr = true;
                    self.state = RecoveryState::AwaitingIdr {
                        broken_gop_id: frame.gop_id,
                        last_good_frame_id: 0,
                        last_idr_request_us: Some(now_us),
                    };
                }
            }
            RecoveryState::Healthy {
                active_gop_id,
                last_delivered_frame_id,
            } => {
                if frame.frame_id <= last_delivered_frame_id {
                    actions.dropped_dependent_frames += 1;
                    return;
                }
                if frame.gop_id != active_gop_id {
                    let mut loss = self.transition_to_awaiting_idr(
                        active_gop_id,
                        last_delivered_frame_id,
                        now_us,
                        1,
                    );
                    actions.merge(loss.split_off_self());
                    return;
                }
                if frame.frame_id == last_delivered_frame_id.saturating_add(1) {
                    self.state = RecoveryState::Healthy {
                        active_gop_id,
                        last_delivered_frame_id: frame.frame_id,
                    };
                    actions.deliver_frames.push(frame);
                    self.drain_contiguous_from_reorder(actions);
                    return;
                }
                if self.config.max_reorder_completed_frames == 0 {
                    let mut loss = self.transition_to_awaiting_idr(
                        active_gop_id,
                        last_delivered_frame_id,
                        now_us,
                        1,
                    );
                    actions.merge(loss.split_off_self());
                    return;
                }
                let _ = self.reorder_queue.insert(
                    frame.frame_id,
                    QueuedReorderFrame {
                        queued_at_us: now_us,
                        frame,
                    },
                );
                if self.reorder_queue.len() > self.config.max_reorder_completed_frames
                    || (!older_in_flight
                        && self.reorder_queue.len() >= self.config.max_reorder_completed_frames)
                {
                    let mut lost_actions = self.transition_to_awaiting_idr(
                        active_gop_id,
                        last_delivered_frame_id,
                        now_us,
                        0,
                    );
                    actions.merge(lost_actions.split_off_self());
                }
            }
        }
    }

    /// Poll for missing `frame_id` gaps whose buffered successor frames waited past `reorder_gap_timeout_us`.
    pub fn poll_reorder_timeout(&mut self, now_us: u64) -> RecoveryActions {
        let RecoveryState::Healthy {
            active_gop_id,
            last_delivered_frame_id,
        } = self.state
        else {
            return RecoveryActions::default();
        };
        let Some(first) = self.reorder_queue.values().next() else {
            return RecoveryActions::default();
        };
        if now_us.saturating_sub(first.queued_at_us) >= self.config.reorder_gap_timeout_us {
            return self.transition_to_awaiting_idr(
                active_gop_id,
                last_delivered_frame_id,
                now_us,
                0,
            );
        }
        RecoveryActions::default()
    }

    /// Handle explicit frame loss/expiry/eviction notification from [`Reassembler`].
    pub fn on_frame_lost(
        &mut self,
        lost_frame_id: u32,
        lost_gop_id: u16,
        now_us: u64,
    ) -> RecoveryActions {
        let mut actions = RecoveryActions::default();
        if let Some(removed) = self.reorder_queue.remove(&lost_frame_id) {
            let _ = removed;
            actions.dropped_dependent_frames += 1;
        }

        match self.state {
            RecoveryState::Healthy {
                active_gop_id,
                last_delivered_frame_id,
            } => {
                // Only losses at/after the last delivered frame in the active GOP break the chain.
                if lost_frame_id > last_delivered_frame_id && lost_gop_id == active_gop_id {
                    let mut loss_actions = self.transition_to_awaiting_idr(
                        active_gop_id,
                        last_delivered_frame_id,
                        now_us,
                        0,
                    );
                    actions.merge(loss_actions.split_off_self());
                }
                actions
            }
            RecoveryState::AwaitingIdr {
                broken_gop_id,
                last_good_frame_id,
                last_idr_request_us,
            } => {
                if self.cooldown_elapsed(last_idr_request_us, now_us) {
                    actions.request_idr = true;
                    self.state = RecoveryState::AwaitingIdr {
                        broken_gop_id,
                        last_good_frame_id,
                        last_idr_request_us: Some(now_us),
                    };
                }
                actions
            }
            RecoveryState::InitialAwaitingIdr => {
                actions.request_idr = true;
                self.state = RecoveryState::AwaitingIdr {
                    broken_gop_id: lost_gop_id,
                    last_good_frame_id: 0,
                    last_idr_request_us: Some(now_us),
                };
                actions
            }
            RecoveryState::ProtectedBlanked { .. } => {
                // Protected blank state waits for a clean IDR without treating expired content as packet loss.
                actions
            }
        }
    }

    /// Process expired/discarded notices returned by [`Reassembler::expire`].
    pub fn on_discarded_notices(
        &mut self,
        notices: &[DiscardedFrameNotice],
        now_us: u64,
    ) -> RecoveryActions {
        let mut actions = RecoveryActions::default();
        for n in notices {
            actions.merge(self.on_frame_lost(n.frame_id, n.gop_id, now_us));
        }
        actions
    }

    /// Handle a semantic `FLAG_PROTECTED_BLANK` event.
    ///
    /// Immediately clears dependent queued frames and signals `hide_content_for_protected_blank`
    /// without treating the event as ordinary packet loss.
    pub fn on_protected_blank(
        &mut self,
        event: ProtectedBlankEvent,
        _now_us: u64,
    ) -> RecoveryActions {
        let mut actions = RecoveryActions::default();
        if event.frame_id >= self.config.frame_id_renewal_threshold {
            actions.session_renewal_required = true;
        }
        if event.frame_id > self.highest_seen_frame_id {
            self.highest_seen_frame_id = event.frame_id;
        }
        if let Some(last) = self.last_delivered_or_blank() {
            if event.frame_id <= last {
                return actions;
            }
        }
        actions.dropped_dependent_frames = self.reorder_queue.len();
        self.reorder_queue.clear();
        self.state = RecoveryState::ProtectedBlanked {
            last_blank_frame_id: event.frame_id,
        };
        actions.hide_content_for_protected_blank = true;
        actions
    }

    fn drain_contiguous_from_reorder(&mut self, actions: &mut RecoveryActions) {
        while let RecoveryState::Healthy {
            active_gop_id,
            last_delivered_frame_id,
        } = self.state
        {
            let next_expected = last_delivered_frame_id.saturating_add(1);
            let Some(next_item) = self.reorder_queue.remove(&next_expected) else {
                break;
            };
            let f = next_item.frame;
            if f.gop_id != active_gop_id {
                actions.dropped_dependent_frames += 1;
                break;
            }
            self.state = RecoveryState::Healthy {
                active_gop_id,
                last_delivered_frame_id: f.frame_id,
            };
            actions.deliver_frames.push(f);
        }
    }

    fn transition_to_awaiting_idr(
        &mut self,
        broken_gop_id: u16,
        last_good_frame_id: u32,
        now_us: u64,
        extra_dropped: usize,
    ) -> RecoveryActions {
        let dropped_queued = self.reorder_queue.len();
        self.reorder_queue.clear();
        self.state = RecoveryState::AwaitingIdr {
            broken_gop_id,
            last_good_frame_id,
            last_idr_request_us: Some(now_us),
        };
        RecoveryActions {
            deliver_frames: Vec::new(),
            dropped_dependent_frames: extra_dropped.saturating_add(dropped_queued),
            request_idr: true,
            hide_content_for_protected_blank: false,
            session_renewal_required: false,
        }
    }

    const fn cooldown_elapsed(&self, last_request_us: Option<u64>, now_us: u64) -> bool {
        match last_request_us {
            None => true,
            Some(prev) => now_us.saturating_sub(prev) >= self.config.idr_request_cooldown_us,
        }
    }

    const fn last_delivered_or_blank(&self) -> Option<u32> {
        match self.state {
            RecoveryState::InitialAwaitingIdr => None,
            RecoveryState::Healthy {
                last_delivered_frame_id,
                ..
            } => Some(last_delivered_frame_id),
            RecoveryState::AwaitingIdr {
                last_good_frame_id, ..
            } => {
                if last_good_frame_id == 0 {
                    None
                } else {
                    Some(last_good_frame_id)
                }
            }
            RecoveryState::ProtectedBlanked {
                last_blank_frame_id,
            } => Some(last_blank_frame_id),
        }
    }
}

trait TakeSelf {
    fn split_off_self(&mut self) -> Self;
}

impl TakeSelf for RecoveryActions {
    fn split_off_self(&mut self) -> Self {
        core::mem::take(self)
    }
}
