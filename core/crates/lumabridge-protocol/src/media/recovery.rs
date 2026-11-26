// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pure, clock-driven GOP dependency and `AwaitingIdr` recovery state machine (`ADR-0005` §1.4).
//!
//! Each [`GopRecoveryStateMachine`] instance is strictly bound to one `(session_id, display_id)`
//! pair, persists its `last_idr_request_us` rate-limiter across GOP recoveries, enforces both
//! frame-count and payload-byte ceilings on its reorder queue, and tracks earliest gap arrival
//! times without sleeping or invoking any codec decoder.

use core::fmt;
use std::collections::BTreeMap;

use crate::error::LimitConfigError;
use crate::limits::{RecoveryConfig, MAX_VALID_DISPLAY_ID};
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
    },
    /// Source sent `FLAG_PROTECTED_BLANK`; receiver MUST hide previous content until a clean `IDR`.
    ProtectedBlanked { last_blank_frame_id: u32 },
}

/// Pure output actions produced by [`GopRecoveryStateMachine`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryActions {
    /// Intact frames ready for decoder submission in strictly ascending `frame_id` order.
    pub deliver_frames: Vec<ReassembledFrame>,
    /// Number of out-of-order/orphan `P-frames` or duplicate queued frames dropped.
    pub dropped_dependent_frames: usize,
    /// Number of foreign `(session_id, display_id)` events ignored due to identity isolation.
    pub ignored_foreign_events: usize,
    /// Emit `MediaFeedback(request_idr = true)` respecting persistent cooldown and retry cap.
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
        self.ignored_foreign_events = self
            .ignored_foreign_events
            .saturating_add(other.ignored_foreign_events);
        self.request_idr |= other.request_idr;
        self.hide_content_for_protected_blank |= other.hide_content_for_protected_blank;
        self.session_renewal_required |= other.session_renewal_required;
    }
}

struct QueuedReorderFrame {
    queued_at_us: u64,
    frame: ReassembledFrame,
}

/// Pure `(session_id, display_id)`-bound GOP dependency and recovery state machine driven by
/// caller monotonic clock `now_us`.
pub struct GopRecoveryStateMachine {
    session_id: u64,
    display_id: u16,
    config: RecoveryConfig,
    state: RecoveryState,
    reorder_queue: BTreeMap<u32, QueuedReorderFrame>,
    queued_reorder_bytes: usize,
    highest_seen_frame_id: u32,
    last_idr_request_us: Option<u64>,
    unanswered_idr_requests: u32,
}

impl fmt::Debug for GopRecoveryStateMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GopRecoveryStateMachine")
            .field("session_id", &self.session_id)
            .field("display_id", &self.display_id)
            .field("config", &self.config)
            .field("state", &self.state)
            .field("queued_reorder_len", &self.reorder_queue.len())
            .field("queued_reorder_bytes", &self.queued_reorder_bytes)
            .field("highest_seen_frame_id", &self.highest_seen_frame_id)
            .field("last_idr_request_us", &self.last_idr_request_us)
            .field("unanswered_idr_requests", &self.unanswered_idr_requests)
            .finish()
    }
}

impl GopRecoveryStateMachine {
    /// Construct a recovery state machine explicitly bound to `(session_id, display_id)`.
    pub fn new(
        session_id: u64,
        display_id: u16,
        config: RecoveryConfig,
    ) -> Result<Self, LimitConfigError> {
        if session_id == 0 {
            return Err(LimitConfigError::InvalidValue(
                "GopRecoveryStateMachine session_id must be non-zero",
            ));
        }
        if display_id > MAX_VALID_DISPLAY_ID {
            return Err(LimitConfigError::InvalidValue(
                "GopRecoveryStateMachine display_id must be <= 0xFFFE",
            ));
        }
        config.validate()?;
        Ok(Self {
            session_id,
            display_id,
            config,
            state: RecoveryState::InitialAwaitingIdr,
            reorder_queue: BTreeMap::new(),
            queued_reorder_bytes: 0,
            highest_seen_frame_id: 0,
            last_idr_request_us: None,
            unanswered_idr_requests: 0,
        })
    }

    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    #[must_use]
    pub const fn display_id(&self) -> u16 {
        self.display_id
    }

    #[must_use]
    pub const fn state(&self) -> RecoveryState {
        self.state
    }

    #[must_use]
    pub fn queued_reorder_len(&self) -> usize {
        self.reorder_queue.len()
    }

    #[must_use]
    pub const fn queued_reorder_bytes(&self) -> usize {
        self.queued_reorder_bytes
    }

    #[must_use]
    pub const fn last_idr_request_us(&self) -> Option<u64> {
        self.last_idr_request_us
    }

    #[must_use]
    pub const fn unanswered_idr_requests(&self) -> u32 {
        self.unanswered_idr_requests
    }

    #[must_use]
    const fn matches_identity(&self, session_id: u64, display_id: u16) -> bool {
        self.session_id == session_id && self.display_id == display_id
    }

    /// Reset state machine, queues, and IDR rate-limiter history for the bound identity.
    pub fn reset(&mut self) {
        self.state = RecoveryState::InitialAwaitingIdr;
        self.reorder_queue.clear();
        self.queued_reorder_bytes = 0;
        self.highest_seen_frame_id = 0;
        self.last_idr_request_us = None;
        self.unanswered_idr_requests = 0;
    }

    /// Process a [`ReassemblyReport`] filtered strictly by the bound `(session_id, display_id)`.
    pub fn on_reassembly_report(
        &mut self,
        report: ReassemblyReport,
        now_us: u64,
        reassembler: &Reassembler,
    ) -> RecoveryActions {
        let mut actions = self.on_discarded_notices(&report.discarded, now_us);

        match report.outcome {
            ReassemblyOutcome::Completed(frame) => {
                if self.matches_identity(frame.session_id, frame.display_id) {
                    let older_in_flight = reassembler.has_incomplete_older_frame(
                        frame.session_id,
                        frame.display_id,
                        frame.frame_id,
                    );
                    actions.merge(self.on_frame_completed(frame, now_us, older_in_flight));
                } else {
                    actions.ignored_foreign_events =
                        actions.ignored_foreign_events.saturating_add(1);
                }
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

    /// Process a newly reassembled video frame if it belongs to the bound `(session_id, display_id)`.
    pub fn on_frame_completed(
        &mut self,
        frame: ReassembledFrame,
        now_us: u64,
        older_in_flight: bool,
    ) -> RecoveryActions {
        let mut actions = RecoveryActions::default();
        if !self.matches_identity(frame.session_id, frame.display_id) {
            actions.ignored_foreign_events = 1;
            return actions;
        }
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
        actions.dropped_dependent_frames += self.discard_reorder_at_or_before(frame.frame_id);

        let fid = frame.frame_id;
        let gop = frame.gop_id;
        // Preserve `last_idr_request_us` so a subsequent immediate loss stays rate-limited.
        self.unanswered_idr_requests = 0;
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
            RecoveryState::InitialAwaitingIdr => {
                actions.dropped_dependent_frames += 1;
                actions.request_idr = self.maybe_request_idr(now_us);
                self.state = RecoveryState::AwaitingIdr {
                    broken_gop_id: frame.gop_id,
                    last_good_frame_id: 0,
                };
            }
            RecoveryState::AwaitingIdr { .. } => {
                actions.dropped_dependent_frames += 1;
                actions.request_idr = self.maybe_request_idr(now_us);
            }
            RecoveryState::ProtectedBlanked { .. } => {
                actions.dropped_dependent_frames += 1;
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
                if self.reorder_queue.contains_key(&frame.frame_id) {
                    actions.dropped_dependent_frames += 1;
                    return;
                }
                let frame_bytes = frame.payload.len();
                if self.queued_reorder_bytes.saturating_add(frame_bytes)
                    > self.config.max_reorder_bytes
                {
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
                self.queued_reorder_bytes = self.queued_reorder_bytes.saturating_add(frame_bytes);
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

    /// Poll for missing `frame_id` gaps based on the **earliest** queued frame arrival timestamp
    /// across the entire reorder queue (preventing late lower-ID arrivals from shifting deadlines).
    pub fn poll_reorder_timeout(&mut self, now_us: u64) -> RecoveryActions {
        let RecoveryState::Healthy {
            active_gop_id,
            last_delivered_frame_id,
        } = self.state
        else {
            return RecoveryActions::default();
        };
        let Some(earliest_queued_at) = self.reorder_queue.values().map(|q| q.queued_at_us).min()
        else {
            return RecoveryActions::default();
        };
        if now_us.saturating_sub(earliest_queued_at) >= self.config.reorder_gap_timeout_us {
            return self.transition_to_awaiting_idr(
                active_gop_id,
                last_delivered_frame_id,
                now_us,
                0,
            );
        }
        RecoveryActions::default()
    }

    /// Poll for bounded IDR retransmission when remaining in `AwaitingIdr` without new packets.
    pub fn poll_idr_retry(&mut self, now_us: u64) -> RecoveryActions {
        let mut actions = RecoveryActions::default();
        if matches!(self.state, RecoveryState::AwaitingIdr { .. }) {
            actions.request_idr = self.maybe_request_idr(now_us);
        }
        actions
    }

    /// Advance both reorder-gap expiration and unanswered `AwaitingIdr` retry timers cleanly.
    pub fn poll_timers(&mut self, now_us: u64) -> RecoveryActions {
        let mut actions = self.poll_reorder_timeout(now_us);
        if !actions.request_idr {
            actions.merge(self.poll_idr_retry(now_us));
        }
        actions
    }

    /// Handle explicit frame loss/expiry/eviction notification for `(session_id, display_id)`.
    pub fn on_frame_lost(
        &mut self,
        session_id: u64,
        display_id: u16,
        lost_frame_id: u32,
        lost_gop_id: u16,
        now_us: u64,
    ) -> RecoveryActions {
        let mut actions = RecoveryActions::default();
        if !self.matches_identity(session_id, display_id) {
            actions.ignored_foreign_events = 1;
            return actions;
        }
        if let Some(removed) = self.remove_reorder_frame(lost_frame_id) {
            let _ = removed;
            actions.dropped_dependent_frames += 1;
        }

        match self.state {
            RecoveryState::Healthy {
                active_gop_id,
                last_delivered_frame_id,
            } => {
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
            RecoveryState::AwaitingIdr { .. } => {
                actions.request_idr = self.maybe_request_idr(now_us);
                actions
            }
            RecoveryState::InitialAwaitingIdr => {
                actions.request_idr = self.maybe_request_idr(now_us);
                self.state = RecoveryState::AwaitingIdr {
                    broken_gop_id: lost_gop_id,
                    last_good_frame_id: 0,
                };
                actions
            }
            RecoveryState::ProtectedBlanked { .. } => actions,
        }
    }

    /// Process expired/discarded notices filtered strictly by the bound `(session_id, display_id)`.
    pub fn on_discarded_notices(
        &mut self,
        notices: &[DiscardedFrameNotice],
        now_us: u64,
    ) -> RecoveryActions {
        let mut actions = RecoveryActions::default();
        for n in notices {
            actions.merge(self.on_frame_lost(
                n.session_id,
                n.display_id,
                n.frame_id,
                n.gop_id,
                now_us,
            ));
        }
        actions
    }

    /// Handle a semantic `FLAG_PROTECTED_BLANK` event for the bound `(session_id, display_id)`.
    pub fn on_protected_blank(
        &mut self,
        event: ProtectedBlankEvent,
        _now_us: u64,
    ) -> RecoveryActions {
        let mut actions = RecoveryActions::default();
        if !self.matches_identity(event.session_id, event.display_id) {
            actions.ignored_foreign_events = 1;
            return actions;
        }
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
        actions.dropped_dependent_frames = self.clear_reorder_queue();
        self.unanswered_idr_requests = 0;
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
            let Some(next_item) = self.remove_reorder_frame(next_expected) else {
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

    fn remove_reorder_frame(&mut self, frame_id: u32) -> Option<QueuedReorderFrame> {
        let removed = self.reorder_queue.remove(&frame_id)?;
        self.queued_reorder_bytes = self
            .queued_reorder_bytes
            .saturating_sub(removed.frame.payload.len());
        Some(removed)
    }

    fn discard_reorder_at_or_before(&mut self, threshold_fid: u32) -> usize {
        let stale_ids: Vec<u32> = self
            .reorder_queue
            .keys()
            .copied()
            .take_while(|&fid| fid <= threshold_fid)
            .collect();
        let count = stale_ids.len();
        for fid in stale_ids {
            let _ = self.remove_reorder_frame(fid);
        }
        count
    }

    fn clear_reorder_queue(&mut self) -> usize {
        let count = self.reorder_queue.len();
        self.reorder_queue.clear();
        self.queued_reorder_bytes = 0;
        count
    }

    fn transition_to_awaiting_idr(
        &mut self,
        broken_gop_id: u16,
        last_good_frame_id: u32,
        now_us: u64,
        extra_dropped: usize,
    ) -> RecoveryActions {
        let dropped_queued = self.clear_reorder_queue();
        let request_idr = self.maybe_request_idr(now_us);
        self.state = RecoveryState::AwaitingIdr {
            broken_gop_id,
            last_good_frame_id,
        };
        RecoveryActions {
            deliver_frames: Vec::new(),
            dropped_dependent_frames: extra_dropped.saturating_add(dropped_queued),
            ignored_foreign_events: 0,
            request_idr,
            hide_content_for_protected_blank: false,
            session_renewal_required: false,
        }
    }

    fn maybe_request_idr(&mut self, now_us: u64) -> bool {
        if self.unanswered_idr_requests >= self.config.max_unanswered_idr_requests {
            return false;
        }
        let elapsed = match self.last_idr_request_us {
            None => true,
            Some(prev) => now_us.saturating_sub(prev) >= self.config.idr_request_cooldown_us,
        };
        if !elapsed {
            return false;
        }
        self.last_idr_request_us = Some(now_us);
        self.unanswered_idr_requests = self.unanswered_idr_requests.saturating_add(1);
        true
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
