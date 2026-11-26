// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bounded, incremental video frame reassembly keyed by `(session_id, display_id, frame_id)`.
//!
//! Enforces configurable limits on per-frame payload bytes, per-display bytes, per-session bytes,
//! global bytes, total tracked displays, total pending frames, and per-fragment metadata overhead
//! BEFORE allocating memory. Never pre-allocates `frag_count` buffers or `8 MiB` per frame.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::error::{ReassemblyError, VideoHeaderError};
use crate::limits::ReassemblyConfig;
use crate::media::header::{decode_video_packet, VideoFlags, VideoPacketHeader};
use crate::version::CodecId;

const MAX_RETIRED_IDS_PER_DISPLAY: usize = 256;

/// Complete reassembled frame handed to the consumer.
///
/// Note on memory accounting: once delivered to the consumer, ownership of `payload` transfers
/// out of the [`Reassembler`] and no longer counts against the reassembly byte budget.
#[derive(Clone, PartialEq, Eq)]
pub struct ReassembledFrame {
    pub session_id: u64,
    pub display_id: u16,
    pub codec_id: CodecId,
    pub frame_id: u32,
    pub gop_id: u16,
    pub flags: VideoFlags,
    pub capture_ts_us: u64,
    pub encode_done_ts_us: u64,
    pub payload: Vec<u8>,
}

impl fmt::Debug for ReassembledFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReassembledFrame")
            .field("session_id", &self.session_id)
            .field("display_id", &self.display_id)
            .field("codec_id", &self.codec_id)
            .field("frame_id", &self.frame_id)
            .field("gop_id", &self.gop_id)
            .field("flags", &self.flags)
            .field("capture_ts_us", &self.capture_ts_us)
            .field("encode_done_ts_us", &self.encode_done_ts_us)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Distinct semantic event signaled when the sender replaces content due to DRM/HDCP protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedBlankEvent {
    pub session_id: u64,
    pub display_id: u16,
    pub codec_id: CodecId,
    pub frame_id: u32,
    pub gop_id: u16,
    pub mirror_source: bool,
    pub capture_ts_us: u64,
    pub encode_done_ts_us: u64,
}

/// Reason an incomplete frame was discarded from the reassembler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardReason {
    Expired,
    EvictedByWindow,
    EvictedByNewerKeyframe,
    EvictedByProtectedBlank,
    ConflictingMetadata,
    ConflictingPayload,
    BudgetExceeded,
}

/// Notice emitted whenever an incomplete frame is dropped or invalidated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscardedFrameNotice {
    pub session_id: u64,
    pub display_id: u16,
    pub frame_id: u32,
    pub gop_id: u16,
    pub reason: DiscardReason,
}

/// Outcome of submitting a single validated media packet into [`Reassembler`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyOutcome {
    Incomplete {
        frame_id: u32,
        received_fragments: u16,
        total_fragments: u16,
    },
    DuplicateIgnored {
        frame_id: u32,
    },
    StaleIgnored {
        frame_id: u32,
    },
    Completed(ReassembledFrame),
    ProtectedBlank(ProtectedBlankEvent),
    Rejected(ReassemblyError),
}

/// Combined outcome and any frames evicted/discarded during packet ingestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassemblyReport {
    pub outcome: ReassemblyOutcome,
    pub discarded: Vec<DiscardedFrameNotice>,
}

/// Live accounting snapshot of [`Reassembler`] memory and slot usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReassemblyStats {
    pub global_payload_bytes: usize,
    pub global_metadata_bytes: usize,
    pub total_displays: usize,
    pub active_sessions: usize,
    pub total_pending_frames: usize,
}

impl ReassemblyStats {
    #[must_use]
    pub const fn global_total_bytes(self) -> usize {
        self.global_payload_bytes
            .saturating_add(self.global_metadata_bytes)
    }
}

/// Unified ingestion error separating invalid packets from valid-packet reassembly tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestPacketError {
    InvalidPacket(VideoHeaderError),
}

struct PendingFrame {
    codec_id: CodecId,
    gop_id: u16,
    frag_count: u16,
    invariant_flags: u16,
    has_codec_config: bool,
    capture_ts_us: u64,
    encode_done_ts_us: u64,
    first_seen_us: u64,
    last_updated_us: u64,
    fragments: BTreeMap<u16, Vec<u8>>,
    payload_bytes: usize,
    metadata_bytes: usize,
}

impl PendingFrame {
    const fn total_bytes(&self) -> usize {
        self.payload_bytes.saturating_add(self.metadata_bytes)
    }
}

#[derive(Default)]
struct DisplayState {
    pending: BTreeMap<u32, PendingFrame>,
    accounted_bytes: usize,
    retired_floor: u32,
    retired_set: BTreeSet<u32>,
    retired_order: VecDeque<u32>,
}

impl DisplayState {
    fn is_retired(&self, frame_id: u32) -> bool {
        frame_id <= self.retired_floor || self.retired_set.contains(&frame_id)
    }

    fn retire_id(&mut self, frame_id: u32) {
        if frame_id <= self.retired_floor || !self.retired_set.insert(frame_id) {
            return;
        }
        self.retired_order.push_back(frame_id);
        while self.retired_order.len() > MAX_RETIRED_IDS_PER_DISPLAY {
            if let Some(evicted) = self.retired_order.pop_front() {
                self.retired_set.remove(&evicted);
                if evicted > self.retired_floor {
                    self.retired_floor = evicted;
                }
            }
        }
    }

    fn retire_all_at_or_below(&mut self, frame_id: u32) {
        if frame_id > self.retired_floor {
            self.retired_floor = frame_id;
        }
        while let Some(&first) = self.retired_set.first() {
            if first <= self.retired_floor {
                self.retired_set.remove(&first);
            } else {
                break;
            }
        }
        self.retired_order.retain(|&id| id > self.retired_floor);
    }
}

/// Bounded multi-session, multi-display media packet reassembler.
pub struct Reassembler {
    config: ReassemblyConfig,
    displays: BTreeMap<(u64, u16), DisplayState>,
    session_bytes: BTreeMap<u64, usize>,
    global_payload_bytes: usize,
    global_metadata_bytes: usize,
    total_pending_frames: usize,
}

impl Reassembler {
    /// Create a new reassembler enforcing all configured hierarchical budgets.
    pub fn new(config: ReassemblyConfig) -> Result<Self, crate::error::LimitConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            displays: BTreeMap::new(),
            session_bytes: BTreeMap::new(),
            global_payload_bytes: 0,
            global_metadata_bytes: 0,
            total_pending_frames: 0,
        })
    }

    #[must_use]
    pub const fn config(&self) -> ReassemblyConfig {
        self.config
    }

    /// Return current memory and pending-frame counts.
    #[must_use]
    pub fn stats(&self) -> ReassemblyStats {
        ReassemblyStats {
            global_payload_bytes: self.global_payload_bytes,
            global_metadata_bytes: self.global_metadata_bytes,
            total_displays: self.displays.len(),
            active_sessions: self.session_bytes.len(),
            total_pending_frames: self.total_pending_frames,
        }
    }

    /// Return `true` if `display` currently holds any incomplete frame strictly older than `frame_id`.
    #[must_use]
    pub fn has_incomplete_older_frame(
        &self,
        session_id: u64,
        display_id: u16,
        frame_id: u32,
    ) -> bool {
        self.displays
            .get(&(session_id, display_id))
            .and_then(|d| d.pending.keys().next().copied())
            .is_some_and(|oldest| oldest < frame_id)
    }

    /// Decode and ingest a raw media packet (`44 B header + fragment`) at caller clock `now_us`.
    pub fn ingest_packet(
        &mut self,
        packet: &[u8],
        max_packet_budget: usize,
        now_us: u64,
    ) -> Result<ReassemblyReport, IngestPacketError> {
        let (header, fragment) = decode_video_packet(packet, max_packet_budget)
            .map_err(IngestPacketError::InvalidPacket)?;
        Ok(self.ingest_decoded(header, fragment, now_us))
    }

    /// Ingest an already-validated [`VideoPacketHeader`] and fragment payload slice.
    pub fn ingest_decoded(
        &mut self,
        header: VideoPacketHeader,
        fragment: &[u8],
        now_us: u64,
    ) -> ReassemblyReport {
        let discarded = Vec::new();
        let key = (header.session_id, header.display_id);

        if let Some(d) = self.displays.get(&key) {
            if d.is_retired(header.frame_id) {
                return ReassemblyReport {
                    outcome: ReassemblyOutcome::StaleIgnored {
                        frame_id: header.frame_id,
                    },
                    discarded,
                };
            }
        } else if self.displays.len() >= self.config.max_total_displays {
            return ReassemblyReport {
                outcome: ReassemblyOutcome::Rejected(ReassemblyError::TooManyDisplays),
                discarded,
            };
        }

        if header.flags.contains(VideoFlags::PROTECTED_BLANK) {
            return self.handle_protected_blank(header, discarded);
        }

        let is_existing_frame = self
            .displays
            .get(&key)
            .is_some_and(|d| d.pending.contains_key(&header.frame_id));

        if is_existing_frame {
            self.ingest_into_existing_frame(header, fragment, now_us, discarded)
        } else {
            self.ingest_new_frame(header, fragment, now_us, discarded)
        }
    }

    fn handle_protected_blank(
        &mut self,
        header: VideoPacketHeader,
        mut discarded: Vec<DiscardedFrameNotice>,
    ) -> ReassemblyReport {
        let key = (header.session_id, header.display_id);
        let conflict = self
            .displays
            .get(&key)
            .is_some_and(|d| d.pending.contains_key(&header.frame_id));

        if conflict {
            if let Some(removed) = self.remove_pending_frame(key, header.frame_id) {
                discarded.push(DiscardedFrameNotice {
                    session_id: header.session_id,
                    display_id: header.display_id,
                    frame_id: header.frame_id,
                    gop_id: removed.gop_id,
                    reason: DiscardReason::ConflictingMetadata,
                });
            }
            if let Some(d) = self.displays.get_mut(&key) {
                d.retire_id(header.frame_id);
            }
            return ReassemblyReport {
                outcome: ReassemblyOutcome::Rejected(
                    ReassemblyError::ConflictingFragmentMetadata {
                        frame_id: header.frame_id,
                    },
                ),
                discarded,
            };
        }

        discarded.extend(self.discard_older_frames(
            key,
            header.frame_id,
            DiscardReason::EvictedByProtectedBlank,
        ));
        let display = self.displays.entry(key).or_default();
        display.retire_all_at_or_below(header.frame_id);

        ReassemblyReport {
            outcome: ReassemblyOutcome::ProtectedBlank(ProtectedBlankEvent {
                session_id: header.session_id,
                display_id: header.display_id,
                codec_id: header.codec_id,
                frame_id: header.frame_id,
                gop_id: header.gop_id,
                mirror_source: header.flags.contains(VideoFlags::MIRROR_SOURCE),
                capture_ts_us: header.capture_ts_us,
                encode_done_ts_us: header.encode_done_ts_us,
            }),
            discarded,
        }
    }

    fn ingest_into_existing_frame(
        &mut self,
        header: VideoPacketHeader,
        fragment: &[u8],
        now_us: u64,
        mut discarded: Vec<DiscardedFrameNotice>,
    ) -> ReassemblyReport {
        let key = (header.session_id, header.display_id);

        match self.check_existing_fragment(key, header, fragment) {
            Ok(true) => {
                return ReassemblyReport {
                    outcome: ReassemblyOutcome::DuplicateIgnored {
                        frame_id: header.frame_id,
                    },
                    discarded,
                };
            }
            Err(err) => {
                let reason = match err {
                    ReassemblyError::ConflictingFragmentPayload { .. } => {
                        DiscardReason::ConflictingPayload
                    }
                    _ => DiscardReason::ConflictingMetadata,
                };
                self.invalidate_pending_frame(key, header.frame_id, reason, &mut discarded);
                return ReassemblyReport {
                    outcome: ReassemblyOutcome::Rejected(err),
                    discarded,
                };
            }
            Ok(false) => {}
        }

        let frag_len = fragment.len();
        let meta_cost = self.config.metadata_overhead_per_fragment_bytes;
        if let Err(err) = self.check_fragment_budget(key, header.frame_id, frag_len, meta_cost) {
            self.invalidate_pending_frame(
                key,
                header.frame_id,
                DiscardReason::BudgetExceeded,
                &mut discarded,
            );
            return ReassemblyReport {
                outcome: ReassemblyOutcome::Rejected(err),
                discarded,
            };
        }

        let frag_total_cost = frag_len.saturating_add(meta_cost);
        let is_complete = {
            let display = self.displays.get_mut(&key).expect("display exists");
            display.accounted_bytes = display.accounted_bytes.saturating_add(frag_total_cost);
            let pf = display
                .pending
                .get_mut(&header.frame_id)
                .expect("frame exists");
            pf.last_updated_us = now_us;
            pf.has_codec_config |= header.flags.contains(VideoFlags::HAS_CODEC_CONFIG);
            pf.payload_bytes = pf.payload_bytes.saturating_add(frag_len);
            pf.metadata_bytes = pf.metadata_bytes.saturating_add(meta_cost);
            pf.fragments.insert(header.frag_index, fragment.to_vec());
            pf.fragments.len() == usize::from(pf.frag_count)
        };
        *self.session_bytes.entry(header.session_id).or_insert(0) += frag_total_cost;
        self.global_payload_bytes = self.global_payload_bytes.saturating_add(frag_len);
        self.global_metadata_bytes = self.global_metadata_bytes.saturating_add(meta_cost);

        if is_complete {
            self.finalize_frame(key, header.frame_id, discarded)
        } else {
            let pf = &self.displays[&key].pending[&header.frame_id];
            ReassemblyReport {
                outcome: ReassemblyOutcome::Incomplete {
                    frame_id: header.frame_id,
                    received_fragments: u16::try_from(pf.fragments.len()).unwrap_or(u16::MAX),
                    total_fragments: pf.frag_count,
                },
                discarded,
            }
        }
    }

    fn check_existing_fragment(
        &self,
        key: (u64, u16),
        header: VideoPacketHeader,
        fragment: &[u8],
    ) -> Result<bool, ReassemblyError> {
        let display = &self.displays[&key];
        let pf = &display.pending[&header.frame_id];
        let meta_matches = pf.codec_id == header.codec_id
            && pf.gop_id == header.gop_id
            && pf.frag_count == header.frag_count
            && pf.invariant_flags == header.flags.invariant_bits()
            && pf.capture_ts_us == header.capture_ts_us
            && pf.encode_done_ts_us == header.encode_done_ts_us;
        if !meta_matches {
            return Err(ReassemblyError::ConflictingFragmentMetadata {
                frame_id: header.frame_id,
            });
        }
        if let Some(existing) = pf.fragments.get(&header.frag_index) {
            if existing.as_slice() == fragment {
                return Ok(true);
            }
            return Err(ReassemblyError::ConflictingFragmentPayload {
                frame_id: header.frame_id,
                frag_index: header.frag_index,
            });
        }
        Ok(false)
    }

    fn invalidate_pending_frame(
        &mut self,
        key: (u64, u16),
        frame_id: u32,
        reason: DiscardReason,
        discarded: &mut Vec<DiscardedFrameNotice>,
    ) {
        if let Some(removed) = self.remove_pending_frame(key, frame_id) {
            discarded.push(DiscardedFrameNotice {
                session_id: key.0,
                display_id: key.1,
                frame_id,
                gop_id: removed.gop_id,
                reason,
            });
        }
        if let Some(d) = self.displays.get_mut(&key) {
            d.retire_id(frame_id);
        }
    }

    fn ingest_new_frame(
        &mut self,
        header: VideoPacketHeader,
        fragment: &[u8],
        now_us: u64,
        mut discarded: Vec<DiscardedFrameNotice>,
    ) -> ReassemblyReport {
        let key = (header.session_id, header.display_id);

        // Enforce per-display window (max 4 incomplete frames) BEFORE admitting a new frame.
        let pending_count = self.displays.get(&key).map_or(0, |d| d.pending.len());
        if pending_count >= self.config.max_incomplete_frames_per_display {
            let oldest_fid = self.displays[&key]
                .pending
                .keys()
                .next()
                .copied()
                .expect("pending non-empty");
            if header.frame_id < oldest_fid {
                // Incoming frame is already older than the entire active window; do not evict newer work.
                if let Some(d) = self.displays.get_mut(&key) {
                    d.retire_id(header.frame_id);
                }
                discarded.push(DiscardedFrameNotice {
                    session_id: header.session_id,
                    display_id: header.display_id,
                    frame_id: header.frame_id,
                    gop_id: header.gop_id,
                    reason: DiscardReason::EvictedByWindow,
                });
                return ReassemblyReport {
                    outcome: ReassemblyOutcome::StaleIgnored {
                        frame_id: header.frame_id,
                    },
                    discarded,
                };
            }
            if let Some(evicted) = self.remove_pending_frame(key, oldest_fid) {
                discarded.push(DiscardedFrameNotice {
                    session_id: header.session_id,
                    display_id: header.display_id,
                    frame_id: oldest_fid,
                    gop_id: evicted.gop_id,
                    reason: DiscardReason::EvictedByWindow,
                });
            }
            if let Some(d) = self.displays.get_mut(&key) {
                d.retire_id(oldest_fid);
            }
        }

        if self.total_pending_frames >= self.config.max_pending_frames {
            return ReassemblyReport {
                outcome: ReassemblyOutcome::Rejected(ReassemblyError::TooManyPendingFrames),
                discarded,
            };
        }

        let frag_len = fragment.len();
        let meta_cost = self.config.metadata_overhead_per_fragment_bytes;
        if let Err(err) = self.check_new_frame_budget(key, header.frame_id, frag_len, meta_cost) {
            return ReassemblyReport {
                outcome: ReassemblyOutcome::Rejected(err),
                discarded,
            };
        }

        let frag_total_cost = frag_len.saturating_add(meta_cost);
        let mut fragments = BTreeMap::new();
        fragments.insert(header.frag_index, fragment.to_vec());

        let pf = PendingFrame {
            codec_id: header.codec_id,
            gop_id: header.gop_id,
            frag_count: header.frag_count,
            invariant_flags: header.flags.invariant_bits(),
            has_codec_config: header.flags.contains(VideoFlags::HAS_CODEC_CONFIG),
            capture_ts_us: header.capture_ts_us,
            encode_done_ts_us: header.encode_done_ts_us,
            first_seen_us: now_us,
            last_updated_us: now_us,
            fragments,
            payload_bytes: frag_len,
            metadata_bytes: meta_cost,
        };

        let display = self.displays.entry(key).or_default();
        display.accounted_bytes = display.accounted_bytes.saturating_add(frag_total_cost);
        display.pending.insert(header.frame_id, pf);
        *self.session_bytes.entry(header.session_id).or_insert(0) += frag_total_cost;
        self.global_payload_bytes = self.global_payload_bytes.saturating_add(frag_len);
        self.global_metadata_bytes = self.global_metadata_bytes.saturating_add(meta_cost);
        self.total_pending_frames = self.total_pending_frames.saturating_add(1);

        if header.frag_count == 1 {
            self.finalize_frame(key, header.frame_id, discarded)
        } else {
            ReassemblyReport {
                outcome: ReassemblyOutcome::Incomplete {
                    frame_id: header.frame_id,
                    received_fragments: 1,
                    total_fragments: header.frag_count,
                },
                discarded,
            }
        }
    }

    fn check_new_frame_budget(
        &self,
        key: (u64, u16),
        frame_id: u32,
        frag_len: usize,
        meta_cost: usize,
    ) -> Result<(), ReassemblyError> {
        if frag_len > self.config.max_frame_bytes {
            return Err(ReassemblyError::FrameExceedsMaxBytes {
                frame_id,
                attempted: frag_len,
                max: self.config.max_frame_bytes,
            });
        }
        self.check_hierarchical_byte_caps(key, frag_len.saturating_add(meta_cost))
    }

    fn check_fragment_budget(
        &self,
        key: (u64, u16),
        frame_id: u32,
        frag_len: usize,
        meta_cost: usize,
    ) -> Result<(), ReassemblyError> {
        let cur_payload = self.displays[&key].pending[&frame_id].payload_bytes;
        let attempted_payload = cur_payload.saturating_add(frag_len);
        if attempted_payload > self.config.max_frame_bytes {
            return Err(ReassemblyError::FrameExceedsMaxBytes {
                frame_id,
                attempted: attempted_payload,
                max: self.config.max_frame_bytes,
            });
        }
        self.check_hierarchical_byte_caps(key, frag_len.saturating_add(meta_cost))
    }

    fn check_hierarchical_byte_caps(
        &self,
        key: (u64, u16),
        delta_total: usize,
    ) -> Result<(), ReassemblyError> {
        let display_used = self.displays.get(&key).map_or(0, |d| d.accounted_bytes);
        if display_used.saturating_add(delta_total) > self.config.max_display_bytes {
            return Err(ReassemblyError::DisplayBudgetExceeded { display_id: key.1 });
        }
        let session_used = self.session_bytes.get(&key.0).copied().unwrap_or(0);
        if session_used.saturating_add(delta_total) > self.config.max_session_bytes {
            return Err(ReassemblyError::SessionBudgetExceeded { session_id: key.0 });
        }
        let global_used = self
            .global_payload_bytes
            .saturating_add(self.global_metadata_bytes);
        if global_used.saturating_add(delta_total) > self.config.max_global_bytes {
            return Err(ReassemblyError::GlobalBudgetExceeded);
        }
        Ok(())
    }

    fn finalize_frame(
        &mut self,
        key: (u64, u16),
        frame_id: u32,
        mut discarded: Vec<DiscardedFrameNotice>,
    ) -> ReassemblyReport {
        let pf = self
            .remove_pending_frame(key, frame_id)
            .expect("completed pending frame exists");

        let mut payload = Vec::with_capacity(pf.payload_bytes);
        for (_, chunk) in pf.fragments {
            payload.extend_from_slice(&chunk);
        }

        let mut raw_flags = pf.invariant_flags | VideoFlags::END_OF_FRAME.raw();
        if pf.has_codec_config {
            raw_flags |= VideoFlags::HAS_CODEC_CONFIG.raw();
        }
        let flags = VideoFlags::from_wire(raw_flags).expect("validated flags");

        if flags.contains(VideoFlags::KEYFRAME) {
            discarded.extend(self.discard_older_frames(
                key,
                frame_id,
                DiscardReason::EvictedByNewerKeyframe,
            ));
            if let Some(d) = self.displays.get_mut(&key) {
                d.retire_all_at_or_below(frame_id);
            }
        } else if let Some(d) = self.displays.get_mut(&key) {
            d.retire_id(frame_id);
        }

        let frame = ReassembledFrame {
            session_id: key.0,
            display_id: key.1,
            codec_id: pf.codec_id,
            frame_id,
            gop_id: pf.gop_id,
            flags,
            capture_ts_us: pf.capture_ts_us,
            encode_done_ts_us: pf.encode_done_ts_us,
            payload,
        };

        ReassemblyReport {
            outcome: ReassemblyOutcome::Completed(frame),
            discarded,
        }
    }

    fn discard_older_frames(
        &mut self,
        key: (u64, u16),
        threshold_frame_id: u32,
        reason: DiscardReason,
    ) -> Vec<DiscardedFrameNotice> {
        let older_ids: Vec<u32> = self.displays.get(&key).map_or_else(Vec::new, |d| {
            d.pending
                .keys()
                .copied()
                .take_while(|&fid| fid < threshold_frame_id)
                .collect()
        });

        let mut notices = Vec::with_capacity(older_ids.len());
        for fid in older_ids {
            if let Some(removed) = self.remove_pending_frame(key, fid) {
                notices.push(DiscardedFrameNotice {
                    session_id: key.0,
                    display_id: key.1,
                    frame_id: fid,
                    gop_id: removed.gop_id,
                    reason,
                });
            }
            if let Some(d) = self.displays.get_mut(&key) {
                d.retire_id(fid);
            }
        }
        notices
    }

    fn remove_pending_frame(&mut self, key: (u64, u16), frame_id: u32) -> Option<PendingFrame> {
        let display = self.displays.get_mut(&key)?;
        let pf = display.pending.remove(&frame_id)?;
        let frame_total = pf.total_bytes();
        display.accounted_bytes = display.accounted_bytes.saturating_sub(frame_total);
        if let Some(sb) = self.session_bytes.get_mut(&key.0) {
            *sb = sb.saturating_sub(frame_total);
        }
        self.global_payload_bytes = self.global_payload_bytes.saturating_sub(pf.payload_bytes);
        self.global_metadata_bytes = self.global_metadata_bytes.saturating_sub(pf.metadata_bytes);
        self.total_pending_frames = self.total_pending_frames.saturating_sub(1);
        Some(pf)
    }

    /// Expire incomplete frames older than `fragment_timeout_us` relative to caller monotonic clock `now_us`.
    pub fn expire(&mut self, now_us: u64) -> Vec<DiscardedFrameNotice> {
        let timeout = self.config.fragment_timeout_us;
        let expired_targets: Vec<((u64, u16), u32)> = self
            .displays
            .iter()
            .flat_map(|(&key, d)| {
                d.pending.iter().filter_map(move |(&fid, pf)| {
                    let age = now_us.saturating_sub(pf.first_seen_us);
                    let idle = now_us.saturating_sub(pf.last_updated_us);
                    if age >= timeout || idle >= timeout {
                        Some((key, fid))
                    } else {
                        None
                    }
                })
            })
            .collect();

        let mut notices = Vec::with_capacity(expired_targets.len());
        for (key, fid) in expired_targets {
            if let Some(removed) = self.remove_pending_frame(key, fid) {
                notices.push(DiscardedFrameNotice {
                    session_id: key.0,
                    display_id: key.1,
                    frame_id: fid,
                    gop_id: removed.gop_id,
                    reason: DiscardReason::Expired,
                });
            }
            if let Some(d) = self.displays.get_mut(&key) {
                d.retire_id(fid);
            }
        }
        notices
    }

    /// Free all state and budgets associated with `(session_id, display_id)`.
    pub fn remove_display(&mut self, session_id: u64, display_id: u16) -> usize {
        let key = (session_id, display_id);
        let Some(display) = self.displays.remove(&key) else {
            return 0;
        };
        let mut freed_frames = 0usize;
        for (_, pf) in display.pending {
            self.global_payload_bytes = self.global_payload_bytes.saturating_sub(pf.payload_bytes);
            self.global_metadata_bytes =
                self.global_metadata_bytes.saturating_sub(pf.metadata_bytes);
            self.total_pending_frames = self.total_pending_frames.saturating_sub(1);
            freed_frames += 1;
        }
        if let Some(sb) = self.session_bytes.get_mut(&session_id) {
            *sb = sb.saturating_sub(display.accounted_bytes);
            if *sb == 0 && !self.displays.keys().any(|&(sid, _)| sid == session_id) {
                self.session_bytes.remove(&session_id);
            }
        }
        freed_frames
    }

    /// Free all state and budgets associated with `session_id` across all displays.
    pub fn remove_session(&mut self, session_id: u64) -> usize {
        let display_ids: Vec<u16> = self
            .displays
            .keys()
            .filter_map(|&(sid, did)| if sid == session_id { Some(did) } else { None })
            .collect();
        let mut freed = 0usize;
        for did in display_ids {
            freed += self.remove_display(session_id, did);
        }
        self.session_bytes.remove(&session_id);
        freed
    }

    /// Clear all displays, sessions, and pending reassemblies cleanly.
    pub fn clear(&mut self) {
        self.displays.clear();
        self.session_bytes.clear();
        self.global_payload_bytes = 0;
        self.global_metadata_bytes = 0;
        self.total_pending_frames = 0;
    }
}
