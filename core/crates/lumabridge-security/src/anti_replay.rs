// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bounded single-use challenge replay guards, timestamp skew checks, and sequence tracking.

use crate::error::SecurityError;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

/// Maximum number of tracked challenge digests before deterministic FIFO eviction of expired/oldest entries.
pub const MAX_TRACKED_CHALLENGES: usize = 4096;

/// Bounded single-use challenge / pairing-attempt anti-replay cache with expiry tracking.
#[derive(Default)]
pub struct BoundedChallengeCache {
    state: Mutex<ChallengeCacheInner>,
}

#[derive(Default)]
struct ChallengeCacheInner {
    order: VecDeque<[u8; 32]>,
    entries: BTreeMap<[u8; 32], u64>,
}

impl BoundedChallengeCache {
    /// Create a bounded replay cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify timestamp bounds `[now - max_past_skew, now + max_future_skew]` and check/record challenge once.
    pub fn check_and_insert_unique(
        &self,
        context_tag: &[u8],
        challenge_bytes: &[u8],
        issued_at_unix: u64,
        now_unix: u64,
        max_past_skew_secs: u64,
        max_future_skew_secs: u64,
    ) -> Result<(), SecurityError> {
        let oldest_allowed = now_unix.saturating_sub(max_past_skew_secs);
        let newest_allowed = now_unix.saturating_add(max_future_skew_secs);
        if issued_at_unix < oldest_allowed || issued_at_unix > newest_allowed {
            return Err(SecurityError::InvalidTimestamp(
                "challenge timestamp outside permitted skew window",
            ));
        }

        let mut hasher = Sha256::new();
        hasher.update(context_tag);
        hasher.update([0u8]);
        hasher.update(challenge_bytes);
        let digest: [u8; 32] = hasher.finalize().into();

        let expires_at = issued_at_unix.saturating_add(max_past_skew_secs);
        let mut guard = self
            .state
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("replay cache lock poisoned"))?;

        // Evict expired head entries first while keeping FIFO invariants intact.
        while let Some(&front) = guard.order.front() {
            let expired = guard.entries.get(&front).is_none_or(|&exp| exp < now_unix);
            if expired {
                let _ = guard.order.pop_front();
                guard.entries.remove(&front);
            } else {
                break;
            }
        }

        if guard.entries.contains_key(&digest) {
            return Err(SecurityError::ReplayDetected);
        }

        while guard.entries.len() >= MAX_TRACKED_CHALLENGES {
            if let Some(oldest) = guard.order.pop_front() {
                guard.entries.remove(&oldest);
            } else {
                break;
            }
        }

        guard.entries.insert(digest, expires_at);
        guard.order.push_back(digest);
        Ok(())
    }

    /// Number of currently tracked challenge digests (for tests and telemetry invariants).
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().map_or(0, |g| g.entries.len())
    }

    /// Whether the replay cache has zero tracked entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Strictly monotonic sequence guard rejecting zero, duplicate, and regressive counters.
#[derive(Debug, Clone, Default)]
pub struct MonotonicSeqGuard {
    highest_seen: Option<u64>,
}

impl MonotonicSeqGuard {
    /// Construct a new sequence guard starting before sequence `1`.
    #[must_use]
    pub const fn new() -> Self {
        Self { highest_seen: None }
    }

    /// Accept strictly increasing positive sequence numbers (`seq > highest_seen`, `seq >= 1`).
    pub fn check_and_advance(&mut self, seq: u64) -> Result<(), SecurityError> {
        if seq == 0 {
            return Err(SecurityError::ReplayDetected);
        }
        if let Some(prev) = self.highest_seen {
            if seq <= prev {
                return Err(SecurityError::ReplayDetected);
            }
        }
        self.highest_seen = Some(seq);
        Ok(())
    }

    /// Return highest accepted sequence number so far.
    #[must_use]
    pub const fn highest_seen(&self) -> Option<u64> {
        self.highest_seen
    }
}
