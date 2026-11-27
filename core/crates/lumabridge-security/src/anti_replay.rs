// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bounded fail-closed single-use challenge replay guards, timestamp skew checks, and sequence tracking.

use crate::error::SecurityError;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

/// Maximum number of unexpired challenge digests tracked concurrently.
///
/// When saturated with unexpired entries, inserts fail closed (`ResourceExhausted`) rather than
/// evicting active unexpired challenges (preventing replay-cache eviction attacks).
pub const MAX_TRACKED_CHALLENGES: usize = 4096;

/// Bounded fail-closed single-use challenge / pairing-attempt anti-replay cache with expiry tracking.
#[derive(Default)]
pub struct BoundedChallengeCache {
    state: Mutex<ChallengeCacheInner>,
}

#[derive(Default)]
struct ChallengeCacheInner {
    by_expiry: BTreeSet<(u64, [u8; 32])>,
    entries: BTreeMap<[u8; 32], u64>,
}

impl BoundedChallengeCache {
    /// Create a bounded fail-closed replay cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify timestamp bounds `[now - max_past_skew, now + max_future_skew]` and check/record challenge once.
    ///
    /// Purges all expired entries first; if `MAX_TRACKED_CHALLENGES` unexpired entries remain,
    /// rejects new inserts with [`SecurityError::ResourceExhausted`] rather than evicting valid anti-replay state.
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
        let tag_len = u32::try_from(context_tag.len()).unwrap_or(u32::MAX);
        hasher.update(tag_len.to_be_bytes());
        hasher.update(context_tag);
        let chall_len = u32::try_from(challenge_bytes.len()).unwrap_or(u32::MAX);
        hasher.update(chall_len.to_be_bytes());
        hasher.update(challenge_bytes);
        let digest: [u8; 32] = hasher.finalize().into();

        let expires_at = issued_at_unix.saturating_add(max_past_skew_secs);
        let mut guard = self
            .state
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("replay cache lock poisoned"))?;

        // Purge expired entries strictly ordered by expiry timestamp.
        while let Some(&(exp, old_digest)) = guard.by_expiry.first() {
            if exp < now_unix {
                guard.by_expiry.remove(&(exp, old_digest));
                guard.entries.remove(&old_digest);
            } else {
                break;
            }
        }

        if guard.entries.contains_key(&digest) {
            return Err(SecurityError::ReplayDetected);
        }

        if guard.entries.len() >= MAX_TRACKED_CHALLENGES {
            return Err(SecurityError::ResourceExhausted(
                "anti-replay cache saturated with unexpired challenges",
            ));
        }

        guard.entries.insert(digest, expires_at);
        guard.by_expiry.insert((expires_at, digest));
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
