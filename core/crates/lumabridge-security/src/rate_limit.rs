// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-peer exponential backoff and global multi-endpoint PIN brute-force rate limiting.

use crate::error::SecurityError;
use crate::identity::DeviceId;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

/// Maximum tracked peer backoff buckets to bound attacker-induced memory allocation.
pub const MAX_TRACKED_PEER_BUCKETS: usize = 2048;

/// Policy parameters governing per-peer and global brute-force protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Initial backoff after first failed authentication attempt (ms).
    pub base_backoff_ms: u64,
    /// Upper ceiling on exponential backoff per peer (ms).
    pub max_backoff_ms: u64,
    /// Consecutive failures after which peer receives extended lockout `max_backoff_ms`.
    pub lockout_threshold: u32,
    /// Sliding window length for tracking global failures across all peer endpoints (ms).
    pub global_window_ms: u64,
    /// Maximum total failed attempts allowed across ALL peer identities in `global_window_ms`.
    pub max_global_failures_in_window: u32,
    /// Global cooldown duration enforced when `max_global_failures_in_window` is reached (ms).
    pub global_cooldown_ms: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            base_backoff_ms: 1_000,
            max_backoff_ms: 300_000,
            lockout_threshold: 5,
            global_window_ms: 60_000,
            max_global_failures_in_window: 15,
            global_cooldown_ms: 60_000,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PeerFailureState {
    consecutive_failures: u32,
    blocked_until_ms: u64,
    last_updated_ms: u64,
}

#[derive(Default)]
struct RateLimitInner {
    peers: BTreeMap<DeviceId, PeerFailureState>,
    global_failures_ms: VecDeque<u64>,
    global_blocked_until_ms: u64,
}

/// Thread-safe pairing/authentication rate limiter with BOTH per-peer and global multi-endpoint caps.
pub struct AuthRateLimiter {
    config: RateLimitConfig,
    inner: Mutex<RateLimitInner>,
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

impl AuthRateLimiter {
    /// Construct a limiter with explicit policy thresholds.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(RateLimitInner::default()),
        }
    }

    /// Check whether an authentication attempt from `peer_id` at `now_ms` is currently permitted.
    pub fn check_allowed(&self, peer_id: DeviceId, now_ms: u64) -> Result<(), SecurityError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("rate limiter lock poisoned"))?;
        self.prune_global_window(&mut guard, now_ms);

        let peer_wait = guard
            .peers
            .get(&peer_id)
            .map_or(0, |s| s.blocked_until_ms.saturating_sub(now_ms));
        let global_wait = guard.global_blocked_until_ms.saturating_sub(now_ms);
        let retry_after_ms = peer_wait.max(global_wait);
        if retry_after_ms > 0 {
            return Err(SecurityError::RateLimited { retry_after_ms });
        }
        Ok(())
    }

    /// Record a failed pairing / authentication attempt and return applied `retry_after_ms`.
    pub fn record_failure(&self, peer_id: DeviceId, now_ms: u64) -> Result<u64, SecurityError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("rate limiter lock poisoned"))?;
        self.prune_global_window(&mut guard, now_ms);

        if !guard.peers.contains_key(&peer_id) && guard.peers.len() >= MAX_TRACKED_PEER_BUCKETS {
            if let Some((&evict_id, _)) = guard
                .peers
                .iter()
                .min_by_key(|(_, state)| state.last_updated_ms)
            {
                guard.peers.remove(&evict_id);
            }
        }

        let peer_wait_ms = {
            let entry = guard.peers.entry(peer_id).or_default();
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.last_updated_ms = now_ms;
            let backoff = if entry.consecutive_failures >= self.config.lockout_threshold {
                self.config.max_backoff_ms
            } else {
                let shift = entry.consecutive_failures.saturating_sub(1).min(20);
                self.config
                    .base_backoff_ms
                    .saturating_mul(1u64 << shift)
                    .min(self.config.max_backoff_ms)
            };
            entry.blocked_until_ms = entry.blocked_until_ms.max(now_ms.saturating_add(backoff));
            entry.blocked_until_ms.saturating_sub(now_ms)
        };

        guard.global_failures_ms.push_back(now_ms);
        if guard.global_failures_ms.len()
            >= usize::try_from(self.config.max_global_failures_in_window).unwrap_or(usize::MAX)
        {
            guard.global_blocked_until_ms = guard
                .global_blocked_until_ms
                .max(now_ms.saturating_add(self.config.global_cooldown_ms));
        }

        let global_wait_ms = guard.global_blocked_until_ms.saturating_sub(now_ms);
        Ok(peer_wait_ms.max(global_wait_ms))
    }

    /// Clear per-peer failure streak after a cryptographically verified pairing success.
    ///
    /// Preserves the global sliding window so a compromised peer cannot reset global abuse accounting.
    pub fn record_success(&self, peer_id: DeviceId) -> Result<(), SecurityError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("rate limiter lock poisoned"))?;
        guard.peers.remove(&peer_id);
        Ok(())
    }

    fn prune_global_window(&self, guard: &mut RateLimitInner, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.config.global_window_ms);
        while let Some(&ts) = guard.global_failures_ms.front() {
            if ts < cutoff {
                let _ = guard.global_failures_ms.pop_front();
            } else {
                break;
            }
        }
    }
}
