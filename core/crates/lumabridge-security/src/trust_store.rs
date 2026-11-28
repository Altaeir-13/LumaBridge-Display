// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Zero-trust peer store, monotonic revocation, atomic permission updates, and trust lifecycle policies.
//!
//! IMPORTANT: [`InMemoryTrustStore`] is an in-memory reference implementation of
//! [`TrustStore`] for protocol qualification and tests. Persistent platform vaults
//! (Windows DPAPI / CNG, Android Keystore, macOS Keychain, Linux Secret Service)
//! remain outside the portable `lumabridge-security` crate boundary.

use crate::error::SecurityError;
use crate::identity::{DeviceId, PeerRole, PublicIdentity};
use crate::pairing::ApprovedPairingCommit;
use lumabridge_protocol::control::Permissions;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::RwLock;

/// Maximum number of paired trusted peers persisted in [`InMemoryTrustStore`].
pub const MAX_TRUSTED_PEERS: usize = 256;

/// Maximum number of revocation tombstones persisted in [`InMemoryTrustStore`].
pub const MAX_REVOKED_PEERS: usize = 1024;

/// Maximum number of consumed pairing commit channel-binding digests retained for replay rejection.
pub const MAX_CONSUMED_PAIRING_COMMITS: usize = 1024;

/// Maximum UTF-8 byte length permitted for stored peer friendly names (`LBWP` `PairHello` limit).
pub const MAX_FRIENDLY_NAME_BYTES: usize = 48;

/// Explicit administrative / vault-hydration record separated from ordinary live pairing commits.
///
/// MUST ONLY be used by administrative import or persistent OS keystore hydration paths, never
/// to bypass cryptographic pairing + local human approval on a live pairing connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminTrustImportRecord {
    pub identity: PublicIdentity,
    pub role: PeerRole,
    pub friendly_name: String,
    pub base_permissions: Permissions,
    pub paired_at_unix: u64,
    pub last_seen_unix: u64,
    pub trust_epoch: u64,
    pub perm_epoch: u64,
}

/// Reason recorded when revoking a trusted device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    UserRemovedDevice,
    SuspectedCompromise,
    KeyRotation,
    PolicyViolation,
}

/// Typed operational action emitted when revoking a peer (executed by transport in `M1.4`/`M1.5`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityAction {
    DisconnectPeerSessions {
        device_id: DeviceId,
        reason: RevocationReason,
        revoked_epoch: u64,
    },
}

/// Metadata persisted for a paired and trusted remote peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPeerRecord {
    pub device_id: DeviceId,
    pub spki_der: [u8; 44],
    pub role: PeerRole,
    pub friendly_name: String,
    pub base_permissions: Permissions,
    pub paired_at_unix: u64,
    pub last_seen_unix: u64,
    pub trust_epoch: u64,
    pub perm_epoch: u64,
}

/// Tombstone recorded when a previously trusted device is revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationRecord {
    pub device_id: DeviceId,
    pub revoked_at_unix: u64,
    pub reason: RevocationReason,
    pub revoked_epoch: u64,
}

/// Abstract trust store interface implemented by in-memory tests and future OS keystore adapters.
pub trait TrustStore: Send + Sync {
    /// Authorize a peer presenting `identity` with `expected_role`, rejecting unknown or revoked peers.
    fn verify_trusted_peer(
        &self,
        identity: &PublicIdentity,
        expected_role: PeerRole,
    ) -> Result<TrustedPeerRecord, SecurityError>;

    /// Query whether `device_id` is currently revoked.
    fn is_revoked(&self, device_id: DeviceId) -> bool;

    /// Lookup trusted peer metadata without mutating store state.
    fn get_peer(&self, device_id: DeviceId) -> Option<TrustedPeerRecord>;

    /// Return the highest known trust/revocation epoch observed for `device_id` (`0` if unknown).
    fn peer_epoch(&self, device_id: DeviceId) -> u64;
}

#[derive(Default)]
struct StoreInner {
    trusted: BTreeMap<DeviceId, TrustedPeerRecord>,
    revoked: BTreeMap<DeviceId, RevocationRecord>,
    consumed_commits: BTreeSet<[u8; 32]>,
    consumed_commits_order: VecDeque<[u8; 32]>,
}

impl StoreInner {
    fn current_peer_epoch(&self, device_id: DeviceId) -> u64 {
        self.revoked
            .get(&device_id)
            .map(|r| r.revoked_epoch)
            .into_iter()
            .chain(self.trusted.get(&device_id).map(|p| p.trust_epoch))
            .max()
            .unwrap_or(0)
    }

    fn record_consumed_commit(&mut self, digest: [u8; 32]) {
        if self.consumed_commits.insert(digest) {
            if self.consumed_commits_order.len() >= MAX_CONSUMED_PAIRING_COMMITS {
                if let Some(oldest) = self.consumed_commits_order.pop_front() {
                    self.consumed_commits.remove(&oldest);
                }
            }
            self.consumed_commits_order.push_back(digest);
        }
    }
}

/// Thread-safe in-memory reference [`TrustStore`].
#[derive(Default)]
pub struct InMemoryTrustStore {
    inner: RwLock<StoreInner>,
}

impl InMemoryTrustStore {
    /// Create an empty zero-trust store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Persist a proven [`ApprovedPairingCommit`] produced after cryptographic auth + local human approval.
    ///
    /// Consumes `commit` by value, rejects `INPUT_*` permissions, rejects revoked peers (use
    /// [`Self::re_trust_after_approved_pairing`]), rejects replayed commits, and rejects commits whose
    /// `expected_peer_epoch` no longer matches the live store generation.
    #[allow(clippy::needless_pass_by_value)]
    pub fn insert_approved_pairing(
        &self,
        commit: ApprovedPairingCommit,
        now_unix: u64,
    ) -> Result<TrustedPeerRecord, SecurityError> {
        if commit.granted_base_perms().has_any_input() {
            return Err(SecurityError::AuthorizationDenied(
                "initial pairing cannot persist remote input permissions",
            ));
        }
        let friendly_name = validate_friendly_name(commit.friendly_name().to_owned())?;
        let identity = commit.peer_identity();
        let digest = commit.channel_binding_digest();

        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        let device_id = identity.device_id();
        if guard.consumed_commits.contains(&digest) {
            return Err(SecurityError::ReplayDetected);
        }
        if guard.revoked.contains_key(&device_id) {
            return Err(SecurityError::RevokedDevice);
        }
        let current_epoch = guard.current_peer_epoch(device_id);
        if current_epoch != commit.expected_peer_epoch() {
            return Err(SecurityError::PairingState(
                "stale pairing commit: peer trust epoch changed",
            ));
        }
        if let Some(prev) = guard.trusted.get(&device_id) {
            if prev.spki_der != *identity.spki_der() {
                return Err(SecurityError::IdentityMismatch(
                    "refusing silent SPKI overwrite for existing DeviceId",
                ));
            }
        } else if guard.trusted.len() >= MAX_TRUSTED_PEERS {
            return Err(SecurityError::ResourceExhausted(
                "trusted peer store capacity reached",
            ));
        }
        let next_epoch = current_epoch
            .checked_add(1)
            .ok_or(SecurityError::ResourceExhausted("trust epoch overflow"))?;
        guard.record_consumed_commit(digest);
        let record = TrustedPeerRecord {
            device_id,
            spki_der: *identity.spki_der(),
            role: commit.peer_role(),
            friendly_name,
            base_permissions: commit.granted_base_perms(),
            paired_at_unix: now_unix,
            last_seen_unix: now_unix,
            trust_epoch: next_epoch,
            perm_epoch: 1,
        };
        guard.trusted.insert(device_id, record.clone());
        Ok(record)
    }

    /// Re-pair a previously revoked (or previously trusted) device using a fresh [`ApprovedPairingCommit`]
    /// bound to the peer's current trust/revocation epoch (`expected_peer_epoch`).
    ///
    /// Consumes `commit` by value, advances `trust_epoch` strictly past the revoked epoch, and
    /// rejects stale commits produced prior to a newer revocation or trust-epoch update.
    #[allow(clippy::needless_pass_by_value)]
    pub fn re_trust_after_approved_pairing(
        &self,
        commit: ApprovedPairingCommit,
        now_unix: u64,
    ) -> Result<TrustedPeerRecord, SecurityError> {
        if commit.granted_base_perms().has_any_input() {
            return Err(SecurityError::AuthorizationDenied(
                "re-pairing cannot persist remote input permissions",
            ));
        }
        let friendly_name = validate_friendly_name(commit.friendly_name().to_owned())?;
        let identity = commit.peer_identity();
        let digest = commit.channel_binding_digest();

        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        let device_id = identity.device_id();
        if guard.consumed_commits.contains(&digest) {
            return Err(SecurityError::ReplayDetected);
        }
        let current_epoch = guard.current_peer_epoch(device_id);
        if current_epoch == 0 {
            return Err(SecurityError::PairingState(
                "re_trust_after_approved_pairing requires prior trust or revocation history",
            ));
        }
        if current_epoch != commit.expected_peer_epoch() {
            return Err(SecurityError::PairingState(
                "stale re-pairing commit: peer trust epoch changed",
            ));
        }
        if let Some(prev) = guard.trusted.get(&device_id) {
            if prev.spki_der != *identity.spki_der() {
                return Err(SecurityError::IdentityMismatch(
                    "refusing silent SPKI overwrite for existing DeviceId",
                ));
            }
        } else if guard.trusted.len() >= MAX_TRUSTED_PEERS {
            return Err(SecurityError::ResourceExhausted(
                "trusted peer store capacity reached",
            ));
        }
        guard.revoked.remove(&device_id);
        let next_epoch = current_epoch
            .checked_add(1)
            .ok_or(SecurityError::ResourceExhausted("trust epoch overflow"))?;
        guard.record_consumed_commit(digest);
        let record = TrustedPeerRecord {
            device_id,
            spki_der: *identity.spki_der(),
            role: commit.peer_role(),
            friendly_name,
            base_permissions: commit.granted_base_perms(),
            paired_at_unix: now_unix,
            last_seen_unix: now_unix,
            trust_epoch: next_epoch,
            perm_epoch: 1,
        };
        guard.trusted.insert(device_id, record.clone());
        Ok(record)
    }

    /// Explicitly import a pre-persisted peer record from an administrative vault/restore source.
    ///
    /// Separated from ordinary pairing APIs; enforces monotonic epoch ordering against revocations
    /// and rejects silent SPKI overwrites.
    pub fn import_trusted_peer_admin(
        &self,
        import: AdminTrustImportRecord,
    ) -> Result<TrustedPeerRecord, SecurityError> {
        if import.trust_epoch == 0
            || import.perm_epoch == 0
            || import.trust_epoch == u64::MAX
            || import.perm_epoch == u64::MAX
        {
            return Err(SecurityError::InvalidTimestamp(
                "administrative trust import requires trust_epoch and perm_epoch in 1..u64::MAX",
            ));
        }
        let friendly_name = validate_friendly_name(import.friendly_name)?;
        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        let device_id = import.identity.device_id();
        if let Some(rev) = guard.revoked.get(&device_id) {
            if rev.revoked_epoch >= import.trust_epoch {
                return Err(SecurityError::RevokedDevice);
            }
        }
        if let Some(prev) = guard.trusted.get(&device_id) {
            if prev.spki_der != *import.identity.spki_der() {
                return Err(SecurityError::IdentityMismatch(
                    "refusing silent SPKI overwrite for existing DeviceId",
                ));
            }
            if prev.trust_epoch >= import.trust_epoch {
                return Err(SecurityError::PairingState(
                    "cannot import stale administrative trust epoch",
                ));
            }
        } else if guard.trusted.len() >= MAX_TRUSTED_PEERS {
            return Err(SecurityError::ResourceExhausted(
                "trusted peer store capacity reached",
            ));
        }
        guard.revoked.remove(&device_id);
        let record = TrustedPeerRecord {
            device_id,
            spki_der: *import.identity.spki_der(),
            role: import.role,
            friendly_name,
            base_permissions: import.base_permissions,
            paired_at_unix: import.paired_at_unix,
            last_seen_unix: import.last_seen_unix,
            trust_epoch: import.trust_epoch,
            perm_epoch: import.perm_epoch,
        };
        guard.trusted.insert(device_id, record.clone());
        Ok(record)
    }

    /// Test-only helper to seed a trusted peer fixture without running a full pairing handshake.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn insert_trusted_peer_for_testing(
        &self,
        identity: &PublicIdentity,
        role: PeerRole,
        friendly_name: impl Into<String>,
        base_permissions: Permissions,
        now_unix: u64,
    ) -> Result<TrustedPeerRecord, SecurityError> {
        if base_permissions.has_any_input() {
            return Err(SecurityError::AuthorizationDenied(
                "initial pairing cannot persist remote input permissions",
            ));
        }
        let friendly_name = validate_friendly_name(friendly_name.into())?;
        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        let device_id = identity.device_id();
        if guard.revoked.contains_key(&device_id) {
            return Err(SecurityError::RevokedDevice);
        }
        if let Some(prev) = guard.trusted.get(&device_id) {
            if prev.spki_der != *identity.spki_der() {
                return Err(SecurityError::IdentityMismatch(
                    "refusing silent SPKI overwrite for existing DeviceId",
                ));
            }
        } else if guard.trusted.len() >= MAX_TRUSTED_PEERS {
            return Err(SecurityError::ResourceExhausted(
                "trusted peer store capacity reached",
            ));
        }
        let next_epoch = guard.current_peer_epoch(device_id).saturating_add(1);
        let record = TrustedPeerRecord {
            device_id,
            spki_der: *identity.spki_der(),
            role,
            friendly_name,
            base_permissions,
            paired_at_unix: now_unix,
            last_seen_unix: now_unix,
            trust_epoch: next_epoch,
            perm_epoch: 1,
        };
        guard.trusted.insert(device_id, record.clone());
        Ok(record)
    }

    /// Test-only helper to re-trust a previously revoked peer fixture without running full pairing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn re_trust_peer_for_testing(
        &self,
        identity: &PublicIdentity,
        role: PeerRole,
        friendly_name: impl Into<String>,
        base_permissions: Permissions,
        now_unix: u64,
    ) -> Result<TrustedPeerRecord, SecurityError> {
        if base_permissions.has_any_input() {
            return Err(SecurityError::AuthorizationDenied(
                "re-pairing cannot persist remote input permissions",
            ));
        }
        let friendly_name = validate_friendly_name(friendly_name.into())?;
        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        let device_id = identity.device_id();
        if !guard.trusted.contains_key(&device_id) && guard.trusted.len() >= MAX_TRUSTED_PEERS {
            return Err(SecurityError::ResourceExhausted(
                "trusted peer store capacity reached",
            ));
        }
        let prev_epoch = guard.current_peer_epoch(device_id);
        guard.revoked.remove(&device_id);
        let record = TrustedPeerRecord {
            device_id,
            spki_der: *identity.spki_der(),
            role,
            friendly_name,
            base_permissions,
            paired_at_unix: now_unix,
            last_seen_unix: now_unix,
            trust_epoch: prev_epoch.saturating_add(1),
            perm_epoch: 1,
        };
        guard.trusted.insert(device_id, record.clone());
        Ok(record)
    }

    /// Revoke a device atomically, advance `revoked_epoch` strictly past any prior epoch,
    /// and record a monotonic revocation tombstone.
    pub fn revoke(
        &self,
        device_id: DeviceId,
        reason: RevocationReason,
        now_unix: u64,
    ) -> Result<RevocationRecord, SecurityError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        if !guard.revoked.contains_key(&device_id) && guard.revoked.len() >= MAX_REVOKED_PEERS {
            return Err(SecurityError::ResourceExhausted(
                "revocation tombstone store capacity reached",
            ));
        }
        let prior_trusted = guard.trusted.remove(&device_id);
        let prior_revoked = guard.revoked.get(&device_id).copied();
        let next_epoch = prior_trusted
            .map(|p| p.trust_epoch)
            .into_iter()
            .chain(prior_revoked.map(|r| r.revoked_epoch))
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let tombstone = RevocationRecord {
            device_id,
            revoked_at_unix: now_unix,
            reason,
            revoked_epoch: next_epoch,
        };
        guard.revoked.insert(device_id, tombstone);
        Ok(tombstone)
    }

    /// Update base permissions for a currently trusted peer (for example, downgrading input rights).
    pub fn update_base_permissions(
        &self,
        device_id: DeviceId,
        new_base_permissions: Permissions,
        now_unix: u64,
    ) -> Result<TrustedPeerRecord, SecurityError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        if guard.revoked.contains_key(&device_id) {
            return Err(SecurityError::RevokedDevice);
        }
        let rec = guard
            .trusted
            .get_mut(&device_id)
            .ok_or(SecurityError::UntrustedDevice)?;
        rec.base_permissions = new_base_permissions;
        rec.perm_epoch = rec.perm_epoch.saturating_add(1);
        rec.last_seen_unix = rec.last_seen_unix.max(now_unix);
        Ok(rec.clone())
    }

    /// Atomically verify peer trust, role, SPKI, `expected_trust_epoch`, and `expected_perm_epoch`
    /// under a single write lock, then union `add_perms` into `base_permissions` and advance `perm_epoch`.
    pub fn elevate_permissions_atomic(
        &self,
        peer_identity: &PublicIdentity,
        expected_role: PeerRole,
        expected_trust_epoch: u64,
        expected_perm_epoch: u64,
        add_perms: Permissions,
        now_unix: u64,
    ) -> Result<TrustedPeerRecord, SecurityError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        let device_id = peer_identity.device_id();
        if guard.revoked.contains_key(&device_id) {
            return Err(SecurityError::RevokedDevice);
        }
        let rec = guard
            .trusted
            .get_mut(&device_id)
            .ok_or(SecurityError::UntrustedDevice)?;
        if rec.spki_der != *peer_identity.spki_der() {
            return Err(SecurityError::IdentityMismatch(
                "stored SPKI differs from authenticated peer",
            ));
        }
        if rec.role != expected_role {
            return Err(SecurityError::RoleConfusion);
        }
        if rec.trust_epoch != expected_trust_epoch {
            return Err(SecurityError::RevokedDevice);
        }
        if rec.perm_epoch != expected_perm_epoch {
            return Err(SecurityError::AuthorizationDenied(
                "stale permission epoch; upgrade request invalidated by concurrent permission change",
            ));
        }
        rec.base_permissions = rec.base_permissions.union(add_perms);
        rec.perm_epoch = rec.perm_epoch.saturating_add(1);
        rec.last_seen_unix = rec.last_seen_unix.max(now_unix);
        Ok(rec.clone())
    }

    /// Record last-seen timestamp for a trusted device.
    pub fn touch_last_seen(&self, device_id: DeviceId, now_unix: u64) -> Result<(), SecurityError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        let rec = guard
            .trusted
            .get_mut(&device_id)
            .ok_or(SecurityError::UntrustedDevice)?;
        rec.last_seen_unix = rec.last_seen_unix.max(now_unix);
        Ok(())
    }
}

impl TrustStore for InMemoryTrustStore {
    fn verify_trusted_peer(
        &self,
        identity: &PublicIdentity,
        expected_role: PeerRole,
    ) -> Result<TrustedPeerRecord, SecurityError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        let device_id = identity.device_id();
        if guard.revoked.contains_key(&device_id) {
            return Err(SecurityError::RevokedDevice);
        }
        let record = guard
            .trusted
            .get(&device_id)
            .ok_or(SecurityError::UntrustedDevice)?;
        if record.spki_der != *identity.spki_der() {
            return Err(SecurityError::IdentityMismatch(
                "stored SPKI differs from presented certificate",
            ));
        }
        if record.role != expected_role {
            return Err(SecurityError::RoleConfusion);
        }
        Ok(record.clone())
    }

    fn is_revoked(&self, device_id: DeviceId) -> bool {
        self.inner
            .read()
            .map_or(true, |g| g.revoked.contains_key(&device_id))
    }

    fn get_peer(&self, device_id: DeviceId) -> Option<TrustedPeerRecord> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.trusted.get(&device_id).cloned())
    }

    fn peer_epoch(&self, device_id: DeviceId) -> u64 {
        self.inner
            .read()
            .map_or(0, |g| g.current_peer_epoch(device_id))
    }
}

fn validate_friendly_name(name: String) -> Result<String, SecurityError> {
    if name.is_empty() || name.len() > MAX_FRIENDLY_NAME_BYTES {
        return Err(SecurityError::ProtocolViolation(
            "friendly_name length must be within 1..=48 bytes",
        ));
    }
    if name.bytes().any(|b| b == 0 || b.is_ascii_control()) {
        return Err(SecurityError::ProtocolViolation(
            "friendly_name must not contain NUL or control characters",
        ));
    }
    Ok(name)
}
