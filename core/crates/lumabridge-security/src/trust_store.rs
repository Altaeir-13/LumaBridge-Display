// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Zero-trust peer store, monotonic revocation, and trust lifecycle policies.
//!
//! IMPORTANT: [`InMemoryTrustStore`] is an in-memory reference implementation of
//! [`TrustStore`] for protocol qualification and tests. Persistent platform vaults
//! (Windows DPAPI / CNG, Android Keystore, macOS Keychain, Linux Secret Service)
//! remain outside the portable `lumabridge-security` crate boundary.

use crate::error::SecurityError;
use crate::identity::{DeviceId, PeerRole, PublicIdentity};
use lumabridge_protocol::control::Permissions;
use std::collections::BTreeMap;
use std::sync::RwLock;

/// Reason recorded when revoking a trusted device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    UserRemovedDevice,
    SuspectedCompromise,
    KeyRotation,
    PolicyViolation,
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
}

#[derive(Default)]
struct StoreInner {
    trusted: BTreeMap<DeviceId, TrustedPeerRecord>,
    revoked: BTreeMap<DeviceId, RevocationRecord>,
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

    /// Persist a newly paired device after authenticated pairing and local approval.
    ///
    /// Rejects registration if the device was previously revoked unless [`Self::re_trust_after_pairing`]
    /// is invoked explicitly with fresh pairing verification.
    pub fn insert_newly_paired(
        &self,
        identity: &PublicIdentity,
        role: PeerRole,
        friendly_name: impl Into<String>,
        base_permissions: Permissions,
        now_unix: u64,
    ) -> Result<TrustedPeerRecord, SecurityError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        let device_id = identity.device_id();
        if guard.revoked.contains_key(&device_id) {
            return Err(SecurityError::RevokedDevice);
        }
        let next_epoch = guard
            .trusted
            .get(&device_id)
            .map_or(1, |prev| prev.trust_epoch.saturating_add(1));
        let record = TrustedPeerRecord {
            device_id,
            spki_der: *identity.spki_der(),
            role,
            friendly_name: friendly_name.into(),
            base_permissions,
            paired_at_unix: now_unix,
            last_seen_unix: now_unix,
            trust_epoch: next_epoch,
        };
        guard.trusted.insert(device_id, record.clone());
        Ok(record)
    }

    /// Re-pair a previously revoked device after a fresh out-of-band pairing flow.
    ///
    /// Advances `trust_epoch` strictly past the revoked epoch so tokens bound to older epochs stay invalid.
    pub fn re_trust_after_pairing(
        &self,
        identity: &PublicIdentity,
        role: PeerRole,
        friendly_name: impl Into<String>,
        base_permissions: Permissions,
        now_unix: u64,
    ) -> Result<TrustedPeerRecord, SecurityError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| SecurityError::AuthorizationDenied("trust store lock poisoned"))?;
        let device_id = identity.device_id();
        let prev_epoch = guard
            .revoked
            .remove(&device_id)
            .map(|r| r.revoked_epoch)
            .into_iter()
            .chain(guard.trusted.get(&device_id).map(|p| p.trust_epoch))
            .max()
            .unwrap_or(0);
        let record = TrustedPeerRecord {
            device_id,
            spki_der: *identity.spki_der(),
            role,
            friendly_name: friendly_name.into(),
            base_permissions,
            paired_at_unix: now_unix,
            last_seen_unix: now_unix,
            trust_epoch: prev_epoch.saturating_add(1),
        };
        guard.trusted.insert(device_id, record.clone());
        Ok(record)
    }

    /// Revoke a device atomically and record a monotonic revocation tombstone.
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
        let prior_trusted = guard.trusted.remove(&device_id);
        let prior_revoked = guard.revoked.get(&device_id).copied();
        let epoch = prior_trusted
            .map(|p| p.trust_epoch)
            .or_else(|| prior_revoked.map(|r| r.revoked_epoch))
            .unwrap_or(1);
        let tombstone = RevocationRecord {
            device_id,
            revoked_at_unix: now_unix,
            reason,
            revoked_epoch: epoch,
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
        rec.last_seen_unix = now_unix;
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
}
