// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cryptographically bound session tokens and single-use rotating resume tokens.

use crate::channel_binding::ChannelBinding;
use crate::error::SecurityError;
use crate::identity::{DeviceId, PeerRole, PublicIdentity};
use crate::secret::{constant_time_eq, CheckedOsCryptoRng, ResumeTokenSecret, SessionTokenSecret};
use crate::transcript::{derive_resume_channel_proof, derive_token_digest};
use crate::trust_store::TrustStore;
use core::fmt;
use lumabridge_protocol::control::{Permissions, OPAQUE_TOKEN_LEN};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Maximum permitted lifetime for a session credential (24 hours).
pub const MAX_SESSION_TTL_SECS: u64 = 86_400;

/// Maximum permitted lifetime for a single-use resume credential (15 minutes).
pub const MAX_RESUME_TTL_SECS: u64 = 900;

/// Newly issued credentials returned to the caller on `SessionOpen`.
pub struct IssuedSessionCredentials {
    pub session_id: u64,
    pub peer_device_id: DeviceId,
    pub trust_epoch: u64,
    pub effective_permissions: Permissions,
    pub session_token: SessionTokenSecret,
    pub resume_token: ResumeTokenSecret,
    pub session_expires_at_unix: u64,
    pub resume_expires_at_unix: u64,
}

impl fmt::Debug for IssuedSessionCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedSessionCredentials")
            .field("session_id", &self.session_id)
            .field("peer_device_id", &self.peer_device_id)
            .field("trust_epoch", &self.trust_epoch)
            .field("effective_permissions", &self.effective_permissions)
            .field("session_token", &"[REDACTED]")
            .field("resume_token", &"[REDACTED]")
            .field("session_expires_at_unix", &self.session_expires_at_unix)
            .field("resume_expires_at_unix", &self.resume_expires_at_unix)
            .finish()
    }
}

/// Output produced after atomically validating and rotating a single-use resume token.
pub struct ValidatedResumeResult {
    pub session_id: u64,
    pub peer_device_id: DeviceId,
    pub trust_epoch: u64,
    pub effective_permissions: Permissions,
    pub rotated_resume_token: ResumeTokenSecret,
    pub session_expires_at_unix: u64,
    pub resume_expires_at_unix: u64,
}

impl fmt::Debug for ValidatedResumeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedResumeResult")
            .field("session_id", &self.session_id)
            .field("peer_device_id", &self.peer_device_id)
            .field("trust_epoch", &self.trust_epoch)
            .field("effective_permissions", &self.effective_permissions)
            .field("rotated_resume_token", &"[REDACTED]")
            .field("session_expires_at_unix", &self.session_expires_at_unix)
            .field("resume_expires_at_unix", &self.resume_expires_at_unix)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct ActiveSessionEntry {
    session_id: u64,
    peer_device_id: DeviceId,
    expected_role: PeerRole,
    trust_epoch: u64,
    session_granted_perms: Permissions,
    session_token_digest: [u8; 32],
    session_expires_at_unix: u64,
    revoked: bool,
}

#[derive(Debug, Clone, Copy)]
struct ResumeEntry {
    session_id: u64,
    peer_device_id: DeviceId,
    trust_epoch: u64,
    expires_at_unix: u64,
    consumed: bool,
}

#[derive(Default)]
struct SessionStoreInner {
    sessions: BTreeMap<u64, ActiveSessionEntry>,
    resume_by_digest: BTreeMap<[u8; 32], ResumeEntry>,
}

/// Thread-safe session & single-use resume token authority storing HMAC-SHA256 digests only.
#[derive(Default)]
pub struct SessionTokenManager {
    inner: Mutex<SessionStoreInner>,
}

impl SessionTokenManager {
    /// Create an empty session token manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a fresh session and single-use resume token for a trusted peer.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_session(
        &self,
        rng: &mut CheckedOsCryptoRng,
        trust_store: &dyn TrustStore,
        peer_identity: &PublicIdentity,
        expected_role: PeerRole,
        requested_perms: Permissions,
        now_unix: u64,
        session_ttl_secs: u64,
        resume_ttl_secs: u64,
    ) -> Result<IssuedSessionCredentials, SecurityError> {
        if session_ttl_secs == 0 || session_ttl_secs > MAX_SESSION_TTL_SECS {
            return Err(SecurityError::InvalidTimestamp(
                "session_ttl_secs must be within 1..=86400",
            ));
        }
        if resume_ttl_secs == 0 || resume_ttl_secs > MAX_RESUME_TTL_SECS {
            return Err(SecurityError::InvalidTimestamp(
                "resume_ttl_secs must be within 1..=900",
            ));
        }

        let record = trust_store.verify_trusted_peer(peer_identity, expected_role)?;
        let effective = record.base_permissions.intersection(requested_perms);

        let session_expires_at_unix = now_unix
            .checked_add(session_ttl_secs)
            .ok_or(SecurityError::InvalidTimestamp("session expiry overflow"))?;
        let resume_expires_at_unix = now_unix
            .checked_add(resume_ttl_secs)
            .ok_or(SecurityError::InvalidTimestamp("resume expiry overflow"))?;

        let mut id_bytes = [0u8; 8];
        rng.fill_bytes(&mut id_bytes)?;
        let mut session_id = u64::from_be_bytes(id_bytes);
        if session_id == 0 {
            session_id = 1;
        }
        let session_token = SessionTokenSecret::generate(rng)?;
        let resume_token = ResumeTokenSecret::generate(rng)?;

        let session_digest = derive_token_digest(
            session_token.expose_secret(),
            record.device_id,
            record.trust_epoch,
        );
        let resume_digest = derive_token_digest(
            resume_token.expose_secret(),
            record.device_id,
            record.trust_epoch,
        );

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("session store lock poisoned"))?;
        while guard.sessions.contains_key(&session_id) || session_id == 0 {
            session_id = session_id.wrapping_add(1);
        }
        // Opportunistically prune expired records to bound memory.
        guard
            .sessions
            .retain(|_, s| !s.revoked && s.session_expires_at_unix >= now_unix);
        guard
            .resume_by_digest
            .retain(|_, r| r.expires_at_unix >= now_unix);

        guard.sessions.insert(
            session_id,
            ActiveSessionEntry {
                session_id,
                peer_device_id: record.device_id,
                expected_role,
                trust_epoch: record.trust_epoch,
                session_granted_perms: effective,
                session_token_digest: session_digest,
                session_expires_at_unix,
                revoked: false,
            },
        );
        guard.resume_by_digest.insert(
            resume_digest,
            ResumeEntry {
                session_id,
                peer_device_id: record.device_id,
                trust_epoch: record.trust_epoch,
                expires_at_unix: resume_expires_at_unix,
                consumed: false,
            },
        );
        drop(guard);

        Ok(IssuedSessionCredentials {
            session_id,
            peer_device_id: record.device_id,
            trust_epoch: record.trust_epoch,
            effective_permissions: effective,
            session_token,
            resume_token,
            session_expires_at_unix,
            resume_expires_at_unix,
        })
    }

    /// Validate a session token against live `TrustStore` state and return live effective perms.
    pub fn validate_session_token(
        &self,
        trust_store: &dyn TrustStore,
        peer_identity: &PublicIdentity,
        expected_role: PeerRole,
        session_id: u64,
        raw_session_token: &[u8],
        now_unix: u64,
    ) -> Result<Permissions, SecurityError> {
        let token_arr: [u8; OPAQUE_TOKEN_LEN] = raw_session_token
            .try_into()
            .map_err(|_| SecurityError::SessionTokenInvalid("session token must be 32 bytes"))?;
        let record = trust_store.verify_trusted_peer(peer_identity, expected_role)?;
        let candidate_digest =
            derive_token_digest(&token_arr, record.device_id, record.trust_epoch);

        let guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("session store lock poisoned"))?;
        let entry = guard
            .sessions
            .get(&session_id)
            .ok_or(SecurityError::SessionTokenInvalid("unknown session_id"))?;
        if entry.revoked || entry.trust_epoch != record.trust_epoch {
            return Err(SecurityError::RevokedDevice);
        }
        if entry.peer_device_id != record.device_id || entry.expected_role != expected_role {
            return Err(SecurityError::IdentityMismatch(
                "session token owner or role mismatch",
            ));
        }
        if !constant_time_eq(&entry.session_token_digest, &candidate_digest) {
            return Err(SecurityError::SessionTokenInvalid(
                "session token digest mismatch",
            ));
        }
        if now_unix > entry.session_expires_at_unix {
            return Err(SecurityError::SessionTokenInvalid("session token expired"));
        }

        Ok(record
            .base_permissions
            .intersection(entry.session_granted_perms))
    }

    /// Atomically consume a single-use resume token (optionally enforcing channel-bound proof)
    /// and rotate it to a fresh `ResumeTokenSecret`.
    #[allow(clippy::too_many_arguments)]
    pub fn consume_and_rotate_resume_token(
        &self,
        rng: &mut CheckedOsCryptoRng,
        trust_store: &dyn TrustStore,
        peer_identity: &PublicIdentity,
        expected_role: PeerRole,
        session_id: u64,
        raw_resume_token: &[u8],
        channel_binding: Option<&ChannelBinding>,
        presented_channel_proof: Option<&[u8; 32]>,
        now_unix: u64,
        new_resume_ttl_secs: u64,
    ) -> Result<ValidatedResumeResult, SecurityError> {
        if new_resume_ttl_secs == 0 || new_resume_ttl_secs > MAX_RESUME_TTL_SECS {
            return Err(SecurityError::InvalidTimestamp(
                "new_resume_ttl_secs must be within 1..=900",
            ));
        }
        let token = ResumeTokenSecret::from_slice(raw_resume_token)
            .map_err(|_| SecurityError::SessionTokenInvalid("resume token must be 32 bytes"))?;
        let record = trust_store.verify_trusted_peer(peer_identity, expected_role)?;

        if let (Some(cb), Some(expected_proof)) = (channel_binding, presented_channel_proof) {
            let computed = derive_resume_channel_proof(&token, cb, record.device_id, session_id)?;
            if !constant_time_eq(&computed, expected_proof) {
                return Err(SecurityError::ChannelBindingMismatch);
            }
        } else if channel_binding.is_some() ^ presented_channel_proof.is_some() {
            return Err(SecurityError::ChannelBindingMismatch);
        }

        let digest =
            derive_token_digest(token.expose_secret(), record.device_id, record.trust_epoch);
        let next_resume = ResumeTokenSecret::generate(rng)?;
        let next_digest = derive_token_digest(
            next_resume.expose_secret(),
            record.device_id,
            record.trust_epoch,
        );
        let next_resume_expires_at = now_unix
            .checked_add(new_resume_ttl_secs)
            .ok_or(SecurityError::InvalidTimestamp("resume expiry overflow"))?;

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("session store lock poisoned"))?;

        let (consumed, resume_expired, entry_session_id, entry_device, entry_epoch) = {
            let r_entry = guard
                .resume_by_digest
                .get_mut(&digest)
                .ok_or(SecurityError::SessionTokenInvalid("unknown resume token"))?;
            let was_consumed = r_entry.consumed;
            r_entry.consumed = true;
            (
                was_consumed,
                now_unix > r_entry.expires_at_unix,
                r_entry.session_id,
                r_entry.peer_device_id,
                r_entry.trust_epoch,
            )
        };

        if consumed {
            return Err(SecurityError::SessionTokenReused);
        }
        if entry_session_id != session_id || entry_device != record.device_id {
            return Err(SecurityError::IdentityMismatch(
                "resume token bound to different session or peer",
            ));
        }
        if entry_epoch != record.trust_epoch {
            return Err(SecurityError::RevokedDevice);
        }
        if resume_expired {
            return Err(SecurityError::SessionTokenInvalid("resume token expired"));
        }

        let s_entry =
            guard
                .sessions
                .get(&session_id)
                .copied()
                .ok_or(SecurityError::SessionTokenInvalid(
                    "session no longer active",
                ))?;
        if s_entry.revoked || s_entry.trust_epoch != record.trust_epoch {
            return Err(SecurityError::RevokedDevice);
        }
        if now_unix > s_entry.session_expires_at_unix {
            return Err(SecurityError::SessionTokenInvalid("parent session expired"));
        }

        guard.resume_by_digest.insert(
            next_digest,
            ResumeEntry {
                session_id: s_entry.session_id,
                peer_device_id: record.device_id,
                trust_epoch: record.trust_epoch,
                expires_at_unix: next_resume_expires_at,
                consumed: false,
            },
        );
        drop(guard);

        Ok(ValidatedResumeResult {
            session_id: s_entry.session_id,
            peer_device_id: record.device_id,
            trust_epoch: record.trust_epoch,
            effective_permissions: record
                .base_permissions
                .intersection(s_entry.session_granted_perms),
            rotated_resume_token: next_resume,
            session_expires_at_unix: s_entry.session_expires_at_unix,
            resume_expires_at_unix: next_resume_expires_at,
        })
    }

    /// Synchronize session effective permissions after a runtime authorization update.
    pub fn update_session_permissions(
        &self,
        session_id: u64,
        new_session_perms: Permissions,
    ) -> Result<(), SecurityError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("session store lock poisoned"))?;
        let entry = guard
            .sessions
            .get_mut(&session_id)
            .ok_or(SecurityError::SessionTokenInvalid("unknown session_id"))?;
        entry.session_granted_perms = new_session_perms;
        Ok(())
    }

    /// Immediately invalidate all active sessions and resume tokens belonging to `device_id`.
    pub fn revoke_device_sessions(&self, device_id: DeviceId) -> Result<usize, SecurityError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("session store lock poisoned"))?;
        let mut revoked_count = 0usize;
        for entry in guard.sessions.values_mut() {
            if entry.peer_device_id == device_id && !entry.revoked {
                entry.revoked = true;
                revoked_count += 1;
            }
        }
        guard
            .resume_by_digest
            .retain(|_, resume| resume.peer_device_id != device_id);
        Ok(revoked_count)
    }
}
