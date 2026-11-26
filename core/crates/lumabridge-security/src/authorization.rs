// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Default-deny operational & remote-input authorization policy with live trust re-checks.

use crate::error::SecurityError;
use crate::identity::{DeviceId, PeerRole, PublicIdentity};
use crate::trust_store::{InMemoryTrustStore, TrustStore};
use lumabridge_protocol::control::Permissions;

/// Explicit local user consent port required before granting remote input permissions (`INPUT_MASK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputApprovalDecision {
    /// Local operator explicitly approves elevating to `granted_input_perms`.
    Approve { granted_input_perms: Permissions },
    /// Local operator denies remote input elevation.
    Deny,
}

/// Active session authorization state bound to a peer's `DeviceId`, role, and `trust_epoch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionGrant {
    pub session_id: u64,
    pub peer_device_id: DeviceId,
    pub expected_role: PeerRole,
    pub trust_epoch: u64,
    pub session_granted_perms: Permissions,
    pub expires_at_unix: u64,
}

/// Evaluate initial session permissions as `stored_base_perms ∩ requested_perms` (default-deny).
///
/// Always re-verifies the peer live in `trust_store`, rejecting unknown, revoked, SPKI-mismatched,
/// or wrong-role devices, and strips any `INPUT_MASK` bits absent from `stored_base_perms`.
pub fn authorize_session_open(
    trust_store: &dyn TrustStore,
    peer_identity: &PublicIdentity,
    expected_role: PeerRole,
    requested_perms: Permissions,
    session_id: u64,
    expires_at_unix: u64,
) -> Result<SessionGrant, SecurityError> {
    let record = trust_store.verify_trusted_peer(peer_identity, expected_role)?;
    let effective = record.base_permissions.intersection(requested_perms);
    Ok(SessionGrant {
        session_id,
        peer_device_id: record.device_id,
        expected_role,
        trust_epoch: record.trust_epoch,
        session_granted_perms: effective,
        expires_at_unix,
    })
}

/// Authorize a mid-session operation against BOTH live `trust_store` state and `grant`.
///
/// Immediately returns an error on device revocation, trust-epoch advance (re-pairing),
/// role confusion, session expiration, or live `TrustStore` permission downgrade.
pub fn authorize_action(
    trust_store: &dyn TrustStore,
    peer_identity: &PublicIdentity,
    grant: &SessionGrant,
    required_perm: Permissions,
    now_unix: u64,
) -> Result<Permissions, SecurityError> {
    let record = trust_store.verify_trusted_peer(peer_identity, grant.expected_role)?;
    if record.device_id != grant.peer_device_id {
        return Err(SecurityError::IdentityMismatch(
            "authenticated peer differs from session grant owner",
        ));
    }
    if record.trust_epoch != grant.trust_epoch {
        return Err(SecurityError::RevokedDevice);
    }
    if now_unix > grant.expires_at_unix {
        return Err(SecurityError::SessionTokenInvalid("session grant expired"));
    }

    let effective = record
        .base_permissions
        .intersection(grant.session_granted_perms);
    if !effective.contains(required_perm) {
        return Err(SecurityError::AuthorizationDenied(
            "required permission not active in effective intersection",
        ));
    }
    Ok(effective)
}

/// Elevate a live session grant with remote input rights ONLY upon explicit local approval.
///
/// Updates the authoritative stored peer base permissions atomically in `trust_store` and
/// returns an updated `SessionGrant` containing the approved bits, re-verifying revocation and
/// `trust_epoch` invariants first.
pub fn apply_input_elevation(
    trust_store: &InMemoryTrustStore,
    peer_identity: &PublicIdentity,
    grant: &mut SessionGrant,
    requested_input_perms: Permissions,
    decision: InputApprovalDecision,
    now_unix: u64,
) -> Result<Permissions, SecurityError> {
    let record = trust_store.verify_trusted_peer(peer_identity, grant.expected_role)?;
    if record.device_id != grant.peer_device_id {
        return Err(SecurityError::IdentityMismatch(
            "authenticated peer differs from session grant owner",
        ));
    }
    if record.trust_epoch != grant.trust_epoch {
        return Err(SecurityError::RevokedDevice);
    }
    if now_unix > grant.expires_at_unix {
        return Err(SecurityError::SessionTokenInvalid("session grant expired"));
    }
    if !requested_input_perms.has_any_input() {
        return Err(SecurityError::AuthorizationDenied(
            "input elevation requires at least one INPUT_* bit",
        ));
    }

    match decision {
        InputApprovalDecision::Deny => Err(SecurityError::ApprovalRequired),
        InputApprovalDecision::Approve {
            granted_input_perms,
        } => {
            let input_mask_only = Permissions::from_raw(Permissions::INPUT_MASK)
                .map_err(|_| SecurityError::AuthorizationDenied("invalid input mask"))?;
            let approved_input = requested_input_perms
                .intersection(granted_input_perms)
                .intersection(input_mask_only);
            if approved_input == Permissions::NONE {
                return Err(SecurityError::AuthorizationDenied(
                    "local approval granted no requested input permissions",
                ));
            }
            let updated_base = record.base_permissions.union(approved_input);
            let updated_record =
                trust_store.update_base_permissions(record.device_id, updated_base, now_unix)?;
            if updated_record.trust_epoch != grant.trust_epoch {
                return Err(SecurityError::RevokedDevice);
            }
            grant.session_granted_perms = grant.session_granted_perms.union(approved_input);
            Ok(updated_record
                .base_permissions
                .intersection(grant.session_granted_perms))
        }
    }
}
