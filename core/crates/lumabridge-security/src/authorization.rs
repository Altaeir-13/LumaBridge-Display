// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Default-deny operational & remote-input authorization policy with live trust re-checks,
//! 5-factor permission intersection, and authenticated TLS provenance.

use crate::error::SecurityError;
use crate::identity::{DeviceId, PeerRole};
use crate::tls::AuthenticatedTlsSession;
use crate::trust_store::{InMemoryTrustStore, TrustStore};
use lumabridge_protocol::control::Permissions;

/// Local policy & negotiated capability bounds combined with persisted peer permissions,
/// session grants, and the requested operation (5-factor intersection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationPolicyContext {
    pub local_policy: Permissions,
    pub negotiated_caps: Permissions,
}

impl AuthorizationPolicyContext {
    /// Policy permitting all valid v1 capability bits (subject to persisted trust + session grant).
    #[must_use]
    pub const fn allow_all_v1() -> Self {
        let all = match Permissions::from_raw(Permissions::VALID_V1_MASK) {
            Ok(p) => p,
            Err(_) => Permissions::NONE,
        };
        Self {
            local_policy: all,
            negotiated_caps: all,
        }
    }
}

/// Single-use pending permission upgrade bound to a specific session, sequence number, peer,
/// `trust_epoch`, and `perm_epoch`. Non-`Copy`/`Clone` so approved/denied upgrades cannot be replayed.
#[derive(Debug, PartialEq, Eq)]
pub struct PendingPermissionUpgrade {
    pub session_id: u64,
    pub request_seq: u64,
    pub peer_device_id: DeviceId,
    pub trust_epoch: u64,
    pub perm_epoch: u64,
    pub requested_perms: Permissions,
}

/// Explicit local user consent port required before granting remote input permissions (`INPUT_MASK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputApprovalDecision {
    /// Local operator explicitly approves elevating this exact session/request to `granted_input_perms`.
    Approve {
        session_id: u64,
        request_seq: u64,
        peer_device_id: DeviceId,
        granted_input_perms: Permissions,
    },
    /// Local operator denies remote input elevation for this session/request.
    Deny {
        session_id: u64,
        request_seq: u64,
        peer_device_id: DeviceId,
    },
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

/// Evaluate initial session permissions as
/// `local_policy ∩ stored_base_perms ∩ requested_perms ∩ negotiated_caps` (default-deny).
///
/// Requires a completed operational TLS 1.3 mTLS session (`lumabridge/1`) and always re-verifies
/// live `TrustStore` state before granting any permissions.
pub fn authorize_session_open(
    trust_store: &dyn TrustStore,
    tls_session: &AuthenticatedTlsSession,
    expected_role: PeerRole,
    requested_perms: Permissions,
    policy_ctx: AuthorizationPolicyContext,
    session_id: u64,
    expires_at_unix: u64,
) -> Result<SessionGrant, SecurityError> {
    if session_id == 0 {
        return Err(SecurityError::ProtocolViolation(
            "session_id cannot be zero",
        ));
    }
    tls_session.require_operational_alpn()?;
    let record = trust_store.verify_trusted_peer(tls_session.peer_identity(), expected_role)?;
    let effective = policy_ctx
        .local_policy
        .intersection(record.base_permissions)
        .intersection(requested_perms)
        .intersection(policy_ctx.negotiated_caps);
    Ok(SessionGrant {
        session_id,
        peer_device_id: record.device_id,
        expected_role,
        trust_epoch: record.trust_epoch,
        session_granted_perms: effective,
        expires_at_unix,
    })
}

/// Authorize a mid-session operation against ALL 5 factors:
/// `local_policy ∩ live_stored_base_perms ∩ session_grant ∩ negotiated_caps ∩ required_perm`.
///
/// Immediately rejects revocation, trust-epoch advance, ALPN mismatch, role confusion,
/// session expiration, or live `TrustStore` permission downgrade.
pub fn authorize_action(
    trust_store: &dyn TrustStore,
    tls_session: &AuthenticatedTlsSession,
    grant: &SessionGrant,
    policy_ctx: AuthorizationPolicyContext,
    required_perm: Permissions,
    now_unix: u64,
) -> Result<Permissions, SecurityError> {
    tls_session.require_operational_alpn()?;
    let record =
        trust_store.verify_trusted_peer(tls_session.peer_identity(), grant.expected_role)?;
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

    let effective = policy_ctx
        .local_policy
        .intersection(record.base_permissions)
        .intersection(grant.session_granted_perms)
        .intersection(policy_ctx.negotiated_caps);
    if !effective.contains(required_perm) {
        return Err(SecurityError::AuthorizationDenied(
            "required permission not active in 5-factor effective intersection",
        ));
    }
    Ok(effective)
}

/// Create a bound pending upgrade request after verifying the live TLS session and grant epoch.
pub fn begin_permission_upgrade(
    trust_store: &dyn TrustStore,
    tls_session: &AuthenticatedTlsSession,
    grant: &SessionGrant,
    request_seq: u64,
    requested_input_perms: Permissions,
    now_unix: u64,
) -> Result<PendingPermissionUpgrade, SecurityError> {
    tls_session.require_operational_alpn()?;
    let record =
        trust_store.verify_trusted_peer(tls_session.peer_identity(), grant.expected_role)?;
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
    Ok(PendingPermissionUpgrade {
        session_id: grant.session_id,
        request_seq,
        peer_device_id: grant.peer_device_id,
        trust_epoch: grant.trust_epoch,
        perm_epoch: record.perm_epoch,
        requested_perms: requested_input_perms,
    })
}

/// Atomically elevate a live session grant with remote input rights ONLY upon explicit local approval,
/// consuming `pending` by value (single-use) and enforcing `trust_epoch` + `perm_epoch` invariants.
#[allow(clippy::needless_pass_by_value)]
pub fn apply_input_elevation(
    trust_store: &InMemoryTrustStore,
    tls_session: &AuthenticatedTlsSession,
    grant: &mut SessionGrant,
    pending: PendingPermissionUpgrade,
    decision: InputApprovalDecision,
    policy_ctx: AuthorizationPolicyContext,
    now_unix: u64,
) -> Result<Permissions, SecurityError> {
    tls_session.require_operational_alpn()?;
    if pending.session_id != grant.session_id
        || pending.peer_device_id != grant.peer_device_id
        || pending.trust_epoch != grant.trust_epoch
    {
        return Err(SecurityError::IdentityMismatch(
            "pending upgrade does not match session grant",
        ));
    }
    if tls_session.peer_identity().device_id() != grant.peer_device_id {
        return Err(SecurityError::IdentityMismatch(
            "authenticated peer differs from session grant owner",
        ));
    }
    if now_unix > grant.expires_at_unix {
        return Err(SecurityError::SessionTokenInvalid("session grant expired"));
    }
    if !pending.requested_perms.has_any_input() {
        return Err(SecurityError::AuthorizationDenied(
            "input elevation requires at least one INPUT_* bit",
        ));
    }

    match decision {
        InputApprovalDecision::Deny {
            session_id,
            request_seq,
            peer_device_id,
        } => {
            if session_id != pending.session_id
                || request_seq != pending.request_seq
                || peer_device_id != pending.peer_device_id
            {
                return Err(SecurityError::IdentityMismatch(
                    "approval decision does not match pending upgrade request",
                ));
            }
            Err(SecurityError::ApprovalRequired)
        }
        InputApprovalDecision::Approve {
            session_id,
            request_seq,
            peer_device_id,
            granted_input_perms,
        } => {
            if session_id != pending.session_id
                || request_seq != pending.request_seq
                || peer_device_id != pending.peer_device_id
            {
                return Err(SecurityError::IdentityMismatch(
                    "approval decision does not match pending upgrade request",
                ));
            }
            let input_mask_only = Permissions::from_raw(Permissions::INPUT_MASK)
                .map_err(|_| SecurityError::AuthorizationDenied("invalid input mask"))?;
            let approved_input = pending
                .requested_perms
                .intersection(granted_input_perms)
                .intersection(input_mask_only)
                .intersection(policy_ctx.local_policy)
                .intersection(policy_ctx.negotiated_caps);
            if approved_input == Permissions::NONE {
                return Err(SecurityError::AuthorizationDenied(
                    "local approval or policy granted no requested input permissions",
                ));
            }

            let updated_record = trust_store.elevate_permissions_atomic(
                tls_session.peer_identity(),
                grant.expected_role,
                grant.trust_epoch,
                pending.perm_epoch,
                approved_input,
                now_unix,
            )?;
            grant.session_granted_perms = grant.session_granted_perms.union(approved_input);
            Ok(policy_ctx
                .local_policy
                .intersection(updated_record.base_permissions)
                .intersection(grant.session_granted_perms)
                .intersection(policy_ctx.negotiated_caps))
        }
    }
}
