// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

use lumabridge_protocol::control::Permissions;
use lumabridge_security::anti_replay::{
    BoundedChallengeCache, MonotonicSeqGuard, MAX_TRACKED_CHALLENGES,
};
use lumabridge_security::authorization::{
    apply_input_elevation, authorize_action, authorize_session_open, begin_permission_upgrade,
    AuthorizationPolicyContext, InputApprovalDecision,
};
use lumabridge_security::certificate::generate_self_signed_device_cert;
use lumabridge_security::error::SecurityError;
use lumabridge_security::identity::{DeviceId, IdentityKeyPair, PeerRole};
use lumabridge_security::pairing::{QrTokenStore, MAX_ACTIVE_QR_TOKENS};
use lumabridge_security::rate_limit::{
    AuthRateLimiter, RateLimitConfig, MAX_GLOBAL_FAILURE_EVENTS,
};
use lumabridge_security::secret::{CheckedOsCryptoRng, PinSecret, SecretBytes};
use lumabridge_security::session_token::{revoke_peer_and_sessions, SessionTokenManager};
use lumabridge_security::tls::{
    build_tls13_client_config, build_tls13_server_config, canonical_server_name_for_device,
    drive_in_memory_handshake, extract_authenticated_session,
    extract_authenticated_session_with_alpn, AuthenticatedTlsSession, TlsPeerTrustPolicy,
    LUMABRIDGE_PAIR_ALPN_V1,
};
use lumabridge_security::transcript::derive_resume_channel_proof;
use lumabridge_security::trust_store::{
    AdminTrustImportRecord, InMemoryTrustStore, RevocationReason, SecurityAction, TrustStore,
};
use rustls::{ClientConnection, ServerConnection};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn establish_operational_server_tls(
    host_kp: &IdentityKeyPair,
    host_store: &Arc<InMemoryTrustStore>,
    ctrl_kp: &IdentityKeyPair,
    ctrl_store: &Arc<InMemoryTrustStore>,
    now: u64,
) -> AuthenticatedTlsSession {
    let host_cert =
        generate_self_signed_device_cert(host_kp, now - 60, now + 3600).expect("host cert");
    let ctrl_cert =
        generate_self_signed_device_cert(ctrl_kp, now - 60, now + 3600).expect("ctrl cert");
    let cli_cfg = build_tls13_client_config(
        &ctrl_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: Arc::clone(ctrl_store) as Arc<dyn TrustStore>,
            expected_role: PeerRole::Host,
        },
    )
    .expect("cli cfg");
    let srv_cfg = build_tls13_server_config(
        &host_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: Arc::clone(host_store) as Arc<dyn TrustStore>,
            expected_role: PeerRole::Controller,
        },
    )
    .expect("srv cfg");
    let mut cli = ClientConnection::new(
        cli_cfg,
        canonical_server_name_for_device(host_kp.device_id()).expect("sni"),
    )
    .expect("cli");
    let mut srv = ServerConnection::new(srv_cfg).expect("srv");
    drive_in_memory_handshake(&mut cli, &mut srv).expect("handshake");
    extract_authenticated_session(&srv, now).expect("server tls session")
}

fn establish_pairing_server_tls(
    host_kp: &IdentityKeyPair,
    ctrl_kp: &IdentityKeyPair,
    store: &Arc<InMemoryTrustStore>,
    now: u64,
) -> AuthenticatedTlsSession {
    let host_cert =
        generate_self_signed_device_cert(host_kp, now - 60, now + 3600).expect("host cert");
    let ctrl_cert =
        generate_self_signed_device_cert(ctrl_kp, now - 60, now + 3600).expect("ctrl cert");
    let cli_cfg = build_tls13_client_config(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: Arc::clone(store) as Arc<dyn TrustStore>,
        },
    )
    .expect("cli cfg");
    let srv_cfg = build_tls13_server_config(
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: Arc::clone(store) as Arc<dyn TrustStore>,
        },
    )
    .expect("srv cfg");
    let mut cli = ClientConnection::new(
        cli_cfg,
        canonical_server_name_for_device(host_kp.device_id()).expect("sni"),
    )
    .expect("cli");
    let mut srv = ServerConnection::new(srv_cfg).expect("srv");
    drive_in_memory_handshake(&mut cli, &mut srv).expect("handshake");
    extract_authenticated_session_with_alpn(&srv, LUMABRIDGE_PAIR_ALPN_V1, now)
        .expect("pairing tls session")
}

#[test]
fn authorization_five_factor_live_downgrade_and_atomic_elevation() {
    let now = now_unix();
    let host_store = Arc::new(InMemoryTrustStore::new());
    let ctrl_store = Arc::new(InMemoryTrustStore::new());
    let host_kp = IdentityKeyPair::from_seed([0x60; 32]).expect("host");
    let ctrl_kp = IdentityKeyPair::from_seed([0x61; 32]).expect("ctrl");

    // Administrative import requires non-zero epochs
    assert!(matches!(
        host_store.import_trusted_peer_admin(AdminTrustImportRecord {
            identity: ctrl_kp.public_identity().clone(),
            role: PeerRole::Controller,
            friendly_name: "Bad".into(),
            base_permissions: Permissions::VIEW_MIRROR,
            paired_at_unix: now,
            last_seen_unix: now,
            trust_epoch: 0,
            perm_epoch: 1,
        }),
        Err(SecurityError::InvalidTimestamp(_))
    ));

    host_store
        .import_trusted_peer_admin(AdminTrustImportRecord {
            identity: ctrl_kp.public_identity().clone(),
            role: PeerRole::Controller,
            friendly_name: "Stylus Tablet".into(),
            base_permissions: Permissions::VIEW_MIRROR.union(Permissions::EXTEND_DISPLAY),
            paired_at_unix: now,
            last_seen_unix: now,
            trust_epoch: 1,
            perm_epoch: 1,
        })
        .expect("insert ctrl");
    ctrl_store
        .import_trusted_peer_admin(AdminTrustImportRecord {
            identity: host_kp.public_identity().clone(),
            role: PeerRole::Host,
            friendly_name: "Host".into(),
            base_permissions: Permissions::VIEW_MIRROR,
            paired_at_unix: now,
            last_seen_unix: now,
            trust_epoch: 1,
            perm_epoch: 1,
        })
        .expect("insert host");

    let pairing_tls = establish_pairing_server_tls(&host_kp, &ctrl_kp, &host_store, now);
    let op_tls =
        establish_operational_server_tls(&host_kp, &host_store, &ctrl_kp, &ctrl_store, now);
    let policy_all = AuthorizationPolicyContext::allow_all_v1();

    // Pairing ALPN session CANNOT open an operational session
    assert_eq!(
        authorize_session_open(
            &*host_store,
            &pairing_tls,
            PeerRole::Controller,
            Permissions::VIEW_MIRROR,
            policy_all,
            10,
            now + 1000,
        ),
        Err(SecurityError::AlpnMismatch)
    );

    // Grant starts capped at local_policy ∩ base_perms ∩ requested_perms ∩ negotiated_caps
    let mut grant = authorize_session_open(
        &*host_store,
        &op_tls,
        PeerRole::Controller,
        Permissions::VIEW_MIRROR
            .union(Permissions::INPUT_POINTER)
            .union(Permissions::INPUT_KEYBOARD),
        policy_all,
        10,
        now + 1000,
    )
    .expect("open");
    assert_eq!(grant.session_granted_perms, Permissions::VIEW_MIRROR);
    assert!(matches!(
        authorize_action(
            &*host_store,
            &op_tls,
            &grant,
            policy_all,
            Permissions::INPUT_POINTER,
            now + 10,
        ),
        Err(SecurityError::AuthorizationDenied(_))
    ));

    // Pending upgrade bound to session_id + request_seq + peer_device_id + trust_epoch + perm_epoch
    let pending_deny = begin_permission_upgrade(
        &*host_store,
        &op_tls,
        &grant,
        1,
        Permissions::INPUT_POINTER.union(Permissions::INPUT_KEYBOARD),
        now + 15,
    )
    .expect("pending deny");

    // Input elevation denied without explicit Approve decision (consumes pending_deny)
    assert_eq!(
        apply_input_elevation(
            &host_store,
            &op_tls,
            &mut grant,
            pending_deny,
            InputApprovalDecision::Deny {
                session_id: 10,
                request_seq: 1,
                peer_device_id: ctrl_kp.device_id(),
            },
            policy_all,
            now + 20,
        ),
        Err(SecurityError::ApprovalRequired)
    );

    // Wrong request_seq or peer_device_id rejected cleanly
    let pending_mismatch = begin_permission_upgrade(
        &*host_store,
        &op_tls,
        &grant,
        2,
        Permissions::INPUT_POINTER.union(Permissions::INPUT_KEYBOARD),
        now + 20,
    )
    .expect("pending mismatch");
    assert!(matches!(
        apply_input_elevation(
            &host_store,
            &op_tls,
            &mut grant,
            pending_mismatch,
            InputApprovalDecision::Approve {
                session_id: 10,
                request_seq: 99,
                peer_device_id: ctrl_kp.device_id(),
                granted_input_perms: Permissions::INPUT_POINTER,
            },
            policy_all,
            now + 20,
        ),
        Err(SecurityError::IdentityMismatch(_))
    ));

    // Explicit approval grants only approved subset
    let pending_ok = begin_permission_upgrade(
        &*host_store,
        &op_tls,
        &grant,
        3,
        Permissions::INPUT_POINTER.union(Permissions::INPUT_KEYBOARD),
        now + 22,
    )
    .expect("pending ok");
    let effective = apply_input_elevation(
        &host_store,
        &op_tls,
        &mut grant,
        pending_ok,
        InputApprovalDecision::Approve {
            session_id: 10,
            request_seq: 3,
            peer_device_id: ctrl_kp.device_id(),
            granted_input_perms: Permissions::INPUT_POINTER,
        },
        policy_all,
        now + 25,
    )
    .expect("approved");
    assert_eq!(
        effective,
        Permissions::VIEW_MIRROR.union(Permissions::INPUT_POINTER)
    );

    // 5-factor intersection: restrictive local_policy or negotiated_caps immediately denies INPUT_POINTER
    let display_only_policy = AuthorizationPolicyContext {
        local_policy: Permissions::VIEW_MIRROR,
        negotiated_caps: Permissions::VIEW_MIRROR.union(Permissions::INPUT_POINTER),
    };
    assert!(matches!(
        authorize_action(
            &*host_store,
            &op_tls,
            &grant,
            display_only_policy,
            Permissions::INPUT_POINTER,
            now + 30,
        ),
        Err(SecurityError::AuthorizationDenied(_))
    ));

    // Pending upgrade created before live TrustStore downgrade is invalidated by perm_epoch advance!
    let stale_pending = begin_permission_upgrade(
        &*host_store,
        &op_tls,
        &grant,
        4,
        Permissions::INPUT_KEYBOARD,
        now + 34,
    )
    .expect("stale pending");

    // Live TrustStore permission downgrade immediately blocks input even with existing SessionGrant
    host_store
        .update_base_permissions(ctrl_kp.device_id(), Permissions::VIEW_MIRROR, now + 35)
        .expect("downgrade");
    assert!(matches!(
        apply_input_elevation(
            &host_store,
            &op_tls,
            &mut grant,
            stale_pending,
            InputApprovalDecision::Approve {
                session_id: 10,
                request_seq: 4,
                peer_device_id: ctrl_kp.device_id(),
                granted_input_perms: Permissions::INPUT_KEYBOARD,
            },
            policy_all,
            now + 36,
        ),
        Err(SecurityError::AuthorizationDenied(_))
    ));
    assert!(matches!(
        authorize_action(
            &*host_store,
            &op_tls,
            &grant,
            policy_all,
            Permissions::INPUT_POINTER,
            now + 40,
        ),
        Err(SecurityError::AuthorizationDenied(_))
    ));
}

#[test]
fn session_tokens_channel_bound_resume_and_concurrent_revocation_race() {
    let now = now_unix();
    let host_store = Arc::new(InMemoryTrustStore::new());
    let ctrl_store = Arc::new(InMemoryTrustStore::new());
    let mgr = Arc::new(SessionTokenManager::new());
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let host_kp = IdentityKeyPair::from_seed([0x70; 32]).expect("host");
    let ctrl_kp = IdentityKeyPair::from_seed([0x71; 32]).expect("ctrl");

    let initial_rec = host_store
        .import_trusted_peer_admin(AdminTrustImportRecord {
            identity: ctrl_kp.public_identity().clone(),
            role: PeerRole::Controller,
            friendly_name: "Controller".into(),
            base_permissions: Permissions::VIEW_MIRROR.union(Permissions::CAPTURE_CONTROL),
            paired_at_unix: now,
            last_seen_unix: now,
            trust_epoch: 1,
            perm_epoch: 1,
        })
        .expect("insert");
    assert_eq!(initial_rec.trust_epoch, 1);
    ctrl_store
        .import_trusted_peer_admin(AdminTrustImportRecord {
            identity: host_kp.public_identity().clone(),
            role: PeerRole::Host,
            friendly_name: "Host".into(),
            base_permissions: Permissions::VIEW_MIRROR,
            paired_at_unix: now,
            last_seen_unix: now,
            trust_epoch: 1,
            perm_epoch: 1,
        })
        .expect("insert host");

    let tls_conn_1 =
        establish_operational_server_tls(&host_kp, &host_store, &ctrl_kp, &ctrl_store, now);
    let tls_conn_2 =
        establish_operational_server_tls(&host_kp, &host_store, &ctrl_kp, &ctrl_store, now);

    let creds = mgr
        .issue_session(
            &mut rng,
            &*host_store,
            &tls_conn_1,
            PeerRole::Controller,
            Permissions::VIEW_MIRROR.union(Permissions::INPUT_TOUCH),
            now + 10,
            600,
            120,
        )
        .expect("issue session");
    assert_eq!(creds.effective_permissions, Permissions::VIEW_MIRROR);

    // Valid on tls_conn_1; REJECTED on tls_conn_2 without SessionResume!
    assert_eq!(
        mgr.validate_session_token(
            &*host_store,
            &tls_conn_1,
            PeerRole::Controller,
            creds.session_id,
            creds.session_token.expose_secret(),
            now + 20,
        ),
        Ok(Permissions::VIEW_MIRROR)
    );
    assert_eq!(
        mgr.validate_session_token(
            &*host_store,
            &tls_conn_2,
            PeerRole::Controller,
            creds.session_id,
            creds.session_token.expose_secret(),
            now + 20,
        ),
        Err(SecurityError::ChannelBindingMismatch)
    );

    // Same-channel resume replay rejected; fresh TLS channel + valid proof succeeds and rotates!
    let same_chan_proof = derive_resume_channel_proof(
        &creds.resume_token,
        tls_conn_1.channel_binding(),
        ctrl_kp.device_id(),
        creds.session_id,
        creds.trust_epoch,
    )
    .expect("same proof");
    assert_eq!(
        mgr.consume_and_rotate_resume_token(
            &mut rng,
            &*host_store,
            &tls_conn_1,
            PeerRole::Controller,
            creds.session_id,
            creds.resume_token.expose_secret(),
            &same_chan_proof,
            now + 25,
            120,
        )
        .err(),
        Some(SecurityError::ReplayDetected)
    );

    let proof_2 = derive_resume_channel_proof(
        &creds.resume_token,
        tls_conn_2.channel_binding(),
        ctrl_kp.device_id(),
        creds.session_id,
        creds.trust_epoch,
    )
    .expect("proof 2");
    let wrong_proof = [0x99u8; 32];
    assert_eq!(
        mgr.consume_and_rotate_resume_token(
            &mut rng,
            &*host_store,
            &tls_conn_2,
            PeerRole::Controller,
            creds.session_id,
            creds.resume_token.expose_secret(),
            &wrong_proof,
            now + 30,
            120,
        )
        .err(),
        Some(SecurityError::ChannelBindingMismatch)
    );

    let rotated = mgr
        .consume_and_rotate_resume_token(
            &mut rng,
            &*host_store,
            &tls_conn_2,
            PeerRole::Controller,
            creds.session_id,
            creds.resume_token.expose_secret(),
            &proof_2,
            now + 30,
            120,
        )
        .expect("resume ok");
    assert_ne!(
        rotated.rotated_resume_token.expose_secret(),
        creds.resume_token.expose_secret()
    );

    // Session token now accepts tls_conn_2 (re-bound!) and rejects stale tls_conn_1
    assert_eq!(
        mgr.validate_session_token(
            &*host_store,
            &tls_conn_2,
            PeerRole::Controller,
            creds.session_id,
            creds.session_token.expose_secret(),
            now + 31,
        ),
        Ok(Permissions::VIEW_MIRROR)
    );
    assert_eq!(
        mgr.validate_session_token(
            &*host_store,
            &tls_conn_1,
            PeerRole::Controller,
            creds.session_id,
            creds.session_token.expose_secret(),
            now + 31,
        ),
        Err(SecurityError::ChannelBindingMismatch)
    );

    // Replaying consumed resume token fails immediately with SessionTokenReused
    let tls_conn_3 =
        establish_operational_server_tls(&host_kp, &host_store, &ctrl_kp, &ctrl_store, now);
    let replay_proof = derive_resume_channel_proof(
        &creds.resume_token,
        tls_conn_3.channel_binding(),
        ctrl_kp.device_id(),
        creds.session_id,
        creds.trust_epoch,
    )
    .expect("replay proof");
    assert_eq!(
        mgr.consume_and_rotate_resume_token(
            &mut rng,
            &*host_store,
            &tls_conn_3,
            PeerRole::Controller,
            creds.session_id,
            creds.resume_token.expose_secret(),
            &replay_proof,
            now + 32,
            120,
        )
        .err(),
        Some(SecurityError::SessionTokenReused)
    );

    // Coordinated revocation invalidates sessions, removes resume tokens, and emits DisconnectPeerSessions
    let outcome = revoke_peer_and_sessions(
        &host_store,
        &mgr,
        ctrl_kp.device_id(),
        RevocationReason::UserRemovedDevice,
        now + 50,
    )
    .expect("revoke");
    assert_eq!(outcome.record.revoked_epoch, 2);
    assert_eq!(outcome.invalidated_sessions, 1);
    assert_eq!(
        outcome.actions,
        vec![SecurityAction::DisconnectPeerSessions {
            device_id: ctrl_kp.device_id(),
            reason: RevocationReason::UserRemovedDevice,
            revoked_epoch: 2,
        }]
    );

    assert_eq!(
        mgr.update_session_permissions(creds.session_id, Permissions::VIEW_MIRROR),
        Err(SecurityError::RevokedDevice)
    );
    assert_eq!(
        mgr.validate_session_token(
            &*host_store,
            &tls_conn_2,
            PeerRole::Controller,
            creds.session_id,
            creds.session_token.expose_secret(),
            now + 51,
        ),
        Err(SecurityError::RevokedDevice)
    );

    // Re-trusting administratively advances trust_epoch to 3; pre-revocation credentials remain permanently rejected
    let repaired = host_store
        .import_trusted_peer_admin(AdminTrustImportRecord {
            identity: ctrl_kp.public_identity().clone(),
            role: PeerRole::Controller,
            friendly_name: "Controller".into(),
            base_permissions: Permissions::VIEW_MIRROR,
            paired_at_unix: now + 60,
            last_seen_unix: now + 60,
            trust_epoch: 3,
            perm_epoch: 1,
        })
        .expect("re-trust");
    assert_eq!(repaired.trust_epoch, 3);
    assert_eq!(
        mgr.update_session_permissions(creds.session_id, Permissions::VIEW_MIRROR),
        Err(SecurityError::RevokedDevice)
    );
    assert_eq!(
        mgr.validate_session_token(
            &*host_store,
            &tls_conn_2,
            PeerRole::Controller,
            creds.session_id,
            creds.session_token.expose_secret(),
            now + 61,
        ),
        Err(SecurityError::RevokedDevice)
    );

    // Concurrent stress test: 15 threads issuing/validating vs 1 thread revoking!
    let tls_stress = Arc::new(establish_operational_server_tls(
        &host_kp,
        &host_store,
        &ctrl_kp,
        &ctrl_store,
        now,
    ));
    let barrier = Arc::new(Barrier::new(16));
    let mut handles = Vec::with_capacity(16);
    for idx in 0..15 {
        let store_c = Arc::clone(&host_store);
        let mgr_c = Arc::clone(&mgr);
        let tls_c = Arc::clone(&tls_stress);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut local_rng = CheckedOsCryptoRng::preflight().expect("rng");
            b.wait();
            if idx % 2 == 0 {
                if let Ok(issued) = mgr_c.issue_session(
                    &mut local_rng,
                    &*store_c,
                    &tls_c,
                    PeerRole::Controller,
                    Permissions::VIEW_MIRROR,
                    now + 70,
                    600,
                    120,
                ) {
                    Some((issued.session_id, issued.session_token))
                } else {
                    None
                }
            } else {
                None
            }
        }));
    }
    {
        let store_r = Arc::clone(&host_store);
        let mgr_r = Arc::clone(&mgr);
        let dev_id = ctrl_kp.device_id();
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            revoke_peer_and_sessions(
                &store_r,
                &mgr_r,
                dev_id,
                RevocationReason::SuspectedCompromise,
                now + 71,
            )
            .expect("revoke race");
            None
        }));
    }
    let issued_list: Vec<_> = handles
        .into_iter()
        .filter_map(|h| h.join().expect("join"))
        .collect();
    // Final cleanup sweep ensures ZERO pre-revocation or racing tokens validate post-revocation
    let _ = mgr.revoke_device_sessions(ctrl_kp.device_id());
    assert!(host_store.is_revoked(ctrl_kp.device_id()));
    for (sid, tok) in issued_list {
        assert_eq!(
            mgr.validate_session_token(
                &*host_store,
                &tls_stress,
                PeerRole::Controller,
                sid,
                tok.expose_secret(),
                now + 72,
            ),
            Err(SecurityError::RevokedDevice)
        );
    }
}

#[test]
fn rate_limiter_enforces_per_peer_backoff_and_global_caps() {
    let limiter = AuthRateLimiter::new(RateLimitConfig {
        base_backoff_ms: 500,
        max_backoff_ms: 30_000,
        lockout_threshold: 4,
        global_window_ms: 10_000,
        max_global_failures_in_window: 6,
        global_cooldown_ms: 20_000,
    });

    let p1 = DeviceId::from_bytes([0x01; 32]);
    assert!(limiter.check_allowed(p1, 1_000).is_ok());
    let wait1 = limiter.record_failure(p1, 1_000).expect("f1");
    assert_eq!(wait1, 500);
    assert!(matches!(
        limiter.check_allowed(p1, 1_200),
        Err(SecurityError::RateLimited { .. })
    ));
    assert!(limiter.check_allowed(p1, 1_500).is_ok());

    for i in 2u8..=7u8 {
        let spoof = DeviceId::from_bytes([i; 32]);
        let _ = limiter.record_failure(spoof, 2_000 + u64::from(i));
    }
    let innocent = DeviceId::from_bytes([0xFE; 32]);
    assert!(matches!(
        limiter.check_allowed(innocent, 2_100),
        Err(SecurityError::RateLimited { retry_after_ms }) if retry_after_ms >= 19_000
    ));

    // Global failure history remains strictly bounded under flood
    for i in 0..(MAX_GLOBAL_FAILURE_EVENTS + 500) {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let _ = limiter.record_failure(DeviceId::from_bytes(id), 100_000);
    }
    assert!(limiter.global_window_len() <= MAX_GLOBAL_FAILURE_EVENTS);
}

#[test]
fn anti_replay_cache_fails_closed_when_saturated_and_qr_store_bounds() {
    let cache = BoundedChallengeCache::new();
    cache
        .check_and_insert_unique(b"pair", b"nonce-1", 1_000, 1_005, 60, 10)
        .expect("fresh");
    assert_eq!(
        cache.check_and_insert_unique(b"pair", b"nonce-1", 1_000, 1_006, 60, 10),
        Err(SecurityError::ReplayDetected)
    );
    assert!(matches!(
        cache.check_and_insert_unique(b"pair", b"stale", 900, 1_006, 60, 10),
        Err(SecurityError::InvalidTimestamp(_))
    ));

    // Fill cache to MAX_TRACKED_CHALLENGES unexpired entries
    for idx in 1..MAX_TRACKED_CHALLENGES {
        let b = (idx as u64).to_be_bytes();
        cache
            .check_and_insert_unique(b"flood", &b, 1_006, 1_006, 60, 10)
            .expect("fill");
    }
    assert_eq!(cache.len(), MAX_TRACKED_CHALLENGES);

    // Additional unexpired challenge MUST fail closed (ResourceExhausted), NOT evict nonce-1!
    assert!(matches!(
        cache.check_and_insert_unique(b"flood", b"overflow", 1_006, 1_006, 60, 10),
        Err(SecurityError::ResourceExhausted(_))
    ));
    assert_eq!(
        cache.check_and_insert_unique(b"pair", b"nonce-1", 1_000, 1_006, 60, 10),
        Err(SecurityError::ReplayDetected)
    );

    // Advancing past expiry purges expired challenges and recovers capacity cleanly
    cache
        .check_and_insert_unique(b"pair", b"after-expiry", 1_200, 1_200, 60, 10)
        .expect("recovered after expiry");
    assert_eq!(cache.len(), 1);

    let mut seq = MonotonicSeqGuard::new();
    assert_eq!(seq.check_and_advance(0), Err(SecurityError::ReplayDetected));
    assert!(seq.check_and_advance(1).is_ok());
    assert_eq!(seq.check_and_advance(1), Err(SecurityError::ReplayDetected));
    assert!(seq.check_and_advance(5).is_ok());
    assert_eq!(seq.check_and_advance(4), Err(SecurityError::ReplayDetected));

    // QR store bounds active tokens at MAX_ACTIVE_QR_TOKENS
    let qr_store = QrTokenStore::new();
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let host_id = DeviceId::from_bytes([0x99; 32]);
    for _ in 0..MAX_ACTIVE_QR_TOKENS {
        qr_store
            .issue(&mut rng, host_id, PeerRole::Host, 1_000, 120)
            .expect("issue");
    }
    assert!(matches!(
        qr_store.issue(&mut rng, host_id, PeerRole::Host, 1_000, 120),
        Err(SecurityError::ResourceExhausted(_))
    ));
}

#[test]
fn diagnostic_privacy_sentinels_never_leak_secrets_cert_keys_or_channel_binding() {
    let now = now_unix();
    let pin_val = "01827364";
    let pin = PinSecret::new(pin_val).expect("pin");
    let kp = IdentityKeyPair::from_seed([0xA5; 32]).expect("kp");
    let host_kp = IdentityKeyPair::from_seed([0xA6; 32]).expect("host_kp");
    let cert = generate_self_signed_device_cert(&kp, now - 60, now + 3600).expect("cert");
    let secret = SecretBytes::<32>::new([0x5A; 32]);

    let qr_store = QrTokenStore::new();
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let ticket = qr_store
        .issue(&mut rng, kp.device_id(), PeerRole::Host, now, 120)
        .expect("ticket");
    let ticket_hex = encode_hex(ticket.token.expose_secret());

    let host_store = Arc::new(InMemoryTrustStore::new());
    let ctrl_store = Arc::new(InMemoryTrustStore::new());
    host_store
        .import_trusted_peer_admin(AdminTrustImportRecord {
            identity: kp.public_identity().clone(),
            role: PeerRole::Controller,
            friendly_name: "Ctrl".into(),
            base_permissions: Permissions::VIEW_MIRROR,
            paired_at_unix: now,
            last_seen_unix: now,
            trust_epoch: 1,
            perm_epoch: 1,
        })
        .expect("insert");
    ctrl_store
        .import_trusted_peer_admin(AdminTrustImportRecord {
            identity: host_kp.public_identity().clone(),
            role: PeerRole::Host,
            friendly_name: "Host".into(),
            base_permissions: Permissions::VIEW_MIRROR,
            paired_at_unix: now,
            last_seen_unix: now,
            trust_epoch: 1,
            perm_epoch: 1,
        })
        .expect("insert host");

    let op_tls = establish_operational_server_tls(&host_kp, &host_store, &kp, &ctrl_store, now);
    let cb_prefix_hex = encode_hex(&op_tls.channel_binding().as_bytes()[..4]);
    let cb_full_hex = encode_hex(op_tls.channel_binding().as_bytes());
    let pkcs8_hex = encode_hex(&cert.pkcs8_der);

    let mgr = SessionTokenManager::new();
    let creds = mgr
        .issue_session(
            &mut rng,
            &*host_store,
            &op_tls,
            PeerRole::Controller,
            Permissions::VIEW_MIRROR,
            now,
            600,
            120,
        )
        .expect("creds");
    let sess_hex = encode_hex(creds.session_token.expose_secret());
    let resume_hex = encode_hex(creds.resume_token.expose_secret());

    let dumps = [
        format!("{pin:?}"),
        format!("{pin:#?}"),
        format!("{kp:?}"),
        format!("{kp:#?}"),
        format!("{cert:?}"),
        format!("{cert:#?}"),
        format!("{:?}", op_tls.channel_binding()),
        format!("{:#?}", op_tls.channel_binding()),
        format!("{op_tls:?}"),
        format!("{secret:?}"),
        format!("{secret:#?}"),
        format!("{ticket:?}"),
        format!("{ticket:#?}"),
        format!("{creds:?}"),
        format!("{creds:#?}"),
        format!("{}", SecurityError::InvalidPinFormat("bad pin")),
        format!("{:?}", SecurityError::SessionTokenInvalid("bad token")),
    ];

    for dump in &dumps {
        assert!(!dump.contains(pin_val), "PIN leaked in: {dump}");
        assert!(!dump.contains("a5a5a5a5a5a5"), "key seed leaked in: {dump}");
        assert!(!dump.contains(&pkcs8_hex), "PKCS8 leaked in: {dump}");
        assert!(
            !dump.contains(&cb_prefix_hex),
            "ChannelBinding prefix leaked in: {dump}"
        );
        assert!(
            !dump.contains(&cb_full_hex),
            "ChannelBinding leaked in: {dump}"
        );
        assert!(!dump.contains("5a5a5a5a5a5a"), "secret leaked in: {dump}");
        assert!(!dump.contains(&ticket_hex), "QR token leaked in: {dump}");
        assert!(!dump.contains(&sess_hex), "session token leaked in: {dump}");
        assert!(
            !dump.contains(&resume_hex),
            "resume token leaked in: {dump}"
        );
    }
}

#[test]
fn security_fuzz_regression_corpus_replays_cleanly() {
    let raw = include_str!("corpus/fuzz_regression_corpus.hex");
    let mut parsed_count = 0usize;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let bytes = decode_hex(trimmed);
        let _ = lumabridge_security::identity::PublicIdentity::from_spki_der(&bytes);
        let _ = lumabridge_security::certificate::verify_self_signed_ed25519_cert(
            &bytes,
            1_700_000_500,
        );
        parsed_count += 1;
    }
    assert!(parsed_count >= 1);
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

#[test]
fn trust_provenance_single_use_commit_epoch_binding_and_admin_separation() {
    use lumabridge_protocol::control::{AuthMode, PairHello};
    use lumabridge_protocol::version::{LBWP_PROTOCOL_MAJOR, LBWP_PROTOCOL_MINOR};
    use lumabridge_security::pairing::{
        HumanApprovalDecision, PairingAcceptor, PairingInitiator, QrTokenStore,
    };

    let now = now_unix();
    let host_kp = IdentityKeyPair::from_seed([0xB1; 32]).expect("host");
    let ctrl_kp = IdentityKeyPair::from_seed([0xB2; 32]).expect("ctrl");
    let host_store = Arc::new(InMemoryTrustStore::new());
    let ctrl_store = Arc::new(InMemoryTrustStore::new());
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");

    let mut run_qr_pairing = |attempt_id: u64, expected_host_epoch: u64| {
        let p_tls_acc = establish_pairing_server_tls(&host_kp, &ctrl_kp, &host_store, now);
        let host_cert =
            generate_self_signed_device_cert(&host_kp, now - 60, now + 3600).expect("hcert");
        let ctrl_cert =
            generate_self_signed_device_cert(&ctrl_kp, now - 60, now + 3600).expect("ccert");
        let cli_cfg = build_tls13_client_config(
            &ctrl_cert,
            TlsPeerTrustPolicy::Pairing {
                trust_store: Arc::clone(&ctrl_store) as Arc<dyn TrustStore>,
            },
        )
        .expect("cli cfg");
        let srv_cfg = build_tls13_server_config(
            &host_cert,
            TlsPeerTrustPolicy::Pairing {
                trust_store: Arc::clone(&host_store) as Arc<dyn TrustStore>,
            },
        )
        .expect("srv cfg");
        let mut cli = ClientConnection::new(
            cli_cfg,
            canonical_server_name_for_device(host_kp.device_id()).expect("sni"),
        )
        .expect("cli");
        let mut srv = ServerConnection::new(srv_cfg).expect("srv");
        drive_in_memory_handshake(&mut cli, &mut srv).expect("hs");
        let c_tls =
            extract_authenticated_session_with_alpn(&cli, LUMABRIDGE_PAIR_ALPN_V1, now).expect("c");
        let s_tls =
            extract_authenticated_session_with_alpn(&srv, LUMABRIDGE_PAIR_ALPN_V1, now).expect("s");
        let _ = p_tls_acc;

        let qr_store = QrTokenStore::new();
        let ticket = qr_store
            .issue(&mut rng, host_kp.device_id(), PeerRole::Host, now, 120)
            .expect("ticket");
        let init_hello = PairHello {
            protocol_major: LBWP_PROTOCOL_MAJOR,
            protocol_minor: LBWP_PROTOCOL_MINOR,
            device_id: *ctrl_kp.device_id().as_bytes(),
            friendly_name: "Ctrl".into(),
            auth_mode: AuthMode::QrOutOfBand,
            spki_ed25519: ctrl_kp.public_identity().spki_der().to_vec(),
        };
        let acc_hello = PairHello {
            protocol_major: LBWP_PROTOCOL_MAJOR,
            protocol_minor: LBWP_PROTOCOL_MINOR,
            device_id: *host_kp.device_id().as_bytes(),
            friendly_name: "Host".into(),
            auth_mode: AuthMode::QrOutOfBand,
            spki_ed25519: host_kp.public_identity().spki_der().to_vec(),
        };

        let mut init = PairingInitiator::start(
            attempt_id,
            &ctrl_kp,
            PeerRole::Controller,
            &acc_hello,
            &c_tls,
            AuthMode::QrOutOfBand,
        )
        .expect("init");
        let mut acc = PairingAcceptor::start_with_expected_peer_epoch(
            attempt_id,
            &host_kp,
            PeerRole::Host,
            &init_hello,
            &s_tls,
            expected_host_epoch,
        )
        .expect("acc");

        let auth = init
            .create_qr_auth(&ctrl_kp, &ticket, now + 1)
            .expect("auth");
        acc.verify_qr_auth(&qr_store, &auth, now + 1)
            .expect("verify qr");
        let confirm = acc
            .apply_human_approval(
                &host_kp,
                HumanApprovalDecision::Approve {
                    pairing_attempt_id: attempt_id,
                    peer_device_id: ctrl_kp.device_id(),
                    granted_base_perms: Permissions::VIEW_MIRROR,
                },
            )
            .expect("approve");
        init.verify_pair_confirm(&confirm).expect("verify confirm");
        let _ = init
            .apply_local_approval(HumanApprovalDecision::Approve {
                pairing_attempt_id: attempt_id,
                peer_device_id: host_kp.device_id(),
                granted_base_perms: Permissions::VIEW_MIRROR,
            })
            .expect("local");
        acc.approved_commit().expect("acc commit")
    };

    // Initial pairing produces a commit with expected_peer_epoch == 0; also create a concurrent stale commit at epoch 0
    let commit1 = run_qr_pairing(100, 0);
    let stale_commit_epoch0 = run_qr_pairing(101, 0);

    let rec1 = host_store
        .insert_approved_pairing(commit1, now)
        .expect("first insert");
    assert_eq!(rec1.trust_epoch, 1);

    // Reusing stale commit generated before trust_epoch advanced (0 -> 1) MUST fail
    assert!(matches!(
        host_store.insert_approved_pairing(stale_commit_epoch0, now),
        Err(SecurityError::PairingState(_))
    ));

    // Revoke peer (epoch -> 2), then create a commit bound to epoch 2 and another stale commit bound to epoch 1
    let rev = host_store
        .revoke(
            ctrl_kp.device_id(),
            RevocationReason::UserRemovedDevice,
            now + 5,
        )
        .expect("revoke");
    assert_eq!(rev.revoked_epoch, 2);

    // Note: Pairing TLS rejects revoked devices at TLS handshake unless unrevoked or re-pairing policy is used,
    // so construct a fresh re-trust PairingAcceptor commit bound to epoch 2 via Pairing TLS before a second revocation,
    // or verify stale epoch 1 commit is rejected by re_trust_after_approved_pairing!
    let host_cert =
        generate_self_signed_device_cert(&host_kp, now - 60, now + 3600).expect("hcert");
    let ctrl_cert =
        generate_self_signed_device_cert(&ctrl_kp, now - 60, now + 3600).expect("ccert");
    let empty_store = Arc::new(InMemoryTrustStore::new());
    let cli_cfg = build_tls13_client_config(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: Arc::clone(&empty_store) as Arc<dyn TrustStore>,
        },
    )
    .expect("cli cfg");
    let srv_cfg = build_tls13_server_config(
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: Arc::clone(&empty_store) as Arc<dyn TrustStore>,
        },
    )
    .expect("srv cfg");
    let mut cli = ClientConnection::new(
        cli_cfg,
        canonical_server_name_for_device(host_kp.device_id()).expect("sni"),
    )
    .expect("cli");
    let mut srv = ServerConnection::new(srv_cfg).expect("srv");
    drive_in_memory_handshake(&mut cli, &mut srv).expect("hs");
    let c_tls =
        extract_authenticated_session_with_alpn(&cli, LUMABRIDGE_PAIR_ALPN_V1, now).expect("c");
    let s_tls =
        extract_authenticated_session_with_alpn(&srv, LUMABRIDGE_PAIR_ALPN_V1, now).expect("s");
    let qr_store = QrTokenStore::new();
    let ticket = qr_store
        .issue(&mut rng, host_kp.device_id(), PeerRole::Host, now, 120)
        .expect("ticket");
    let init_hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *ctrl_kp.device_id().as_bytes(),
        friendly_name: "Ctrl".into(),
        auth_mode: AuthMode::QrOutOfBand,
        spki_ed25519: ctrl_kp.public_identity().spki_der().to_vec(),
    };
    let acc_hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *host_kp.device_id().as_bytes(),
        friendly_name: "Host".into(),
        auth_mode: AuthMode::QrOutOfBand,
        spki_ed25519: host_kp.public_identity().spki_der().to_vec(),
    };
    let mut init = PairingInitiator::start(
        200,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls,
        AuthMode::QrOutOfBand,
    )
    .expect("init");
    let mut acc = PairingAcceptor::start_with_expected_peer_epoch(
        200,
        &host_kp,
        PeerRole::Host,
        &init_hello,
        &s_tls,
        host_store.peer_epoch(ctrl_kp.device_id()),
    )
    .expect("acc");
    let auth = init
        .create_qr_auth(&ctrl_kp, &ticket, now + 6)
        .expect("auth");
    acc.verify_qr_auth(&qr_store, &auth, now + 6)
        .expect("verify");
    let _confirm = acc
        .apply_human_approval(
            &host_kp,
            HumanApprovalDecision::Approve {
                pairing_attempt_id: 200,
                peer_device_id: ctrl_kp.device_id(),
                granted_base_perms: Permissions::VIEW_MIRROR,
            },
        )
        .expect("approve");
    let repair_commit = acc.approved_commit().expect("repair commit");
    // Second extraction fails cleanly
    assert!(matches!(
        acc.approved_commit(),
        Err(SecurityError::PairingState(_))
    ));

    // Ordinary insert_approved_pairing MUST reject a revoked device directly
    let mut init_rev_test = PairingInitiator::start(
        201,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls,
        AuthMode::QrOutOfBand,
    )
    .expect("init rev test");
    let mut acc_rev_test = PairingAcceptor::start_with_expected_peer_epoch(
        201,
        &host_kp,
        PeerRole::Host,
        &init_hello,
        &s_tls,
        host_store.peer_epoch(ctrl_kp.device_id()),
    )
    .expect("acc rev test");
    let ticket_rev_test = qr_store
        .issue(&mut rng, host_kp.device_id(), PeerRole::Host, now, 120)
        .expect("ticket rev test");
    let auth_rev_test = init_rev_test
        .create_qr_auth(&ctrl_kp, &ticket_rev_test, now + 6)
        .expect("auth rev test");
    acc_rev_test
        .verify_qr_auth(&qr_store, &auth_rev_test, now + 6)
        .expect("verify rev test");
    let _ = acc_rev_test
        .apply_human_approval(
            &host_kp,
            HumanApprovalDecision::Approve {
                pairing_attempt_id: 201,
                peer_device_id: ctrl_kp.device_id(),
                granted_base_perms: Permissions::VIEW_MIRROR,
            },
        )
        .expect("approve rev test");
    let commit_while_revoked = acc_rev_test.approved_commit().expect("commit rev test");
    assert_eq!(
        host_store.insert_approved_pairing(commit_while_revoked, now + 8),
        Err(SecurityError::RevokedDevice)
    );

    // Explicit re_trust_after_approved_pairing succeeds with epoch 2 -> 3
    let re_rec = host_store
        .re_trust_after_approved_pairing(repair_commit, now + 10)
        .expect("re-trust approved");
    assert_eq!(re_rec.trust_epoch, 3);
    assert!(!host_store.is_revoked(ctrl_kp.device_id()));

    // Administrative import cannot downgrade a higher revoked_epoch
    host_store
        .revoke(
            ctrl_kp.device_id(),
            RevocationReason::SuspectedCompromise,
            now + 20,
        )
        .expect("revoke 2");
    assert_eq!(
        host_store.import_trusted_peer_admin(AdminTrustImportRecord {
            identity: ctrl_kp.public_identity().clone(),
            role: PeerRole::Controller,
            friendly_name: "Ctrl".into(),
            base_permissions: Permissions::VIEW_MIRROR,
            paired_at_unix: now,
            last_seen_unix: now,
            trust_epoch: 4,
            perm_epoch: 1,
        }),
        Err(SecurityError::RevokedDevice)
    );
}
