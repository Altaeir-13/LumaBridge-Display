// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

use lumabridge_protocol::control::Permissions;
use lumabridge_security::anti_replay::{
    BoundedChallengeCache, MonotonicSeqGuard, MAX_TRACKED_CHALLENGES,
};
use lumabridge_security::authorization::{
    apply_input_elevation, authorize_action, authorize_session_open, InputApprovalDecision,
};
use lumabridge_security::channel_binding::ChannelBinding;
use lumabridge_security::error::SecurityError;
use lumabridge_security::identity::{DeviceId, IdentityKeyPair, PeerRole};
use lumabridge_security::pairing::QrTokenStore;
use lumabridge_security::rate_limit::{AuthRateLimiter, RateLimitConfig};
use lumabridge_security::secret::{CheckedOsCryptoRng, PinSecret, SecretBytes};
use lumabridge_security::session_token::SessionTokenManager;
use lumabridge_security::transcript::derive_resume_channel_proof;
use lumabridge_security::trust_store::{InMemoryTrustStore, RevocationReason};

#[test]
fn authorization_live_downgrade_and_elevation_require_explicit_approval() {
    let store = InMemoryTrustStore::new();
    let ctrl_kp = IdentityKeyPair::from_seed([0x61; 32]).expect("ctrl");

    // Zero-trust default denies unpaired device
    assert_eq!(
        authorize_session_open(
            &store,
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            Permissions::VIEW_MIRROR,
            10,
            2_000,
        ),
        Err(SecurityError::UntrustedDevice)
    );

    store
        .insert_newly_paired(
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            "Stylus Tablet",
            Permissions::VIEW_MIRROR.union(Permissions::EXTEND_DISPLAY),
            1_000,
        )
        .expect("insert");

    // Grant starts capped at base_perms ∩ requested_perms even if caller asks for INPUT_MASK
    let mut grant = authorize_session_open(
        &store,
        ctrl_kp.public_identity(),
        PeerRole::Controller,
        Permissions::VIEW_MIRROR
            .union(Permissions::INPUT_POINTER)
            .union(Permissions::INPUT_KEYBOARD),
        10,
        2_000,
    )
    .expect("open");
    assert_eq!(grant.session_granted_perms, Permissions::VIEW_MIRROR);
    assert!(matches!(
        authorize_action(
            &store,
            ctrl_kp.public_identity(),
            &grant,
            Permissions::INPUT_POINTER,
            1_100
        ),
        Err(SecurityError::AuthorizationDenied(_))
    ));

    // Input elevation denied without explicit Approve decision
    assert_eq!(
        apply_input_elevation(
            &store,
            ctrl_kp.public_identity(),
            &mut grant,
            Permissions::INPUT_POINTER,
            InputApprovalDecision::Deny,
            1_100,
        ),
        Err(SecurityError::ApprovalRequired)
    );

    // Explicit approval grants only approved subset
    let effective = apply_input_elevation(
        &store,
        ctrl_kp.public_identity(),
        &mut grant,
        Permissions::INPUT_POINTER.union(Permissions::INPUT_KEYBOARD),
        InputApprovalDecision::Approve {
            granted_input_perms: Permissions::INPUT_POINTER,
        },
        1_110,
    )
    .expect("approved");
    assert_eq!(
        effective,
        Permissions::VIEW_MIRROR.union(Permissions::INPUT_POINTER)
    );
    assert!(authorize_action(
        &store,
        ctrl_kp.public_identity(),
        &grant,
        Permissions::INPUT_POINTER,
        1_120
    )
    .is_ok());

    // Live TrustStore permission downgrade immediately blocks input even with existing SessionGrant
    store
        .update_base_permissions(ctrl_kp.device_id(), Permissions::VIEW_MIRROR, 1_130)
        .expect("downgrade");
    assert!(matches!(
        authorize_action(
            &store,
            ctrl_kp.public_identity(),
            &grant,
            Permissions::INPUT_POINTER,
            1_140
        ),
        Err(SecurityError::AuthorizationDenied(_))
    ));
}

#[test]
fn session_tokens_rotation_channel_proof_and_monotonic_revocation() {
    let store = InMemoryTrustStore::new();
    let mgr = SessionTokenManager::new();
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let ctrl_kp = IdentityKeyPair::from_seed([0x71; 32]).expect("ctrl");

    let initial_rec = store
        .insert_newly_paired(
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            "Controller",
            Permissions::VIEW_MIRROR.union(Permissions::CAPTURE_CONTROL),
            1_000,
        )
        .expect("insert");
    assert_eq!(initial_rec.trust_epoch, 1);

    let creds = mgr
        .issue_session(
            &mut rng,
            &store,
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            Permissions::VIEW_MIRROR.union(Permissions::INPUT_TOUCH),
            1_010,
            600,
            120,
        )
        .expect("issue session");
    // Input permissions not present in TrustStore cannot be minted into session
    assert_eq!(creds.effective_permissions, Permissions::VIEW_MIRROR);

    let active_perms = mgr
        .validate_session_token(
            &store,
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            creds.session_id,
            creds.session_token.expose_secret(),
            1_020,
        )
        .expect("valid token");
    assert_eq!(active_perms, Permissions::VIEW_MIRROR);

    // Channel-bound resume succeeds once and rotates resume token atomically
    let cb = ChannelBinding::from_bytes([0xBB; 32]);
    let proof = derive_resume_channel_proof(
        &creds.resume_token,
        &cb,
        ctrl_kp.device_id(),
        creds.session_id,
    )
    .expect("proof");
    let wrong_cb = ChannelBinding::from_bytes([0xBC; 32]);
    assert_eq!(
        mgr.consume_and_rotate_resume_token(
            &mut rng,
            &store,
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            creds.session_id,
            creds.resume_token.expose_secret(),
            Some(&wrong_cb),
            Some(&proof),
            1_030,
            120,
        )
        .err(),
        Some(SecurityError::ChannelBindingMismatch)
    );

    let rotated = mgr
        .consume_and_rotate_resume_token(
            &mut rng,
            &store,
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            creds.session_id,
            creds.resume_token.expose_secret(),
            Some(&cb),
            Some(&proof),
            1_030,
            120,
        )
        .expect("resume ok");
    assert_ne!(
        rotated.rotated_resume_token.expose_secret(),
        creds.resume_token.expose_secret()
    );

    // Replaying consumed resume token fails immediately with SessionTokenReused
    let replay_proof = derive_resume_channel_proof(
        &creds.resume_token,
        &cb,
        ctrl_kp.device_id(),
        creds.session_id,
    )
    .expect("replay proof");
    assert_eq!(
        mgr.consume_and_rotate_resume_token(
            &mut rng,
            &store,
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            creds.session_id,
            creds.resume_token.expose_secret(),
            Some(&cb),
            Some(&replay_proof),
            1_031,
            120,
        )
        .err(),
        Some(SecurityError::SessionTokenReused)
    );

    // Mid-session revocation immediately invalidates both session & rotated resume token
    store
        .revoke(
            ctrl_kp.device_id(),
            RevocationReason::UserRemovedDevice,
            1_050,
        )
        .expect("revoke");
    mgr.revoke_device_sessions(ctrl_kp.device_id())
        .expect("revoke sessions");

    assert_eq!(
        mgr.validate_session_token(
            &store,
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            creds.session_id,
            creds.session_token.expose_secret(),
            1_051,
        ),
        Err(SecurityError::RevokedDevice)
    );

    // Re-pairing advances trust_epoch to 2; pre-revocation credentials remain permanently rejected
    let repaired = store
        .re_trust_after_pairing(
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            "Controller",
            Permissions::VIEW_MIRROR,
            1_060,
        )
        .expect("re-trust");
    assert_eq!(repaired.trust_epoch, 2);
    assert_eq!(
        mgr.validate_session_token(
            &store,
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            creds.session_id,
            creds.session_token.expose_secret(),
            1_061,
        ),
        Err(SecurityError::RevokedDevice)
    );
}

#[test]
fn rate_limiter_enforces_per_peer_backoff_and_global_multi_endpoint_cap() {
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

    // Distributed PIN brute-force rotating DeviceId across 6 spoofed identities hits global cooldown
    for i in 2u8..=7u8 {
        let spoof = DeviceId::from_bytes([i; 32]);
        let _ = limiter.record_failure(spoof, 2_000 + u64::from(i));
    }
    let innocent = DeviceId::from_bytes([0xFE; 32]);
    assert!(matches!(
        limiter.check_allowed(innocent, 2_100),
        Err(SecurityError::RateLimited { retry_after_ms }) if retry_after_ms >= 19_000
    ));
}

#[test]
fn anti_replay_cache_bounds_and_monotonic_sequence_guard() {
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

    // Capacity remains bounded when flooded with distinct challenges
    for idx in 0..(MAX_TRACKED_CHALLENGES + 256) {
        let b = (idx as u64).to_be_bytes();
        cache
            .check_and_insert_unique(b"flood", &b, 2_000, 2_000, 60, 10)
            .expect("bounded insert");
    }
    assert!(cache.len() <= MAX_TRACKED_CHALLENGES);

    let mut seq = MonotonicSeqGuard::new();
    assert_eq!(seq.check_and_advance(0), Err(SecurityError::ReplayDetected));
    assert!(seq.check_and_advance(1).is_ok());
    assert_eq!(seq.check_and_advance(1), Err(SecurityError::ReplayDetected));
    assert!(seq.check_and_advance(5).is_ok());
    assert_eq!(seq.check_and_advance(4), Err(SecurityError::ReplayDetected));
}

#[test]
fn diagnostic_privacy_sentinels_never_leak_in_debug_pretty_or_display() {
    let pin_val = "9182736450";
    let pin = PinSecret::new(pin_val).expect("pin");
    let kp = IdentityKeyPair::from_seed([0xA5; 32]).expect("kp");
    let secret = SecretBytes::<32>::new([0x5A; 32]);

    let qr_store = QrTokenStore::new();
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let ticket = qr_store
        .issue(&mut rng, kp.device_id(), PeerRole::Host, 1_000, 120)
        .expect("ticket");
    let ticket_hex = encode_hex(ticket.token.expose_secret());

    let store = InMemoryTrustStore::new();
    store
        .insert_newly_paired(
            kp.public_identity(),
            PeerRole::Host,
            "Host",
            Permissions::VIEW_MIRROR,
            1_000,
        )
        .expect("insert");
    let mgr = SessionTokenManager::new();
    let creds = mgr
        .issue_session(
            &mut rng,
            &store,
            kp.public_identity(),
            PeerRole::Host,
            Permissions::VIEW_MIRROR,
            1_000,
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
        assert!(!dump.contains("5a5a5a5a5a5a"), "secret leaked in: {dump}");
        assert!(!dump.contains(&ticket_hex), "QR token leaked in: {dump}");
        assert!(!dump.contains(&sess_hex), "session token leaked in: {dump}");
        assert!(
            !dump.contains(&resume_hex),
            "resume token leaked in: {dump}"
        );
        assert!(!dump.contains("165"), "decimal secret byte pattern check");
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
