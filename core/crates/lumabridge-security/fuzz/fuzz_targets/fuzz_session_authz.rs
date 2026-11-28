// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use lumabridge_protocol::control::Permissions;
use lumabridge_protocol::version::ALPN_OPERATIONAL_V1;
use lumabridge_security::anti_replay::{BoundedChallengeCache, MonotonicSeqGuard};
use lumabridge_security::authorization::{
    authorize_action, authorize_session_open, AuthorizationPolicyContext,
};
use lumabridge_security::certificate::{
    generate_self_signed_device_cert, verify_self_signed_ed25519_cert,
};
use lumabridge_security::channel_binding::ChannelBinding;
use lumabridge_security::identity::{DeviceId, IdentityKeyPair, PeerRole};
use lumabridge_security::rate_limit::{AuthRateLimiter, RateLimitConfig};
use lumabridge_security::secret::CheckedOsCryptoRng;
use lumabridge_security::session_token::SessionTokenManager;
use lumabridge_security::tls::AuthenticatedTlsSession;
use lumabridge_security::trust_store::InMemoryTrustStore;

fuzz_target!(|data: &[u8]| {
    let Ok(ctrl_kp) = IdentityKeyPair::from_seed([0x41; 32]) else {
        return;
    };
    let Ok(ctrl_cert) = generate_self_signed_device_cert(&ctrl_kp, 1_700_000_000, 1_800_000_000)
    else {
        return;
    };
    let Ok(peer_cert) = verify_self_signed_ed25519_cert(&ctrl_cert.cert_der, 1_700_000_100)
    else {
        return;
    };
    let tls_sess = AuthenticatedTlsSession::synthetic_for_testing(
        peer_cert,
        ChannelBinding::synthetic_for_testing([0x11; 32]),
        ALPN_OPERATIONAL_V1.as_bytes().to_vec(),
    );

    let store = InMemoryTrustStore::new();
    let _ = store.insert_trusted_peer_for_testing(
        ctrl_kp.public_identity(),
        PeerRole::Controller,
        "FuzzPeer",
        Permissions::VIEW_MIRROR,
        1_000,
    );

    let req_bits = data.first().copied().unwrap_or(0) as u32 & Permissions::VALID_V1_MASK;
    let req_perms = Permissions::from_raw(req_bits).unwrap_or(Permissions::NONE);
    let session_id = if data.len() >= 8 {
        u64::from_be_bytes(data[..8].try_into().unwrap_or([1; 8]))
    } else {
        1
    };
    let policy_ctx = AuthorizationPolicyContext::allow_all_v1();

    if let Ok(grant) = authorize_session_open(
        &store,
        &tls_sess,
        PeerRole::Controller,
        req_perms,
        policy_ctx,
        session_id,
        2_000,
    ) {
        let _ = authorize_action(
            &store,
            &tls_sess,
            &grant,
            policy_ctx,
            Permissions::VIEW_MIRROR,
            1_500,
        );
    }

    let mgr = SessionTokenManager::new();
    let _ = mgr.validate_session_token(
        &store,
        &tls_sess,
        PeerRole::Controller,
        session_id,
        data,
        1_500,
    );
    if let Ok(mut rng) = CheckedOsCryptoRng::preflight() {
        let proof = [0x22; 32];
        let _ = mgr.consume_and_rotate_resume_token(
            &mut rng,
            &store,
            &tls_sess,
            PeerRole::Controller,
            session_id,
            data,
            &proof,
            1_500,
            60,
        );
    }

    let cache = BoundedChallengeCache::new();
    let _ = cache.check_and_insert_unique(b"fuzz", data, 1_500, 1_500, 60, 10);

    let mut seq = MonotonicSeqGuard::new();
    let _ = seq.check_and_advance(session_id);

    let limiter = AuthRateLimiter::new(RateLimitConfig::default());
    let peer = if data.len() >= 32 {
        DeviceId::from_bytes(data[..32].try_into().unwrap_or([0; 32]))
    } else {
        ctrl_kp.device_id()
    };
    let _ = limiter.check_allowed(peer, 1_500);
    let _ = limiter.record_failure(peer, 1_500);
});
