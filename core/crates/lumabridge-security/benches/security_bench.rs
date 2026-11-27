// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use lumabridge_protocol::control::{AuthMode, PairHello, Permissions};
use lumabridge_protocol::version::{LBWP_PROTOCOL_MAJOR, LBWP_PROTOCOL_MINOR};
use lumabridge_security::authorization::{
    authorize_action, authorize_session_open, AuthorizationPolicyContext,
};
use lumabridge_security::certificate::{
    generate_self_signed_device_cert, verify_self_signed_ed25519_cert,
};
use lumabridge_security::identity::{IdentityKeyPair, PeerRole};
use lumabridge_security::pairing::{
    HumanApprovalDecision, PairingAcceptor, PairingInitiator, PinPairingWindow, QrTokenStore,
};
use lumabridge_security::secret::CheckedOsCryptoRng;
use lumabridge_security::session_token::SessionTokenManager;
use lumabridge_security::tls::{
    build_tls13_client_config, build_tls13_server_config, canonical_server_name_for_device,
    drive_in_memory_handshake, extract_authenticated_session_with_alpn, TlsPeerTrustPolicy,
    LUMABRIDGE_ALPN_V1, LUMABRIDGE_PAIR_ALPN_V1,
};
use lumabridge_security::trust_store::InMemoryTrustStore;
use rustls::{ClientConnection, ServerConnection};
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

struct StatsSummary {
    avg_ns: f64,
    p50_ns: u128,
    p95_ns: u128,
    p99_ns: u128,
    max_ns: u128,
}

fn summarize(samples: &mut [u128]) -> StatsSummary {
    samples.sort_unstable();
    let len = samples.len();
    let sum: u128 = samples.iter().copied().sum();
    let idx = |pct: usize| -> usize { ((len.saturating_sub(1)) * pct) / 100 };
    StatsSummary {
        avg_ns: (sum as f64) / (len as f64),
        p50_ns: samples[idx(50)],
        p95_ns: samples[idx(95)],
        p99_ns: samples[idx(99)],
        max_ns: samples[len.saturating_sub(1)],
    }
}

fn measure<F>(warmup: usize, iters: usize, mut op: F) -> StatsSummary
where
    F: FnMut(usize),
{
    for i in 0..warmup {
        op(i);
    }
    let mut samples = Vec::with_capacity(iters);
    for i in 0..iters {
        let start = Instant::now();
        op(i);
        samples.push(start.elapsed().as_nanos());
    }
    summarize(&mut samples)
}

fn print_summary(name: &str, s: &StatsSummary) {
    println!(
        "{name}: avg={:.1} ns p50={} ns p95={} ns p99={} ns max={} ns",
        s.avg_ns, s.p50_ns, s.p95_ns, s.p99_ns, s.max_ns
    );
}

fn main() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let host_kp = IdentityKeyPair::from_seed([0x10; 32]).expect("host kp");
    let ctrl_kp = IdentityKeyPair::from_seed([0x20; 32]).expect("ctrl kp");
    let host_cert =
        generate_self_signed_device_cert(&host_kp, now - 60, now + 86_400).expect("cert");
    let ctrl_cert =
        generate_self_signed_device_cert(&ctrl_kp, now - 60, now + 86_400).expect("cert");
    let payload = [0x42u8; 256];
    let sig = host_kp.sign(&payload);

    // 1. Ed25519 signing
    let s_sign = measure(50, 500, |_| {
        let out = host_kp.sign(black_box(&payload));
        black_box(out);
    });
    print_summary("ed25519_sign_256b", &s_sign);

    // 2. Ed25519 strict verification
    let s_verify = measure(50, 500, |_| {
        let ok = host_kp
            .public_identity()
            .verify_strict(black_box(&payload), black_box(&sig))
            .is_ok();
        black_box(ok);
    });
    print_summary("ed25519_verify_strict_256b", &s_verify);

    // 3. Self-signed X.509 v3 certificate validation
    let s_x509 = measure(20, 200, |_| {
        let verified =
            verify_self_signed_ed25519_cert(black_box(&host_cert.cert_der), now).expect("cert");
        black_box(verified);
    });
    print_summary("x509_v3_self_signed_verify", &s_x509);

    // 4. Real TLS 1.3 mTLS handshake + RFC 9266 channel binding export
    let host_store = Arc::new(InMemoryTrustStore::new());
    host_store
        .insert_newly_paired(
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            "Tablet",
            Permissions::VIEW_MIRROR,
            now,
        )
        .expect("insert");
    let ctrl_store = Arc::new(InMemoryTrustStore::new());
    ctrl_store
        .insert_newly_paired(
            host_kp.public_identity(),
            PeerRole::Host,
            "Host",
            Permissions::VIEW_MIRROR,
            now,
        )
        .expect("insert");

    let client_cfg = build_tls13_client_config(
        &ctrl_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: Arc::clone(&ctrl_store) as _,
            expected_role: PeerRole::Host,
        },
    )
    .expect("client cfg");
    let server_cfg = build_tls13_server_config(
        &host_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: Arc::clone(&host_store) as _,
            expected_role: PeerRole::Controller,
        },
    )
    .expect("server cfg");
    let sni = canonical_server_name_for_device(host_kp.device_id()).expect("sni");

    let mut last_tls_pair = None;
    let s_tls = measure(10, 80, |_| {
        let mut client = ClientConnection::new(Arc::clone(&client_cfg), sni.clone()).expect("cli");
        let mut server = ServerConnection::new(Arc::clone(&server_cfg)).expect("srv");
        drive_in_memory_handshake(&mut client, &mut server).expect("handshake");
        let cs =
            extract_authenticated_session_with_alpn(&client, LUMABRIDGE_ALPN_V1, now).expect("cs");
        let ss =
            extract_authenticated_session_with_alpn(&server, LUMABRIDGE_ALPN_V1, now).expect("ss");
        black_box((&cs, &ss));
        last_tls_pair = Some((cs, ss));
    });
    print_summary("tls13_mtls_handshake_plus_rfc9266", &s_tls);
    let (_, op_server_tls) = last_tls_pair.expect("tls pair");

    // Setup pairing TLS contexts for steps 5 & 6
    let p_cli_cfg = build_tls13_client_config(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store,
        },
    )
    .expect("p_cli");
    let p_srv_cfg = build_tls13_server_config(
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: Arc::clone(&host_store) as _,
        },
    )
    .expect("p_srv");
    let mut p_cli = ClientConnection::new(p_cli_cfg, sni).expect("cli");
    let mut p_srv = ServerConnection::new(p_srv_cfg).expect("srv");
    drive_in_memory_handshake(&mut p_cli, &mut p_srv).expect("handshake");
    let c_pair_tls =
        extract_authenticated_session_with_alpn(&p_cli, LUMABRIDGE_PAIR_ALPN_V1, now).expect("cs");
    let s_pair_tls =
        extract_authenticated_session_with_alpn(&p_srv, LUMABRIDGE_PAIR_ALPN_V1, now).expect("ss");

    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let pin_window = PinPairingWindow::new();

    let init_spake_hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *ctrl_kp.device_id().as_bytes(),
        friendly_name: "Tablet".into(),
        auth_mode: AuthMode::PinSpake2,
        spki_ed25519: ctrl_kp.public_identity().spki_der().to_vec(),
    };
    let acc_spake_hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *host_kp.device_id().as_bytes(),
        friendly_name: "Host".into(),
        auth_mode: AuthMode::PinSpake2,
        spki_ed25519: host_kp.public_identity().spki_der().to_vec(),
    };

    // 5. Full channel-bound SPAKE2-P256 exchange + confirm + local consent
    let s_spake = measure(10, 60, |i| {
        let attempt = u64::try_from(i + 1).expect("idx");
        let pin = pin_window.open_with_new_pin(&mut rng, now).expect("pin");
        let mut init = PairingInitiator::start(
            attempt,
            &ctrl_kp,
            PeerRole::Controller,
            &acc_spake_hello,
            &c_pair_tls,
            AuthMode::PinSpake2,
        )
        .expect("init");
        let mut acc = PairingAcceptor::start(
            attempt,
            &host_kp,
            PeerRole::Host,
            &init_spake_hello,
            &s_pair_tls,
        )
        .expect("acc");
        let m1 = init.begin_spake2(&pin, &mut rng).expect("m1");
        let m2 = acc
            .handle_spake2_exchange(&pin_window, &m1, now, &mut rng)
            .expect("m2");
        let m3 = init.finish_spake2_and_emit_confirmation(&m2).expect("m3");
        let m4 = acc.verify_spake2_confirmation_and_reply(&m3).expect("m4");
        init.verify_spake2_peer_confirmation(&m4).expect("verify");
        let c = acc
            .apply_human_approval(
                &host_kp,
                HumanApprovalDecision::Approve {
                    pairing_attempt_id: attempt,
                    peer_device_id: ctrl_kp.device_id(),
                    granted_base_perms: Permissions::VIEW_MIRROR,
                },
            )
            .expect("approve");
        init.verify_pair_confirm(&c).expect("verify confirm");
        let commit = init
            .apply_local_approval(HumanApprovalDecision::Approve {
                pairing_attempt_id: attempt,
                peer_device_id: host_kp.device_id(),
                granted_base_perms: Permissions::VIEW_MIRROR,
            })
            .expect("local confirm");
        black_box(commit);
    });
    print_summary("spake2_p256_channel_bound_full", &s_spake);

    // 6. Full channel-bound QR issue + sign + verify + consume + local consent
    let qr_store = QrTokenStore::new();
    let init_qr_hello = PairHello {
        auth_mode: AuthMode::QrOutOfBand,
        ..init_spake_hello
    };
    let acc_qr_hello = PairHello {
        auth_mode: AuthMode::QrOutOfBand,
        ..acc_spake_hello
    };
    let s_qr = measure(20, 200, |i| {
        let attempt = u64::try_from(i + 1000).expect("idx");
        let ticket = qr_store
            .issue(&mut rng, host_kp.device_id(), PeerRole::Host, now, 120)
            .expect("issue");
        let mut init = PairingInitiator::start(
            attempt,
            &ctrl_kp,
            PeerRole::Controller,
            &acc_qr_hello,
            &c_pair_tls,
            AuthMode::QrOutOfBand,
        )
        .expect("init");
        let mut acc = PairingAcceptor::start(
            attempt,
            &host_kp,
            PeerRole::Host,
            &init_qr_hello,
            &s_pair_tls,
        )
        .expect("acc");
        let auth = init.create_qr_auth(&ctrl_kp, &ticket, now).expect("auth");
        acc.verify_qr_auth(&qr_store, &auth, now)
            .expect("verify qr");
        let c = acc
            .apply_human_approval(
                &host_kp,
                HumanApprovalDecision::Approve {
                    pairing_attempt_id: attempt,
                    peer_device_id: ctrl_kp.device_id(),
                    granted_base_perms: Permissions::VIEW_MIRROR,
                },
            )
            .expect("approve");
        init.verify_pair_confirm(&c).expect("verify confirm");
        let commit = init
            .apply_local_approval(HumanApprovalDecision::Approve {
                pairing_attempt_id: attempt,
                peer_device_id: host_kp.device_id(),
                granted_base_perms: Permissions::VIEW_MIRROR,
            })
            .expect("local confirm");
        black_box(commit);
    });
    print_summary("qr_channel_bound_full", &s_qr);

    // 7. Session token validate + live 5-factor TrustStore action authorization
    let tok_mgr = SessionTokenManager::new();
    let creds = tok_mgr
        .issue_session(
            &mut rng,
            &*host_store,
            &op_server_tls,
            PeerRole::Controller,
            Permissions::VIEW_MIRROR,
            now,
            600,
            120,
        )
        .expect("creds");
    let policy_ctx = AuthorizationPolicyContext::allow_all_v1();
    let grant = authorize_session_open(
        &*host_store,
        &op_server_tls,
        PeerRole::Controller,
        Permissions::VIEW_MIRROR,
        policy_ctx,
        creds.session_id,
        now + 600,
    )
    .expect("grant");
    let s_authz = measure(100, 1000, |_| {
        let perms = tok_mgr
            .validate_session_token(
                &*host_store,
                &op_server_tls,
                PeerRole::Controller,
                creds.session_id,
                creds.session_token.expose_secret(),
                now + 5,
            )
            .expect("token ok");
        let authz = authorize_action(
            &*host_store,
            &op_server_tls,
            &grant,
            policy_ctx,
            Permissions::VIEW_MIRROR,
            now + 5,
        )
        .expect("authz ok");
        black_box((perms, authz));
    });
    print_summary("session_token_plus_live_authz", &s_authz);
}
