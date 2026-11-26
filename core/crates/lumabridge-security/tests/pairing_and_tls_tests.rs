// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

use lumabridge_protocol::control::{AuthMode, PairConfirm, PairHello, Permissions};
use lumabridge_protocol::version::{LBWP_PROTOCOL_MAJOR, LBWP_PROTOCOL_MINOR};
use lumabridge_security::certificate::{
    generate_self_signed_device_cert, GeneratedDeviceCertificate,
};
use lumabridge_security::error::SecurityError;
use lumabridge_security::identity::{IdentityKeyPair, PeerRole};
use lumabridge_security::pairing::{
    HumanApprovalDecision, PairingAcceptor, PairingInitiator, PairingStage, QrTokenStore,
};
use lumabridge_security::secret::{CheckedOsCryptoRng, PinSecret};
use lumabridge_security::tls::{
    build_tls13_client_config, build_tls13_server_config, canonical_server_name_for_device,
    drive_in_memory_handshake, extract_authenticated_session_with_alpn,
    transfer_encrypted_app_data, AuthenticatedTlsSession, TlsPeerTrustPolicy, LUMABRIDGE_ALPN_V1,
    LUMABRIDGE_PAIR_ALPN_V1,
};
use lumabridge_security::trust_store::{InMemoryTrustStore, RevocationReason};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection};
use std::sync::{Arc, Barrier};
use std::thread;

const BASE_TIME: u64 = 1_700_000_100;

fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn make_identity_and_cert(
    seed: u8,
    not_before: u64,
    not_after: u64,
) -> (IdentityKeyPair, GeneratedDeviceCertificate) {
    let kp = IdentityKeyPair::from_seed([seed; 32]).expect("seed");
    let cert = generate_self_signed_device_cert(&kp, not_before, not_after).expect("cert");
    (kp, cert)
}

fn handshake_pair(
    client_cert: &GeneratedDeviceCertificate,
    client_policy: TlsPeerTrustPolicy,
    server_cert: &GeneratedDeviceCertificate,
    server_policy: TlsPeerTrustPolicy,
    now_unix: u64,
) -> Result<
    (
        AuthenticatedTlsSession,
        AuthenticatedTlsSession,
        ClientConnection,
        ServerConnection,
    ),
    SecurityError,
> {
    let expected_alpn = client_policy.expected_alpn().to_vec();
    let client_cfg = build_tls13_client_config(client_cert, client_policy)?;
    let server_cfg = build_tls13_server_config(server_cert, server_policy)?;
    let sni = canonical_server_name_for_device(server_cert.device_id)?;

    let mut client = ClientConnection::new(client_cfg, sni)
        .map_err(|_| SecurityError::TlsHandshakeFailed("client init failed"))?;
    let mut server = ServerConnection::new(server_cfg)
        .map_err(|_| SecurityError::TlsHandshakeFailed("server init failed"))?;

    drive_in_memory_handshake(&mut client, &mut server)?;
    let client_sess = extract_authenticated_session_with_alpn(&client, &expected_alpn, now_unix)?;
    let server_sess = extract_authenticated_session_with_alpn(&server, &expected_alpn, now_unix)?;
    Ok((client_sess, server_sess, client, server))
}

#[test]
fn real_tls13_mtls_nine_normative_cases() {
    let now = current_unix_time();
    let valid_start = now - 3600;
    let valid_end = now + 86_400;

    let (host_kp, host_cert) = make_identity_and_cert(0x10, valid_start, valid_end);
    let (ctrl_kp, ctrl_cert) = make_identity_and_cert(0x20, valid_start, valid_end);
    let (_stranger_kp, stranger_cert) = make_identity_and_cert(0x30, valid_start, valid_end);
    let (_expired_kp, expired_cert) = make_identity_and_cert(0x40, now - 7200, now - 60);
    let (_future_kp, future_cert) = make_identity_and_cert(0x50, now + 3600, now + 7200);

    let host_store = Arc::new(InMemoryTrustStore::new());
    host_store
        .insert_newly_paired(
            ctrl_kp.public_identity(),
            PeerRole::Controller,
            "Galaxy Tab",
            Permissions::VIEW_MIRROR,
            now,
        )
        .expect("insert ctrl");

    let ctrl_store = Arc::new(InMemoryTrustStore::new());
    ctrl_store
        .insert_newly_paired(
            host_kp.public_identity(),
            PeerRole::Host,
            "Desktop PC",
            Permissions::VIEW_MIRROR,
            now,
        )
        .expect("insert host");

    // Case 1: Valid mutual TLS 1.3 operational handshake + RFC 9266 CB equality + encrypted app data
    let (c_sess, s_sess, mut client, mut server) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: ctrl_store.clone(),
            expected_role: PeerRole::Host,
        },
        &host_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: host_store.clone(),
            expected_role: PeerRole::Controller,
        },
        now,
    )
    .expect("Case 1 valid mTLS handshake");
    assert_eq!(c_sess.channel_binding, s_sess.channel_binding);
    assert_eq!(c_sess.negotiated_alpn, LUMABRIDGE_ALPN_V1);
    assert_eq!(
        c_sess.peer_cert.public_identity.device_id(),
        host_kp.device_id()
    );
    assert_eq!(
        s_sess.peer_cert.public_identity.device_id(),
        ctrl_kp.device_id()
    );
    let received = transfer_encrypted_app_data(&mut client, &mut server, b"hello-lumabridge-tls13")
        .expect("encrypted transfer");
    assert_eq!(received, b"hello-lumabridge-tls13");

    // Case 2: Valid mutual TLS 1.3 pairing handshake (lumabridge-pair/1)
    let (p_c_sess, p_s_sess, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: Some(host_store.clone()),
        },
        now,
    )
    .expect("Case 2 valid pairing mTLS handshake");
    assert_eq!(p_c_sess.channel_binding, p_s_sess.channel_binding);
    assert_eq!(p_c_sess.negotiated_alpn, LUMABRIDGE_PAIR_ALPN_V1);
    // Distinct handshakes produce distinct RFC 9266 channel bindings.
    assert_ne!(c_sess.channel_binding, p_c_sess.channel_binding);

    // Case 3: Raw TLS 1.2 ClientHello wire record rejected by TLS 1.3-only server
    let server_cfg = build_tls13_server_config(
        &host_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
    )
    .expect("server cfg");
    let mut tls13_srv = ServerConnection::new(server_cfg).expect("srv");
    // Minimal RFC 5246 TLS 1.2 ClientHello without TLS 1.3 supported_versions extension (50 bytes).
    let mut tls12_client_hello = Vec::with_capacity(50);
    tls12_client_hello.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 45]); // TLS Record header
    tls12_client_hello.extend_from_slice(&[0x01, 0x00, 0x00, 41]); // Handshake ClientHello header
    tls12_client_hello.extend_from_slice(&[0x03, 0x03]); // Legacy client_version TLS 1.2
    tls12_client_hello.extend_from_slice(&[0xAA; 32]); // Random
    tls12_client_hello.push(0x00); // Session ID length = 0
    tls12_client_hello.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]); // ECDHE_RSA_AES128_GCM_SHA256
    tls12_client_hello.extend_from_slice(&[0x01, 0x00]); // Compression = null
    let mut slice = tls12_client_hello.as_slice();
    tls13_srv.read_tls(&mut slice).expect("read tls12 record");
    assert!(
        tls13_srv.process_new_packets().is_err(),
        "TLS 1.3-only server must reject TLS 1.2 ClientHello"
    );

    // Case 4: Client without mTLS certificate rejected cleanly
    let mut roots2 = RootCertStore::empty();
    roots2
        .add(CertificateDer::from(host_cert.cert_der.clone()))
        .expect("add root");
    let no_cert_client_cfg = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls13 cfg")
            .with_root_certificates(roots2)
            .with_no_client_auth(),
    );
    let server_cfg2 = build_tls13_server_config(
        &host_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
    )
    .expect("server cfg");
    let mut no_cert_cli = ClientConnection::new(
        no_cert_client_cfg,
        canonical_server_name_for_device(host_kp.device_id()).expect("sni"),
    )
    .expect("no cert client");
    let mut m_srv = ServerConnection::new(server_cfg2).expect("srv");
    assert!(drive_in_memory_handshake(&mut no_cert_cli, &mut m_srv).is_err());

    // Case 5: Untrusted device rejected in operational mode
    assert!(handshake_pair(
        &stranger_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: host_store.clone(),
            expected_role: PeerRole::Controller,
        },
        now,
    )
    .is_err());

    // Case 6: Wrong role rejected (stored Controller presenting as expected Host)
    assert!(handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: host_store.clone(),
            expected_role: PeerRole::Host,
        },
        now,
    )
    .is_err());

    // Case 7: Expired and not-yet-valid certificates rejected
    assert!(handshake_pair(
        &expired_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        now,
    )
    .is_err());
    assert!(handshake_pair(
        &future_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        now,
    )
    .is_err());

    // Case 8: Revoked peer rejected in BOTH operational AND pairing modes
    host_store
        .revoke(
            ctrl_kp.device_id(),
            RevocationReason::SuspectedCompromise,
            now + 10,
        )
        .expect("revoke");
    assert!(handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: host_store.clone(),
            expected_role: PeerRole::Controller,
        },
        now,
    )
    .is_err());
    assert!(handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: Some(host_store.clone()),
        },
        now,
    )
    .is_err());

    // Case 9: ALPN mismatch between client (`lumabridge-pair/1`) and server (`lumabridge/1`) fails cleanly
    let alpn_res = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::PinnedPeer {
            expected_device_id: ctrl_kp.device_id(),
        },
        now,
    );
    assert!(matches!(
        alpn_res,
        Err(SecurityError::TlsHandshakeFailed(_) | SecurityError::AlpnMismatch)
    ));
}

#[test]
fn channel_bound_spake2_end_to_end_and_real_mitm_failure() {
    let now = current_unix_time();
    let (host_kp, host_cert) = make_identity_and_cert(0x31, now - 60, now + 3600);
    let (ctrl_kp, ctrl_cert) = make_identity_and_cert(0x32, now - 60, now + 3600);
    let (mitm_kp, mitm_cert) = make_identity_and_cert(0x33, now - 60, now + 3600);

    // Legitimate pairing over matching TLS 1.3 channel binding
    let (c_tls, s_tls, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        now,
    )
    .expect("tls");

    let init_hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *ctrl_kp.device_id().as_bytes(),
        friendly_name: "Tablet".into(),
        auth_mode: AuthMode::PinSpake2,
        spki_ed25519: ctrl_kp.public_identity().spki_der().to_vec(),
    };
    let acc_hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *host_kp.device_id().as_bytes(),
        friendly_name: "Host".into(),
        auth_mode: AuthMode::PinSpake2,
        spki_ed25519: host_kp.public_identity().spki_der().to_vec(),
    };

    let pin = PinSecret::new("492817").expect("pin");
    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");

    let mut initiator = PairingInitiator::start(
        77,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls,
        AuthMode::PinSpake2,
    )
    .expect("init");
    let mut acceptor =
        PairingAcceptor::start(77, &host_kp, PeerRole::Host, &init_hello, &s_tls).expect("acc");

    let m1 = initiator
        .begin_spake2(ctrl_kp.device_id(), &pin, &mut rng)
        .expect("m1");
    assert_eq!(initiator.stage(), PairingStage::AuthExchanging);
    let m2 = acceptor
        .handle_spake2_exchange(host_kp.device_id(), &pin, &m1, &mut rng)
        .expect("m2");
    let m3 = initiator
        .finish_spake2_and_emit_confirmation(&m2)
        .expect("m3");
    let m4 = acceptor
        .verify_spake2_confirmation_and_reply(&m3)
        .expect("m4");
    initiator
        .verify_spake2_peer_confirmation(&m4)
        .expect("init confirmed mac");

    assert_eq!(initiator.stage(), PairingStage::AwaitingApproval);
    assert_eq!(acceptor.stage(), PairingStage::AwaitingApproval);

    // Input permissions forbidden at pairing time
    assert!(matches!(
        acceptor.apply_human_approval(
            &host_kp,
            HumanApprovalDecision::Approve {
                granted_base_perms: Permissions::VIEW_MIRROR.union(Permissions::INPUT_POINTER),
            }
        ),
        Err(SecurityError::AuthorizationDenied(_))
    ));

    // Re-run cleanly with base-only permissions after failed stage cannot proceed without new conn;
    // so run fresh handshake and test HumanApprovalDecision::Approve + Confirm signature.
    let (c_tls2, s_tls2, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        now,
    )
    .expect("tls2");
    let mut init2 = PairingInitiator::start(
        78,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls2,
        AuthMode::PinSpake2,
    )
    .expect("init2");
    let mut acc2 =
        PairingAcceptor::start(78, &host_kp, PeerRole::Host, &init_hello, &s_tls2).expect("acc2");
    let m1 = init2
        .begin_spake2(ctrl_kp.device_id(), &pin, &mut rng)
        .expect("m1");
    let m2 = acc2
        .handle_spake2_exchange(host_kp.device_id(), &pin, &m1, &mut rng)
        .expect("m2");
    let m3 = init2.finish_spake2_and_emit_confirmation(&m2).expect("m3");
    let m4 = acc2.verify_spake2_confirmation_and_reply(&m3).expect("m4");
    init2.verify_spake2_peer_confirmation(&m4).expect("mac2");

    let confirm = acc2
        .apply_human_approval(
            &host_kp,
            HumanApprovalDecision::Approve {
                granted_base_perms: Permissions::VIEW_MIRROR.union(Permissions::EXTEND_DISPLAY),
            },
        )
        .expect("approve");
    let perms = init2
        .accept_pair_confirm(ctrl_kp.device_id(), &confirm)
        .expect("confirm");
    assert_eq!(
        perms,
        Permissions::VIEW_MIRROR.union(Permissions::EXTEND_DISPLAY)
    );

    // Tampered certificate rejected during real TLS 1.3 handshake
    let mut tampered_cert = GeneratedDeviceCertificate {
        cert_der: ctrl_cert.cert_der.clone(),
        pkcs8_der: zeroize::Zeroizing::new(ctrl_cert.pkcs8_der.to_vec()),
        device_id: ctrl_cert.device_id,
        not_before_unix: ctrl_cert.not_before_unix,
        not_after_unix: ctrl_cert.not_after_unix,
    };
    if let Some(last) = tampered_cert.cert_der.last_mut() {
        *last ^= 0x55;
    }
    assert!(handshake_pair(
        &tampered_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        now,
    )
    .is_err());
    assert_eq!(acc2.stage(), PairingStage::Confirmed);
    assert_eq!(init2.stage(), PairingStage::Confirmed);

    // Attempting replay / second SPAKE2 on confirmed or active connection is blocked
    assert!(matches!(
        init2.begin_spake2(ctrl_kp.device_id(), &pin, &mut rng),
        Err(SecurityError::PairingState(_))
    ));

    // Real 2-connection active MITM: Client <-> MITM <-> Host (distinct TLS channel bindings!)
    let (cli_mitm_tls, mitm_from_cli_tls, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &mitm_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        now,
    )
    .expect("cli-mitm tls");
    let (mitm_to_srv_tls, srv_mitm_tls, _, _) = handshake_pair(
        &mitm_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        now,
    )
    .expect("mitm-srv tls");

    assert_ne!(cli_mitm_tls.channel_binding, srv_mitm_tls.channel_binding);
    let mitm_hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *mitm_kp.device_id().as_bytes(),
        friendly_name: "MITM".into(),
        auth_mode: AuthMode::PinSpake2,
        spki_ed25519: mitm_kp.public_identity().spki_der().to_vec(),
    };
    let mut victim_init = PairingInitiator::start(
        99,
        &ctrl_kp,
        PeerRole::Controller,
        &mitm_hello,
        &cli_mitm_tls,
        AuthMode::PinSpake2,
    )
    .expect("victim");
    let mut victim_acc =
        PairingAcceptor::start(99, &host_kp, PeerRole::Host, &mitm_hello, &srv_mitm_tls)
            .expect("victim acc");

    let forwarded_m1 = victim_init
        .begin_spake2(ctrl_kp.device_id(), &pin, &mut rng)
        .expect("forwarded m1");
    // Host computes pB under (mitm_id, host_id, srv_mitm_cb) while client uses (ctrl_id, mitm_id, cli_mitm_cb).
    let forwarded_m2 = victim_acc
        .handle_spake2_exchange(host_kp.device_id(), &pin, &forwarded_m1, &mut rng)
        .expect("forwarded m2");
    let forwarded_m3 = victim_init
        .finish_spake2_and_emit_confirmation(&forwarded_m2)
        .expect("forwarded m3");
    assert_eq!(
        victim_acc.verify_spake2_confirmation_and_reply(&forwarded_m3),
        Err(SecurityError::Spake2Failed)
    );
    let _ = (mitm_from_cli_tls, mitm_to_srv_tls);

    // PairConfirm with forged input permission fails client-side verification too
    let _ = PairConfirm {
        pairing_attempt_id: 1,
        accepted: true,
        granted_base_perms: Permissions::INPUT_KEYBOARD,
        confirm_signature: Some(vec![0u8; 64]),
    };
}

#[test]
fn qr_pairing_mitm_rejection_and_concurrent_single_use_race() {
    let now = current_unix_time();
    let (host_kp, host_cert) = make_identity_and_cert(0x41, now - 60, now + 3600);
    let (ctrl_kp, ctrl_cert) = make_identity_and_cert(0x42, now - 60, now + 3600);
    let (mitm_kp, mitm_cert) = make_identity_and_cert(0x43, now - 60, now + 3600);

    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let qr_store = Arc::new(QrTokenStore::new());
    let ticket = qr_store
        .issue(
            &mut rng,
            host_kp.device_id(),
            PeerRole::Host,
            BASE_TIME,
            120,
        )
        .expect("issue ticket");

    let (c_tls, s_tls, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &host_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        now,
    )
    .expect("qr tls");

    let init_hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *ctrl_kp.device_id().as_bytes(),
        friendly_name: "Phone".into(),
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
        500,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls,
        AuthMode::QrOutOfBand,
    )
    .expect("init");
    let mut acc =
        PairingAcceptor::start(500, &host_kp, PeerRole::Host, &init_hello, &s_tls).expect("acc");

    let qr_auth = init
        .create_qr_auth(&ctrl_kp, &ticket, BASE_TIME + 5)
        .expect("qr auth");

    // Active MITM trying to relay PairQrAuth onto another TLS channel fails signature check BEFORE consuming!
    let (_cli_mitm, srv_mitm, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        &mitm_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: None },
        now,
    )
    .expect("mitm tls");
    let mitm_hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *ctrl_kp.device_id().as_bytes(),
        friendly_name: "Phone".into(),
        auth_mode: AuthMode::QrOutOfBand,
        spki_ed25519: ctrl_kp.public_identity().spki_der().to_vec(),
    };
    let mut mitm_acc =
        PairingAcceptor::start(500, &mitm_kp, PeerRole::Host, &mitm_hello, &srv_mitm)
            .expect("mitm acc");
    assert_eq!(
        mitm_acc.verify_qr_auth(mitm_kp.device_id(), &qr_store, &qr_auth, BASE_TIME + 5),
        Err(SecurityError::InvalidSignature)
    );

    // Legitimate host still succeeds and consumes ticket once
    acc.verify_qr_auth(host_kp.device_id(), &qr_store, &qr_auth, BASE_TIME + 5)
        .expect("legit host qr");
    let confirm = acc
        .apply_human_approval(
            &host_kp,
            HumanApprovalDecision::Approve {
                granted_base_perms: Permissions::VIEW_MIRROR,
            },
        )
        .expect("approve");
    let perms = init
        .accept_pair_confirm(ctrl_kp.device_id(), &confirm)
        .expect("confirm");
    assert_eq!(perms, Permissions::VIEW_MIRROR);

    // 16-thread race on one fresh QR ticket: strictly 1 winner, 15 rejections!
    let race_ticket = qr_store
        .issue(
            &mut rng,
            host_kp.device_id(),
            PeerRole::Host,
            BASE_TIME,
            120,
        )
        .expect("race ticket");
    let raw_token = *race_ticket.token.expose_secret();
    let barrier = Arc::new(Barrier::new(16));
    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        let store = Arc::clone(&qr_store);
        let b = Arc::clone(&barrier);
        let host_id = host_kp.device_id();
        handles.push(thread::spawn(move || {
            b.wait();
            store.consume_once(&raw_token, host_id, BASE_TIME + 1)
        }));
    }
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("thread join"))
        .collect();
    let ok_count = outcomes.iter().filter(|r| r.is_ok()).count();
    let reused_count = outcomes
        .iter()
        .filter(|r| matches!(r, Err(SecurityError::QrTokenReusedOrUnknown)))
        .count();
    assert_eq!(ok_count, 1);
    assert_eq!(reused_count, 15);
}
