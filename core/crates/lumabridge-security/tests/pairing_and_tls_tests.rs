// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

use lumabridge_protocol::control::{AuthMode, PairConfirm, PairHello, Permissions};
use lumabridge_protocol::version::{LBWP_PROTOCOL_MAJOR, LBWP_PROTOCOL_MINOR};
use lumabridge_security::certificate::{
    generate_self_signed_device_cert, GeneratedDeviceCertificate,
};
use lumabridge_security::channel_binding::ChannelBindingSource;
use lumabridge_security::error::SecurityError;
use lumabridge_security::identity::{IdentityKeyPair, PeerRole};
use lumabridge_security::pairing::{
    HumanApprovalDecision, PairingAcceptor, PairingInitiator, PairingStage, PinPairingWindow,
    QrTokenStore, MAX_PIN_FAILED_ATTEMPTS, PIN_TTL_SECS,
};
use lumabridge_security::secret::{CheckedOsCryptoRng, PinSecret};
use lumabridge_security::tls::{
    build_tls13_client_config, build_tls13_server_config, canonical_server_name_for_device,
    drive_in_memory_handshake, extract_authenticated_session_with_alpn,
    transfer_encrypted_app_data, AuthenticatedTlsSession, TlsPeerTrustPolicy, LUMABRIDGE_ALPN_V1,
    LUMABRIDGE_PAIR_ALPN_V1,
};
use lumabridge_security::trust_store::{
    AdminTrustImportRecord, InMemoryTrustStore, RevocationReason,
};
use rustls::client::Resumption;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ClientConnection, HandshakeKind, RootCertStore, ServerConnection};
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
    assert_ne!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_ne!(server.handshake_kind(), Some(HandshakeKind::Resumed));
    let client_sess = extract_authenticated_session_with_alpn(&client, &expected_alpn, now_unix)?;
    let server_sess = extract_authenticated_session_with_alpn(&server, &expected_alpn, now_unix)?;
    Ok((client_sess, server_sess, client, server))
}

#[test]
fn real_tls13_mtls_normative_cases_pinned_store_and_resumption_disabled() {
    let now = current_unix_time();
    let valid_start = now - 3600;
    let valid_end = now + 86_400;

    let (host_kp, host_cert) = make_identity_and_cert(0x10, valid_start, valid_end);
    let (ctrl_kp, ctrl_cert) = make_identity_and_cert(0x20, valid_start, valid_end);
    let (stranger_kp, stranger_cert) = make_identity_and_cert(0x30, valid_start, valid_end);
    let (_expired_kp, expired_cert) = make_identity_and_cert(0x40, now - 7200, now - 60);
    let (_future_kp, future_cert) = make_identity_and_cert(0x50, now + 3600, now + 7200);

    let host_store = Arc::new(InMemoryTrustStore::new());
    host_store
        .import_trusted_peer_admin(AdminTrustImportRecord {
            identity: ctrl_kp.public_identity().clone(),
            role: PeerRole::Controller,
            friendly_name: "Galaxy Tab".into(),
            base_permissions: Permissions::VIEW_MIRROR,
            paired_at_unix: now,
            last_seen_unix: now,
            trust_epoch: 1,
            perm_epoch: 1,
        })
        .expect("insert ctrl");

    let ctrl_store = Arc::new(InMemoryTrustStore::new());
    ctrl_store
        .import_trusted_peer_admin(AdminTrustImportRecord {
            identity: host_kp.public_identity().clone(),
            role: PeerRole::Host,
            friendly_name: "Desktop PC".into(),
            base_permissions: Permissions::VIEW_MIRROR,
            paired_at_unix: now,
            last_seen_unix: now,
            trust_epoch: 1,
            perm_epoch: 1,
        })
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
    assert_eq!(c_sess.channel_binding(), s_sess.channel_binding());
    assert_eq!(
        c_sess.channel_binding().source(),
        ChannelBindingSource::Tls13Exporter
    );
    assert_eq!(c_sess.negotiated_alpn(), LUMABRIDGE_ALPN_V1);
    assert_eq!(c_sess.peer_identity().device_id(), host_kp.device_id());
    assert_eq!(s_sess.peer_identity().device_id(), ctrl_kp.device_id());
    let received = transfer_encrypted_app_data(&mut client, &mut server, b"hello-lumabridge-tls13")
        .expect("encrypted transfer");
    assert_eq!(received, b"hello-lumabridge-tls13");

    // TLS resumption & 0-RTT explicitly disabled even when client enables in-memory session cache
    let server_cfg_no_resume = build_tls13_server_config(
        &host_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: host_store.clone(),
            expected_role: PeerRole::Controller,
        },
    )
    .expect("srv cfg");
    assert_eq!(server_cfg_no_resume.send_tls13_tickets, 0);
    assert_eq!(server_cfg_no_resume.max_early_data_size, 0);

    let mut greedy_client_cfg = (*build_tls13_client_config(
        &ctrl_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: ctrl_store.clone(),
            expected_role: PeerRole::Host,
        },
    )
    .expect("cli cfg"))
    .clone();
    greedy_client_cfg.resumption = Resumption::in_memory_sessions(16);
    greedy_client_cfg.enable_early_data = true;
    let greedy_client_cfg = Arc::new(greedy_client_cfg);
    let sni = canonical_server_name_for_device(host_kp.device_id()).expect("sni");

    for _ in 0..2 {
        let mut c = ClientConnection::new(Arc::clone(&greedy_client_cfg), sni.clone()).expect("c");
        let mut s = ServerConnection::new(Arc::clone(&server_cfg_no_resume)).expect("s");
        drive_in_memory_handshake(&mut c, &mut s).expect("full handshake");
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(s.handshake_kind(), Some(HandshakeKind::Full));
        assert!(!c.is_early_data_accepted());
    }

    // PinnedPeer MUST enforce TrustStore membership & role, rejecting untrusted or wrong-role pinned IDs
    let empty_store = Arc::new(InMemoryTrustStore::new());
    assert!(handshake_pair(
        &stranger_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: ctrl_store.clone(),
            expected_role: PeerRole::Host,
        },
        &host_cert,
        TlsPeerTrustPolicy::PinnedPeer {
            trust_store: empty_store,
            expected_role: PeerRole::Controller,
            expected_device_id: stranger_kp.device_id(),
        },
        now,
    )
    .is_err());

    // PinnedPeer succeeds when peer is both pinned AND trusted with matching role
    assert!(handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::PinnedPeer {
            trust_store: ctrl_store.clone(),
            expected_role: PeerRole::Host,
            expected_device_id: host_kp.device_id(),
        },
        &host_cert,
        TlsPeerTrustPolicy::PinnedPeer {
            trust_store: host_store.clone(),
            expected_role: PeerRole::Controller,
            expected_device_id: ctrl_kp.device_id(),
        },
        now,
    )
    .is_ok());

    // Case 2: Valid mutual TLS 1.3 pairing handshake (lumabridge-pair/1)
    let (p_c_sess, p_s_sess, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store.clone(),
        },
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: host_store.clone(),
        },
        now,
    )
    .expect("Case 2 valid pairing mTLS handshake");
    assert_eq!(p_c_sess.channel_binding(), p_s_sess.channel_binding());
    assert_eq!(p_c_sess.negotiated_alpn(), LUMABRIDGE_PAIR_ALPN_V1);
    assert_ne!(c_sess.channel_binding(), p_c_sess.channel_binding());

    // Case 3: Raw TLS 1.2 ClientHello wire record rejected by TLS 1.3-only server
    let server_cfg = build_tls13_server_config(
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: host_store.clone(),
        },
    )
    .expect("server cfg");
    let mut tls13_srv = ServerConnection::new(server_cfg).expect("srv");
    let mut tls12_client_hello = Vec::with_capacity(50);
    tls12_client_hello.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 45]);
    tls12_client_hello.extend_from_slice(&[0x01, 0x00, 0x00, 41]);
    tls12_client_hello.extend_from_slice(&[0x03, 0x03]);
    tls12_client_hello.extend_from_slice(&[0xAA; 32]);
    tls12_client_hello.push(0x00);
    tls12_client_hello.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]);
    tls12_client_hello.extend_from_slice(&[0x01, 0x00]);
    let mut slice = tls12_client_hello.as_slice();
    tls13_srv.read_tls(&mut slice).expect("read tls12 record");
    assert!(tls13_srv.process_new_packets().is_err());

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
        TlsPeerTrustPolicy::Pairing {
            trust_store: host_store.clone(),
        },
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
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store.clone(),
        },
        &host_cert,
        TlsPeerTrustPolicy::Trusted {
            trust_store: host_store.clone(),
            expected_role: PeerRole::Controller,
        },
        now,
    )
    .is_err());

    // Case 6: Wrong role rejected
    assert!(handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store.clone(),
        },
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
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store.clone(),
        },
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: host_store.clone(),
        },
        now,
    )
    .is_err());
    assert!(handshake_pair(
        &future_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store.clone(),
        },
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: host_store.clone(),
        },
        now,
    )
    .is_err());

    // Case 9: ALPN mismatch fails cleanly on an unrevoked peer + extractor enforces expected ALPN
    let alpn_res = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store.clone(),
        },
        &host_cert,
        TlsPeerTrustPolicy::PinnedPeer {
            trust_store: host_store.clone(),
            expected_role: PeerRole::Controller,
            expected_device_id: ctrl_kp.device_id(),
        },
        now,
    );
    assert!(matches!(
        alpn_res,
        Err(SecurityError::TlsHandshakeFailed(_) | SecurityError::AlpnMismatch)
    ));
    assert_eq!(
        extract_authenticated_session_with_alpn(&client, LUMABRIDGE_PAIR_ALPN_V1, now),
        Err(SecurityError::AlpnMismatch)
    );

    // Case 8: Revoked peer rejected in BOTH operational (Trusted & PinnedPeer) AND pairing modes
    host_store
        .revoke(
            ctrl_kp.device_id(),
            RevocationReason::SuspectedCompromise,
            now + 10,
        )
        .expect("revoke");
    assert!(handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store.clone(),
        },
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
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store.clone(),
        },
        &host_cert,
        TlsPeerTrustPolicy::PinnedPeer {
            trust_store: host_store.clone(),
            expected_role: PeerRole::Controller,
            expected_device_id: ctrl_kp.device_id(),
        },
        now,
    )
    .is_err());
    assert!(handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store,
        },
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: host_store,
        },
        now,
    )
    .is_err());
}

#[test]
fn channel_bound_spake2_local_consent_pin_budget_and_real_mitm_failure() {
    let now = current_unix_time();
    let (host_kp, host_cert) = make_identity_and_cert(0x31, now - 60, now + 3600);
    let (ctrl_kp, ctrl_cert) = make_identity_and_cert(0x32, now - 60, now + 3600);
    let (mitm_kp, mitm_cert) = make_identity_and_cert(0x33, now - 60, now + 3600);

    let host_store = Arc::new(InMemoryTrustStore::new());
    let ctrl_store = Arc::new(InMemoryTrustStore::new());

    let (c_tls, s_tls, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store.clone(),
        },
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: host_store.clone(),
        },
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

    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let pin_window = PinPairingWindow::new();
    let pin = pin_window.open_with_new_pin(&mut rng, now).expect("pin");
    assert_eq!(pin_window.remaining_attempts(now), MAX_PIN_FAILED_ATTEMPTS);

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

    let m1 = initiator.begin_spake2(&pin, &mut rng).expect("m1");
    assert_eq!(initiator.stage(), PairingStage::AuthExchanging);
    let m2 = acceptor
        .handle_spake2_exchange(&pin_window, &m1, now, &mut rng)
        .expect("m2");
    let m3 = initiator
        .finish_spake2_and_emit_confirmation(&m2)
        .expect("m3");
    let m4 = acceptor
        .verify_spake2_confirmation_and_reply(&m3, now)
        .expect("m4");
    initiator
        .verify_spake2_peer_confirmation(&m4)
        .expect("init confirmed mac");

    // Successful PIN verification consumes & destroys the single-use PIN immediately.
    assert_eq!(pin_window.remaining_attempts(now), 0);
    assert_eq!(initiator.stage(), PairingStage::AwaitingApproval);
    assert_eq!(acceptor.stage(), PairingStage::AwaitingApproval);

    // Input permissions forbidden at pairing time
    assert!(matches!(
        acceptor.apply_human_approval(
            &host_kp,
            HumanApprovalDecision::Approve {
                pairing_attempt_id: 77,
                peer_device_id: ctrl_kp.device_id(),
                granted_base_perms: Permissions::VIEW_MIRROR.union(Permissions::INPUT_POINTER),
            }
        ),
        Err(SecurityError::AuthorizationDenied(_))
    ));

    // Fresh handshake + PinPairingWindow with explicit local approval on BOTH Acceptor & Initiator
    let pin2 = pin_window.open_with_new_pin(&mut rng, now).expect("pin2");
    let (c_tls2, s_tls2, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store.clone(),
        },
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: host_store.clone(),
        },
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
    let m1 = init2.begin_spake2(&pin2, &mut rng).expect("m1");
    let m2 = acc2
        .handle_spake2_exchange(&pin_window, &m1, now, &mut rng)
        .expect("m2");
    let m3 = init2.finish_spake2_and_emit_confirmation(&m2).expect("m3");
    let m4 = acc2
        .verify_spake2_confirmation_and_reply(&m3, now)
        .expect("m4");
    init2.verify_spake2_peer_confirmation(&m4).expect("mac2");

    // Wrong-peer HumanApprovalDecision rejected cleanly
    let prompt_acc = acc2.approval_prompt().expect("prompt acc");
    assert_eq!(prompt_acc.peer_device_id, ctrl_kp.device_id());
    assert_eq!(prompt_acc.untrusted_friendly_name, "Tablet");

    let confirm = acc2
        .apply_human_approval(
            &host_kp,
            HumanApprovalDecision::Approve {
                pairing_attempt_id: 78,
                peer_device_id: ctrl_kp.device_id(),
                granted_base_perms: Permissions::VIEW_MIRROR.union(Permissions::EXTEND_DISPLAY),
            },
        )
        .expect("approve");
    let acc_commit = acc2.approved_commit().expect("acc commit");
    // Single-use ApprovedPairingCommit extraction: second call MUST fail
    assert!(matches!(
        acc2.approved_commit(),
        Err(SecurityError::PairingState(_))
    ));
    host_store
        .insert_approved_pairing(acc_commit, now)
        .expect("persist host trust");

    // Network PairConfirm NEVER promotes initiator to Confirmed without local human approval!
    let offered = init2.verify_pair_confirm(&confirm).expect("verify confirm");
    assert_eq!(
        offered,
        Permissions::VIEW_MIRROR.union(Permissions::EXTEND_DISPLAY)
    );
    assert_eq!(init2.stage(), PairingStage::AwaitingApproval);
    assert!(init2.granted_base_perms().is_none());

    let prompt_init = init2.approval_prompt().expect("prompt init");
    assert_eq!(prompt_init.offered_base_perms, Some(offered));
    let init_commit = init2
        .apply_local_approval(HumanApprovalDecision::Approve {
            pairing_attempt_id: 78,
            peer_device_id: host_kp.device_id(),
            granted_base_perms: Permissions::VIEW_MIRROR.union(Permissions::EXTEND_DISPLAY),
        })
        .expect("local initiator approval");
    assert_eq!(init2.stage(), PairingStage::Confirmed);
    assert_eq!(
        init_commit.granted_base_perms(),
        Permissions::VIEW_MIRROR.union(Permissions::EXTEND_DISPLAY)
    );
    ctrl_store
        .insert_approved_pairing(init_commit, now)
        .expect("persist ctrl trust");

    // Attempting replay / second SPAKE2 on confirmed connection is blocked
    assert!(matches!(
        init2.begin_spake2(&pin2, &mut rng),
        Err(SecurityError::PairingState(_))
    ));

    // Real 2-connection active MITM: Client <-> MITM <-> Host (distinct TLS channel bindings!)
    let mitm_store = Arc::new(InMemoryTrustStore::new());
    let (cli_mitm_tls, mitm_from_cli_tls, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store.clone(),
        },
        &mitm_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: mitm_store.clone(),
        },
        now,
    )
    .expect("cli-mitm tls");
    let (mitm_to_srv_tls, srv_mitm_tls, _, _) = handshake_pair(
        &mitm_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: mitm_store,
        },
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: host_store.clone(),
        },
        now,
    )
    .expect("mitm-srv tls");

    assert_ne!(
        cli_mitm_tls.channel_binding(),
        srv_mitm_tls.channel_binding()
    );
    let mitm_hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *mitm_kp.device_id().as_bytes(),
        friendly_name: "MITM".into(),
        auth_mode: AuthMode::PinSpake2,
        spki_ed25519: mitm_kp.public_identity().spki_der().to_vec(),
    };
    let pin3 = pin_window.open_with_new_pin(&mut rng, now).expect("pin3");
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
        .begin_spake2(&pin3, &mut rng)
        .expect("forwarded m1");
    let forwarded_m2 = victim_acc
        .handle_spake2_exchange(&pin_window, &forwarded_m1, now, &mut rng)
        .expect("forwarded m2");
    let forwarded_m3 = victim_init
        .finish_spake2_and_emit_confirmation(&forwarded_m2)
        .expect("forwarded m3");
    assert_eq!(
        victim_acc.verify_spake2_confirmation_and_reply(&forwarded_m3, now),
        Err(SecurityError::Spake2Failed)
    );
    let _ = (mitm_from_cli_tls, mitm_to_srv_tls);

    // PairConfirm with forged input permission is rejected by initiator verify_pair_confirm
    let (c_tls3, s_tls3, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: ctrl_store,
        },
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: host_store,
        },
        now,
    )
    .expect("tls3");
    let pin4 = pin_window.open_with_new_pin(&mut rng, now).expect("pin4");
    let mut init3 = PairingInitiator::start(
        101,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls3,
        AuthMode::PinSpake2,
    )
    .expect("init3");
    let mut acc3 =
        PairingAcceptor::start(101, &host_kp, PeerRole::Host, &init_hello, &s_tls3).expect("acc3");
    let m1_3 = init3.begin_spake2(&pin4, &mut rng).expect("m1_3");
    let m2_3 = acc3
        .handle_spake2_exchange(&pin_window, &m1_3, now, &mut rng)
        .expect("m2_3");
    let m3_3 = init3
        .finish_spake2_and_emit_confirmation(&m2_3)
        .expect("m3_3");
    let m4_3 = acc3
        .verify_spake2_confirmation_and_reply(&m3_3, now)
        .expect("m4_3");
    init3.verify_spake2_peer_confirmation(&m4_3).expect("mac3");

    let forged_confirm = PairConfirm {
        pairing_attempt_id: 101,
        accepted: true,
        granted_base_perms: Permissions::INPUT_KEYBOARD,
        confirm_signature: Some(vec![0u8; 64]),
    };
    assert!(matches!(
        init3.verify_pair_confirm(&forged_confirm),
        Err(SecurityError::AuthorizationDenied(_))
    ));
    assert_eq!(init3.stage(), PairingStage::Failed);

    // Zero pairing_attempt_id and control-char friendly_name rejected at start()
    assert!(matches!(
        PairingInitiator::start(
            0,
            &ctrl_kp,
            PeerRole::Controller,
            &acc_hello,
            &c_tls3,
            AuthMode::PinSpake2,
        ),
        Err(SecurityError::ProtocolViolation(_))
    ));
    let bad_hello = PairHello {
        friendly_name: "Bad\nName".into(),
        ..init_hello
    };
    assert!(matches!(
        PairingAcceptor::start(102, &host_kp, PeerRole::Host, &bad_hello, &s_tls3),
        Err(SecurityError::ProtocolViolation(_))
    ));
}

#[test]
fn atomic_three_attempt_pin_budget_concurrency_and_expiry_destroy_pin() {
    let now = current_unix_time();
    let (host_kp, host_cert) = make_identity_and_cert(0x71, now - 60, now + 3600);
    let (ctrl_kp, ctrl_cert) = make_identity_and_cert(0x72, now - 60, now + 3600);
    let store = Arc::new(InMemoryTrustStore::new());
    let (c_tls, s_tls, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: store.clone(),
        },
        &host_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: store },
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

    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let window = PinPairingWindow::new();
    let real_pin = window.open_with_new_pin(&mut rng, now).expect("pin");
    let wrong_pin = if real_pin.expose_bytes() == b"00000000" {
        PinSecret::new("11111111").expect("wrong pin")
    } else {
        PinSecret::new("00000000").expect("wrong pin")
    };

    // Three failed attempts exhaust and immediately destroy the PIN!
    for attempt in 1u64..=3u64 {
        let mut init = PairingInitiator::start(
            attempt,
            &ctrl_kp,
            PeerRole::Controller,
            &acc_hello,
            &c_tls,
            AuthMode::PinSpake2,
        )
        .expect("init");
        let mut acc =
            PairingAcceptor::start(attempt, &host_kp, PeerRole::Host, &init_hello, &s_tls)
                .expect("acc");
        let m1 = init.begin_spake2(&wrong_pin, &mut rng).expect("m1");
        let m2 = acc
            .handle_spake2_exchange(&window, &m1, now, &mut rng)
            .expect("m2");
        let m3 = init.finish_spake2_and_emit_confirmation(&m2).expect("m3");
        assert_eq!(
            acc.verify_spake2_confirmation_and_reply(&m3, now),
            Err(SecurityError::Spake2Failed)
        );
    }

    // Even with the CORRECT PIN, attempt 4 MUST fail closed!
    assert_eq!(window.remaining_attempts(now), 0);
    let mut init4 = PairingInitiator::start(
        4,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls,
        AuthMode::PinSpake2,
    )
    .expect("init4");
    let mut acc4 =
        PairingAcceptor::start(4, &host_kp, PeerRole::Host, &init_hello, &s_tls).expect("acc4");
    let m1_4 = init4.begin_spake2(&real_pin, &mut rng).expect("m1_4");
    assert_eq!(
        acc4.handle_spake2_exchange(&window, &m1_4, now, &mut rng),
        Err(SecurityError::PairingWindowClosed)
    );

    // 90s expiry destroys the PIN cleanly even when queried via remaining_attempts
    let _exp_pin = window.open_with_new_pin(&mut rng, now).expect("exp pin");
    assert_eq!(window.remaining_attempts(now + PIN_TTL_SECS + 1), 0);
    assert_eq!(
        window.begin_attempt(now + PIN_TTL_SECS + 1).err(),
        Some(SecurityError::PairingWindowClosed)
    );

    // Cross-generation lease safety: stale leases from PIN_1 failing/succeeding after PIN_2 rotation
    // MUST return PairingWindowClosed AND MUST NOT poison or destroy PIN_2!
    let _pin_gen1 = window.open_with_new_pin(&mut rng, now).expect("gen1");
    let stale_fail_lease = window.begin_attempt(now).expect("stale fail lease");
    let stale_succ_lease = window.begin_attempt(now).expect("stale succ lease");
    let _pin_gen2 = window.open_with_new_pin(&mut rng, now).expect("gen2");
    stale_fail_lease.finish_failure();
    assert_eq!(
        stale_succ_lease.finish_success(now),
        Err(SecurityError::PairingWindowClosed)
    );
    assert_eq!(window.remaining_attempts(now), MAX_PIN_FAILED_ATTEMPTS);
    let fresh_gen2_lease = window.begin_attempt(now).expect("gen2 still active");
    assert_eq!(fresh_gen2_lease.finish_success(now), Ok(()));

    // 16-thread concurrent race on one PinPairingWindow: strictly <= 3 leases ever granted!
    let _race_pin = window.open_with_new_pin(&mut rng, now).expect("race pin");
    let barrier = Arc::new(Barrier::new(16));
    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        let w = window.clone();
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            match w.begin_attempt(now) {
                Ok(lease) => {
                    lease.finish_failure();
                    true
                }
                Err(_) => false,
            }
        }));
    }
    let granted: usize = handles
        .into_iter()
        .map(|h| usize::from(h.join().expect("join")))
        .sum();
    assert_eq!(granted, MAX_PIN_FAILED_ATTEMPTS as usize);
    assert_eq!(window.remaining_attempts(now), 0);
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

    let trust_store = Arc::new(InMemoryTrustStore::new());
    let (c_tls, s_tls, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: trust_store.clone(),
        },
        &host_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: trust_store.clone(),
        },
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

    // Role-mismatched QR ticket (Controller vs expected Host) rejected with RoleConfusion
    let wrong_role_ticket = qr_store
        .issue(
            &mut rng,
            host_kp.device_id(),
            PeerRole::Controller,
            BASE_TIME,
            120,
        )
        .expect("wrong role ticket");
    let mut bad_role_init = PairingInitiator::start(
        501,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls,
        AuthMode::QrOutOfBand,
    )
    .expect("bad role init");
    assert_eq!(
        bad_role_init.create_qr_auth(&ctrl_kp, &wrong_role_ticket, BASE_TIME + 5),
        Err(SecurityError::RoleConfusion)
    );

    let qr_auth = init
        .create_qr_auth(&ctrl_kp, &ticket, BASE_TIME + 5)
        .expect("qr auth");

    // Active MITM trying to relay PairQrAuth onto another TLS channel fails signature check BEFORE consuming!
    let (_cli_mitm, srv_mitm, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: trust_store.clone(),
        },
        &mitm_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: trust_store.clone(),
        },
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
        mitm_acc.verify_qr_auth(&qr_store, &qr_auth, BASE_TIME + 5),
        Err(SecurityError::InvalidSignature)
    );

    // Legitimate host still succeeds and consumes ticket once
    acc.verify_qr_auth(&qr_store, &qr_auth, BASE_TIME + 5)
        .expect("legit host qr");
    let confirm = acc
        .apply_human_approval(
            &host_kp,
            HumanApprovalDecision::Approve {
                pairing_attempt_id: 500,
                peer_device_id: ctrl_kp.device_id(),
                granted_base_perms: Permissions::VIEW_MIRROR,
            },
        )
        .expect("approve");
    init.verify_pair_confirm(&confirm).expect("verify confirm");
    let commit = init
        .apply_local_approval(HumanApprovalDecision::Approve {
            pairing_attempt_id: 500,
            peer_device_id: host_kp.device_id(),
            granted_base_perms: Permissions::VIEW_MIRROR,
        })
        .expect("local confirm");
    assert_eq!(commit.granted_base_perms(), Permissions::VIEW_MIRROR);

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

#[test]
fn pin_confirmation_rejects_expiry_close_rotation_and_concurrent_winner_deterministically() {
    let base_t = current_unix_time();
    let (host_kp, host_cert) = make_identity_and_cert(0x81, base_t - 60, base_t + 3600);
    let (ctrl_kp, ctrl_cert) = make_identity_and_cert(0x82, base_t - 60, base_t + 3600);
    let store = Arc::new(InMemoryTrustStore::new());
    let (c_tls, s_tls, _, _) = handshake_pair(
        &ctrl_cert,
        TlsPeerTrustPolicy::Pairing {
            trust_store: store.clone(),
        },
        &host_cert,
        TlsPeerTrustPolicy::Pairing { trust_store: store },
        base_t,
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

    let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
    let window = PinPairingWindow::new();

    // 1. Reservation at base_t, confirmation past 90s TTL (base_t + PIN_TTL_SECS + 1) MUST fail
    let pin_exp = window.open_with_new_pin(&mut rng, base_t).expect("pin exp");
    let mut init_exp = PairingInitiator::start(
        9001,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls,
        AuthMode::PinSpake2,
    )
    .expect("init exp");
    let mut acc_exp = PairingAcceptor::start(9001, &host_kp, PeerRole::Host, &init_hello, &s_tls)
        .expect("acc exp");
    let m1 = init_exp.begin_spake2(&pin_exp, &mut rng).expect("m1");
    let m2 = acc_exp
        .handle_spake2_exchange(&window, &m1, base_t + 10, &mut rng)
        .expect("m2");
    let m3 = init_exp
        .finish_spake2_and_emit_confirmation(&m2)
        .expect("m3");
    assert_eq!(
        acc_exp.verify_spake2_confirmation_and_reply(&m3, base_t + PIN_TTL_SECS + 1),
        Err(SecurityError::PairingWindowClosed)
    );
    assert_eq!(acc_exp.stage(), PairingStage::Failed);

    // Exact boundary base_t + PIN_TTL_SECS succeeds
    let pin_bnd = window.open_with_new_pin(&mut rng, base_t).expect("pin bnd");
    let mut init_bnd = PairingInitiator::start(
        9002,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls,
        AuthMode::PinSpake2,
    )
    .expect("init bnd");
    let mut acc_bnd = PairingAcceptor::start(9002, &host_kp, PeerRole::Host, &init_hello, &s_tls)
        .expect("acc bnd");
    let m1 = init_bnd.begin_spake2(&pin_bnd, &mut rng).expect("m1");
    let m2 = acc_bnd
        .handle_spake2_exchange(&window, &m1, base_t + 10, &mut rng)
        .expect("m2");
    let m3 = init_bnd
        .finish_spake2_and_emit_confirmation(&m2)
        .expect("m3");
    assert!(acc_bnd
        .verify_spake2_confirmation_and_reply(&m3, base_t + PIN_TTL_SECS)
        .is_ok());

    // 2. Reservation before close(), confirmation after close() MUST fail
    let pin_cls = window.open_with_new_pin(&mut rng, base_t).expect("pin cls");
    let mut init_cls = PairingInitiator::start(
        9003,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls,
        AuthMode::PinSpake2,
    )
    .expect("init cls");
    let mut acc_cls = PairingAcceptor::start(9003, &host_kp, PeerRole::Host, &init_hello, &s_tls)
        .expect("acc cls");
    let m1 = init_cls.begin_spake2(&pin_cls, &mut rng).expect("m1");
    let m2 = acc_cls
        .handle_spake2_exchange(&window, &m1, base_t + 1, &mut rng)
        .expect("m2");
    let m3 = init_cls
        .finish_spake2_and_emit_confirmation(&m2)
        .expect("m3");
    window.close().expect("close");
    assert_eq!(
        acc_cls.verify_spake2_confirmation_and_reply(&m3, base_t + 2),
        Err(SecurityError::PairingWindowClosed)
    );
    assert_eq!(acc_cls.stage(), PairingStage::Failed);

    // 3. Reservation on gen 1, PIN rotation to gen 2, confirmation on gen 1 MUST fail WITHOUT disturbing gen 2
    let pin_g1 = window.open_with_new_pin(&mut rng, base_t).expect("pin g1");
    let mut init_g1 = PairingInitiator::start(
        9004,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls,
        AuthMode::PinSpake2,
    )
    .expect("init g1");
    let mut acc_g1 = PairingAcceptor::start(9004, &host_kp, PeerRole::Host, &init_hello, &s_tls)
        .expect("acc g1");
    let m1 = init_g1.begin_spake2(&pin_g1, &mut rng).expect("m1");
    let m2 = acc_g1
        .handle_spake2_exchange(&window, &m1, base_t + 5, &mut rng)
        .expect("m2");
    let m3 = init_g1
        .finish_spake2_and_emit_confirmation(&m2)
        .expect("m3");
    let pin_g2 = window
        .open_with_new_pin(&mut rng, base_t + 6)
        .expect("pin g2");
    assert_eq!(
        acc_g1.verify_spake2_confirmation_and_reply(&m3, base_t + 7),
        Err(SecurityError::PairingWindowClosed)
    );
    assert_eq!(acc_g1.stage(), PairingStage::Failed);
    assert_eq!(
        window.remaining_attempts(base_t + 7),
        MAX_PIN_FAILED_ATTEMPTS
    );

    // Backwards confirmation clock before reservation timestamp MUST fail cleanly
    let mut init_back = PairingInitiator::start(
        9005,
        &ctrl_kp,
        PeerRole::Controller,
        &acc_hello,
        &c_tls,
        AuthMode::PinSpake2,
    )
    .expect("init back");
    let mut acc_back = PairingAcceptor::start(9005, &host_kp, PeerRole::Host, &init_hello, &s_tls)
        .expect("acc back");
    let m1 = init_back.begin_spake2(&pin_g2, &mut rng).expect("m1");
    let m2 = acc_back
        .handle_spake2_exchange(&window, &m1, base_t + 10, &mut rng)
        .expect("m2");
    let m3 = init_back
        .finish_spake2_and_emit_confirmation(&m2)
        .expect("m3");
    assert!(matches!(
        acc_back.verify_spake2_confirmation_and_reply(&m3, base_t + 9),
        Err(SecurityError::InvalidTimestamp(_))
    ));
    assert_eq!(acc_back.stage(), PairingStage::Failed);

    // 4. Deterministic barrier race: 3 concurrent attempts on ONE PIN race at confirmation -> strictly 1 winner!
    let pin_conc = window
        .open_with_new_pin(&mut rng, base_t + 20)
        .expect("pin conc");
    let barrier = Arc::new(Barrier::new(3));
    let mut prepared = Vec::with_capacity(3);
    for idx in 0..3u64 {
        let mut init = PairingInitiator::start(
            9100 + idx,
            &ctrl_kp,
            PeerRole::Controller,
            &acc_hello,
            &c_tls,
            AuthMode::PinSpake2,
        )
        .expect("init conc");
        let mut acc =
            PairingAcceptor::start(9100 + idx, &host_kp, PeerRole::Host, &init_hello, &s_tls)
                .expect("acc conc");
        let m1 = init.begin_spake2(&pin_conc, &mut rng).expect("m1");
        let m2 = acc
            .handle_spake2_exchange(&window, &m1, base_t + 21, &mut rng)
            .expect("m2");
        let m3 = init.finish_spake2_and_emit_confirmation(&m2).expect("m3");
        prepared.push((acc, m3));
    }

    let mut handles = Vec::with_capacity(3);
    for (mut acc, m3) in prepared {
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let res = acc.verify_spake2_confirmation_and_reply(&m3, base_t + 25);
            (res.is_ok(), res.err(), acc.stage())
        }));
    }
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();
    let winners = outcomes.iter().filter(|(ok, _, _)| *ok).count();
    let closed_losers = outcomes
        .iter()
        .filter(|(ok, err, st)| {
            !*ok && matches!(err, Some(SecurityError::PairingWindowClosed))
                && *st == PairingStage::Failed
        })
        .count();
    assert_eq!(winners, 1);
    assert_eq!(closed_losers, 2);
    assert_eq!(window.remaining_attempts(base_t + 25), 0);
}
