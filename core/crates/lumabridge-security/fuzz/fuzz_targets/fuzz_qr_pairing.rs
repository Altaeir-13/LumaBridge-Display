// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use lumabridge_protocol::cbor::CborDecodeOptions;
use lumabridge_protocol::control::{AuthMode, ControlMessage, MsgType, PairHello, PairQrAuth};
use lumabridge_protocol::version::{ALPN_PAIRING_V1, LBWP_PROTOCOL_MAJOR, LBWP_PROTOCOL_MINOR};
use lumabridge_security::certificate::{
    generate_self_signed_device_cert, verify_self_signed_ed25519_cert,
};
use lumabridge_security::channel_binding::ChannelBinding;
use lumabridge_security::identity::{IdentityKeyPair, PeerRole};
use lumabridge_security::pairing::{PairingAcceptor, QrTokenStore};
use lumabridge_security::tls::AuthenticatedTlsSession;

fuzz_target!(|data: &[u8]| {
    let Ok(ctrl_kp) = IdentityKeyPair::from_seed([0x31; 32]) else {
        return;
    };
    let Ok(host_kp) = IdentityKeyPair::from_seed([0x32; 32]) else {
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
    let tls_sess = AuthenticatedTlsSession {
        peer_cert,
        channel_binding: ChannelBinding::from_bytes([0x66; 32]),
        negotiated_alpn: ALPN_PAIRING_V1.as_bytes().to_vec(),
    };
    let hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *ctrl_kp.device_id().as_bytes(),
        friendly_name: "QrFuzz".into(),
        auth_mode: AuthMode::QrOutOfBand,
        spki_ed25519: ctrl_kp.public_identity().spki_der().to_vec(),
    };
    let qr_store = QrTokenStore::new();
    let Ok(mut acc) = PairingAcceptor::start(42, &host_kp, PeerRole::Host, &hello, &tls_sess)
    else {
        return;
    };

    if let Ok(msg) =
        ControlMessage::decode_cbor(MsgType::PairQrAuth, data, CborDecodeOptions::default())
    {
        if let ControlMessage::PairQrAuth(qr) = msg {
            let _ = acc.verify_qr_auth(host_kp.device_id(), &qr_store, &qr, 1_700_000_100);
        }
    } else if data.len() >= 96 {
        let qr = PairQrAuth {
            pairing_attempt_id: 42,
            one_time_pairing_token: data[..32].to_vec(),
            initiator_signature: data[32..96].to_vec(),
        };
        let _ = acc.verify_qr_auth(host_kp.device_id(), &qr_store, &qr, 1_700_000_100);
    } else {
        let _ = qr_store.consume_once(data, host_kp.device_id(), 1_700_000_100);
    }
});
