// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use lumabridge_protocol::cbor::CborDecodeOptions;
use lumabridge_protocol::control::{AuthMode, ControlMessage, MsgType, PairHello, Permissions};
use lumabridge_protocol::version::{ALPN_PAIRING_V1, LBWP_PROTOCOL_MAJOR, LBWP_PROTOCOL_MINOR};
use lumabridge_security::certificate::{
    generate_self_signed_device_cert, verify_self_signed_ed25519_cert,
};
use lumabridge_security::channel_binding::ChannelBinding;
use lumabridge_security::identity::{IdentityKeyPair, PeerRole};
use lumabridge_security::pairing::{PairingAcceptor, PinPairingWindow};
use lumabridge_security::secret::CheckedOsCryptoRng;
use lumabridge_security::tls::AuthenticatedTlsSession;

fuzz_target!(|data: &[u8]| {
    let Ok(ctrl_kp) = IdentityKeyPair::from_seed([0x21; 32]) else {
        return;
    };
    let Ok(host_kp) = IdentityKeyPair::from_seed([0x22; 32]) else {
        return;
    };
    let Ok(ctrl_cert_gen) = generate_self_signed_device_cert(&ctrl_kp, 1_700_000_000, 1_800_000_000)
    else {
        return;
    };
    let Ok(peer_cert) = verify_self_signed_ed25519_cert(&ctrl_cert_gen.cert_der, 1_700_000_100)
    else {
        return;
    };
    let tls_sess = AuthenticatedTlsSession::synthetic_for_testing(
        peer_cert,
        ChannelBinding::synthetic_for_testing([0x55; 32]),
        ALPN_PAIRING_V1.as_bytes().to_vec(),
    );
    let hello = PairHello {
        protocol_major: LBWP_PROTOCOL_MAJOR,
        protocol_minor: LBWP_PROTOCOL_MINOR,
        device_id: *ctrl_kp.device_id().as_bytes(),
        friendly_name: "Fuzz".into(),
        auth_mode: AuthMode::PinSpake2,
        spki_ed25519: ctrl_kp.public_identity().spki_der().to_vec(),
    };
    let Ok(mut acc) = PairingAcceptor::start(1, &host_kp, PeerRole::Host, &hello, &tls_sess)
    else {
        return;
    };
    let Ok(mut rng) = CheckedOsCryptoRng::preflight() else {
        return;
    };
    let window = PinPairingWindow::new();
    let Ok(_pin) = window.open_with_new_pin(&mut rng, 1_700_000_100) else {
        return;
    };

    if let Ok(msg) =
        ControlMessage::decode_cbor(MsgType::PairSpakeMsg, data, CborDecodeOptions::default())
    {
        if let ControlMessage::PairSpakeMsg(spake) = msg {
            let _ = acc.handle_spake2_exchange(&window, &spake, 1_700_000_100, &mut rng);
            let _ = acc.verify_spake2_confirmation_and_reply(&spake, 1_700_000_100);
        }
    } else {
        let raw_msg = lumabridge_protocol::control::PairSpakeMsg {
            pairing_attempt_id: 1,
            step: lumabridge_protocol::control::SpakeStep::KeyExchange,
            spake_payload: data.to_vec(),
            key_confirmation: None,
        };
        let _ = acc.handle_spake2_exchange(&window, &raw_msg, 1_700_000_100, &mut rng);
    }
    let _ = Permissions::VIEW_MIRROR;
});
