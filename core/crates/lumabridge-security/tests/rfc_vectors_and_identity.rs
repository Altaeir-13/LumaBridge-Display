// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

use lumabridge_protocol::control::ED25519_SPKI_DER_PREFIX;
use lumabridge_security::certificate::{
    generate_self_signed_device_cert, verify_self_signed_ed25519_cert,
};
use lumabridge_security::error::SecurityError;
use lumabridge_security::identity::{DeviceId, IdentityKeyPair, PublicIdentity};
use pakery_core::crypto::CpaceGroup;
use pakery_crypto::{P256Group, Spake2P256};
use pakery_spake2::{PartyA, PartyB};
use proptest::prelude::*;

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

fn decode_32(hex: &str) -> [u8; 32] {
    decode_hex(hex)
        .try_into()
        .expect("expected 32-byte hex scalar")
}

fn scalar_from_rfc9382_be32(hex: &str) -> <P256Group as CpaceGroup>::Scalar {
    let mut wide = [0u8; 64];
    let be = decode_32(hex);
    wide[32..].copy_from_slice(&be);
    P256Group::scalar_from_wide_bytes(&wide).expect("RFC 9382 P-256 scalar")
}

#[test]
fn rfc8032_section_7_1_test1_and_test2_vectors_and_strict_verification() {
    // RFC 8032 §7.1 TEST 1 (empty message)
    let sk1 = decode_32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let expected_pk1 =
        decode_32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let expected_sig1 = decode_hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    let id1 = IdentityKeyPair::from_seed(sk1).expect("RFC 8032 TEST 1 seed");
    assert_eq!(id1.public_identity().public_key_bytes(), &expected_pk1);
    let sig1 = id1.sign(b"");
    assert_eq!(sig1.as_slice(), expected_sig1.as_slice());
    assert!(id1.public_identity().verify_strict(b"", &sig1).is_ok());

    // Tampered message must fail verify_strict.
    assert_eq!(
        id1.public_identity().verify_strict(b"\x00", &sig1),
        Err(SecurityError::InvalidSignature)
    );

    // RFC 8032 §7.1 TEST 2 (message = 0x72)
    let sk2 = decode_32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let expected_pk2 =
        decode_32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let expected_sig2 = decode_hex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );

    let id2 = IdentityKeyPair::from_seed(sk2).expect("RFC 8032 TEST 2 seed");
    assert_eq!(id2.public_identity().public_key_bytes(), &expected_pk2);
    let sig2 = id2.sign(&[0x72]);
    assert_eq!(sig2.as_slice(), expected_sig2.as_slice());
    assert!(id2.public_identity().verify_strict(&[0x72], &sig2).is_ok());

    // Canonical SPKI DER validation must match RFC 8410/9295 44-byte envelope.
    let mut expected_spki = Vec::from(ED25519_SPKI_DER_PREFIX);
    expected_spki.extend_from_slice(&expected_pk2);
    assert_eq!(
        id2.public_identity().spki_der().as_slice(),
        expected_spki.as_slice()
    );

    // Small-order / weak Ed25519 points (identity point and canonical low-order points) rejected.
    let mut weak_identity_spki = Vec::from(ED25519_SPKI_DER_PREFIX);
    weak_identity_spki.push(0x01);
    weak_identity_spki.extend_from_slice(&[0u8; 31]);
    assert!(matches!(
        PublicIdentity::from_spki_der(&weak_identity_spki),
        Err(SecurityError::InvalidSpki(_))
    ));
}

#[test]
fn rfc9382_appendix_b_p256_sha256_hkdf_hmac_all_three_vectors() {
    struct Rfc9382Vec {
        id_a: &'static [u8],
        id_b: &'static [u8],
        w: &'static str,
        x: &'static str,
        y: &'static str,
        p_a: &'static str,
        p_b: &'static str,
        k_e: &'static str,
        c_a: &'static str,
        c_b: &'static str,
    }

    let vectors = [
        // RFC 9382 Appendix B Vector 1: A='server', B='client'
        Rfc9382Vec {
            id_a: b"server",
            id_b: b"client",
            w: "2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f",
            x: "43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729",
            y: "dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be",
            p_a: "04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470\
                  f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c",
            p_b: "0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676\
                  d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7",
            k_e: "0e0672dc86f8e45565d338b0540abe69",
            c_a: "58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0",
            c_b: "d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b",
        },
        // RFC 9382 Appendix B Vector 2: A='', B='client'
        Rfc9382Vec {
            id_a: b"",
            id_b: b"client",
            w: "0548d8729f730589e579b0475a582c1608138ddf7054b73b5381c7e883e2efae",
            x: "403abbe3b1b4b9ba17e3032849759d723939a27a27b9d921c500edde18ed654b",
            y: "903023b6598908936ea7c929bd761af6039577a9c3f9581064187c3049d87065",
            p_a: "04a897b769e681c62ac1c2357319a3d363f610839c4477720d24cbe32f5fd85f\
                  44fb92ba966578c1b712be6962498834078262caa5b441ecfa9d4a9485720e918a",
            p_b: "04e0f816fd1c35e22065d5556215c097e799390d16661c386e0ecc84593974a6\
                  1b881a8c82327687d0501862970c64565560cb5671f696048050ca66ca5f8cc7fc",
            k_e: "642f05c473c2cd79909f9a841e2f30a7",
            c_a: "47d29e6666af1b7dd450d571233085d7a9866e4d49d2645e2df975489521232b",
            c_b: "3313c5cefc361d27fb16847a91c2a73b766ffa90a4839122a9b70a2f6bd1d6df",
        },
        // RFC 9382 Appendix B Vector 3: A='server', B=''
        Rfc9382Vec {
            id_a: b"server",
            id_b: b"",
            w: "626e0cdc7b14c9db3e52a0b1b3a768c98e37852d5db30febe0497b14eae8c254",
            x: "07adb3db6bc623d3399726bfdbfd3d15a58ea776ab8a308b00392621291f9633",
            y: "b6a4fc8dbb629d4ba51d6f91ed1532cf87adec98f25dd153a75accafafedec16",
            p_a: "04f88fb71c99bfffaea370966b7eb99cd4be0ff1a7d335caac4211c4afd855e2\
                  e15a873b298503ad8ba1d9cbb9a392d2ba309b48bfd7879aefd0f2cea6009763b0",
            p_b: "040c269d6be017dccb15182ac6bfcd9e2a14de019dd587eaf4bdfd353f031101\
                  e7cca177f8eb362a6e83e7d5e729c0732e1b528879c086f39ba0f31a9661bd34db",
            k_e: "005184ff460da2ce59062c87733c299c",
            c_a: "bc9f9bbe99f26d0b2260e6456e05a86196a3307ec6663a18bf6ac825736533b2",
            c_b: "c2370e1bf813b086dff0d834e74425a06e6390f48f5411900276dcccc5a297ec",
        },
    ];

    for (idx, v) in vectors.iter().enumerate() {
        let w = scalar_from_rfc9382_be32(v.w);
        let x = scalar_from_rfc9382_be32(v.x);
        let y = scalar_from_rfc9382_be32(v.y);

        let (pa_bytes, state_a) =
            PartyA::<Spake2P256>::start_with_scalar(&w, &x, v.id_a, v.id_b, b"")
                .expect("PartyA start_with_scalar");
        let (pb_bytes, state_b) =
            PartyB::<Spake2P256>::start_with_scalar(&w, &y, v.id_a, v.id_b, b"")
                .expect("PartyB start_with_scalar");

        assert_eq!(pa_bytes, decode_hex(v.p_a), "vector {idx} pA mismatch");
        assert_eq!(pb_bytes, decode_hex(v.p_b), "vector {idx} pB mismatch");

        let out_a = state_a.finish(&pb_bytes).expect("PartyA finish");
        let out_b = state_b.finish(&pa_bytes).expect("PartyB finish");

        assert_eq!(
            out_a.confirmation_mac,
            decode_hex(v.c_a),
            "vector {idx} cA mismatch"
        );
        assert_eq!(
            out_b.confirmation_mac,
            decode_hex(v.c_b),
            "vector {idx} cB mismatch"
        );

        assert!(out_a
            .verify_peer_confirmation(&out_b.confirmation_mac)
            .is_ok());
        assert!(out_b
            .verify_peer_confirmation(&out_a.confirmation_mac)
            .is_ok());

        let ke_a = out_a.into_session_key();
        let ke_b = out_b.into_session_key();
        assert_eq!(
            ke_a.as_bytes(),
            decode_hex(v.k_e).as_slice(),
            "vector {idx} Ke A mismatch"
        );
        assert_eq!(
            ke_b.as_bytes(),
            decode_hex(v.k_e).as_slice(),
            "vector {idx} Ke B mismatch"
        );
    }
}

#[test]
fn certificate_validation_rejects_expiry_truncation_tamper_and_wrong_spki() {
    let id = IdentityKeyPair::from_seed([0x11; 32]).expect("seed");
    let cert = generate_self_signed_device_cert(&id, 1_700_000_000, 1_700_086_400).expect("cert");

    // Valid inside window
    let verified = verify_self_signed_ed25519_cert(&cert.cert_der, 1_700_000_500).expect("valid");
    assert_eq!(verified.public_identity.device_id(), id.device_id());

    // Before not_before and after not_after rejected as CertificateExpired
    assert_eq!(
        verify_self_signed_ed25519_cert(&cert.cert_der, 1_699_999_999),
        Err(SecurityError::CertificateExpired)
    );
    assert_eq!(
        verify_self_signed_ed25519_cert(&cert.cert_der, 1_700_086_401),
        Err(SecurityError::CertificateExpired)
    );

    // Trailing garbage rejected
    let mut with_trailing = cert.cert_der.clone();
    with_trailing.push(0x00);
    assert!(matches!(
        verify_self_signed_ed25519_cert(&with_trailing, 1_700_000_500),
        Err(SecurityError::CertificateValidation(_))
    ));

    // Bit-flipped signature rejected
    let mut tampered = cert.cert_der;
    let last_idx = tampered.len() - 1;
    tampered[last_idx] ^= 0x01;
    assert_eq!(
        verify_self_signed_ed25519_cert(&tampered, 1_700_000_500),
        Err(SecurityError::InvalidSignature)
    );

    // Invalid SPKI header/length rejected
    assert!(matches!(
        DeviceId::from_spki_der(&[0u8; 43]),
        Err(SecurityError::InvalidSpki(_))
    ));
    let mut wrong_oid = [0u8; 44];
    wrong_oid[..12].copy_from_slice(&ED25519_SPKI_DER_PREFIX);
    wrong_oid[8] = 0x71; // X448 OID instead of Ed25519 (0x70)
    assert!(matches!(
        PublicIdentity::from_spki_der(&wrong_oid),
        Err(SecurityError::InvalidSpki(_))
    ));
}

proptest! {
    #[test]
    fn prop_identity_and_self_signed_cert_roundtrip_and_fuzz_reject(
        seed in any::<[u8; 32]>(),
        msg in proptest::collection::vec(any::<u8>(), 0..256),
        garbage in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let kp = IdentityKeyPair::from_seed(seed).expect("32-byte seed generates keypair");
        let sig = kp.sign(&msg);
        prop_assert!(kp.public_identity().verify_strict(&msg, &sig).is_ok());
        prop_assert_eq!(
            DeviceId::from_spki_der(kp.public_identity().spki_der()),
            Ok(kp.device_id())
        );

        let cert = generate_self_signed_device_cert(&kp, 1_700_000_000, 1_705_000_000).expect("cert");
        let verified = verify_self_signed_ed25519_cert(&cert.cert_der, 1_701_000_000).expect("verify");
        prop_assert_eq!(verified.public_identity.device_id(), kp.device_id());

        // Arbitrary untrusted SPKI or X.509 DER bytes never panic.
        let _ = PublicIdentity::from_spki_der(&garbage);
        let _ = verify_self_signed_ed25519_cert(&garbage, 1_701_000_000);
    }
}
