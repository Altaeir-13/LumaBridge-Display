// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Self-signed X.509 v3 Ed25519 device certificates tightly bound to `IdentityKeyPair`.

use crate::error::SecurityError;
use crate::identity::{DeviceId, IdentityKeyPair, PublicIdentity};
use der::{asn1::ObjectIdentifier, Decode, Encode};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, SanType, PKCS_ED25519,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use time::OffsetDateTime;
use x509_cert::certificate::{Certificate, Version};

/// OID `1.3.101.112` (`id-Ed25519`, RFC 8410).
const ID_ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Default certificate validity window (365 days in seconds).
pub const DEFAULT_CERT_VALIDITY_SECS: u64 = 365 * 24 * 60 * 60;

/// Generated X.509 v3 DER certificate and matching PKCS#8 private key material.
pub struct GeneratedDeviceCertificate {
    pub cert_der: Vec<u8>,
    pub pkcs8_der: zeroize::Zeroizing<Vec<u8>>,
    pub device_id: DeviceId,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
}

/// Verified peer certificate attributes extracted after strict DER + signature checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeviceCertificate {
    pub public_identity: PublicIdentity,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
}

/// Mint a self-signed X.509 v3 certificate from `identity` valid for `[not_before_unix, not_after_unix]`.
pub fn generate_self_signed_device_cert(
    identity: &IdentityKeyPair,
    not_before_unix: u64,
    not_after_unix: u64,
) -> Result<GeneratedDeviceCertificate, SecurityError> {
    if not_after_unix <= not_before_unix {
        return Err(SecurityError::InvalidTimestamp(
            "certificate not_after must exceed not_before",
        ));
    }
    let not_before_ts = i64::try_from(not_before_unix)
        .map_err(|_| SecurityError::InvalidTimestamp("not_before out of range"))?;
    let not_after_ts = i64::try_from(not_after_unix)
        .map_err(|_| SecurityError::InvalidTimestamp("not_after out of range"))?;

    let not_before = OffsetDateTime::from_unix_timestamp(not_before_ts)
        .map_err(|_| SecurityError::InvalidTimestamp("invalid not_before timestamp"))?;
    let not_after = OffsetDateTime::from_unix_timestamp(not_after_ts)
        .map_err(|_| SecurityError::InvalidTimestamp("invalid not_after timestamp"))?;

    let pkcs8_der = identity.to_pkcs8_v1_der();
    let pkcs8_ref = PrivatePkcs8KeyDer::from(pkcs8_der.as_slice());
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_ref, &PKCS_ED25519)
        .map_err(|_| SecurityError::CertificateGeneration("failed to load Ed25519 PKCS#8 key"))?;

    let short = identity.device_id().short_hex();
    let san_dns = format!("lumabridge-{short}.local");
    let san = rcgen::string::Ia5String::try_from(san_dns)
        .map_err(|_| SecurityError::CertificateGeneration("invalid SAN IA5 string"))?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("LumaBridge Device {short}"));
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(san)];
    params.not_before = not_before;
    params.not_after = not_after;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.use_authority_key_identifier_extension = false;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|_| SecurityError::CertificateGeneration("rcgen self-signed generation failed"))?;

    Ok(GeneratedDeviceCertificate {
        cert_der: cert.der().to_vec(),
        pkcs8_der,
        device_id: identity.device_id(),
        not_before_unix,
        not_after_unix,
    })
}

/// Strictly parse and validate a self-signed Ed25519 X.509 v3 certificate at `now_unix_secs`.
///
/// Enforces:
/// 1. Strict DER round-trip with no trailing bytes.
/// 2. X.509 Version 3.
/// 3. Outer and inner algorithm OIDs equal `id-Ed25519` (`1.3.101.112`) with absent parameters.
/// 4. Non-empty, matching validity window checked against `now_unix_secs`.
/// 5. Canonical 44-byte Ed25519 SPKI DER without weak/small-order key points.
/// 6. Strict RFC 8032 self-signature over `tbsCertificate` DER.
pub fn verify_self_signed_ed25519_cert(
    cert_der: &[u8],
    now_unix_secs: u64,
) -> Result<VerifiedDeviceCertificate, SecurityError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|_| SecurityError::CertificateValidation("malformed X.509 DER"))?;

    let reencoded = cert
        .to_der()
        .map_err(|_| SecurityError::CertificateValidation("certificate DER re-encode failed"))?;
    if reencoded.as_slice() != cert_der {
        return Err(SecurityError::CertificateValidation(
            "non-canonical DER or trailing garbage rejected",
        ));
    }

    if cert.tbs_certificate().version() != Version::V3 {
        return Err(SecurityError::CertificateValidation(
            "certificate must be X.509 v3",
        ));
    }

    if cert.signature_algorithm().oid != ID_ED25519_OID
        || cert.signature_algorithm().parameters.is_some()
    {
        return Err(SecurityError::CertificateValidation(
            "certificate signature algorithm must be pure Ed25519 without parameters",
        ));
    }

    if cert.tbs_certificate().signature() != cert.signature_algorithm() {
        return Err(SecurityError::CertificateValidation(
            "TBS signature algorithm does not match outer signature algorithm",
        ));
    }

    let validity = cert.tbs_certificate().validity();
    let not_before_unix = validity.not_before.to_unix_duration().as_secs();
    let not_after_unix = validity.not_after.to_unix_duration().as_secs();
    if not_after_unix <= not_before_unix {
        return Err(SecurityError::CertificateValidation(
            "invalid certificate validity interval",
        ));
    }
    if now_unix_secs < not_before_unix || now_unix_secs > not_after_unix {
        return Err(SecurityError::CertificateExpired);
    }

    let spki_der = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|_| SecurityError::CertificateValidation("SPKI DER encoding failed"))?;
    let public_identity = PublicIdentity::from_spki_der(&spki_der)?;

    if cert.signature().unused_bits() != 0 {
        return Err(SecurityError::CertificateValidation(
            "signature bitstring must have zero unused bits",
        ));
    }

    let tbs_der = cert
        .tbs_certificate()
        .to_der()
        .map_err(|_| SecurityError::CertificateValidation("TBS DER encoding failed"))?;
    public_identity.verify_strict(&tbs_der, cert.signature().raw_bytes())?;

    Ok(VerifiedDeviceCertificate {
        public_identity,
        not_before_unix,
        not_after_unix,
    })
}
