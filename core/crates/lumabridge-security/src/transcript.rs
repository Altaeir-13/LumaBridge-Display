// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Domain-separated canonical deterministic CBOR (`LBWP-CBOR-v1`) cryptographic transcripts
//! bound to RFC 9266 `EXPORTER-Channel-Binding`, and separated token digest derivations.

use crate::channel_binding::ChannelBinding;
use crate::error::SecurityError;
use crate::identity::{DeviceId, PeerRole};
use crate::secret::{PinSecret, ResumeTokenSecret};
use hkdf::Hkdf;
use lumabridge_protocol::cbor::CborMapEncoder;
use lumabridge_protocol::control::{AuthMode, Permissions, ED25519_SPKI_DER_LEN};
use lumabridge_protocol::version::ALPN_PAIRING_V1;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Normative HKDF salt prefix for PIN-to-scalar conversion (`m1-3-security-architecture-spec.md` §4.2).
pub const PAIR_PIN_SALT_DOMAIN: &[u8] = b"lumabridge.pair.pin.salt.v1";

/// Normative HKDF info prefix for RFC 9382 `w` derivation (`m1-3-security-architecture-spec.md` §4.2).
pub const PAIR_W_INFO_DOMAIN: &[u8] = b"lumabridge.pair.spake2.w.v1";

/// Normative CBOR domain tag for RFC 9382 SPAKE2 AAD (`m1-3-security-architecture-spec.md` §4.1).
pub const PAIR_AAD_DOMAIN: &str = "lumabridge.pair.spake2.aad.v1";

/// Normative CBOR domain tag for `PairQrAuth` Ed25519 signature (`m1-3-security-architecture-spec.md` §4.1).
pub const PAIR_QR_SIG_DOMAIN: &str = "lumabridge.pair.qr.auth.v1";

/// Normative CBOR domain tag for `PairConfirm` Ed25519 signature (`m1-3-security-architecture-spec.md` §4.1).
pub const PAIR_CONFIRM_SIG_DOMAIN: &str = "lumabridge.pair.confirm.v1";

/// Normative SHA-256 domain for opaque session access token storage digests.
pub const SESSION_ACCESS_TOKEN_DOMAIN: &[u8] = b"lumabridge.session.access.token.v1";

/// Normative SHA-256 domain for opaque resume token storage digests (`m1-3-security-architecture-spec.md` §4.1).
pub const SESSION_RESUME_TOKEN_DOMAIN: &[u8] = b"lumabridge.session.resume.token.v1";

/// Normative HKDF info domain for channel-bound session resume proof.
pub const SESSION_RESUME_PROOF_DOMAIN: &[u8] = b"lumabridge.session.resume.proof.v1";

/// Construct RFC 9382 Party A / Party B role-separated endpoint identities (`LB-INIT:` / `LB-ACC:`).
#[must_use]
pub fn spake_endpoint_identities(
    initiator_id: DeviceId,
    acceptor_id: DeviceId,
) -> ([u8; 40], [u8; 39]) {
    let mut id_a = [0u8; 40];
    id_a[..8].copy_from_slice(b"LB-INIT:");
    id_a[8..].copy_from_slice(initiator_id.as_bytes());

    let mut id_b = [0u8; 39];
    id_b[..7].copy_from_slice(b"LB-ACC:");
    id_b[7..].copy_from_slice(acceptor_id.as_bytes());
    (id_a, id_b)
}

/// Derive 64 uniform wide bytes for RFC 9382 P-256 `w` scalar reduction via HKDF-SHA256.
///
/// Matches `m1-3-security-architecture-spec.md` §4.2:
/// - `salt = b"lumabridge.pair.pin.salt.v1" || attempt_id_be64`
/// - `ikm = pin_ascii_8bytes`
/// - `info = b"lumabridge.pair.spake2.w.v1" || init_id_32B || acc_id_32B`
pub fn derive_spake2_wide_secret(
    pin: &PinSecret,
    pairing_attempt_id: u64,
    initiator_id: DeviceId,
    acceptor_id: DeviceId,
) -> Result<Zeroizing<[u8; 64]>, SecurityError> {
    let mut salt = Zeroizing::new(Vec::with_capacity(PAIR_PIN_SALT_DOMAIN.len() + 8));
    salt.extend_from_slice(PAIR_PIN_SALT_DOMAIN);
    salt.extend_from_slice(&pairing_attempt_id.to_be_bytes());

    let mut info = Vec::with_capacity(PAIR_W_INFO_DOMAIN.len() + 64);
    info.extend_from_slice(PAIR_W_INFO_DOMAIN);
    info.extend_from_slice(initiator_id.as_bytes());
    info.extend_from_slice(acceptor_id.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), pin.expose_bytes());
    let mut wide = Zeroizing::new([0u8; 64]);
    hk.expand(&info, wide.as_mut())
        .map_err(|_| SecurityError::Spake2Failed)?;
    Ok(wide)
}

/// Structured inputs for deterministic `LBWP-CBOR-v1` RFC 9382 SPAKE2 AAD construction.
#[derive(Clone, Copy)]
pub struct Spake2AadContext<'a> {
    pub channel_binding: &'a ChannelBinding,
    pub pairing_attempt_id: u64,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub initiator_id: DeviceId,
    pub initiator_spki: &'a [u8; ED25519_SPKI_DER_LEN],
    pub initiator_role: PeerRole,
    pub acceptor_id: DeviceId,
    pub acceptor_spki: &'a [u8; ED25519_SPKI_DER_LEN],
    pub acceptor_role: PeerRole,
}

/// Build deterministic `LBWP-CBOR-v1` map AAD passed into RFC 9382 key confirmation schedule.
pub fn build_spake2_aad(ctx: Spake2AadContext<'_>) -> Result<Zeroizing<Vec<u8>>, SecurityError> {
    let mut buf = Zeroizing::new(Vec::with_capacity(320));
    let mut enc = CborMapEncoder::start(&mut buf, 13)
        .map_err(|_| SecurityError::ProtocolViolation("failed to encode SPAKE2 AAD CBOR map"))?;
    enc.put_text(1, PAIR_AAD_DOMAIN)
        .and_then(|()| enc.put_u64(2, u64::from(ctx.protocol_major)))
        .and_then(|()| enc.put_u64(3, u64::from(ctx.protocol_minor)))
        .and_then(|()| enc.put_u64(4, u64::from(AuthMode::PinSpake2 as u8)))
        .and_then(|()| enc.put_text(5, ALPN_PAIRING_V1))
        .and_then(|()| enc.put_u64(6, ctx.pairing_attempt_id))
        .and_then(|()| enc.put_bytes(7, ctx.initiator_id.as_bytes()))
        .and_then(|()| enc.put_bytes(8, ctx.initiator_spki))
        .and_then(|()| enc.put_text(9, ctx.initiator_role.as_label()))
        .and_then(|()| enc.put_bytes(10, ctx.acceptor_id.as_bytes()))
        .and_then(|()| enc.put_bytes(11, ctx.acceptor_spki))
        .and_then(|()| enc.put_text(12, ctx.acceptor_role.as_label()))
        .and_then(|()| enc.put_bytes(13, ctx.channel_binding.as_bytes()))
        .and_then(|()| enc.finish())
        .map_err(|_| SecurityError::ProtocolViolation("failed to serialize SPAKE2 AAD"))?;
    Ok(buf)
}

/// Structured inputs for deterministic `LBWP-CBOR-v1` `PairQrAuth` Ed25519 signature payload.
#[derive(Clone, Copy)]
pub struct QrAuthTranscriptContext<'a> {
    pub channel_binding: &'a ChannelBinding,
    pub pairing_attempt_id: u64,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub initiator_id: DeviceId,
    pub initiator_spki: &'a [u8; ED25519_SPKI_DER_LEN],
    pub acceptor_id: DeviceId,
    pub acceptor_spki: &'a [u8; ED25519_SPKI_DER_LEN],
    pub one_time_pairing_token: &'a [u8; 32],
}

/// Canonical deterministic CBOR payload signed by the initiator in `PairQrAuth`.
///
/// Signs `SHA-256(one_time_pairing_token)` alongside protocol version, ALPN, attempt ID,
/// canonical identities/SPKIs, and RFC 9266 `tls-exporter` channel binding.
pub fn build_qr_auth_signing_message(
    ctx: QrAuthTranscriptContext<'_>,
) -> Result<Zeroizing<Vec<u8>>, SecurityError> {
    let token_sha256: [u8; 32] = Sha256::digest(ctx.one_time_pairing_token).into();
    let mut buf = Zeroizing::new(Vec::with_capacity(320));
    let mut enc = CborMapEncoder::start(&mut buf, 12)
        .map_err(|_| SecurityError::ProtocolViolation("failed to encode QR auth CBOR map"))?;
    enc.put_text(1, PAIR_QR_SIG_DOMAIN)
        .and_then(|()| enc.put_u64(2, u64::from(ctx.protocol_major)))
        .and_then(|()| enc.put_u64(3, u64::from(ctx.protocol_minor)))
        .and_then(|()| enc.put_u64(4, u64::from(AuthMode::QrOutOfBand as u8)))
        .and_then(|()| enc.put_text(5, ALPN_PAIRING_V1))
        .and_then(|()| enc.put_u64(6, ctx.pairing_attempt_id))
        .and_then(|()| enc.put_bytes(7, ctx.initiator_id.as_bytes()))
        .and_then(|()| enc.put_bytes(8, ctx.initiator_spki))
        .and_then(|()| enc.put_bytes(9, ctx.acceptor_id.as_bytes()))
        .and_then(|()| enc.put_bytes(10, ctx.acceptor_spki))
        .and_then(|()| enc.put_bytes(11, ctx.channel_binding.as_bytes()))
        .and_then(|()| enc.put_bytes(12, &token_sha256))
        .and_then(|()| enc.finish())
        .map_err(|_| SecurityError::ProtocolViolation("failed to serialize QR auth payload"))?;
    Ok(buf)
}

/// Structured inputs for deterministic `LBWP-CBOR-v1` `PairConfirm` Ed25519 signature payload.
#[derive(Clone, Copy)]
pub struct PairConfirmTranscriptContext<'a> {
    pub channel_binding: &'a ChannelBinding,
    pub pairing_attempt_id: u64,
    pub auth_mode: AuthMode,
    pub accepted: bool,
    pub granted_base_perms: Permissions,
    pub initiator_id: DeviceId,
    pub initiator_spki: &'a [u8; ED25519_SPKI_DER_LEN],
    pub acceptor_id: DeviceId,
    pub acceptor_spki: &'a [u8; ED25519_SPKI_DER_LEN],
}

/// Canonical deterministic CBOR payload signed by the acceptor in `PairConfirm`.
pub fn build_pair_confirm_signing_message(
    ctx: PairConfirmTranscriptContext<'_>,
) -> Result<Zeroizing<Vec<u8>>, SecurityError> {
    let mut buf = Zeroizing::new(Vec::with_capacity(288));
    let mut enc = CborMapEncoder::start(&mut buf, 10)
        .map_err(|_| SecurityError::ProtocolViolation("failed to encode PairConfirm CBOR map"))?;
    enc.put_text(1, PAIR_CONFIRM_SIG_DOMAIN)
        .and_then(|()| enc.put_u64(2, ctx.pairing_attempt_id))
        .and_then(|()| enc.put_u64(3, u64::from(ctx.auth_mode as u8)))
        .and_then(|()| enc.put_bool(4, ctx.accepted))
        .and_then(|()| enc.put_u64(5, u64::from(ctx.granted_base_perms.raw())))
        .and_then(|()| enc.put_bytes(6, ctx.initiator_id.as_bytes()))
        .and_then(|()| enc.put_bytes(7, ctx.initiator_spki))
        .and_then(|()| enc.put_bytes(8, ctx.acceptor_id.as_bytes()))
        .and_then(|()| enc.put_bytes(9, ctx.acceptor_spki))
        .and_then(|()| enc.put_bytes(10, ctx.channel_binding.as_bytes()))
        .and_then(|()| enc.finish())
        .map_err(|_| SecurityError::ProtocolViolation("failed to serialize PairConfirm payload"))?;
    Ok(buf)
}

/// Derive a non-recoverable SHA-256 storage digest for an opaque session access token,
/// bound to `device_id`, `session_id`, and `trust_epoch`.
#[must_use]
pub fn derive_session_access_token_digest(
    token: &[u8; 32],
    device_id: DeviceId,
    session_id: u64,
    trust_epoch: u64,
) -> [u8; 32] {
    derive_domain_token_digest(
        SESSION_ACCESS_TOKEN_DOMAIN,
        token,
        device_id,
        session_id,
        trust_epoch,
    )
}

/// Derive a non-recoverable SHA-256 storage digest for an opaque single-use resume token
/// (`"lumabridge.session.resume.token.v1"`), bound to `device_id`, `session_id`, and `trust_epoch`.
#[must_use]
pub fn derive_resume_token_digest(
    token: &[u8; 32],
    device_id: DeviceId,
    session_id: u64,
    trust_epoch: u64,
) -> [u8; 32] {
    derive_domain_token_digest(
        SESSION_RESUME_TOKEN_DOMAIN,
        token,
        device_id,
        session_id,
        trust_epoch,
    )
}

fn derive_domain_token_digest(
    domain: &[u8],
    token: &[u8; 32],
    device_id: DeviceId,
    session_id: u64,
    trust_epoch: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    hasher.update(device_id.as_bytes());
    hasher.update(session_id.to_be_bytes());
    hasher.update(trust_epoch.to_be_bytes());
    hasher.update(token);
    hasher.finalize().into()
}

/// Derive a channel-bound authentication proof for resuming a session inside a new TLS 1.3 channel.
pub fn derive_resume_channel_proof(
    resume_token: &ResumeTokenSecret,
    channel_binding: &ChannelBinding,
    device_id: DeviceId,
    session_id: u64,
    trust_epoch: u64,
) -> Result<Zeroizing<[u8; 32]>, SecurityError> {
    let mut info = Vec::with_capacity(SESSION_RESUME_PROOF_DOMAIN.len() + 48);
    info.extend_from_slice(SESSION_RESUME_PROOF_DOMAIN);
    info.extend_from_slice(device_id.as_bytes());
    info.extend_from_slice(&session_id.to_be_bytes());
    info.extend_from_slice(&trust_epoch.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(
        Some(channel_binding.as_bytes()),
        resume_token.expose_secret(),
    );
    let mut proof = Zeroizing::new([0u8; 32]);
    hk.expand(&info, proof.as_mut())
        .map_err(|_| SecurityError::SessionTokenInvalid("proof derivation failed"))?;
    Ok(proof)
}
