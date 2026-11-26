// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Domain-separated canonical cryptographic transcripts bound to RFC 9266 channel bindings.

use crate::channel_binding::ChannelBinding;
use crate::error::SecurityError;
use crate::identity::{DeviceId, PeerRole};
use crate::secret::{PinSecret, SessionTokenSecret};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use lumabridge_protocol::control::Permissions;
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const PAIR_W_DOMAIN: &[u8] = b"LumaBridge-Pair-SPAKE2-W-v1";
const PAIR_AAD_DOMAIN: &[u8] = b"LumaBridge-Pair-SPAKE2-AAD-v1";
const PAIR_QR_SIG_DOMAIN: &[u8] = b"LumaBridge-Pair-QR-Auth-v1";
const PAIR_CONFIRM_SIG_DOMAIN: &[u8] = b"LumaBridge-Pair-Confirm-v1";
const SESSION_TOKEN_BIND_DOMAIN: &[u8] = b"LumaBridge-Session-Token-Bind-v1";
const SESSION_TOKEN_MAC_DOMAIN: &[u8] = b"LumaBridge-Session-Token-Hmac-v1";

fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Construct RFC 9382 Party A / Party B role-separated endpoint identities.
#[must_use]
pub fn spake_endpoint_identities(
    initiator_id: DeviceId,
    acceptor_id: DeviceId,
) -> ([u8; 37], [u8; 37]) {
    let mut id_a = [0u8; 37];
    id_a[..5].copy_from_slice(b"init:");
    id_a[5..].copy_from_slice(initiator_id.as_bytes());

    let mut id_b = [0u8; 37];
    id_b[..5].copy_from_slice(b"accp:");
    id_b[5..].copy_from_slice(acceptor_id.as_bytes());
    (id_a, id_b)
}

/// Derive 64 uniform wide bytes for RFC 9382 P-256 `w` scalar reduction via HKDF-SHA256.
///
/// Binds the PIN to the active TLS 1.3 `channel_binding`, `pairing_attempt_id`, and both
/// endpoint canonical `DeviceId`s so stale or cross-channel PIN exchanges fail cleanly.
pub fn derive_spake2_wide_secret(
    pin: &PinSecret,
    channel_binding: &ChannelBinding,
    pairing_attempt_id: u64,
    initiator_id: DeviceId,
    acceptor_id: DeviceId,
) -> Result<Zeroizing<[u8; 64]>, SecurityError> {
    let mut info = Vec::with_capacity(PAIR_W_DOMAIN.len() + 96);
    push_len_prefixed(&mut info, PAIR_W_DOMAIN);
    info.extend_from_slice(&pairing_attempt_id.to_be_bytes());
    push_len_prefixed(&mut info, initiator_id.as_bytes());
    push_len_prefixed(&mut info, acceptor_id.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(channel_binding.as_bytes()), pin.expose_bytes());
    let mut wide = Zeroizing::new([0u8; 64]);
    hk.expand(&info, wide.as_mut())
        .map_err(|_| SecurityError::Spake2Failed)?;
    Ok(wide)
}

/// Structured inputs for canonical RFC 9382 SPAKE2 AAD construction.
#[derive(Debug, Clone, Copy)]
pub struct Spake2AadContext<'a> {
    pub channel_binding: &'a ChannelBinding,
    pub pairing_attempt_id: u64,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub initiator_id: DeviceId,
    pub initiator_role: PeerRole,
    pub acceptor_id: DeviceId,
    pub acceptor_role: PeerRole,
}

/// Build length-prefixed AAD passed into RFC 9382 key confirmation schedule.
#[must_use]
pub fn build_spake2_aad(ctx: Spake2AadContext<'_>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(192);
    push_len_prefixed(&mut aad, PAIR_AAD_DOMAIN);
    aad.extend_from_slice(ctx.channel_binding.as_bytes());
    aad.extend_from_slice(&ctx.pairing_attempt_id.to_be_bytes());
    aad.extend_from_slice(&ctx.protocol_major.to_be_bytes());
    aad.extend_from_slice(&ctx.protocol_minor.to_be_bytes());
    push_len_prefixed(&mut aad, ctx.initiator_id.as_bytes());
    push_len_prefixed(&mut aad, ctx.initiator_role.as_label().as_bytes());
    push_len_prefixed(&mut aad, ctx.acceptor_id.as_bytes());
    push_len_prefixed(&mut aad, ctx.acceptor_role.as_label().as_bytes());
    aad
}

/// Canonical message signed by the initiator in `PairQrAuth`.
#[must_use]
pub fn build_qr_auth_signing_message(
    channel_binding: &ChannelBinding,
    pairing_attempt_id: u64,
    initiator_id: DeviceId,
    acceptor_id: DeviceId,
    one_time_pairing_token: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(192);
    push_len_prefixed(&mut msg, PAIR_QR_SIG_DOMAIN);
    msg.extend_from_slice(channel_binding.as_bytes());
    msg.extend_from_slice(&pairing_attempt_id.to_be_bytes());
    push_len_prefixed(&mut msg, initiator_id.as_bytes());
    push_len_prefixed(&mut msg, acceptor_id.as_bytes());
    push_len_prefixed(&mut msg, one_time_pairing_token);
    msg
}

/// Canonical message signed by the acceptor in `PairConfirm`.
#[must_use]
pub fn build_pair_confirm_signing_message(
    channel_binding: &ChannelBinding,
    pairing_attempt_id: u64,
    initiator_id: DeviceId,
    acceptor_id: DeviceId,
    granted_base_perms: Permissions,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(160);
    push_len_prefixed(&mut msg, PAIR_CONFIRM_SIG_DOMAIN);
    msg.extend_from_slice(channel_binding.as_bytes());
    msg.extend_from_slice(&pairing_attempt_id.to_be_bytes());
    push_len_prefixed(&mut msg, initiator_id.as_bytes());
    push_len_prefixed(&mut msg, acceptor_id.as_bytes());
    msg.extend_from_slice(&granted_base_perms.raw().to_be_bytes());
    msg
}

/// Derive a keyed MAC binding digest for storing opaque session/resume tokens at rest.
#[must_use]
pub fn derive_token_digest(token: &[u8; 32], device_id: DeviceId, trust_epoch: u64) -> [u8; 32] {
    let mut mac_key_material = Vec::with_capacity(96);
    push_len_prefixed(&mut mac_key_material, SESSION_TOKEN_BIND_DOMAIN);
    push_len_prefixed(&mut mac_key_material, device_id.as_bytes());
    mac_key_material.extend_from_slice(&trust_epoch.to_be_bytes());

    let Ok(mut mac) = HmacSha256::new_from_slice(token) else {
        unreachable!("HMAC-SHA256 accepts any key length");
    };
    mac.update(&mac_key_material);
    mac.finalize().into_bytes().into()
}

/// Derive a channel-bound authentication proof for resuming a session inside a new TLS 1.3 channel.
pub fn derive_resume_channel_proof(
    resume_token: &SessionTokenSecret,
    channel_binding: &ChannelBinding,
    device_id: DeviceId,
    session_id: u64,
) -> Result<[u8; 32], SecurityError> {
    let mut info = Vec::with_capacity(96);
    push_len_prefixed(&mut info, SESSION_TOKEN_MAC_DOMAIN);
    push_len_prefixed(&mut info, device_id.as_bytes());
    info.extend_from_slice(&session_id.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(
        Some(channel_binding.as_bytes()),
        resume_token.expose_secret(),
    );
    let mut proof = [0u8; 32];
    hk.expand(&info, &mut proof)
        .map_err(|_| SecurityError::SessionTokenInvalid("proof derivation failed"))?;
    Ok(proof)
}
