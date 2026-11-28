// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Canonical Ed25519 device identity, RFC 8410/9295 SPKI validation, and strict RFC 8032 signatures.

use crate::error::SecurityError;
use crate::secret::CheckedOsCryptoRng;
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use lumabridge_protocol::control::{
    ED25519_SIGNATURE_LEN, ED25519_SPKI_DER_LEN, ED25519_SPKI_DER_PREFIX,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Logical role of a peer device in `LumaBridge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PeerRole {
    /// Display source / Windows host.
    Host,
    /// Remote display / mobile / tablet controller.
    Controller,
}

impl PeerRole {
    /// Canonical lowercase role label used inside cryptographic transcripts.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Controller => "controller",
        }
    }

    /// Return the expected peer role for the opposite side of a connection.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Host => Self::Controller,
            Self::Controller => Self::Host,
        }
    }
}

/// Canonical 32-byte device identifier equal to `SHA-256(spki_ed25519_der)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    /// Derive a canonical `DeviceId` from a validated 44-byte Ed25519 SPKI DER blob.
    pub fn from_spki_der(spki_der: &[u8]) -> Result<Self, SecurityError> {
        let canonical = parse_canonical_ed25519_spki(spki_der)?;
        Ok(Self(Sha256::digest(canonical).into()))
    }

    /// Construct directly from raw 32 bytes (e.g., from a persisted store).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return raw 32-byte digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Full lowercase hexadecimal representation (64 chars).
    #[must_use]
    pub fn to_hex(&self) -> String {
        encode_hex_lower(&self.0)
    }

    /// Short 16-hex-char fingerprint for sanitized diagnostic metadata and human consent UI.
    #[must_use]
    pub fn short_hex(&self) -> String {
        encode_hex_lower(&self.0[..8])
    }

    /// Formatted cryptographic fingerprint for local human pairing confirmation.
    #[must_use]
    pub fn fingerprint_display(&self) -> String {
        let hex = self.short_hex();
        format!(
            "{}-{}-{}-{}",
            &hex[0..4],
            &hex[4..8],
            &hex[8..12],
            &hex[12..16]
        )
    }

    /// Constant-time comparison against another `DeviceId`.
    #[must_use]
    pub fn ct_eq_id(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.short_hex())
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short_hex())
    }
}

/// Validated public Ed25519 device identity bound to canonical RFC 8410/9295 SPKI DER.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    spki_der: [u8; ED25519_SPKI_DER_LEN],
    verifying_key: VerifyingKey,
    device_id: DeviceId,
}

impl PublicIdentity {
    /// Parse canonical 44-byte Ed25519 SPKI DER, reject weak keys, and derive `DeviceId`.
    pub fn from_spki_der(spki_der: &[u8]) -> Result<Self, SecurityError> {
        let canonical = parse_canonical_ed25519_spki(spki_der)?;
        let raw_pk: [u8; 32] = canonical[ED25519_SPKI_DER_PREFIX.len()..]
            .try_into()
            .map_err(|_| SecurityError::InvalidSpki("SPKI payload slice length mismatch"))?;
        let verifying_key = VerifyingKey::from_bytes(&raw_pk)
            .map_err(|_| SecurityError::InvalidSpki("invalid compressed Ed25519 public point"))?;
        if verifying_key.is_weak() {
            return Err(SecurityError::InvalidSpki(
                "small-order/weak Ed25519 public key rejected",
            ));
        }
        let device_id = DeviceId(Sha256::digest(canonical).into());
        Ok(Self {
            spki_der: canonical,
            verifying_key,
            device_id,
        })
    }

    /// Return the exact 44-byte RFC 8410/9295 SPKI DER encoding.
    #[must_use]
    pub const fn spki_der(&self) -> &[u8; ED25519_SPKI_DER_LEN] {
        &self.spki_der
    }

    /// Return the canonical `DeviceId`.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Return raw 32-byte Ed25519 public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }

    /// Perform strict RFC 8032 signature verification (rejecting malleable/small-order elements).
    pub fn verify_strict(&self, message: &[u8], signature: &[u8]) -> Result<(), SecurityError> {
        let sig_bytes: [u8; ED25519_SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| SecurityError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        self.verifying_key
            .verify_strict(message, &sig)
            .map_err(|_| SecurityError::InvalidSignature)
    }
}

impl fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicIdentity")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// Long-term local Ed25519 device identity key pair (`ZeroizeOnDrop`).
pub struct IdentityKeyPair {
    seed: Zeroizing<[u8; 32]>,
    signing_key: SigningKey,
    public: PublicIdentity,
}

impl IdentityKeyPair {
    /// Generate a fresh long-term Ed25519 identity using `CheckedOsCryptoRng` without stack copies.
    pub fn generate(rng: &mut CheckedOsCryptoRng) -> Result<Self, SecurityError> {
        let seed = rng.random_zeroizing::<32>()?;
        Self::from_seed_zeroizing(seed)
    }

    /// Reconstruct an `IdentityKeyPair` deterministically from a `Zeroizing<[u8; 32]>` seed.
    pub fn from_seed_zeroizing(seed: Zeroizing<[u8; 32]>) -> Result<Self, SecurityError> {
        let signing_key = SigningKey::from_bytes(&seed);
        let pk_bytes = signing_key.verifying_key().to_bytes();
        let mut spki_der = [0u8; ED25519_SPKI_DER_LEN];
        spki_der[..ED25519_SPKI_DER_PREFIX.len()].copy_from_slice(&ED25519_SPKI_DER_PREFIX);
        spki_der[ED25519_SPKI_DER_PREFIX.len()..].copy_from_slice(&pk_bytes);
        let public = PublicIdentity::from_spki_der(&spki_der)?;
        Ok(Self {
            seed,
            signing_key,
            public,
        })
    }

    /// Reconstruct an `IdentityKeyPair` deterministically from a 32-byte Ed25519 seed,
    /// zeroizing the caller-passed stack copy before returning.
    pub fn from_seed(mut seed: [u8; 32]) -> Result<Self, SecurityError> {
        let wrapped = Zeroizing::new(seed);
        seed.zeroize();
        Self::from_seed_zeroizing(wrapped)
    }

    /// Borrow the public identity portion.
    #[must_use]
    pub const fn public_identity(&self) -> &PublicIdentity {
        &self.public
    }

    /// Shortcut to the canonical `DeviceId`.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.public.device_id()
    }

    /// Sign `message` with Ed25519.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIGNATURE_LEN] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Encode private key as RFC 8410/5958 PKCS#8 v1 DER (`Zeroizing<Vec<u8>>`).
    #[must_use]
    pub fn to_pkcs8_v1_der(&self) -> Zeroizing<Vec<u8>> {
        // RFC 8410 Ed25519 PrivateKeyInfo (v1, no publicKey field):
        // 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 || seed[32]
        const PKCS8_V1_PREFIX: [u8; 16] = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        let mut out = Zeroizing::new(Vec::with_capacity(48));
        out.extend_from_slice(&PKCS8_V1_PREFIX);
        out.extend_from_slice(&*self.seed);
        out
    }
}

impl fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("device_id", &self.public.device_id)
            .field("private_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

fn parse_canonical_ed25519_spki(
    spki_der: &[u8],
) -> Result<[u8; ED25519_SPKI_DER_LEN], SecurityError> {
    if spki_der.len() != ED25519_SPKI_DER_LEN {
        return Err(SecurityError::InvalidSpki(
            "SPKI DER must be exactly 44 bytes for Ed25519",
        ));
    }
    if !spki_der.starts_with(&ED25519_SPKI_DER_PREFIX) {
        return Err(SecurityError::InvalidSpki(
            "SPKI DER header must match RFC 8410 Ed25519 with absent parameters",
        ));
    }
    spki_der
        .try_into()
        .map_err(|_| SecurityError::InvalidSpki("SPKI length check failed"))
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}
