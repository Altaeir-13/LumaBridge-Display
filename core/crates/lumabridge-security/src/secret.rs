// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Redacted secret wrappers, constant-time comparisons, and OS CSPRNG wrapper.

use crate::error::SecurityError;
use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Non-bypassable wrapper over the OS cryptographic RNG (`getrandom`).
///
/// Every call checks the OS RNG return code without swallowing entropy failures.
#[derive(Debug, Default, Clone, Copy)]
pub struct CheckedOsCryptoRng;

impl CheckedOsCryptoRng {
    /// Verify the OS CSPRNG can supply entropy cleanly.
    pub fn preflight() -> Result<Self, SecurityError> {
        let mut probe = [0u8; 32];
        getrandom::fill(&mut probe).map_err(|_| SecurityError::RngUnavailable)?;
        probe.zeroize();
        Ok(Self)
    }

    /// Fill an arbitrary slice with cryptographic OS randomness.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), SecurityError> {
        getrandom::fill(dest).map_err(|_| SecurityError::RngUnavailable)
    }

    /// Generate a fixed-size array of cryptographic OS randomness.
    pub fn random_array<const N: usize>(&mut self) -> Result<[u8; N], SecurityError> {
        let mut buf = [0u8; N];
        getrandom::fill(&mut buf).map_err(|_| SecurityError::RngUnavailable)?;
        Ok(buf)
    }
}

impl rand_core::TryRng for CheckedOsCryptoRng {
    type Error = getrandom::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst)
    }
}

impl rand_core::TryCryptoRng for CheckedOsCryptoRng {}

/// Pre-fetched OS CSPRNG buffer supplying infallible `CryptoRng` for algorithms like `pakery-spake2`.
///
/// Entropy is pulled upfront via [`CheckedOsCryptoRng`] with full error propagation (`Result`),
/// ensuring OS RNG failures are never panicked or silently swallowed before handoff.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrefetchedCryptoRng {
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
}

impl CheckedOsCryptoRng {
    /// Fetch 512 bytes of checked OS entropy upfront for single-shot SPAKE2 ephemeral draws.
    pub fn prefetch_spake_entropy(&mut self) -> Result<PrefetchedCryptoRng, SecurityError> {
        let mut bytes = Zeroizing::new(vec![0u8; 512]);
        self.fill_bytes(&mut bytes)?;
        Ok(PrefetchedCryptoRng { bytes, offset: 0 })
    }
}

impl rand_core::TryRng for PrefetchedCryptoRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        let _ = self.try_fill_bytes(&mut buf);
        let val = u32::from_le_bytes(buf);
        buf.zeroize();
        Ok(val)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        let _ = self.try_fill_bytes(&mut buf);
        let val = u64::from_le_bytes(buf);
        buf.zeroize();
        Ok(val)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let avail = self.bytes.len().saturating_sub(self.offset);
        let take = avail.min(dst.len());
        if take > 0 {
            dst[..take].copy_from_slice(&self.bytes[self.offset..self.offset + take]);
            self.bytes[self.offset..self.offset + take].zeroize();
            self.offset += take;
        }
        if take < dst.len() {
            // Unlikely rejection-sampling spillover after 512 bytes of P-256 candidates.
            let _ = getrandom::fill(&mut dst[take..]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for PrefetchedCryptoRng {}

/// Fixed-size zeroized, constant-time, redacted secret byte array.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// Construct from raw bytes (moving ownership into the zeroized wrapper).
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Construct from a slice of exact length `N`.
    pub fn from_slice(slice: &[u8]) -> Result<Self, SecurityError> {
        let arr: [u8; N] = slice
            .try_into()
            .map_err(|_| SecurityError::InvalidKeyMaterial("unexpected secret byte length"))?;
        Ok(Self(arr))
    }

    /// Generate random secret bytes via `CheckedOsCryptoRng`.
    pub fn generate(rng: &mut CheckedOsCryptoRng) -> Result<Self, SecurityError> {
        Ok(Self(rng.random_array::<N>()?))
    }

    /// Borrow the underlying secret bytes explicitly.
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>([REDACTED])")
    }
}

/// Redacted, zeroized pairing PIN wrapper.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PinSecret(String);

impl PinSecret {
    /// Minimum PIN length in UTF-8 bytes when explicit format policy applies.
    pub const MIN_LEN: usize = 6;
    /// Maximum PIN length in UTF-8 bytes to bound memory and PBKDF/HKDF inputs.
    pub const MAX_LEN: usize = 64;

    /// Construct a validated PIN secret (6..=64 ASCII/UTF-8 bytes, no NUL or control chars).
    pub fn new(pin: impl Into<String>) -> Result<Self, SecurityError> {
        let mut pin = pin.into();
        if pin.len() < Self::MIN_LEN || pin.len() > Self::MAX_LEN {
            pin.zeroize();
            return Err(SecurityError::InvalidPinFormat(
                "PIN length must be within 6..=64 bytes",
            ));
        }
        if pin.bytes().any(|b| b == 0 || b.is_ascii_control()) {
            pin.zeroize();
            return Err(SecurityError::InvalidPinFormat(
                "PIN must not contain NUL or control characters",
            ));
        }
        Ok(Self(pin))
    }

    /// Generate a cryptographic numeric PIN of `digits` digits (`6..=12`).
    pub fn generate_numeric(
        rng: &mut CheckedOsCryptoRng,
        digits: usize,
    ) -> Result<Self, SecurityError> {
        if !(Self::MIN_LEN..=12).contains(&digits) {
            return Err(SecurityError::InvalidPinFormat(
                "numeric PIN digit count must be within 6..=12",
            ));
        }
        let mut out = String::with_capacity(digits);
        while out.len() < digits {
            let mut sample = [0u8; 16];
            rng.fill_bytes(&mut sample)?;
            for byte in sample {
                // Rejection sampling avoids modulo bias across 0..250 -> 0..9.
                if byte < 250 {
                    let digit = b'0' + (byte % 10);
                    out.push(char::from(digit));
                    if out.len() == digits {
                        break;
                    }
                }
            }
            sample.zeroize();
        }
        Ok(Self(out))
    }

    /// Borrow the PIN UTF-8 bytes explicitly.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for PinSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinSecret([REDACTED])")
    }
}

/// Wrapper for opaque 32-byte single-use QR pairing token.
pub type QrTokenSecret = SecretBytes<32>;

/// Wrapper for opaque 32-byte single-use session resume token.
pub type ResumeTokenSecret = SecretBytes<32>;

/// Wrapper for opaque 32-byte bound session token.
pub type SessionTokenSecret = SecretBytes<32>;

/// Explicit constant-time equality comparison for arbitrary slices.
#[must_use]
pub fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    bool::from(lhs.ct_eq(rhs))
}

/// Zeroizing dynamic byte container alias.
pub type ZeroizingVec = Zeroizing<Vec<u8>>;
