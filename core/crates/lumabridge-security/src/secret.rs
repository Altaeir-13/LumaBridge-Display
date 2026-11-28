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
        let mut probe = Zeroizing::new([0u8; 32]);
        getrandom::fill(probe.as_mut()).map_err(|_| SecurityError::RngUnavailable)?;
        Ok(Self)
    }

    /// Fill an arbitrary slice with cryptographic OS randomness.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), SecurityError> {
        getrandom::fill(dest).map_err(|_| SecurityError::RngUnavailable)
    }

    /// Generate a fixed-size array of cryptographic OS randomness.
    pub fn random_array<const N: usize>(&mut self) -> Result<[u8; N], SecurityError> {
        let mut buf = [0u8; N];
        if getrandom::fill(&mut buf).is_err() {
            buf.zeroize();
            return Err(SecurityError::RngUnavailable);
        }
        Ok(buf)
    }

    /// Generate a zeroized fixed-size secret array directly into `Zeroizing<[u8; N]>`.
    pub fn random_zeroizing<const N: usize>(
        &mut self,
    ) -> Result<Zeroizing<[u8; N]>, SecurityError> {
        let mut buf = Zeroizing::new([0u8; N]);
        getrandom::fill(buf.as_mut()).map_err(|_| SecurityError::RngUnavailable)?;
        Ok(buf)
    }

    /// Fetch 1024 bytes of checked OS entropy upfront for single-shot SPAKE2 ephemeral draws.
    pub(crate) fn prefetch_spake_entropy(&mut self) -> Result<PrefetchedCryptoRng, SecurityError> {
        #[cfg(test)]
        {
            if test_hooks::take_prefetch_fail() {
                return Err(SecurityError::RngUnavailable);
            }
            if test_hooks::take_refill_fail() {
                return Ok(PrefetchedCryptoRng {
                    bytes: Zeroizing::new(Vec::new()),
                    offset: 0,
                    rng_failed: false,
                    failed_draws: 0,
                    fail_on_refill: true,
                });
            }
        }
        let mut bytes = Zeroizing::new(vec![0u8; 1024]);
        self.fill_bytes(&mut bytes)?;
        Ok(PrefetchedCryptoRng {
            bytes,
            offset: 0,
            rng_failed: false,
            failed_draws: 0,
            #[cfg(test)]
            fail_on_refill: false,
        })
    }
}

#[cfg(test)]
mod test_hooks {
    use core::cell::Cell;

    std::thread_local! {
        static PREFETCH_FAIL: Cell<bool> = const { Cell::new(false) };
        static REFILL_FAIL: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn set_next_prefetch_fail(val: bool) {
        PREFETCH_FAIL.with(|c| c.set(val));
    }

    pub(crate) fn take_prefetch_fail() -> bool {
        PREFETCH_FAIL.with(|c| c.replace(false))
    }

    pub(crate) fn set_next_refill_fail(val: bool) {
        REFILL_FAIL.with(|c| c.set(val));
    }

    pub(crate) fn take_refill_fail() -> bool {
        REFILL_FAIL.with(|c| c.replace(false))
    }
}

#[cfg(test)]
pub(crate) fn set_next_spake_prefetch_fail_for_test() {
    test_hooks::set_next_prefetch_fail(true);
}

#[cfg(test)]
pub(crate) fn set_next_spake_refill_fail_for_test() {
    test_hooks::set_next_refill_fail(true);
}

impl rand_core::TryRng for CheckedOsCryptoRng {
    type Error = getrandom::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        if let Err(err) = getrandom::fill(&mut buf) {
            buf.zeroize();
            return Err(err);
        }
        let out = u32::from_le_bytes(buf);
        buf.zeroize();
        Ok(out)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        if let Err(err) = getrandom::fill(&mut buf) {
            buf.zeroize();
            return Err(err);
        }
        let out = u64::from_le_bytes(buf);
        buf.zeroize();
        Ok(out)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst)
    }
}

impl rand_core::TryCryptoRng for CheckedOsCryptoRng {}

/// Pre-fetched OS CSPRNG buffer supplying infallible `CryptoRng` for algorithms like `pakery-spake2`.
///
/// Entropy is pulled upfront via [`CheckedOsCryptoRng`] with full error propagation (`Result`).
/// Any unexpected refill error records `rng_failed = true`, zeroizes remaining prefetched entropy,
/// and fills `dst` with a deterministic non-zero canonical abort pattern (`0x01`) so any external
/// non-zero scalar rejection loop terminates in a single bounded draw rather than spinning forever.
/// Callers MUST enforce [`PrefetchedCryptoRng::ensure_healthy`] and zeroize/discard all outputs on error.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct PrefetchedCryptoRng {
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
    rng_failed: bool,
    failed_draws: u32,
    #[cfg(test)]
    fail_on_refill: bool,
}

impl PrefetchedCryptoRng {
    /// Verify that no OS CSPRNG refill failure occurred during scalar generation.
    pub const fn ensure_healthy(&self) -> Result<(), SecurityError> {
        if self.rng_failed {
            Err(SecurityError::RngUnavailable)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) const fn failed_draws(&self) -> u32 {
        self.failed_draws
    }

    fn record_failure_and_abort_fill(&mut self, dst: &mut [u8]) {
        self.rng_failed = true;
        self.failed_draws = self.failed_draws.saturating_add(1);
        self.bytes.zeroize();
        self.offset = self.bytes.len();
        // Non-zero canonical abort pattern (0x0101..01 < P-256 order n, != 0) guarantees
        // any rejection sampler exits on the first draw; output MUST be discarded via ensure_healthy().
        dst.fill(0x01);
    }

    fn fill_internal(&mut self, dst: &mut [u8]) {
        if self.rng_failed {
            self.record_failure_and_abort_fill(dst);
            return;
        }
        let avail = self.bytes.len().saturating_sub(self.offset);
        let take = avail.min(dst.len());
        if take > 0 {
            dst[..take].copy_from_slice(&self.bytes[self.offset..self.offset + take]);
            self.bytes[self.offset..self.offset + take].zeroize();
            self.offset += take;
        }
        if take < dst.len() {
            #[cfg(test)]
            if self.fail_on_refill {
                self.record_failure_and_abort_fill(dst);
                return;
            }
            if getrandom::fill(&mut dst[take..]).is_err() {
                self.record_failure_and_abort_fill(dst);
            }
        }
    }
}

impl rand_core::TryRng for PrefetchedCryptoRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.fill_internal(&mut buf);
        let val = u32::from_le_bytes(buf);
        buf.zeroize();
        Ok(val)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.fill_internal(&mut buf);
        let val = u64::from_le_bytes(buf);
        buf.zeroize();
        Ok(val)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.fill_internal(dst);
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
        let bytes = rng.random_zeroizing::<N>()?;
        Ok(Self(*bytes))
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

/// Redacted, zeroized pairing PIN wrapper enforcing the normative 8-digit CSPRNG policy.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PinSecret(String);

impl PinSecret {
    /// Normative pairing PIN length: exactly 8 ASCII decimal digits (`00000000..=99999999`).
    pub const PAIRING_PIN_DIGITS: usize = 8;

    /// Construct a validated 8-digit ASCII numeric pairing PIN (`00000000..=99999999`),
    /// preserving leading zeros and zeroizing rejected inputs.
    pub fn new(pin: impl Into<String>) -> Result<Self, SecurityError> {
        let mut pin = pin.into();
        if pin.len() != Self::PAIRING_PIN_DIGITS {
            pin.zeroize();
            return Err(SecurityError::InvalidPinFormat(
                "pairing PIN must be exactly 8 ASCII digits",
            ));
        }
        if !pin.bytes().all(|b| b.is_ascii_digit()) {
            pin.zeroize();
            return Err(SecurityError::InvalidPinFormat(
                "pairing PIN must contain ASCII digits 0-9 only",
            ));
        }
        Ok(Self(pin))
    }

    /// Generate a cryptographic 8-digit numeric PIN (`00000000..=99999999`, preserving leading zeros)
    /// using unbiased rejection sampling over `CheckedOsCryptoRng`.
    pub fn generate_numeric(rng: &mut CheckedOsCryptoRng) -> Result<Self, SecurityError> {
        let mut out = String::with_capacity(Self::PAIRING_PIN_DIGITS);
        while out.len() < Self::PAIRING_PIN_DIGITS {
            let mut sample = [0u8; 16];
            if let Err(err) = rng.fill_bytes(&mut sample) {
                sample.zeroize();
                out.zeroize();
                return Err(err);
            }
            for byte in sample {
                // Rejection sampling avoids modulo bias across 0..250 -> 0..9.
                if byte < 250 {
                    let digit = b'0' + (byte % 10);
                    out.push(char::from(digit));
                    if out.len() == Self::PAIRING_PIN_DIGITS {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::TryRng;

    #[test]
    fn prefetched_rng_failure_is_recorded_zeroizes_output_and_never_succeeds_silently() {
        let mut rng = CheckedOsCryptoRng::preflight().expect("preflight");
        let mut prefetched = rng.prefetch_spake_entropy().expect("prefetch");
        prefetched.fail_on_refill = true;

        // Drain the 1024-byte prefetch buffer cleanly.
        let mut drain = [0u8; 1024];
        prefetched.try_fill_bytes(&mut drain).expect("infallible");
        assert!(prefetched.ensure_healthy().is_ok());

        // Subsequent draw forces refill -> simulated CSPRNG failure -> flags error & returns bounded abort fill.
        let mut spillover = [0xAAu8; 32];
        prefetched
            .try_fill_bytes(&mut spillover)
            .expect("infallible");
        assert_eq!(spillover, [0x01u8; 32]);
        assert_eq!(prefetched.failed_draws(), 1);
        assert_eq!(
            prefetched.ensure_healthy(),
            Err(SecurityError::RngUnavailable)
        );

        // Non-zero rejection loop (e.g., OPRF/EC scalar sampler rejecting all-zero) terminates on 1st draw.
        let mut draws = 0u32;
        loop {
            draws += 1;
            let mut candidate = [0u8; 32];
            prefetched
                .try_fill_bytes(&mut candidate)
                .expect("infallible");
            if candidate.iter().any(|&b| b != 0) || draws >= 16 {
                break;
            }
        }
        assert_eq!(draws, 1);
        assert_eq!(
            prefetched.ensure_healthy(),
            Err(SecurityError::RngUnavailable)
        );
    }

    #[test]
    fn pin_secret_enforces_exact_8_ascii_digits_with_leading_zeros() {
        assert!(PinSecret::new("00000001").is_ok());
        assert!(PinSecret::new("123456").is_err());
        assert!(PinSecret::new("123456789").is_err());
        assert!(PinSecret::new("1234567a").is_err());

        let mut rng = CheckedOsCryptoRng::preflight().expect("rng");
        let generated = PinSecret::generate_numeric(&mut rng).expect("gen");
        assert_eq!(generated.expose_bytes().len(), 8);
        assert!(generated.expose_bytes().iter().all(u8::is_ascii_digit));
    }
}
