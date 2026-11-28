// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Channel-bound pairing state machines: RFC 9382 SPAKE2-P256 and atomic single-use QR pairing.

use crate::channel_binding::ChannelBinding;
use crate::error::SecurityError;
use crate::identity::{DeviceId, IdentityKeyPair, PeerRole, PublicIdentity};
use crate::secret::{CheckedOsCryptoRng, PinSecret, QrTokenSecret};
use crate::tls::AuthenticatedTlsSession;
use crate::transcript::{
    build_pair_confirm_signing_message, build_qr_auth_signing_message, build_spake2_aad,
    derive_spake2_wide_secret, spake_endpoint_identities, PairConfirmTranscriptContext,
    QrAuthTranscriptContext, Spake2AadContext,
};
use core::fmt;
use lumabridge_protocol::control::{
    AuthMode, PairConfirm, PairHello, PairQrAuth, PairSpakeMsg, Permissions, SpakeStep,
    OPAQUE_TOKEN_LEN, SPAKE2_CONFIRM_MAC_LEN, SPAKE2_P256_PUBLIC_SHARE_LEN,
};
use lumabridge_protocol::version::{LBWP_PROTOCOL_MAJOR, LBWP_PROTOCOL_MINOR};
use pakery_core::crypto::CpaceGroup;
use pakery_crypto::{P256Group, Spake2P256};
use pakery_spake2::{PartyA, PartyAState, PartyB, Spake2Output};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

/// Maximum permitted lifetime of a single-use QR pairing token (seconds).
pub const MAX_QR_TOKEN_TTL_SECS: u64 = 300;

/// Normative PIN pairing window lifetime (seconds).
pub const PIN_TTL_SECS: u64 = 90;

/// Maximum invalid PIN attempts before the active PIN is destroyed atomically.
pub const MAX_PIN_FAILED_ATTEMPTS: u32 = 3;

/// Hard upper bound on active QR pairing tokens stored concurrently.
pub const MAX_ACTIVE_QR_TOKENS: usize = 64;

/// Hard upper bound on active pairing attempts tracked in one PIN window.
pub const MAX_ACTIVE_PAIRING_ATTEMPTS: usize = 16;

/// Explicit 5-stage semantic pairing lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingStage {
    /// Hello validated against mTLS peer cert & RFC 9266 channel binding.
    Init,
    /// SPAKE2 or QR token exchange in flight (one exchange per connection).
    AuthExchanging,
    /// Cryptographic authentication succeeded; waiting on explicit local human approval.
    AwaitingApproval,
    /// Pairing confirmation signed/verified and base display-only permissions finalized.
    Confirmed,
    /// Terminal failure state (prevents downgrade or retry on the same pairing channel).
    Failed,
}

/// Sanitized human-consent prompt metadata rendered to the local operator.
///
/// Explicitly marks `untrusted_friendly_name` as untrusted peer-supplied text alongside
/// the cryptographically verified `peer_device_id` and `peer_fingerprint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingApprovalPrompt {
    pub pairing_attempt_id: u64,
    pub peer_device_id: DeviceId,
    pub peer_fingerprint: String,
    pub untrusted_friendly_name: String,
    pub auth_mode: AuthMode,
    pub offered_base_perms: Option<Permissions>,
}

/// Explicit port for local human consent bound to a specific attempt ID and peer `DeviceId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HumanApprovalDecision {
    /// Local user explicitly approves pairing this exact peer/attempt with `granted_base_perms` (no input).
    Approve {
        pairing_attempt_id: u64,
        peer_device_id: DeviceId,
        granted_base_perms: Permissions,
    },
    /// Local user denies pairing for this peer/attempt.
    Reject {
        pairing_attempt_id: u64,
        peer_device_id: DeviceId,
    },
}

/// Proven local pairing commit produced ONLY after cryptographic verification + local human approval.
///
/// Fields are private and the type is non-`Clone` so external callers cannot forge or duplicate
/// pairing provenance before persisting into [`crate::trust_store::InMemoryTrustStore`].
#[derive(Debug, PartialEq, Eq)]
pub struct ApprovedPairingCommit {
    pairing_attempt_id: u64,
    peer_identity: PublicIdentity,
    peer_role: PeerRole,
    friendly_name: String,
    granted_base_perms: Permissions,
    channel_binding_digest: [u8; 32],
    expected_peer_epoch: u64,
    _sealed: (),
}

impl ApprovedPairingCommit {
    #[must_use]
    pub const fn pairing_attempt_id(&self) -> u64 {
        self.pairing_attempt_id
    }

    #[must_use]
    pub const fn peer_identity(&self) -> &PublicIdentity {
        &self.peer_identity
    }

    #[must_use]
    pub const fn peer_role(&self) -> PeerRole {
        self.peer_role
    }

    #[must_use]
    pub fn friendly_name(&self) -> &str {
        &self.friendly_name
    }

    #[must_use]
    pub const fn granted_base_perms(&self) -> Permissions {
        self.granted_base_perms
    }

    #[must_use]
    pub const fn expected_peer_epoch(&self) -> u64 {
        self.expected_peer_epoch
    }

    #[must_use]
    pub(crate) const fn channel_binding_digest(&self) -> [u8; 32] {
        self.channel_binding_digest
    }
}

#[derive(Debug)]
struct ActivePinState {
    pin: PinSecret,
    pin_generation: u64,
    opened_at_secs: u64,
    expires_at_secs: u64,
    failed_attempts: u32,
    in_flight_attempts: u32,
}

#[derive(Debug, Default)]
struct PinWindowInner {
    active: Option<ActivePinState>,
    next_pin_generation: u64,
    active_attempts: usize,
}

/// Thread-safe PIN pairing window enforcing an atomic 3-attempt budget across all concurrent peers,
/// 90-second expiration, and immediate zeroization upon success, exhaustion, expiry, or close.
#[derive(Debug, Clone, Default)]
pub struct PinPairingWindow {
    inner: Arc<Mutex<PinWindowInner>>,
}

impl PinPairingWindow {
    /// Create a closed PIN pairing window.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Open (or rotate) the pairing window with a fresh CSPRNG 8-digit PIN valid for 90 monotonic seconds.
    ///
    /// Callers MUST supply process-local monotonic seconds (`now_mono_secs`), keeping PIN TTL
    /// independent of wall-clock jumps used by X.509 certificates or cross-device QR tickets.
    pub fn open_with_new_pin(
        &self,
        rng: &mut CheckedOsCryptoRng,
        now_mono_secs: u64,
    ) -> Result<PinSecret, SecurityError> {
        let pin = PinSecret::generate_numeric(rng)?;
        let expires_at_secs = now_mono_secs
            .checked_add(PIN_TTL_SECS)
            .ok_or(SecurityError::InvalidTimestamp("PIN expiry overflow"))?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("PIN window lock poisoned"))?;
        guard.next_pin_generation = guard.next_pin_generation.saturating_add(1);
        let gen = guard.next_pin_generation;
        guard.active = Some(ActivePinState {
            pin: pin.clone(),
            pin_generation: gen,
            opened_at_secs: now_mono_secs,
            expires_at_secs,
            failed_attempts: 0,
            in_flight_attempts: 0,
        });
        Ok(pin)
    }

    /// Close the pairing window immediately and zeroize any active PIN.
    pub fn close(&self) -> Result<(), SecurityError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("PIN window lock poisoned"))?;
        guard.active = None;
        Ok(())
    }

    /// Remaining attempts before PIN destruction (`0` if closed, expired, before opening, or exhausted).
    ///
    /// Clears and zeroizes expired PIN material if observed past `expires_at_secs`.
    #[must_use]
    pub fn remaining_attempts(&self, now_mono_secs: u64) -> u32 {
        let Ok(mut guard) = self.inner.lock() else {
            return 0;
        };
        let Some(ref st) = guard.active else {
            return 0;
        };
        if now_mono_secs < st.opened_at_secs {
            return 0;
        }
        if now_mono_secs > st.expires_at_secs {
            guard.active = None;
            return 0;
        }
        MAX_PIN_FAILED_ATTEMPTS
            .saturating_sub(st.failed_attempts.saturating_add(st.in_flight_attempts))
    }

    /// Atomically reserve one PIN attempt slot under the 3-attempt budget across concurrent callers.
    pub fn begin_attempt(&self, now_mono_secs: u64) -> Result<PinAttemptLease, SecurityError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("PIN window lock poisoned"))?;
        if guard.active_attempts >= MAX_ACTIVE_PAIRING_ATTEMPTS {
            return Err(SecurityError::ResourceExhausted(
                "maximum concurrent pairing attempts reached",
            ));
        }
        let Some(ref mut st) = guard.active else {
            return Err(SecurityError::PairingWindowClosed);
        };
        if now_mono_secs < st.opened_at_secs {
            return Err(SecurityError::InvalidTimestamp(
                "attempt reservation precedes PIN window opening",
            ));
        }
        if now_mono_secs > st.expires_at_secs {
            guard.active = None;
            return Err(SecurityError::PairingWindowClosed);
        }
        if st.failed_attempts.saturating_add(st.in_flight_attempts) >= MAX_PIN_FAILED_ATTEMPTS {
            if st.failed_attempts >= MAX_PIN_FAILED_ATTEMPTS {
                guard.active = None;
            }
            return Err(SecurityError::PinAttemptsExhausted);
        }
        st.in_flight_attempts = st.in_flight_attempts.saturating_add(1);
        let pin_copy = st.pin.clone();
        let pin_generation = st.pin_generation;
        guard.active_attempts = guard.active_attempts.saturating_add(1);

        Ok(PinAttemptLease {
            inner: Arc::clone(&self.inner),
            pin_generation,
            reserved_at_secs: now_mono_secs,
            pin: Some(pin_copy),
            resolved: false,
        })
    }
}

/// RAII lease over a single PIN pairing attempt; dropping without `finish_success` counts as failure
/// and automatically destroys the active PIN if the 3rd failure is reached for the same generation.
pub struct PinAttemptLease {
    inner: Arc<Mutex<PinWindowInner>>,
    pin_generation: u64,
    reserved_at_secs: u64,
    pin: Option<PinSecret>,
    resolved: bool,
}

impl PinAttemptLease {
    fn pin(&self) -> Result<&PinSecret, SecurityError> {
        self.pin.as_ref().ok_or(SecurityError::PairingState(
            "PIN attempt lease already resolved",
        ))
    }

    /// Atomically consume and destroy the active PIN upon cryptographic verification success,
    /// rejecting closed, expired, rotated, or concurrently consumed windows.
    pub fn finish_success(mut self, now_mono_secs: u64) -> Result<(), SecurityError> {
        self.resolved = true;
        self.pin = None;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("PIN window lock poisoned"))?;
        guard.active_attempts = guard.active_attempts.saturating_sub(1);
        let Some(ref mut st) = guard.active else {
            return Err(SecurityError::PairingWindowClosed);
        };
        if st.pin_generation != self.pin_generation {
            return Err(SecurityError::PairingWindowClosed);
        }
        st.in_flight_attempts = st.in_flight_attempts.saturating_sub(1);
        if now_mono_secs < self.reserved_at_secs || now_mono_secs < st.opened_at_secs {
            st.failed_attempts = st.failed_attempts.saturating_add(1);
            if st.failed_attempts >= MAX_PIN_FAILED_ATTEMPTS {
                guard.active = None;
            }
            return Err(SecurityError::InvalidTimestamp(
                "confirmation timestamp precedes attempt reservation",
            ));
        }
        if now_mono_secs > st.expires_at_secs {
            guard.active = None;
            return Err(SecurityError::PairingWindowClosed);
        }
        guard.active = None;
        Ok(())
    }

    /// Record a failed verification and destroy the active PIN if 3 failures have occurred.
    pub fn finish_failure(mut self) {
        self.record_failure_inner();
    }

    fn record_failure_inner(&mut self) {
        if self.resolved {
            return;
        }
        self.resolved = true;
        self.pin = None;
        if let Ok(mut guard) = self.inner.lock() {
            guard.active_attempts = guard.active_attempts.saturating_sub(1);
            let should_destroy = if let Some(ref mut st) = guard.active {
                if st.pin_generation == self.pin_generation {
                    st.in_flight_attempts = st.in_flight_attempts.saturating_sub(1);
                    st.failed_attempts = st.failed_attempts.saturating_add(1);
                    st.failed_attempts >= MAX_PIN_FAILED_ATTEMPTS
                } else {
                    false
                }
            } else {
                false
            };
            if should_destroy {
                guard.active = None;
            }
        }
    }
}

impl Drop for PinAttemptLease {
    fn drop(&mut self) {
        self.record_failure_inner();
    }
}

/// Out-of-band QR pairing token metadata shown by the pairing host.
#[derive(Clone)]
pub struct QrPairingTicket {
    pub version: u8,
    pub acceptor_device_id: DeviceId,
    pub acceptor_role: PeerRole,
    pub token: QrTokenSecret,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

impl fmt::Debug for QrPairingTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QrPairingTicket")
            .field("version", &self.version)
            .field("acceptor_device_id", &self.acceptor_device_id)
            .field("acceptor_role", &self.acceptor_role)
            .field("token", &"[REDACTED]")
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct StoredQrRecord {
    acceptor_device_id: DeviceId,
    expires_at_unix: u64,
    consumed: bool,
}

/// Bounded atomic single-use QR pairing token store (stores SHA-256 digests only, never raw tokens).
#[derive(Default)]
pub struct QrTokenStore {
    records: Mutex<BTreeMap<[u8; 32], StoredQrRecord>>,
}

impl QrTokenStore {
    /// Create an empty single-use QR token store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a fresh 32-byte CSPRNG QR pairing token expiring within `ttl_secs <= MAX_QR_TOKEN_TTL_SECS`.
    pub fn issue(
        &self,
        rng: &mut CheckedOsCryptoRng,
        acceptor_device_id: DeviceId,
        acceptor_role: PeerRole,
        now_unix: u64,
        ttl_secs: u64,
    ) -> Result<QrPairingTicket, SecurityError> {
        if ttl_secs == 0 || ttl_secs > MAX_QR_TOKEN_TTL_SECS {
            return Err(SecurityError::QrPairingInvalid(
                "QR token TTL must be in 1..=300 seconds",
            ));
        }
        let expires_at_unix = now_unix
            .checked_add(ttl_secs)
            .ok_or(SecurityError::InvalidTimestamp("QR expiry overflow"))?;
        let token = QrTokenSecret::generate(rng)?;
        let digest: [u8; 32] = Sha256::digest(token.expose_secret()).into();

        let mut guard = self
            .records
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("QR store lock poisoned"))?;
        guard.retain(|_, rec| !rec.consumed && rec.expires_at_unix >= now_unix);
        if guard.len() >= MAX_ACTIVE_QR_TOKENS {
            return Err(SecurityError::ResourceExhausted(
                "active QR pairing token limit reached",
            ));
        }
        guard.insert(
            digest,
            StoredQrRecord {
                acceptor_device_id,
                expires_at_unix,
                consumed: false,
            },
        );
        drop(guard);

        Ok(QrPairingTicket {
            version: 1,
            acceptor_device_id,
            acceptor_role,
            token,
            issued_at_unix: now_unix,
            expires_at_unix,
        })
    }

    /// Atomically consume a QR pairing token exactly once; concurrent second callers fail cleanly.
    pub fn consume_once(
        &self,
        raw_token: &[u8],
        expected_acceptor_id: DeviceId,
        now_unix: u64,
    ) -> Result<(), SecurityError> {
        let token_arr = Zeroizing::new(
            <[u8; OPAQUE_TOKEN_LEN]>::try_from(raw_token)
                .map_err(|_| SecurityError::QrPairingInvalid("QR token must be 32 bytes"))?,
        );
        let digest: [u8; 32] = Sha256::digest(token_arr.as_slice()).into();

        let mut guard = self
            .records
            .lock()
            .map_err(|_| SecurityError::AuthorizationDenied("QR store lock poisoned"))?;
        let record = guard
            .get_mut(&digest)
            .ok_or(SecurityError::QrTokenReusedOrUnknown)?;
        if record.acceptor_device_id != expected_acceptor_id {
            return Err(SecurityError::IdentityMismatch(
                "QR token is bound to a different acceptor device",
            ));
        }
        if record.consumed {
            return Err(SecurityError::QrTokenReusedOrUnknown);
        }
        if now_unix > record.expires_at_unix {
            return Err(SecurityError::QrPairingInvalid("QR pairing token expired"));
        }
        record.consumed = true;
        Ok(())
    }
}

/// Bind a validated `PairHello` byte-for-byte against an active TLS 1.3 mTLS session.
pub fn validate_pair_hello_against_tls(
    hello: &PairHello,
    tls_peer: &AuthenticatedTlsSession,
) -> Result<PublicIdentity, SecurityError> {
    tls_peer.require_pairing_alpn()?;
    if hello.protocol_major != LBWP_PROTOCOL_MAJOR {
        return Err(SecurityError::ProtocolViolation(
            "unsupported PairHello major version",
        ));
    }
    let claimed = PublicIdentity::from_spki_der(&hello.spki_ed25519)?;
    if claimed.device_id().as_bytes() != &hello.device_id {
        return Err(SecurityError::IdentityMismatch(
            "PairHello device_id does not equal SHA-256(spki_ed25519)",
        ));
    }
    if claimed.spki_der() != tls_peer.peer_identity().spki_der() {
        return Err(SecurityError::IdentityMismatch(
            "PairHello SPKI does not match authenticated mTLS peer certificate",
        ));
    }
    Ok(claimed)
}

/// Initiator pairing state machine (`Controller -> Host` or `Init -> Acc`).
pub struct PairingInitiator {
    stage: PairingStage,
    pairing_attempt_id: u64,
    expected_peer_epoch: u64,
    local_identity: PublicIdentity,
    local_role: PeerRole,
    peer_role: PeerRole,
    peer_identity: PublicIdentity,
    peer_friendly_name: String,
    channel_binding: ChannelBinding,
    auth_mode: AuthMode,
    protocol_major: u16,
    effective_minor: u16,
    spake_state: Option<PartyAState<Spake2P256>>,
    spake_output: Option<Spake2Output>,
    peer_confirmed: bool,
    remote_offered_perms: Option<Permissions>,
    granted_base_perms: Option<Permissions>,
}

impl PairingInitiator {
    /// Start an initiator pairing session over an already-completed TLS 1.3 mTLS connection
    /// for a brand-new peer (`expected_peer_epoch == 0`).
    pub fn start(
        pairing_attempt_id: u64,
        local_identity: &IdentityKeyPair,
        local_role: PeerRole,
        peer_hello: &PairHello,
        tls_peer: &AuthenticatedTlsSession,
        auth_mode: AuthMode,
    ) -> Result<Self, SecurityError> {
        Self::start_with_expected_peer_epoch(
            pairing_attempt_id,
            local_identity,
            local_role,
            peer_hello,
            tls_peer,
            auth_mode,
            0,
        )
    }

    /// Start an initiator pairing session explicitly pinned to the peer's trust epoch observed
    /// in `TrustStore` before pairing began (`0` for new peers, `revoked_epoch` for re-pairing).
    pub fn start_with_expected_peer_epoch(
        pairing_attempt_id: u64,
        local_identity: &IdentityKeyPair,
        local_role: PeerRole,
        peer_hello: &PairHello,
        tls_peer: &AuthenticatedTlsSession,
        auth_mode: AuthMode,
        expected_peer_epoch: u64,
    ) -> Result<Self, SecurityError> {
        if pairing_attempt_id == 0 {
            return Err(SecurityError::ProtocolViolation(
                "pairing_attempt_id cannot be zero",
            ));
        }
        validate_pairing_friendly_name(&peer_hello.friendly_name)?;
        let peer_identity = validate_pair_hello_against_tls(peer_hello, tls_peer)?;
        if local_identity.device_id() == peer_identity.device_id() {
            return Err(SecurityError::IdentityMismatch(
                "self-pairing with own DeviceId is forbidden",
            ));
        }
        if peer_hello.auth_mode != auth_mode {
            return Err(SecurityError::PairingState(
                "PairHello auth_mode mismatch with local choice",
            ));
        }
        Ok(Self {
            stage: PairingStage::Init,
            pairing_attempt_id,
            expected_peer_epoch,
            local_identity: local_identity.public_identity().clone(),
            local_role,
            peer_role: local_role.opposite(),
            peer_identity,
            peer_friendly_name: peer_hello.friendly_name.clone(),
            channel_binding: tls_peer.channel_binding().clone(),
            auth_mode,
            protocol_major: LBWP_PROTOCOL_MAJOR,
            effective_minor: negotiate_minor(peer_hello.protocol_minor),
            spake_state: None,
            spake_output: None,
            peer_confirmed: false,
            remote_offered_perms: None,
            granted_base_perms: None,
        })
    }

    fn fail(&mut self) {
        self.stage = PairingStage::Failed;
        self.spake_state = None;
        self.spake_output = None;
        self.remote_offered_perms = None;
    }

    /// Current 5-stage pairing state.
    #[must_use]
    pub const fn stage(&self) -> PairingStage {
        self.stage
    }

    /// Peer canonical public identity bound to TLS + `PairHello`.
    #[must_use]
    pub const fn peer_identity(&self) -> &PublicIdentity {
        &self.peer_identity
    }

    /// Active RFC 9266 TLS 1.3 channel binding.
    #[must_use]
    pub const fn channel_binding(&self) -> &ChannelBinding {
        &self.channel_binding
    }

    /// Base display permissions finalized upon local approval.
    #[must_use]
    pub const fn granted_base_perms(&self) -> Option<Permissions> {
        self.granted_base_perms
    }

    /// Render sanitized prompt details for local human confirmation on the Initiator.
    pub fn approval_prompt(&self) -> Result<PairingApprovalPrompt, SecurityError> {
        if self.stage != PairingStage::AwaitingApproval || self.remote_offered_perms.is_none() {
            return Err(SecurityError::PairingState(
                "approval prompt requires verified PairConfirm before local consent",
            ));
        }
        Ok(PairingApprovalPrompt {
            pairing_attempt_id: self.pairing_attempt_id,
            peer_device_id: self.peer_identity.device_id(),
            peer_fingerprint: self.peer_identity.device_id().fingerprint_display(),
            untrusted_friendly_name: self.peer_friendly_name.clone(),
            auth_mode: self.auth_mode,
            offered_base_perms: self.remote_offered_perms,
        })
    }

    /// Begin RFC 9382 SPAKE2-P256 exchange and emit the initial `KeyExchange` message (`pA`).
    pub fn begin_spake2(
        &mut self,
        pin: &PinSecret,
        rng: &mut CheckedOsCryptoRng,
    ) -> Result<PairSpakeMsg, SecurityError> {
        if self.stage != PairingStage::Init || self.auth_mode != AuthMode::PinSpake2 {
            self.fail();
            return Err(SecurityError::PairingState(
                "SPAKE2 start requires Init stage and PinSpake2 mode",
            ));
        }

        let wide = derive_spake2_wide_secret(
            pin,
            self.pairing_attempt_id,
            self.local_identity.device_id(),
            self.peer_identity.device_id(),
        )
        .inspect_err(|_| self.fail())?;
        let w = P256Group::scalar_from_wide_bytes(wide.as_slice()).map_err(|_| {
            self.fail();
            SecurityError::Spake2Failed
        })?;
        let (id_a, id_b) = spake_endpoint_identities(
            self.local_identity.device_id(),
            self.peer_identity.device_id(),
        );
        let aad = build_spake2_aad(Spake2AadContext {
            channel_binding: &self.channel_binding,
            pairing_attempt_id: self.pairing_attempt_id,
            protocol_major: self.protocol_major,
            protocol_minor: self.effective_minor,
            initiator_id: self.local_identity.device_id(),
            initiator_spki: self.local_identity.spki_der(),
            initiator_role: self.local_role,
            acceptor_id: self.peer_identity.device_id(),
            acceptor_spki: self.peer_identity.spki_der(),
            acceptor_role: self.peer_role,
        })
        .inspect_err(|_| self.fail())?;

        let mut spake_rng = rng.prefetch_spake_entropy().inspect_err(|_| self.fail())?;
        let (mut p_a, state) = PartyA::<Spake2P256>::start(&w, &id_a, &id_b, &aad, &mut spake_rng)
            .map_err(|_| {
                self.fail();
                SecurityError::Spake2Failed
            })?;
        if let Err(err) = spake_rng.ensure_healthy() {
            p_a.zeroize();
            drop(state);
            self.fail();
            return Err(err);
        }
        validate_uncompressed_p256_share(&p_a).inspect_err(|_| self.fail())?;

        self.spake_state = Some(state);
        self.stage = PairingStage::AuthExchanging;
        Ok(PairSpakeMsg {
            pairing_attempt_id: self.pairing_attempt_id,
            step: SpakeStep::KeyExchange,
            spake_payload: p_a,
            key_confirmation: None,
        })
    }

    /// Process acceptor's `KeyExchange` (`pB`) and emit initiator's `KeyConfirmation` (`cA`).
    pub fn finish_spake2_and_emit_confirmation(
        &mut self,
        peer_msg: &PairSpakeMsg,
    ) -> Result<PairSpakeMsg, SecurityError> {
        if self.stage != PairingStage::AuthExchanging || self.auth_mode != AuthMode::PinSpake2 {
            self.fail();
            return Err(SecurityError::PairingState(
                "unexpected SPAKE2 peer message state",
            ));
        }
        if peer_msg.pairing_attempt_id != self.pairing_attempt_id
            || peer_msg.step != SpakeStep::KeyExchange
            || peer_msg.key_confirmation.is_some()
        {
            self.fail();
            return Err(SecurityError::PairingState(
                "expected KeyExchange message matching pairing_attempt_id",
            ));
        }
        validate_uncompressed_p256_share(&peer_msg.spake_payload).inspect_err(|_| self.fail())?;

        let Some(state) = self.spake_state.take() else {
            self.fail();
            return Err(SecurityError::PairingState(
                "missing SPAKE2 initiator state",
            ));
        };
        let output = state.finish(&peer_msg.spake_payload).map_err(|_| {
            self.fail();
            SecurityError::Spake2Failed
        })?;
        if output.confirmation_mac.len() != SPAKE2_CONFIRM_MAC_LEN {
            self.fail();
            return Err(SecurityError::Spake2Failed);
        }
        let mac = output.confirmation_mac.clone();
        self.spake_output = Some(output);

        Ok(PairSpakeMsg {
            pairing_attempt_id: self.pairing_attempt_id,
            step: SpakeStep::KeyConfirmation,
            spake_payload: Vec::new(),
            key_confirmation: Some(mac),
        })
    }

    /// Verify acceptor's `KeyConfirmation` (`cB`) and advance to `AwaitingApproval`.
    pub fn verify_spake2_peer_confirmation(
        &mut self,
        peer_msg: &PairSpakeMsg,
    ) -> Result<(), SecurityError> {
        if self.stage != PairingStage::AuthExchanging || self.auth_mode != AuthMode::PinSpake2 {
            self.fail();
            return Err(SecurityError::PairingState(
                "unexpected SPAKE2 confirmation state",
            ));
        }
        if peer_msg.pairing_attempt_id != self.pairing_attempt_id
            || peer_msg.step != SpakeStep::KeyConfirmation
            || !peer_msg.spake_payload.is_empty()
        {
            self.fail();
            return Err(SecurityError::PairingState(
                "expected KeyConfirmation message matching pairing_attempt_id",
            ));
        }
        let Some(ref peer_mac) = peer_msg.key_confirmation else {
            self.fail();
            return Err(SecurityError::Spake2Failed);
        };
        if peer_mac.len() != SPAKE2_CONFIRM_MAC_LEN {
            self.fail();
            return Err(SecurityError::Spake2Failed);
        }
        let Some(output) = self.spake_output.take() else {
            self.fail();
            return Err(SecurityError::PairingState(
                "missing SPAKE2 initiator output",
            ));
        };
        output.verify_peer_confirmation(peer_mac).map_err(|_| {
            self.fail();
            SecurityError::Spake2Failed
        })?;
        drop(output.into_session_key());
        self.peer_confirmed = true;
        self.stage = PairingStage::AwaitingApproval;
        Ok(())
    }

    /// Build a channel-bound `PairQrAuth` signed by the initiator over TLS channel binding.
    pub fn create_qr_auth(
        &mut self,
        local_identity: &IdentityKeyPair,
        ticket: &QrPairingTicket,
        now_unix: u64,
    ) -> Result<PairQrAuth, SecurityError> {
        if self.stage != PairingStage::Init || self.auth_mode != AuthMode::QrOutOfBand {
            self.fail();
            return Err(SecurityError::PairingState(
                "QR pairing requires Init stage and QrOutOfBand mode",
            ));
        }
        if local_identity.device_id() != self.local_identity.device_id() {
            self.fail();
            return Err(SecurityError::IdentityMismatch(
                "signing keypair does not match initiator session identity",
            ));
        }
        if ticket.acceptor_device_id != self.peer_identity.device_id() {
            self.fail();
            return Err(SecurityError::IdentityMismatch(
                "QR ticket acceptor does not match connected TLS peer",
            ));
        }
        if ticket.acceptor_role != self.peer_role {
            self.fail();
            return Err(SecurityError::RoleConfusion);
        }
        if now_unix > ticket.expires_at_unix {
            self.fail();
            return Err(SecurityError::QrPairingInvalid("QR ticket already expired"));
        }

        let signing_msg = build_qr_auth_signing_message(QrAuthTranscriptContext {
            channel_binding: &self.channel_binding,
            pairing_attempt_id: self.pairing_attempt_id,
            protocol_major: self.protocol_major,
            protocol_minor: self.effective_minor,
            initiator_id: self.local_identity.device_id(),
            initiator_spki: self.local_identity.spki_der(),
            acceptor_id: self.peer_identity.device_id(),
            acceptor_spki: self.peer_identity.spki_der(),
            one_time_pairing_token: ticket.token.expose_secret(),
        })
        .inspect_err(|_| self.fail())?;
        let signature = local_identity.sign(&signing_msg);
        self.peer_confirmed = true;
        self.stage = PairingStage::AwaitingApproval;

        Ok(PairQrAuth {
            pairing_attempt_id: self.pairing_attempt_id,
            one_time_pairing_token: ticket.token.expose_secret().to_vec(),
            initiator_signature: signature.to_vec(),
        })
    }

    /// Verify peer's network `PairConfirm` signature and non-input permissions, WITHOUT promoting
    /// to `Confirmed`. Local human approval via [`Self::apply_local_approval`] remains mandatory.
    pub fn verify_pair_confirm(
        &mut self,
        confirm: &PairConfirm,
    ) -> Result<Permissions, SecurityError> {
        if self.stage != PairingStage::AwaitingApproval
            || !self.peer_confirmed
            || self.remote_offered_perms.is_some()
        {
            self.fail();
            return Err(SecurityError::PairingState(
                "PairConfirm received in invalid pairing state",
            ));
        }
        if confirm.pairing_attempt_id != self.pairing_attempt_id {
            self.fail();
            return Err(SecurityError::PairingState(
                "PairConfirm attempt id mismatch",
            ));
        }
        if !confirm.accepted {
            self.fail();
            return Err(SecurityError::ApprovalRequired);
        }
        if confirm.granted_base_perms.has_any_input() {
            self.fail();
            return Err(SecurityError::AuthorizationDenied(
                "PairConfirm cannot grant remote input permissions",
            ));
        }
        let Some(ref sig) = confirm.confirm_signature else {
            self.fail();
            return Err(SecurityError::InvalidSignature);
        };
        let msg = build_pair_confirm_signing_message(PairConfirmTranscriptContext {
            channel_binding: &self.channel_binding,
            pairing_attempt_id: self.pairing_attempt_id,
            auth_mode: self.auth_mode,
            accepted: confirm.accepted,
            granted_base_perms: confirm.granted_base_perms,
            initiator_id: self.local_identity.device_id(),
            initiator_spki: self.local_identity.spki_der(),
            acceptor_id: self.peer_identity.device_id(),
            acceptor_spki: self.peer_identity.spki_der(),
        })
        .inspect_err(|_| self.fail())?;
        self.peer_identity
            .verify_strict(&msg, sig)
            .inspect_err(|_| self.fail())?;
        self.remote_offered_perms = Some(confirm.granted_base_perms);
        Ok(confirm.granted_base_perms)
    }

    /// Finalize initiator trust ONLY after explicit local human consent matching peer & attempt ID.
    pub fn apply_local_approval(
        &mut self,
        decision: HumanApprovalDecision,
    ) -> Result<ApprovedPairingCommit, SecurityError> {
        if self.stage != PairingStage::AwaitingApproval || !self.peer_confirmed {
            self.fail();
            return Err(SecurityError::PairingState(
                "local approval requires AwaitingApproval after peer authentication",
            ));
        }
        let Some(remote_offered) = self.remote_offered_perms else {
            self.fail();
            return Err(SecurityError::PairingState(
                "cannot approve locally before verifying peer PairConfirm",
            ));
        };

        match decision {
            HumanApprovalDecision::Reject {
                pairing_attempt_id,
                peer_device_id,
            } => {
                if pairing_attempt_id != self.pairing_attempt_id
                    || peer_device_id != self.peer_identity.device_id()
                {
                    self.fail();
                    return Err(SecurityError::IdentityMismatch(
                        "approval decision does not match active peer/attempt",
                    ));
                }
                self.fail();
                Err(SecurityError::ApprovalRequired)
            }
            HumanApprovalDecision::Approve {
                pairing_attempt_id,
                peer_device_id,
                granted_base_perms,
            } => {
                if pairing_attempt_id != self.pairing_attempt_id
                    || peer_device_id != self.peer_identity.device_id()
                {
                    self.fail();
                    return Err(SecurityError::IdentityMismatch(
                        "approval decision does not match active peer/attempt",
                    ));
                }
                if granted_base_perms.has_any_input() {
                    self.fail();
                    return Err(SecurityError::AuthorizationDenied(
                        "initial pairing cannot grant remote input permissions",
                    ));
                }
                let effective = remote_offered.intersection(granted_base_perms);
                self.granted_base_perms = Some(effective);
                self.stage = PairingStage::Confirmed;
                let cb_digest: [u8; 32] = Sha256::digest(self.channel_binding.as_bytes()).into();
                Ok(ApprovedPairingCommit {
                    pairing_attempt_id: self.pairing_attempt_id,
                    peer_identity: self.peer_identity.clone(),
                    peer_role: self.peer_role,
                    friendly_name: self.peer_friendly_name.clone(),
                    granted_base_perms: effective,
                    channel_binding_digest: cb_digest,
                    expected_peer_epoch: self.expected_peer_epoch,
                    _sealed: (),
                })
            }
        }
    }
}

impl Drop for PairingInitiator {
    fn drop(&mut self) {
        self.fail();
        self.channel_binding.zeroize();
    }
}

/// Acceptor pairing state machine (`Host` receiving `PairHello` + auth proof from `Controller`).
pub struct PairingAcceptor {
    stage: PairingStage,
    pairing_attempt_id: u64,
    expected_peer_epoch: u64,
    local_identity: PublicIdentity,
    local_role: PeerRole,
    peer_role: PeerRole,
    peer_identity: PublicIdentity,
    peer_friendly_name: String,
    channel_binding: ChannelBinding,
    auth_mode: AuthMode,
    protocol_major: u16,
    effective_minor: u16,
    spake_output: Option<Spake2Output>,
    pin_lease: Option<PinAttemptLease>,
    spake_consumed: bool,
    qr_consumed: bool,
    commit_taken: bool,
    granted_base_perms: Option<Permissions>,
}

impl PairingAcceptor {
    /// Start an acceptor pairing session bound to TLS 1.3 peer cert and channel binding
    /// for a brand-new peer (`expected_peer_epoch == 0`).
    pub fn start(
        pairing_attempt_id: u64,
        local_identity: &IdentityKeyPair,
        local_role: PeerRole,
        peer_hello: &PairHello,
        tls_peer: &AuthenticatedTlsSession,
    ) -> Result<Self, SecurityError> {
        Self::start_with_expected_peer_epoch(
            pairing_attempt_id,
            local_identity,
            local_role,
            peer_hello,
            tls_peer,
            0,
        )
    }

    /// Start an acceptor pairing session explicitly pinned to the peer's trust epoch observed
    /// in `TrustStore` before pairing began (`0` for new peers, `revoked_epoch` for re-pairing).
    pub fn start_with_expected_peer_epoch(
        pairing_attempt_id: u64,
        local_identity: &IdentityKeyPair,
        local_role: PeerRole,
        peer_hello: &PairHello,
        tls_peer: &AuthenticatedTlsSession,
        expected_peer_epoch: u64,
    ) -> Result<Self, SecurityError> {
        if pairing_attempt_id == 0 {
            return Err(SecurityError::ProtocolViolation(
                "pairing_attempt_id cannot be zero",
            ));
        }
        validate_pairing_friendly_name(&peer_hello.friendly_name)?;
        let peer_identity = validate_pair_hello_against_tls(peer_hello, tls_peer)?;
        if local_identity.device_id() == peer_identity.device_id() {
            return Err(SecurityError::IdentityMismatch(
                "self-pairing with own DeviceId is forbidden",
            ));
        }
        Ok(Self {
            stage: PairingStage::Init,
            pairing_attempt_id,
            expected_peer_epoch,
            local_identity: local_identity.public_identity().clone(),
            local_role,
            peer_role: local_role.opposite(),
            peer_identity,
            peer_friendly_name: peer_hello.friendly_name.clone(),
            channel_binding: tls_peer.channel_binding().clone(),
            auth_mode: peer_hello.auth_mode,
            protocol_major: LBWP_PROTOCOL_MAJOR,
            effective_minor: negotiate_minor(peer_hello.protocol_minor),
            spake_output: None,
            pin_lease: None,
            spake_consumed: false,
            qr_consumed: false,
            commit_taken: false,
            granted_base_perms: None,
        })
    }

    fn fail(&mut self) {
        self.stage = PairingStage::Failed;
        self.spake_output = None;
        if let Some(lease) = self.pin_lease.take() {
            lease.finish_failure();
        }
    }

    /// Current 5-stage pairing state.
    #[must_use]
    pub const fn stage(&self) -> PairingStage {
        self.stage
    }

    /// Peer canonical public identity bound to TLS + `PairHello`.
    #[must_use]
    pub const fn peer_identity(&self) -> &PublicIdentity {
        &self.peer_identity
    }

    /// Active RFC 9266 TLS 1.3 channel binding.
    #[must_use]
    pub const fn channel_binding(&self) -> &ChannelBinding {
        &self.channel_binding
    }

    /// Render sanitized prompt details for local human confirmation on the Acceptor.
    pub fn approval_prompt(&self) -> Result<PairingApprovalPrompt, SecurityError> {
        if self.stage != PairingStage::AwaitingApproval {
            return Err(SecurityError::PairingState(
                "approval prompt requires AwaitingApproval stage",
            ));
        }
        Ok(PairingApprovalPrompt {
            pairing_attempt_id: self.pairing_attempt_id,
            peer_device_id: self.peer_identity.device_id(),
            peer_fingerprint: self.peer_identity.device_id().fingerprint_display(),
            untrusted_friendly_name: self.peer_friendly_name.clone(),
            auth_mode: self.auth_mode,
            offered_base_perms: None,
        })
    }

    /// Produce a single-use [`ApprovedPairingCommit`] once local approval is confirmed.
    pub fn approved_commit(&mut self) -> Result<ApprovedPairingCommit, SecurityError> {
        if self.stage != PairingStage::Confirmed {
            return Err(SecurityError::PairingState(
                "approved commit requires Confirmed stage",
            ));
        }
        if self.commit_taken {
            return Err(SecurityError::PairingState(
                "approved pairing commit already consumed",
            ));
        }
        let perms = self
            .granted_base_perms
            .ok_or(SecurityError::PairingState("missing granted permissions"))?;
        self.commit_taken = true;
        let cb_digest: [u8; 32] = Sha256::digest(self.channel_binding.as_bytes()).into();
        Ok(ApprovedPairingCommit {
            pairing_attempt_id: self.pairing_attempt_id,
            peer_identity: self.peer_identity.clone(),
            peer_role: self.peer_role,
            friendly_name: self.peer_friendly_name.clone(),
            granted_base_perms: perms,
            channel_binding_digest: cb_digest,
            expected_peer_epoch: self.expected_peer_epoch,
            _sealed: (),
        })
    }

    /// Atomically reserve a slot in `pin_window`'s 3-attempt budget, process initiator's
    /// `KeyExchange` (`pA`) at most once per connection, and return acceptor `pB`.
    pub fn handle_spake2_exchange(
        &mut self,
        pin_window: &PinPairingWindow,
        peer_msg: &PairSpakeMsg,
        now_mono_secs: u64,
        rng: &mut CheckedOsCryptoRng,
    ) -> Result<PairSpakeMsg, SecurityError> {
        if self.stage != PairingStage::Init
            || self.auth_mode != AuthMode::PinSpake2
            || self.spake_consumed
        {
            self.fail();
            return Err(SecurityError::PairingState(
                "SPAKE2 exchange permitted once per pairing connection",
            ));
        }
        self.spake_consumed = true;

        if peer_msg.pairing_attempt_id != self.pairing_attempt_id
            || peer_msg.step != SpakeStep::KeyExchange
            || peer_msg.key_confirmation.is_some()
        {
            self.fail();
            return Err(SecurityError::PairingState(
                "expected KeyExchange message matching pairing_attempt_id",
            ));
        }
        validate_uncompressed_p256_share(&peer_msg.spake_payload).inspect_err(|_| self.fail())?;

        let lease = pin_window.begin_attempt(now_mono_secs).inspect_err(|_| {
            self.stage = PairingStage::Failed;
        })?;
        let pin = lease.pin()?;

        let wide = derive_spake2_wide_secret(
            pin,
            self.pairing_attempt_id,
            self.peer_identity.device_id(),
            self.local_identity.device_id(),
        )
        .inspect_err(|_| {
            self.stage = PairingStage::Failed;
        })?;
        let w = P256Group::scalar_from_wide_bytes(wide.as_slice()).map_err(|_| {
            self.stage = PairingStage::Failed;
            SecurityError::Spake2Failed
        })?;
        let (id_a, id_b) = spake_endpoint_identities(
            self.peer_identity.device_id(),
            self.local_identity.device_id(),
        );
        let aad = build_spake2_aad(Spake2AadContext {
            channel_binding: &self.channel_binding,
            pairing_attempt_id: self.pairing_attempt_id,
            protocol_major: self.protocol_major,
            protocol_minor: self.effective_minor,
            initiator_id: self.peer_identity.device_id(),
            initiator_spki: self.peer_identity.spki_der(),
            initiator_role: self.peer_role,
            acceptor_id: self.local_identity.device_id(),
            acceptor_spki: self.local_identity.spki_der(),
            acceptor_role: self.local_role,
        })
        .inspect_err(|_| {
            self.stage = PairingStage::Failed;
        })?;

        let mut spake_rng = rng.prefetch_spake_entropy().inspect_err(|_| {
            self.stage = PairingStage::Failed;
        })?;
        let (mut p_b, state_b) =
            PartyB::<Spake2P256>::start(&w, &id_a, &id_b, &aad, &mut spake_rng).map_err(|_| {
                self.stage = PairingStage::Failed;
                SecurityError::Spake2Failed
            })?;
        if let Err(err) = spake_rng.ensure_healthy() {
            p_b.zeroize();
            drop(state_b);
            self.stage = PairingStage::Failed;
            return Err(err);
        }
        validate_uncompressed_p256_share(&p_b).inspect_err(|_| {
            self.stage = PairingStage::Failed;
        })?;

        let output = state_b.finish(&peer_msg.spake_payload).map_err(|_| {
            self.stage = PairingStage::Failed;
            SecurityError::Spake2Failed
        })?;
        self.spake_output = Some(output);
        self.pin_lease = Some(lease);
        self.stage = PairingStage::AuthExchanging;

        Ok(PairSpakeMsg {
            pairing_attempt_id: self.pairing_attempt_id,
            step: SpakeStep::KeyExchange,
            spake_payload: p_b,
            key_confirmation: None,
        })
    }

    /// Verify initiator's `KeyConfirmation` (`cA`), emit acceptor `KeyConfirmation` (`cB`),
    /// atomically consume/destroy the PIN at monotonic confirmation time `now_mono_secs` (failing
    /// if expired, closed, rotated, or consumed concurrently), and advance to `AwaitingApproval`.
    pub fn verify_spake2_confirmation_and_reply(
        &mut self,
        peer_msg: &PairSpakeMsg,
        now_mono_secs: u64,
    ) -> Result<PairSpakeMsg, SecurityError> {
        if self.stage != PairingStage::AuthExchanging || self.auth_mode != AuthMode::PinSpake2 {
            self.fail();
            return Err(SecurityError::PairingState(
                "unexpected SPAKE2 confirmation state",
            ));
        }
        if peer_msg.pairing_attempt_id != self.pairing_attempt_id
            || peer_msg.step != SpakeStep::KeyConfirmation
            || !peer_msg.spake_payload.is_empty()
        {
            self.fail();
            return Err(SecurityError::PairingState(
                "expected KeyConfirmation message matching pairing_attempt_id",
            ));
        }
        let Some(ref peer_mac) = peer_msg.key_confirmation else {
            self.fail();
            return Err(SecurityError::Spake2Failed);
        };
        if peer_mac.len() != SPAKE2_CONFIRM_MAC_LEN {
            self.fail();
            return Err(SecurityError::Spake2Failed);
        }
        let Some(output) = self.spake_output.take() else {
            self.fail();
            return Err(SecurityError::PairingState(
                "missing SPAKE2 acceptor output",
            ));
        };
        if output.verify_peer_confirmation(peer_mac).is_err() {
            self.fail();
            return Err(SecurityError::Spake2Failed);
        }
        if output.confirmation_mac.len() != SPAKE2_CONFIRM_MAC_LEN {
            self.fail();
            return Err(SecurityError::Spake2Failed);
        }
        let reply_mac = output.confirmation_mac.clone();
        drop(output.into_session_key());

        let Some(lease) = self.pin_lease.take() else {
            self.fail();
            return Err(SecurityError::PairingState("missing PIN attempt lease"));
        };
        if let Err(err) = lease.finish_success(now_mono_secs) {
            self.fail();
            return Err(err);
        }
        self.stage = PairingStage::AwaitingApproval;

        Ok(PairSpakeMsg {
            pairing_attempt_id: self.pairing_attempt_id,
            step: SpakeStep::KeyConfirmation,
            spake_payload: Vec::new(),
            key_confirmation: Some(reply_mac),
        })
    }

    /// Verify channel-bound `PairQrAuth`, atomically consume single-use QR token, and move to `AwaitingApproval`.
    pub fn verify_qr_auth(
        &mut self,
        qr_store: &QrTokenStore,
        qr_auth: &PairQrAuth,
        now_unix: u64,
    ) -> Result<(), SecurityError> {
        if self.stage != PairingStage::Init
            || self.auth_mode != AuthMode::QrOutOfBand
            || self.qr_consumed
        {
            self.fail();
            return Err(SecurityError::PairingState(
                "QR pairing permitted once in Init/QrOutOfBand state",
            ));
        }
        self.qr_consumed = true;
        if qr_auth.pairing_attempt_id != self.pairing_attempt_id {
            self.fail();
            return Err(SecurityError::PairingState(
                "PairQrAuth attempt id mismatch",
            ));
        }
        let token_arr = Zeroizing::new(
            <[u8; OPAQUE_TOKEN_LEN]>::try_from(qr_auth.one_time_pairing_token.as_slice()).map_err(
                |_| {
                    self.fail();
                    SecurityError::QrPairingInvalid("QR token length must be 32 bytes")
                },
            )?,
        );

        let signing_msg = build_qr_auth_signing_message(QrAuthTranscriptContext {
            channel_binding: &self.channel_binding,
            pairing_attempt_id: self.pairing_attempt_id,
            protocol_major: self.protocol_major,
            protocol_minor: self.effective_minor,
            initiator_id: self.peer_identity.device_id(),
            initiator_spki: self.peer_identity.spki_der(),
            acceptor_id: self.local_identity.device_id(),
            acceptor_spki: self.local_identity.spki_der(),
            one_time_pairing_token: &token_arr,
        })
        .inspect_err(|_| self.fail())?;
        self.peer_identity
            .verify_strict(&signing_msg, &qr_auth.initiator_signature)
            .inspect_err(|_| self.fail())?;

        qr_store
            .consume_once(&*token_arr, self.local_identity.device_id(), now_unix)
            .inspect_err(|_| self.fail())?;

        self.stage = PairingStage::AwaitingApproval;
        Ok(())
    }

    /// Finalize pairing ONLY after explicit [`HumanApprovalDecision`] bound to this peer & attempt;
    /// rejects input perms cleanly.
    pub fn apply_human_approval(
        &mut self,
        local_identity: &IdentityKeyPair,
        decision: HumanApprovalDecision,
    ) -> Result<PairConfirm, SecurityError> {
        if self.stage != PairingStage::AwaitingApproval {
            self.fail();
            return Err(SecurityError::PairingState(
                "human approval requires AwaitingApproval stage",
            ));
        }
        if local_identity.device_id() != self.local_identity.device_id() {
            self.fail();
            return Err(SecurityError::IdentityMismatch(
                "signing keypair does not match acceptor session identity",
            ));
        }
        match decision {
            HumanApprovalDecision::Reject {
                pairing_attempt_id,
                peer_device_id,
            } => {
                if pairing_attempt_id != self.pairing_attempt_id
                    || peer_device_id != self.peer_identity.device_id()
                {
                    self.fail();
                    return Err(SecurityError::IdentityMismatch(
                        "approval decision does not match active peer/attempt",
                    ));
                }
                self.fail();
                Ok(PairConfirm {
                    pairing_attempt_id: self.pairing_attempt_id,
                    accepted: false,
                    granted_base_perms: Permissions::NONE,
                    confirm_signature: None,
                })
            }
            HumanApprovalDecision::Approve {
                pairing_attempt_id,
                peer_device_id,
                granted_base_perms,
            } => {
                if pairing_attempt_id != self.pairing_attempt_id
                    || peer_device_id != self.peer_identity.device_id()
                {
                    self.fail();
                    return Err(SecurityError::IdentityMismatch(
                        "approval decision does not match active peer/attempt",
                    ));
                }
                if granted_base_perms.has_any_input() {
                    self.fail();
                    return Err(SecurityError::AuthorizationDenied(
                        "initial pairing cannot grant remote input permissions",
                    ));
                }
                let msg = build_pair_confirm_signing_message(PairConfirmTranscriptContext {
                    channel_binding: &self.channel_binding,
                    pairing_attempt_id: self.pairing_attempt_id,
                    auth_mode: self.auth_mode,
                    accepted: true,
                    granted_base_perms,
                    initiator_id: self.peer_identity.device_id(),
                    initiator_spki: self.peer_identity.spki_der(),
                    acceptor_id: self.local_identity.device_id(),
                    acceptor_spki: self.local_identity.spki_der(),
                })
                .inspect_err(|_| self.fail())?;
                let sig = local_identity.sign(&msg);
                self.granted_base_perms = Some(granted_base_perms);
                self.stage = PairingStage::Confirmed;

                Ok(PairConfirm {
                    pairing_attempt_id: self.pairing_attempt_id,
                    accepted: true,
                    granted_base_perms,
                    confirm_signature: Some(sig.to_vec()),
                })
            }
        }
    }
}

impl Drop for PairingAcceptor {
    fn drop(&mut self) {
        self.fail();
        self.channel_binding.zeroize();
    }
}

fn validate_uncompressed_p256_share(share: &[u8]) -> Result<(), SecurityError> {
    if share.len() != SPAKE2_P256_PUBLIC_SHARE_LEN || share[0] != 0x04 {
        return Err(SecurityError::Spake2Failed);
    }
    Ok(())
}

const fn negotiate_minor(peer_minor: u16) -> u16 {
    if LBWP_PROTOCOL_MINOR < peer_minor {
        LBWP_PROTOCOL_MINOR
    } else {
        peer_minor
    }
}

fn validate_pairing_friendly_name(name: &str) -> Result<(), SecurityError> {
    if name.is_empty() || name.len() > 48 {
        return Err(SecurityError::ProtocolViolation(
            "PairHello friendly_name length must be within 1..=48 bytes",
        ));
    }
    if name.bytes().any(|b| b == 0 || b.is_ascii_control()) {
        return Err(SecurityError::ProtocolViolation(
            "PairHello friendly_name must not contain NUL or control characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::{generate_self_signed_device_cert, verify_self_signed_ed25519_cert};
    use crate::secret::{
        set_next_spake_prefetch_fail_for_test, set_next_spake_refill_fail_for_test,
    };
    use lumabridge_protocol::version::{ALPN_PAIRING_V1, LBWP_PROTOCOL_MAJOR, LBWP_PROTOCOL_MINOR};
    use std::time::Instant;

    #[test]
    fn spake2_entropy_failure_terminates_boundedly_and_emits_no_proof() {
        let now = 1_700_000_100u64;
        let host_kp = IdentityKeyPair::from_seed([0x11; 32]).expect("host");
        let ctrl_kp = IdentityKeyPair::from_seed([0x22; 32]).expect("ctrl");
        let host_cert =
            generate_self_signed_device_cert(&host_kp, now - 60, now + 3600).expect("host cert");
        let ctrl_cert =
            generate_self_signed_device_cert(&ctrl_kp, now - 60, now + 3600).expect("ctrl cert");
        let host_verified = verify_self_signed_ed25519_cert(&host_cert.cert_der, now).expect("hv");
        let ctrl_verified = verify_self_signed_ed25519_cert(&ctrl_cert.cert_der, now).expect("cv");

        let c_tls = AuthenticatedTlsSession::synthetic_for_testing(
            host_verified,
            ChannelBinding::synthetic_for_testing([0x55; 32]),
            ALPN_PAIRING_V1.as_bytes().to_vec(),
        );
        let s_tls = AuthenticatedTlsSession::synthetic_for_testing(
            ctrl_verified,
            ChannelBinding::synthetic_for_testing([0x55; 32]),
            ALPN_PAIRING_V1.as_bytes().to_vec(),
        );
        let init_hello = PairHello {
            protocol_major: LBWP_PROTOCOL_MAJOR,
            protocol_minor: LBWP_PROTOCOL_MINOR,
            device_id: *ctrl_kp.device_id().as_bytes(),
            friendly_name: "Init".into(),
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
        let pin = PinSecret::new("12345678").expect("pin");

        // 1. Prefetch failure inside begin_spake2
        let mut init1 = PairingInitiator::start(
            1,
            &ctrl_kp,
            PeerRole::Controller,
            &acc_hello,
            &c_tls,
            AuthMode::PinSpake2,
        )
        .expect("init1");
        set_next_spake_prefetch_fail_for_test();
        assert_eq!(
            init1.begin_spake2(&pin, &mut rng),
            Err(SecurityError::RngUnavailable)
        );
        assert_eq!(init1.stage(), PairingStage::Failed);

        // 2. Mid-SPAKE2 refill failure inside begin_spake2 completes in bounded time and emits no proof
        let mut init2 = PairingInitiator::start(
            2,
            &ctrl_kp,
            PeerRole::Controller,
            &acc_hello,
            &c_tls,
            AuthMode::PinSpake2,
        )
        .expect("init2");
        set_next_spake_refill_fail_for_test();
        let t0 = Instant::now();
        assert_eq!(
            init2.begin_spake2(&pin, &mut rng),
            Err(SecurityError::RngUnavailable)
        );
        assert!(t0.elapsed().as_millis() < 500);
        assert_eq!(init2.stage(), PairingStage::Failed);

        // 3. Valid initiator p_a -> Mid-SPAKE2 refill failure inside handle_spake2_exchange
        let mut good_init = PairingInitiator::start(
            3,
            &ctrl_kp,
            PeerRole::Controller,
            &acc_hello,
            &c_tls,
            AuthMode::PinSpake2,
        )
        .expect("good init");
        let valid_pa = good_init.begin_spake2(&pin, &mut rng).expect("valid pa");

        let window = PinPairingWindow::new();
        let _wpin = window.open_with_new_pin(&mut rng, now).expect("wpin");
        let mut acc =
            PairingAcceptor::start(3, &host_kp, PeerRole::Host, &init_hello, &s_tls).expect("acc");
        set_next_spake_refill_fail_for_test();
        let t1 = Instant::now();
        assert_eq!(
            acc.handle_spake2_exchange(&window, &valid_pa, now, &mut rng),
            Err(SecurityError::RngUnavailable)
        );
        assert!(t1.elapsed().as_millis() < 500);
        assert_eq!(acc.stage(), PairingStage::Failed);
    }
}
