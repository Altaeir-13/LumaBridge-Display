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
    derive_spake2_wide_secret, spake_endpoint_identities, Spake2AadContext,
};
use core::fmt;
use lumabridge_protocol::control::{
    AuthMode, PairConfirm, PairHello, PairQrAuth, PairSpakeMsg, Permissions, SpakeStep,
    OPAQUE_TOKEN_LEN, SPAKE2_CONFIRM_MAC_LEN, SPAKE2_P256_PUBLIC_SHARE_LEN,
};
use lumabridge_protocol::version::{ALPN_PAIRING_V1, LBWP_PROTOCOL_MAJOR};
use pakery_core::crypto::CpaceGroup;
use pakery_crypto::{P256Group, Spake2P256};
use pakery_spake2::{PartyA, PartyAState, PartyB, Spake2Output};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Maximum permitted lifetime of a single-use QR pairing token (seconds).
pub const MAX_QR_TOKEN_TTL_SECS: u64 = 300;

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

/// Explicit port for local human consent before trusting a newly paired peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HumanApprovalDecision {
    /// Local user explicitly approves pairing with `granted_base_perms` (no remote input perms).
    Approve { granted_base_perms: Permissions },
    /// Local user denies pairing.
    Reject,
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

/// Atomic single-use QR pairing token store (stores SHA-256 digests only, never raw tokens).
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
        // Opportunistically prune expired consumed records to keep store bounded.
        guard.retain(|_, rec| rec.expires_at_unix >= now_unix);
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
        let token_arr: [u8; OPAQUE_TOKEN_LEN] = raw_token
            .try_into()
            .map_err(|_| SecurityError::QrPairingInvalid("QR token must be 32 bytes"))?;
        let digest: [u8; 32] = Sha256::digest(token_arr).into();

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

/// Bind a validated `PairHello` against an active TLS 1.3 mTLS session.
pub fn validate_pair_hello_against_tls(
    hello: &PairHello,
    tls_peer: &AuthenticatedTlsSession,
) -> Result<PublicIdentity, SecurityError> {
    if tls_peer.negotiated_alpn.as_slice() != ALPN_PAIRING_V1.as_bytes() {
        return Err(SecurityError::AlpnMismatch);
    }
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
    if claimed.device_id() != tls_peer.peer_cert.public_identity.device_id() {
        return Err(SecurityError::IdentityMismatch(
            "PairHello identity does not match authenticated mTLS peer certificate",
        ));
    }
    Ok(claimed)
}

/// Initiator pairing state machine (`Controller -> Host` or `Init -> Acc`).
pub struct PairingInitiator {
    stage: PairingStage,
    pairing_attempt_id: u64,
    local_role: PeerRole,
    peer_role: PeerRole,
    peer_identity: PublicIdentity,
    channel_binding: ChannelBinding,
    auth_mode: AuthMode,
    protocol_major: u16,
    protocol_minor: u16,
    spake_state: Option<PartyAState<Spake2P256>>,
    spake_output: Option<Spake2Output>,
    peer_confirmed: bool,
    granted_base_perms: Option<Permissions>,
}

impl PairingInitiator {
    /// Start an initiator pairing session over an already-completed TLS 1.3 mTLS connection.
    pub fn start(
        pairing_attempt_id: u64,
        local_identity: &IdentityKeyPair,
        local_role: PeerRole,
        peer_hello: &PairHello,
        tls_peer: &AuthenticatedTlsSession,
        auth_mode: AuthMode,
    ) -> Result<Self, SecurityError> {
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
            local_role,
            peer_role: local_role.opposite(),
            peer_identity,
            channel_binding: tls_peer.channel_binding,
            auth_mode,
            protocol_major: peer_hello.protocol_major,
            protocol_minor: peer_hello.protocol_minor,
            spake_state: None,
            spake_output: None,
            peer_confirmed: false,
            granted_base_perms: None,
        })
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
    pub const fn channel_binding(&self) -> ChannelBinding {
        self.channel_binding
    }

    /// Base display permissions confirmed by peer upon completion.
    #[must_use]
    pub const fn granted_base_perms(&self) -> Option<Permissions> {
        self.granted_base_perms
    }

    /// Begin RFC 9382 SPAKE2-P256 exchange and emit the initial `KeyExchange` message (`pA`).
    pub fn begin_spake2(
        &mut self,
        local_id: DeviceId,
        pin: &PinSecret,
        rng: &mut CheckedOsCryptoRng,
    ) -> Result<PairSpakeMsg, SecurityError> {
        if self.stage != PairingStage::Init || self.auth_mode != AuthMode::PinSpake2 {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "SPAKE2 start requires Init stage and PinSpake2 mode",
            ));
        }

        let wide = derive_spake2_wide_secret(
            pin,
            &self.channel_binding,
            self.pairing_attempt_id,
            local_id,
            self.peer_identity.device_id(),
        )?;
        let w = P256Group::scalar_from_wide_bytes(wide.as_slice())
            .map_err(|_| SecurityError::Spake2Failed)?;
        let (id_a, id_b) = spake_endpoint_identities(local_id, self.peer_identity.device_id());
        let aad = build_spake2_aad(Spake2AadContext {
            channel_binding: &self.channel_binding,
            pairing_attempt_id: self.pairing_attempt_id,
            protocol_major: self.protocol_major,
            protocol_minor: self.protocol_minor,
            initiator_id: local_id,
            initiator_role: self.local_role,
            acceptor_id: self.peer_identity.device_id(),
            acceptor_role: self.peer_role,
        });

        let mut spake_rng = rng.prefetch_spake_entropy()?;
        let (p_a, state) = PartyA::<Spake2P256>::start(&w, &id_a, &id_b, &aad, &mut spake_rng)
            .map_err(|_| SecurityError::Spake2Failed)?;
        validate_uncompressed_p256_share(&p_a)?;

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
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "unexpected SPAKE2 peer message state",
            ));
        }
        if peer_msg.pairing_attempt_id != self.pairing_attempt_id
            || peer_msg.step != SpakeStep::KeyExchange
            || peer_msg.key_confirmation.is_some()
        {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "expected KeyExchange message matching pairing_attempt_id",
            ));
        }
        validate_uncompressed_p256_share(&peer_msg.spake_payload)?;

        let Some(state) = self.spake_state.take() else {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "missing SPAKE2 initiator state",
            ));
        };
        let output = state.finish(&peer_msg.spake_payload).map_err(|_| {
            self.stage = PairingStage::Failed;
            SecurityError::Spake2Failed
        })?;
        if output.confirmation_mac.len() != SPAKE2_CONFIRM_MAC_LEN {
            self.stage = PairingStage::Failed;
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
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "unexpected SPAKE2 confirmation state",
            ));
        }
        if peer_msg.pairing_attempt_id != self.pairing_attempt_id
            || peer_msg.step != SpakeStep::KeyConfirmation
            || !peer_msg.spake_payload.is_empty()
        {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "expected KeyConfirmation message matching pairing_attempt_id",
            ));
        }
        let Some(ref peer_mac) = peer_msg.key_confirmation else {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::Spake2Failed);
        };
        if peer_mac.len() != SPAKE2_CONFIRM_MAC_LEN {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::Spake2Failed);
        }
        let Some(output) = self.spake_output.take() else {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "missing SPAKE2 initiator output",
            ));
        };
        output.verify_peer_confirmation(peer_mac).map_err(|_| {
            self.stage = PairingStage::Failed;
            SecurityError::Spake2Failed
        })?;
        // Consume derived session key explicitly after key confirmation succeeds.
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
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "QR pairing requires Init stage and QrOutOfBand mode",
            ));
        }
        if ticket.acceptor_device_id != self.peer_identity.device_id() {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::IdentityMismatch(
                "QR ticket acceptor does not match connected TLS peer",
            ));
        }
        if now_unix > ticket.expires_at_unix {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::QrPairingInvalid("QR ticket already expired"));
        }

        let signing_msg = build_qr_auth_signing_message(
            &self.channel_binding,
            self.pairing_attempt_id,
            local_identity.device_id(),
            self.peer_identity.device_id(),
            ticket.token.expose_secret(),
        );
        let signature = local_identity.sign(&signing_msg);
        self.peer_confirmed = true;
        self.stage = PairingStage::AwaitingApproval;

        Ok(PairQrAuth {
            pairing_attempt_id: self.pairing_attempt_id,
            one_time_pairing_token: ticket.token.expose_secret().to_vec(),
            initiator_signature: signature.to_vec(),
        })
    }

    /// Verify `PairConfirm` signature, reject any input permission escalation, and reach `Confirmed`.
    pub fn accept_pair_confirm(
        &mut self,
        local_id: DeviceId,
        confirm: &PairConfirm,
    ) -> Result<Permissions, SecurityError> {
        if self.stage != PairingStage::AwaitingApproval || !self.peer_confirmed {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "PairConfirm received before authentication completed",
            ));
        }
        if confirm.pairing_attempt_id != self.pairing_attempt_id {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "PairConfirm attempt id mismatch",
            ));
        }
        if !confirm.accepted {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::ApprovalRequired);
        }
        if confirm.granted_base_perms.has_any_input() {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::AuthorizationDenied(
                "PairConfirm cannot grant remote input permissions",
            ));
        }
        let Some(ref sig) = confirm.confirm_signature else {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::InvalidSignature);
        };
        let msg = build_pair_confirm_signing_message(
            &self.channel_binding,
            self.pairing_attempt_id,
            local_id,
            self.peer_identity.device_id(),
            confirm.granted_base_perms,
        );
        self.peer_identity
            .verify_strict(&msg, sig)
            .inspect_err(|_| {
                self.stage = PairingStage::Failed;
            })?;
        self.granted_base_perms = Some(confirm.granted_base_perms);
        self.stage = PairingStage::Confirmed;
        Ok(confirm.granted_base_perms)
    }
}

/// Acceptor pairing state machine (`Host` receiving `PairHello` + auth proof from `Controller`).
pub struct PairingAcceptor {
    stage: PairingStage,
    pairing_attempt_id: u64,
    local_role: PeerRole,
    peer_role: PeerRole,
    peer_identity: PublicIdentity,
    channel_binding: ChannelBinding,
    auth_mode: AuthMode,
    protocol_major: u16,
    protocol_minor: u16,
    spake_output: Option<Spake2Output>,
    spake_consumed: bool,
    qr_consumed: bool,
    granted_base_perms: Option<Permissions>,
}

impl PairingAcceptor {
    /// Start an acceptor pairing session bound to TLS 1.3 peer cert and channel binding.
    pub fn start(
        pairing_attempt_id: u64,
        local_identity: &IdentityKeyPair,
        local_role: PeerRole,
        peer_hello: &PairHello,
        tls_peer: &AuthenticatedTlsSession,
    ) -> Result<Self, SecurityError> {
        let peer_identity = validate_pair_hello_against_tls(peer_hello, tls_peer)?;
        if local_identity.device_id() == peer_identity.device_id() {
            return Err(SecurityError::IdentityMismatch(
                "self-pairing with own DeviceId is forbidden",
            ));
        }
        Ok(Self {
            stage: PairingStage::Init,
            pairing_attempt_id,
            local_role,
            peer_role: local_role.opposite(),
            peer_identity,
            channel_binding: tls_peer.channel_binding,
            auth_mode: peer_hello.auth_mode,
            protocol_major: peer_hello.protocol_major,
            protocol_minor: peer_hello.protocol_minor,
            spake_output: None,
            spake_consumed: false,
            qr_consumed: false,
            granted_base_perms: None,
        })
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
    pub const fn channel_binding(&self) -> ChannelBinding {
        self.channel_binding
    }

    /// Process initiator's `KeyExchange` (`pA`) at most once per connection and return acceptor `pB`.
    pub fn handle_spake2_exchange(
        &mut self,
        local_id: DeviceId,
        pin: &PinSecret,
        peer_msg: &PairSpakeMsg,
        rng: &mut CheckedOsCryptoRng,
    ) -> Result<PairSpakeMsg, SecurityError> {
        if self.stage != PairingStage::Init
            || self.auth_mode != AuthMode::PinSpake2
            || self.spake_consumed
        {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "SPAKE2 exchange permitted once per pairing connection",
            ));
        }
        self.spake_consumed = true;

        if peer_msg.pairing_attempt_id != self.pairing_attempt_id
            || peer_msg.step != SpakeStep::KeyExchange
            || peer_msg.key_confirmation.is_some()
        {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "expected KeyExchange message matching pairing_attempt_id",
            ));
        }
        validate_uncompressed_p256_share(&peer_msg.spake_payload)?;

        let wide = derive_spake2_wide_secret(
            pin,
            &self.channel_binding,
            self.pairing_attempt_id,
            self.peer_identity.device_id(),
            local_id,
        )?;
        let w = P256Group::scalar_from_wide_bytes(wide.as_slice())
            .map_err(|_| SecurityError::Spake2Failed)?;
        let (id_a, id_b) = spake_endpoint_identities(self.peer_identity.device_id(), local_id);
        let aad = build_spake2_aad(Spake2AadContext {
            channel_binding: &self.channel_binding,
            pairing_attempt_id: self.pairing_attempt_id,
            protocol_major: self.protocol_major,
            protocol_minor: self.protocol_minor,
            initiator_id: self.peer_identity.device_id(),
            initiator_role: self.peer_role,
            acceptor_id: local_id,
            acceptor_role: self.local_role,
        });

        let mut spake_rng = rng.prefetch_spake_entropy()?;
        let (p_b, state_b) = PartyB::<Spake2P256>::start(&w, &id_a, &id_b, &aad, &mut spake_rng)
            .map_err(|_| SecurityError::Spake2Failed)?;
        validate_uncompressed_p256_share(&p_b)?;

        let output = state_b.finish(&peer_msg.spake_payload).map_err(|_| {
            self.stage = PairingStage::Failed;
            SecurityError::Spake2Failed
        })?;
        self.spake_output = Some(output);
        self.stage = PairingStage::AuthExchanging;

        Ok(PairSpakeMsg {
            pairing_attempt_id: self.pairing_attempt_id,
            step: SpakeStep::KeyExchange,
            spake_payload: p_b,
            key_confirmation: None,
        })
    }

    /// Verify initiator's `KeyConfirmation` (`cA`), emit acceptor `KeyConfirmation` (`cB`),
    /// and advance to `AwaitingApproval`.
    pub fn verify_spake2_confirmation_and_reply(
        &mut self,
        peer_msg: &PairSpakeMsg,
    ) -> Result<PairSpakeMsg, SecurityError> {
        if self.stage != PairingStage::AuthExchanging || self.auth_mode != AuthMode::PinSpake2 {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "unexpected SPAKE2 confirmation state",
            ));
        }
        if peer_msg.pairing_attempt_id != self.pairing_attempt_id
            || peer_msg.step != SpakeStep::KeyConfirmation
            || !peer_msg.spake_payload.is_empty()
        {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "expected KeyConfirmation message matching pairing_attempt_id",
            ));
        }
        let Some(ref peer_mac) = peer_msg.key_confirmation else {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::Spake2Failed);
        };
        if peer_mac.len() != SPAKE2_CONFIRM_MAC_LEN {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::Spake2Failed);
        }
        let Some(output) = self.spake_output.take() else {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "missing SPAKE2 acceptor output",
            ));
        };
        output.verify_peer_confirmation(peer_mac).map_err(|_| {
            self.stage = PairingStage::Failed;
            SecurityError::Spake2Failed
        })?;
        if output.confirmation_mac.len() != SPAKE2_CONFIRM_MAC_LEN {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::Spake2Failed);
        }
        let reply_mac = output.confirmation_mac.clone();
        drop(output.into_session_key());
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
        local_id: DeviceId,
        qr_store: &QrTokenStore,
        qr_auth: &PairQrAuth,
        now_unix: u64,
    ) -> Result<(), SecurityError> {
        if self.stage != PairingStage::Init
            || self.auth_mode != AuthMode::QrOutOfBand
            || self.qr_consumed
        {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "QR pairing permitted once in Init/QrOutOfBand state",
            ));
        }
        self.qr_consumed = true;
        if qr_auth.pairing_attempt_id != self.pairing_attempt_id {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "PairQrAuth attempt id mismatch",
            ));
        }
        let token_arr: [u8; OPAQUE_TOKEN_LEN] = qr_auth
            .one_time_pairing_token
            .as_slice()
            .try_into()
            .map_err(|_| {
                self.stage = PairingStage::Failed;
                SecurityError::QrPairingInvalid("QR token length must be 32 bytes")
            })?;

        let signing_msg = build_qr_auth_signing_message(
            &self.channel_binding,
            self.pairing_attempt_id,
            self.peer_identity.device_id(),
            local_id,
            &token_arr,
        );
        self.peer_identity
            .verify_strict(&signing_msg, &qr_auth.initiator_signature)
            .inspect_err(|_| {
                self.stage = PairingStage::Failed;
            })?;

        qr_store
            .consume_once(&token_arr, local_id, now_unix)
            .inspect_err(|_| {
                self.stage = PairingStage::Failed;
            })?;

        self.stage = PairingStage::AwaitingApproval;
        Ok(())
    }

    /// Finalize pairing ONLY after explicit [`HumanApprovalDecision`]; rejects input perms cleanly.
    pub fn apply_human_approval(
        &mut self,
        local_identity: &IdentityKeyPair,
        decision: HumanApprovalDecision,
    ) -> Result<PairConfirm, SecurityError> {
        if self.stage != PairingStage::AwaitingApproval {
            self.stage = PairingStage::Failed;
            return Err(SecurityError::PairingState(
                "human approval requires AwaitingApproval stage",
            ));
        }
        match decision {
            HumanApprovalDecision::Reject => {
                self.stage = PairingStage::Failed;
                Ok(PairConfirm {
                    pairing_attempt_id: self.pairing_attempt_id,
                    accepted: false,
                    granted_base_perms: Permissions::NONE,
                    confirm_signature: None,
                })
            }
            HumanApprovalDecision::Approve { granted_base_perms } => {
                if granted_base_perms.has_any_input() {
                    self.stage = PairingStage::Failed;
                    return Err(SecurityError::AuthorizationDenied(
                        "initial pairing cannot grant remote input permissions",
                    ));
                }
                let msg = build_pair_confirm_signing_message(
                    &self.channel_binding,
                    self.pairing_attempt_id,
                    self.peer_identity.device_id(),
                    local_identity.device_id(),
                    granted_base_perms,
                );
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

fn validate_uncompressed_p256_share(share: &[u8]) -> Result<(), SecurityError> {
    if share.len() != SPAKE2_P256_PUBLIC_SHARE_LEN || share[0] != 0x04 {
        return Err(SecurityError::Spake2Failed);
    }
    Ok(())
}
