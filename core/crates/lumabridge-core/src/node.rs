// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! End-to-end `LumaBridgeNode` orchestrator unifying `lumabridge-protocol`, `lumabridge-security`,
//! and `lumabridge-transport` for Phase 1 SPAKE2/QR pairing, Phase 2 mTLS sessions, adaptive GOP
//! recovery, `ProtectedBlank` signaling, default-deny input authorization, and live revocation.

use crate::telemetry::{ClockSyncTracker, LatencyPercentileTracker, SessionTelemetrySummary};
use core::fmt;
use lumabridge_protocol::control::{
    ActiveDisplayConfig, AuthMode, CloseReasonCode, ControlMessage, DisplayFrameCursor,
    DisplayRequest, InputBatch, MediaFeedback, NodeCapabilities, PairCancel, PairCancelReason,
    PairHello, PermissionUpdate, PermissionUpgradeRequest, Permissions, SessionClose,
    SessionOpenRequest, SessionOpenResponse, SessionOpenStatus, SessionResumeResponse,
};
use lumabridge_protocol::media::fragmentation::FrameKind;
use lumabridge_protocol::media::reassembly::{ProtectedBlankEvent, ReassembledFrame};
use lumabridge_protocol::version::{LBWP_PROTOCOL_MAJOR, LBWP_PROTOCOL_MINOR};
use lumabridge_security::authorization::{
    apply_input_elevation, authorize_action, authorize_session_open, begin_permission_upgrade,
    AuthorizationPolicyContext, InputApprovalDecision, PendingPermissionUpgrade, SessionGrant,
};
use lumabridge_security::certificate::{
    generate_self_signed_device_cert, GeneratedDeviceCertificate,
};
use lumabridge_security::error::SecurityError;
use lumabridge_security::identity::{DeviceId, IdentityKeyPair, PeerRole, PublicIdentity};
use lumabridge_security::pairing::{
    HumanApprovalDecision, PairingAcceptor, PairingApprovalPrompt, PairingInitiator,
    PinPairingWindow, QrPairingTicket, QrTokenStore,
};
use lumabridge_security::rate_limit::AuthRateLimiter;
use lumabridge_security::secret::{CheckedOsCryptoRng, PinSecret, ResumeTokenSecret};
use lumabridge_security::session_token::{
    revoke_peer_and_sessions, RevocationOutcome, SessionTokenManager,
};
use lumabridge_security::tls::{TlsPeerTrustPolicy, LUMABRIDGE_ALPN_V1, LUMABRIDGE_PAIR_ALPN_V1};
use lumabridge_security::trust_store::{
    InMemoryTrustStore, RevocationReason, TrustStore, TrustedPeerRecord,
};
use lumabridge_transport::config::{TransportConfig, TransportKind};
use lumabridge_transport::connection::{
    connect_client_link, ConnectionRegistry, MediaRxEvent, NegotiatedSessionInfo,
    OperationalConnection, PairingConnection, PeerTransportLink, TransportServer,
};
use lumabridge_transport::error::TransportError;
use lumabridge_transport::queue::{EnqueueOutcome, OutboundVideoFrame};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Privacy-sanitized errors emitted by [`LumaBridgeNode`] and [`ActiveNodeSession`].
#[derive(Debug)]
pub enum NodeError {
    Security(SecurityError),
    Transport(TransportError),
    InvalidConfig(&'static str),
    Protocol(&'static str),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Security(e) => write!(f, "node security failure: {e}"),
            Self::Transport(e) => write!(f, "node transport failure: {e}"),
            Self::InvalidConfig(msg) => write!(f, "invalid node config: {msg}"),
            Self::Protocol(msg) => write!(f, "node protocol failure: {msg}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<SecurityError> for NodeError {
    fn from(value: SecurityError) -> Self {
        Self::Security(value)
    }
}

impl From<TransportError> for NodeError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

/// Configuration constructing a [`LumaBridgeNode`].
#[derive(Clone)]
pub struct NodeConfig {
    pub friendly_name: String,
    pub role: PeerRole,
    pub capabilities: NodeCapabilities,
    pub transport_config: TransportConfig,
    pub policy_ctx: AuthorizationPolicyContext,
    pub session_ttl_secs: u64,
    pub resume_ttl_secs: u64,
    pub max_connections: usize,
}

impl NodeConfig {
    pub fn validate(&self) -> Result<(), NodeError> {
        if self.friendly_name.is_empty() || self.friendly_name.len() > 48 {
            return Err(NodeError::InvalidConfig(
                "friendly_name length must be within 1..=48 bytes",
            ));
        }
        if self.session_ttl_secs == 0 || self.session_ttl_secs > 86_400 {
            return Err(NodeError::InvalidConfig(
                "session_ttl_secs must be within 1..=86400",
            ));
        }
        if self.resume_ttl_secs == 0 || self.resume_ttl_secs > 900 {
            return Err(NodeError::InvalidConfig(
                "resume_ttl_secs must be within 1..=900",
            ));
        }
        if self.max_connections == 0 {
            return Err(NodeError::InvalidConfig("max_connections must be non-zero"));
        }
        self.transport_config.validate()?;
        Ok(())
    }
}

/// Media/feedback event delivered from [`ActiveNodeSession::poll_media_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeMediaEvent {
    Frame(ReassembledFrame),
    ProtectedBlank(ProtectedBlankEvent),
    ForceIdrRequested(MediaFeedback),
    DroppedDependentFrames(usize),
    SessionRenewalRequired,
}

/// Control/feedback/input event processed by [`ActiveNodeSession::poll_next_control_or_feedback_or_input`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeSignalEvent {
    RemoteForceIdr {
        display_id: u16,
        broken_gop_id: Option<u16>,
    },
    InputAccepted {
        display_id: u16,
        input_seq: u64,
        accepted_events: usize,
    },
    InputDenied {
        display_id: u16,
        input_seq: u64,
        dropped_events: usize,
    },
    PermissionUpgradeRequested {
        session_id: u64,
        request_seq: u64,
        requested_perms: Permissions,
    },
    PermissionUpdated(PermissionUpdate),
    ClockSyncUpdated {
        rtt_us: u64,
        offset_us: i64,
    },
    ClockSyncReplied {
        seq: u64,
    },
    HeartbeatReceived {
        seq: u64,
        uptime_ms: u64,
    },
    SessionClosed(SessionClose),
}

/// Shared operational node holding identity, cert, live `TrustStore`, session authority,
/// active connection registry, and rate limiter.
pub struct LumaBridgeNode {
    config: NodeConfig,
    identity: IdentityKeyPair,
    cert: GeneratedDeviceCertificate,
    trust_store: Arc<InMemoryTrustStore>,
    session_mgr: Arc<SessionTokenManager>,
    registry: ConnectionRegistry,
    rate_limiter: Arc<AuthRateLimiter>,
}

impl LumaBridgeNode {
    /// Generate a fresh Ed25519 node identity and self-signed X.509 v3 certificate.
    pub fn generate(
        config: NodeConfig,
        rng: &mut CheckedOsCryptoRng,
        now_unix: u64,
        cert_ttl_secs: u64,
    ) -> Result<Self, NodeError> {
        config.validate()?;
        if cert_ttl_secs == 0 {
            return Err(NodeError::InvalidConfig("cert_ttl_secs must be non-zero"));
        }
        let not_after = now_unix
            .checked_add(cert_ttl_secs)
            .ok_or(NodeError::InvalidConfig("certificate expiry overflow"))?;
        let identity = IdentityKeyPair::generate(rng)?;
        let cert = generate_self_signed_device_cert(&identity, now_unix, not_after)?;
        let registry = ConnectionRegistry::new(config.max_connections);
        Ok(Self {
            config,
            identity,
            cert,
            trust_store: Arc::new(InMemoryTrustStore::new()),
            session_mgr: Arc::new(SessionTokenManager::new()),
            registry,
            rate_limiter: Arc::new(AuthRateLimiter::default()),
        })
    }

    #[must_use]
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.identity.device_id()
    }

    #[must_use]
    pub fn public_identity(&self) -> &PublicIdentity {
        self.identity.public_identity()
    }

    #[must_use]
    pub fn cert(&self) -> &GeneratedDeviceCertificate {
        &self.cert
    }

    #[must_use]
    pub fn trust_store(&self) -> &Arc<InMemoryTrustStore> {
        &self.trust_store
    }

    #[must_use]
    pub fn session_manager(&self) -> &Arc<SessionTokenManager> {
        &self.session_mgr
    }

    #[must_use]
    pub fn connection_registry(&self) -> &ConnectionRegistry {
        &self.registry
    }

    #[must_use]
    pub fn pairing_trust_policy(&self) -> TlsPeerTrustPolicy {
        let store: Arc<dyn TrustStore> = self.trust_store.clone();
        TlsPeerTrustPolicy::Pairing { trust_store: store }
    }

    #[must_use]
    pub fn operational_server_trust_policy(&self) -> TlsPeerTrustPolicy {
        let store: Arc<dyn TrustStore> = self.trust_store.clone();
        TlsPeerTrustPolicy::Trusted {
            trust_store: store,
            expected_role: self.config.role.opposite(),
        }
    }

    #[must_use]
    pub fn operational_pinned_trust_policy(&self, peer_device_id: DeviceId) -> TlsPeerTrustPolicy {
        let store: Arc<dyn TrustStore> = self.trust_store.clone();
        TlsPeerTrustPolicy::PinnedPeer {
            trust_store: store,
            expected_role: self.config.role.opposite(),
            expected_device_id: peer_device_id,
        }
    }

    /// Bind an operational or pairing server on `bind_addr`.
    pub async fn bind_server(
        &self,
        kind: TransportKind,
        bind_addr: SocketAddr,
        pairing_mode: bool,
    ) -> Result<TransportServer, NodeError> {
        let policy = if pairing_mode {
            self.pairing_trust_policy()
        } else {
            self.operational_server_trust_policy()
        };
        Ok(TransportServer::bind(
            kind,
            bind_addr,
            &self.cert,
            policy,
            self.config.transport_config.clone(),
        )
        .await?)
    }

    /// Execute Phase 1 pairing acceptor flow (`ALPN "lumabridge-pair/1"`) supporting both
    /// channel-bound SPAKE2-P256 and single-use QR tokens, requiring explicit `consent_cb`.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn accept_pairing_over_link<F>(
        &self,
        link: PeerTransportLink,
        pin_window: Option<&PinPairingWindow>,
        qr_store: Option<&QrTokenStore>,
        now_unix: u64,
        now_mono_ms: u64,
        consent_cb: F,
    ) -> Result<TrustedPeerRecord, NodeError>
    where
        F: FnOnce(&PairingApprovalPrompt) -> HumanApprovalDecision,
    {
        let conn = PairingConnection::from_link(link, self.config.transport_config.clone(), false)?;
        let peer_tls_id = conn.tls_session().peer_identity().device_id();
        if self.trust_store.is_revoked(peer_tls_id) {
            conn.close();
            return Err(NodeError::Security(SecurityError::RevokedDevice));
        }
        if let Err(err) = self.rate_limiter.check_allowed(peer_tls_id, now_mono_ms) {
            conn.close();
            return Err(NodeError::Security(err));
        }

        let res = self
            .accept_pairing_inner(
                &conn,
                pin_window,
                qr_store,
                now_unix,
                now_mono_ms,
                consent_cb,
            )
            .await;
        match res {
            Ok(rec) => {
                let _ = self.rate_limiter.record_success(peer_tls_id);
                conn.close();
                Ok(rec)
            }
            Err(err) => {
                let _ = self.rate_limiter.record_failure(peer_tls_id, now_mono_ms);
                conn.close();
                Err(err)
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn accept_pairing_inner<F>(
        &self,
        conn: &PairingConnection,
        pin_window: Option<&PinPairingWindow>,
        qr_store: Option<&QrTokenStore>,
        now_unix: u64,
        now_mono_ms: u64,
        consent_cb: F,
    ) -> Result<TrustedPeerRecord, NodeError>
    where
        F: FnOnce(&PairingApprovalPrompt) -> HumanApprovalDecision,
    {
        let ControlMessage::PairHello(peer_hello) = conn.recv_pairing_message().await? else {
            return Err(NodeError::Protocol("expected PairHello on pairing channel"));
        };
        let local_hello = ControlMessage::PairHello(PairHello {
            protocol_major: LBWP_PROTOCOL_MAJOR,
            protocol_minor: LBWP_PROTOCOL_MINOR,
            auth_mode: peer_hello.auth_mode,
            device_id: *self.identity.device_id().as_bytes(),
            spki_ed25519: self.identity.public_identity().spki_der().to_vec(),
            friendly_name: self.config.friendly_name.clone(),
        });
        conn.send_pairing_message(&local_hello).await?;

        let first_auth = conn.recv_pairing_message().await?;
        let attempt_id = match &first_auth {
            ControlMessage::PairSpakeMsg(m) => m.pairing_attempt_id,
            ControlMessage::PairQrAuth(m) => m.pairing_attempt_id,
            _ => {
                return Err(NodeError::Protocol(
                    "expected PairSpakeMsg or PairQrAuth after PairHello",
                ));
            }
        };

        let expected_peer_epoch = self
            .trust_store
            .peer_epoch(conn.tls_session().peer_identity().device_id());
        let mut acceptor = PairingAcceptor::start_with_expected_peer_epoch(
            attempt_id,
            &self.identity,
            self.config.role,
            &peer_hello,
            conn.tls_session(),
            expected_peer_epoch,
        )?;

        let mut completion_unix = now_unix;
        match (peer_hello.auth_mode, first_auth) {
            (AuthMode::PinSpake2, ControlMessage::PairSpakeMsg(p_a)) => {
                let Some(win) = pin_window else {
                    return Err(NodeError::Security(SecurityError::PairingState(
                        "PIN pairing window closed",
                    )));
                };
                let mut rng = CheckedOsCryptoRng::preflight()?;
                let attempt_start = std::time::Instant::now();
                let pin_reserve_mono_secs = now_mono_ms / 1_000;
                let p_b =
                    acceptor.handle_spake2_exchange(win, &p_a, pin_reserve_mono_secs, &mut rng)?;
                conn.send_pairing_message(&ControlMessage::PairSpakeMsg(p_b))
                    .await?;
                let ControlMessage::PairSpakeMsg(c_a) = conn.recv_pairing_message().await? else {
                    return Err(NodeError::Protocol("expected PairSpakeMsg KeyConfirmation"));
                };
                let elapsed_secs = attempt_start.elapsed().as_secs();
                completion_unix = now_unix.saturating_add(elapsed_secs);
                let pin_confirm_mono_secs = pin_reserve_mono_secs.saturating_add(elapsed_secs);
                match acceptor.verify_spake2_confirmation_and_reply(&c_a, pin_confirm_mono_secs) {
                    Ok(c_b) => {
                        conn.send_pairing_message(&ControlMessage::PairSpakeMsg(c_b))
                            .await?;
                    }
                    Err(err) => {
                        let _ = conn
                            .send_pairing_message(&ControlMessage::PairCancel(PairCancel {
                                pairing_attempt_id: Some(attempt_id),
                                reason_code: PairCancelReason::ProtocolError,
                                detail_ascii: None,
                            }))
                            .await;
                        conn.flush().await;
                        return Err(NodeError::Security(err));
                    }
                }
            }
            (AuthMode::QrOutOfBand, ControlMessage::PairQrAuth(qr_auth)) => {
                let Some(store) = qr_store else {
                    return Err(NodeError::Security(SecurityError::QrTokenReusedOrUnknown));
                };
                if let Err(err) = acceptor.verify_qr_auth(store, &qr_auth, now_unix) {
                    let _ = conn
                        .send_pairing_message(&ControlMessage::PairCancel(PairCancel {
                            pairing_attempt_id: Some(attempt_id),
                            reason_code: PairCancelReason::ProtocolError,
                            detail_ascii: None,
                        }))
                        .await;
                    conn.flush().await;
                    return Err(NodeError::Security(err));
                }
            }
            _ => {
                return Err(NodeError::Protocol("pairing auth_mode/message mismatch"));
            }
        }

        let prompt = acceptor.approval_prompt()?;
        let decision = consent_cb(&prompt);
        let confirm = acceptor.apply_human_approval(&self.identity, decision)?;
        let accepted = confirm.accepted;
        conn.send_pairing_message(&ControlMessage::PairConfirm(confirm))
            .await?;
        conn.flush().await;
        if !accepted {
            return Err(NodeError::Security(SecurityError::ApprovalRequired));
        }
        let commit = acceptor.approved_commit()?;
        let rec = self
            .trust_store
            .insert_approved_pairing(commit, completion_unix)?;
        Ok(rec)
    }

    /// Execute Phase 1 SPAKE2 PIN pairing as initiator (`ALPN "lumabridge-pair/1"`).
    pub async fn pair_with_pin<F>(
        &self,
        kind: TransportKind,
        remote: SocketAddr,
        server_hint: DeviceId,
        pin: &PinSecret,
        now_unix: u64,
        consent_cb: F,
    ) -> Result<TrustedPeerRecord, NodeError>
    where
        F: FnOnce(&PairingApprovalPrompt) -> HumanApprovalDecision,
    {
        let link = connect_client_link(
            kind,
            remote,
            &self.cert,
            self.pairing_trust_policy(),
            server_hint,
            LUMABRIDGE_PAIR_ALPN_V1,
            now_unix,
            &self.config.transport_config,
        )
        .await?;
        let conn = PairingConnection::from_link(link, self.config.transport_config.clone(), true)?;

        let mut rng = CheckedOsCryptoRng::preflight()?;
        let mut attempt_bytes = [0u8; 8];
        rng.fill_bytes(&mut attempt_bytes)?;
        let attempt_id = u64::from_be_bytes(attempt_bytes).max(1);

        let hello = ControlMessage::PairHello(PairHello {
            protocol_major: LBWP_PROTOCOL_MAJOR,
            protocol_minor: LBWP_PROTOCOL_MINOR,
            auth_mode: AuthMode::PinSpake2,
            device_id: *self.identity.device_id().as_bytes(),
            spki_ed25519: self.identity.public_identity().spki_der().to_vec(),
            friendly_name: self.config.friendly_name.clone(),
        });
        conn.send_pairing_message(&hello).await?;

        let ControlMessage::PairHello(peer_hello) = conn.recv_pairing_message().await? else {
            conn.close();
            return Err(NodeError::Protocol("expected acceptor PairHello"));
        };
        let expected_peer_epoch = self
            .trust_store
            .peer_epoch(conn.tls_session().peer_identity().device_id());
        let mut init = PairingInitiator::start_with_expected_peer_epoch(
            attempt_id,
            &self.identity,
            self.config.role,
            &peer_hello,
            conn.tls_session(),
            AuthMode::PinSpake2,
            expected_peer_epoch,
        )?;
        let p_a = init.begin_spake2(pin, &mut rng)?;
        conn.send_pairing_message(&ControlMessage::PairSpakeMsg(p_a))
            .await?;

        let p_b = match conn.recv_pairing_message().await? {
            ControlMessage::PairSpakeMsg(msg) => msg,
            ControlMessage::PairCancel(_) => {
                conn.close();
                return Err(NodeError::Security(SecurityError::Spake2Failed));
            }
            _ => {
                conn.close();
                return Err(NodeError::Protocol("expected acceptor PairSpakeMsg"));
            }
        };
        let c_a = init.finish_spake2_and_emit_confirmation(&p_b)?;
        conn.send_pairing_message(&ControlMessage::PairSpakeMsg(c_a))
            .await?;

        let c_b = match conn.recv_pairing_message().await? {
            ControlMessage::PairSpakeMsg(msg) => msg,
            ControlMessage::PairCancel(_) => {
                conn.close();
                return Err(NodeError::Security(SecurityError::Spake2Failed));
            }
            _ => {
                conn.close();
                return Err(NodeError::Protocol("expected acceptor KeyConfirmation"));
            }
        };
        init.verify_spake2_peer_confirmation(&c_b)?;

        let ControlMessage::PairConfirm(confirm) = conn.recv_pairing_message().await? else {
            conn.close();
            return Err(NodeError::Protocol("expected PairConfirm"));
        };
        let _offered = init.verify_pair_confirm(&confirm)?;
        let prompt = init.approval_prompt()?;
        let decision = consent_cb(&prompt);
        let commit = init.apply_local_approval(decision)?;
        let rec = self.trust_store.insert_approved_pairing(commit, now_unix)?;
        conn.close();
        Ok(rec)
    }

    /// Execute Phase 1 out-of-band QR pairing as initiator, strictly verifying acceptor SPKI
    /// BEFORE transmitting `PairQrAuth` credentials.
    pub async fn pair_with_qr<F>(
        &self,
        kind: TransportKind,
        remote: SocketAddr,
        ticket: &QrPairingTicket,
        now_unix: u64,
        consent_cb: F,
    ) -> Result<TrustedPeerRecord, NodeError>
    where
        F: FnOnce(&PairingApprovalPrompt) -> HumanApprovalDecision,
    {
        let link = connect_client_link(
            kind,
            remote,
            &self.cert,
            self.pairing_trust_policy(),
            ticket.acceptor_device_id,
            LUMABRIDGE_PAIR_ALPN_V1,
            now_unix,
            &self.config.transport_config,
        )
        .await?;
        let conn = PairingConnection::from_link(link, self.config.transport_config.clone(), true)?;

        // Anti-MITM invariant: assert TLS peer SPKI matches out-of-band QR ticket BEFORE sending PairHello/PairQrAuth!
        if conn.tls_session().peer_identity().device_id() != ticket.acceptor_device_id {
            conn.close();
            return Err(NodeError::Security(SecurityError::IdentityMismatch(
                "TLS acceptor certificate does not match QR ticket SPKI",
            )));
        }

        let mut rng = CheckedOsCryptoRng::preflight()?;
        let mut attempt_bytes = [0u8; 8];
        rng.fill_bytes(&mut attempt_bytes)?;
        let attempt_id = u64::from_be_bytes(attempt_bytes).max(1);

        let hello = ControlMessage::PairHello(PairHello {
            protocol_major: LBWP_PROTOCOL_MAJOR,
            protocol_minor: LBWP_PROTOCOL_MINOR,
            auth_mode: AuthMode::QrOutOfBand,
            device_id: *self.identity.device_id().as_bytes(),
            spki_ed25519: self.identity.public_identity().spki_der().to_vec(),
            friendly_name: self.config.friendly_name.clone(),
        });
        conn.send_pairing_message(&hello).await?;

        let ControlMessage::PairHello(peer_hello) = conn.recv_pairing_message().await? else {
            conn.close();
            return Err(NodeError::Protocol("expected acceptor PairHello"));
        };
        let expected_peer_epoch = self
            .trust_store
            .peer_epoch(conn.tls_session().peer_identity().device_id());
        let mut init = PairingInitiator::start_with_expected_peer_epoch(
            attempt_id,
            &self.identity,
            self.config.role,
            &peer_hello,
            conn.tls_session(),
            AuthMode::QrOutOfBand,
            expected_peer_epoch,
        )?;
        let qr_auth = init.create_qr_auth(&self.identity, ticket, now_unix)?;
        conn.send_pairing_message(&ControlMessage::PairQrAuth(qr_auth))
            .await?;

        let confirm = match conn.recv_pairing_message().await? {
            ControlMessage::PairConfirm(c) => c,
            ControlMessage::PairCancel(_) => {
                conn.close();
                return Err(NodeError::Security(SecurityError::QrTokenReusedOrUnknown));
            }
            _ => {
                conn.close();
                return Err(NodeError::Protocol("expected PairConfirm after PairQrAuth"));
            }
        };
        let _offered = init.verify_pair_confirm(&confirm)?;
        let prompt = init.approval_prompt()?;
        let decision = consent_cb(&prompt);
        let commit = init.apply_local_approval(decision)?;
        let rec = self.trust_store.insert_approved_pairing(commit, now_unix)?;
        conn.close();
        Ok(rec)
    }

    /// Accept and authenticate a Phase 2 mTLS operational session (`SessionOpenRequest` or `SessionResumeRequest`).
    #[allow(clippy::too_many_lines)]
    pub async fn accept_operational_session<F>(
        &self,
        link: PeerTransportLink,
        build_displays: F,
        now_unix: u64,
    ) -> Result<ActiveNodeSession, NodeError>
    where
        F: FnOnce(&[DisplayRequest], &NodeCapabilities) -> Vec<ActiveDisplayConfig>,
    {
        let expected_role = self.config.role.opposite();
        let mut conn = OperationalConnection::from_link_verified(
            link,
            self.config.transport_config.clone(),
            false,
            self.registry.clone(),
            self.trust_store.as_ref(),
            expected_role,
        )?;
        let info = conn
            .handshake_acceptor(
                self.identity.device_id(),
                self.trust_store.as_ref(),
                expected_role,
                self.config.capabilities.clone(),
            )
            .await?;

        let msg = conn.recv_control_message().await?;
        let transport_label = format!("{:?}", conn.transport_kind());
        let mut rng = CheckedOsCryptoRng::preflight()?;

        match msg {
            ControlMessage::SessionOpenRequest(req) => {
                let mut issued = self.session_mgr.issue_session(
                    &mut rng,
                    self.trust_store.as_ref(),
                    conn.tls_session(),
                    expected_role,
                    req.requested_perms,
                    now_unix,
                    self.config.session_ttl_secs,
                    self.config.resume_ttl_secs,
                )?;
                let grant = authorize_session_open(
                    self.trust_store.as_ref(),
                    conn.tls_session(),
                    expected_role,
                    req.requested_perms,
                    self.config.policy_ctx,
                    issued.session_id,
                    issued.session_expires_at_unix,
                )?;
                self.session_mgr
                    .update_session_permissions(issued.session_id, grant.session_granted_perms)?;
                issued.effective_permissions = grant.session_granted_perms;
                let active_displays = build_displays(&req.displays, &info.peer_capabilities);
                let resp = SessionOpenResponse {
                    status: SessionOpenStatus::Accepted,
                    session_id: issued.session_id,
                    resume_token: Some(issued.resume_token.expose_secret().to_vec()),
                    active_displays: active_displays.clone(),
                    granted_perms: grant.session_granted_perms,
                };
                conn.send_control_message(&ControlMessage::SessionOpenResponse(resp))
                    .await?;
                conn.set_active_session(issued.session_id, grant.session_granted_perms);

                Ok(ActiveNodeSession {
                    node_identity: self.identity.device_id(),
                    transport_kind: conn.transport_kind(),
                    conn,
                    info,
                    grant,
                    resume_token: Some(issued.resume_token),
                    active_displays,
                    trust_store: Arc::clone(&self.trust_store),
                    session_mgr: Arc::clone(&self.session_mgr),
                    policy_ctx: self.config.policy_ctx,
                    clock_sync: ClockSyncTracker::new(),
                    telemetry: LatencyPercentileTracker::new(transport_label),
                    next_update_seq: 1,
                })
            }
            ControlMessage::SessionResumeRequest(req) => {
                let displays = build_displays(&[], &info.peer_capabilities);
                let display_ids: Vec<u16> = displays.iter().map(|d| d.display_id).collect();
                let res = conn
                    .handle_session_resume(
                        &mut rng,
                        self.trust_store.as_ref(),
                        &self.session_mgr,
                        expected_role,
                        &req,
                        displays.clone(),
                        display_ids,
                        now_unix,
                        self.config.resume_ttl_secs,
                    )
                    .await?;
                let Some(validated) = res else {
                    return Err(NodeError::Security(SecurityError::SessionTokenInvalid(
                        "session resume rejected",
                    )));
                };
                let grant = authorize_session_open(
                    self.trust_store.as_ref(),
                    conn.tls_session(),
                    expected_role,
                    validated.effective_permissions,
                    self.config.policy_ctx,
                    validated.session_id,
                    validated.session_expires_at_unix,
                )?;
                self.session_mgr.update_session_permissions(
                    validated.session_id,
                    grant.session_granted_perms,
                )?;
                conn.set_active_session(validated.session_id, grant.session_granted_perms);
                Ok(ActiveNodeSession {
                    node_identity: self.identity.device_id(),
                    transport_kind: conn.transport_kind(),
                    conn,
                    info,
                    grant,
                    resume_token: Some(validated.rotated_resume_token),
                    active_displays: displays,
                    trust_store: Arc::clone(&self.trust_store),
                    session_mgr: Arc::clone(&self.session_mgr),
                    policy_ctx: self.config.policy_ctx,
                    clock_sync: ClockSyncTracker::new(),
                    telemetry: LatencyPercentileTracker::new(transport_label),
                    next_update_seq: 1,
                })
            }
            _ => Err(NodeError::Protocol(
                "expected SessionOpenRequest or SessionResumeRequest",
            )),
        }
    }

    /// Connect and open a Phase 2 mTLS operational session as initiator (`ALPN "lumabridge/1"`).
    pub async fn connect_operational_session(
        &self,
        kind: TransportKind,
        remote: SocketAddr,
        peer_device_id: DeviceId,
        displays: Vec<DisplayRequest>,
        requested_perms: Permissions,
        now_unix: u64,
    ) -> Result<ActiveNodeSession, NodeError> {
        let expected_role = self.config.role.opposite();
        let link = connect_client_link(
            kind,
            remote,
            &self.cert,
            self.operational_pinned_trust_policy(peer_device_id),
            peer_device_id,
            LUMABRIDGE_ALPN_V1,
            now_unix,
            &self.config.transport_config,
        )
        .await?;
        let mut conn = OperationalConnection::from_link_verified(
            link,
            self.config.transport_config.clone(),
            true,
            self.registry.clone(),
            self.trust_store.as_ref(),
            expected_role,
        )?;
        let info = conn
            .handshake_initiator(
                self.identity.device_id(),
                self.trust_store.as_ref(),
                expected_role,
                "0.1.0",
                self.config.capabilities.clone(),
            )
            .await?;

        let mut rng = CheckedOsCryptoRng::preflight()?;
        let mut sid_bytes = [0u8; 8];
        rng.fill_bytes(&mut sid_bytes)?;
        let proposed_session_id = u64::from_be_bytes(sid_bytes).max(1);
        let open_req = SessionOpenRequest {
            session_id: proposed_session_id,
            displays,
            requested_perms,
        };
        conn.send_control_message(&ControlMessage::SessionOpenRequest(open_req))
            .await?;
        let ControlMessage::SessionOpenResponse(resp) = conn.recv_control_message().await? else {
            return Err(NodeError::Protocol("expected SessionOpenResponse"));
        };
        if resp.status != SessionOpenStatus::Accepted {
            return Err(NodeError::Security(SecurityError::AuthorizationDenied(
                "session open rejected by peer",
            )));
        }
        let clamped_perms = info
            .granted_stored_perms
            .intersection(resp.granted_perms)
            .intersection(self.config.policy_ctx.local_policy)
            .intersection(self.config.policy_ctx.negotiated_caps);
        let grant = authorize_session_open(
            self.trust_store.as_ref(),
            conn.tls_session(),
            expected_role,
            clamped_perms,
            self.config.policy_ctx,
            resp.session_id,
            now_unix.saturating_add(self.config.session_ttl_secs),
        )?;
        let resume_token = resp
            .resume_token
            .as_deref()
            .and_then(|bytes| ResumeTokenSecret::from_slice(bytes).ok());
        conn.set_active_session(resp.session_id, grant.session_granted_perms);

        Ok(ActiveNodeSession {
            node_identity: self.identity.device_id(),
            transport_kind: conn.transport_kind(),
            conn,
            info,
            grant,
            resume_token,
            active_displays: resp.active_displays,
            trust_store: Arc::clone(&self.trust_store),
            session_mgr: Arc::clone(&self.session_mgr),
            policy_ctx: self.config.policy_ctx,
            clock_sync: ClockSyncTracker::new(),
            telemetry: LatencyPercentileTracker::new(format!("{kind:?}")),
            next_update_seq: 1,
        })
    }

    /// Reconnect and perform channel-bound `SessionResumeRequest` rotation on a new TLS link,
    /// returning both the live resumed [`ActiveNodeSession`] and the peer's [`SessionResumeResponse`].
    #[allow(clippy::too_many_arguments)]
    pub async fn resume_operational_session(
        &self,
        kind: TransportKind,
        remote: SocketAddr,
        peer_device_id: DeviceId,
        session_id: u64,
        resume_token: &ResumeTokenSecret,
        cursors: Vec<DisplayFrameCursor>,
        now_unix: u64,
    ) -> Result<(ActiveNodeSession, SessionResumeResponse), NodeError> {
        let expected_role = self.config.role.opposite();
        let rec = self
            .trust_store
            .get_peer(peer_device_id)
            .ok_or(NodeError::Security(SecurityError::UntrustedDevice))?;
        let link = connect_client_link(
            kind,
            remote,
            &self.cert,
            self.operational_pinned_trust_policy(peer_device_id),
            peer_device_id,
            LUMABRIDGE_ALPN_V1,
            now_unix,
            &self.config.transport_config,
        )
        .await?;
        let mut conn = OperationalConnection::from_link_verified(
            link,
            self.config.transport_config.clone(),
            true,
            self.registry.clone(),
            self.trust_store.as_ref(),
            expected_role,
        )?;
        let info = conn
            .handshake_initiator(
                self.identity.device_id(),
                self.trust_store.as_ref(),
                expected_role,
                "0.1.0",
                self.config.capabilities.clone(),
            )
            .await?;
        let resp = conn
            .resume_session_as_client(
                self.identity.device_id(),
                session_id,
                rec.trust_epoch,
                resume_token,
                cursors,
            )
            .await?;
        if !resp.accepted {
            return Err(NodeError::Security(SecurityError::SessionTokenInvalid(
                "session resume rejected by peer",
            )));
        }
        let grant = authorize_session_open(
            self.trust_store.as_ref(),
            conn.tls_session(),
            expected_role,
            rec.base_permissions,
            self.config.policy_ctx,
            resp.session_id,
            now_unix.saturating_add(self.config.session_ttl_secs),
        )?;
        let rotated = resp
            .rotated_resume_token
            .as_deref()
            .and_then(|bytes| ResumeTokenSecret::from_slice(bytes).ok());
        conn.set_active_session(resp.session_id, grant.session_granted_perms);
        let active_displays = resp.preserved_displays.clone();
        let session = ActiveNodeSession {
            node_identity: self.identity.device_id(),
            transport_kind: conn.transport_kind(),
            conn,
            info,
            grant,
            resume_token: rotated,
            active_displays,
            trust_store: Arc::clone(&self.trust_store),
            session_mgr: Arc::clone(&self.session_mgr),
            policy_ctx: self.config.policy_ctx,
            clock_sync: ClockSyncTracker::new(),
            telemetry: LatencyPercentileTracker::new(format!("{kind:?}")),
            next_update_seq: 1,
        };
        Ok((session, resp))
    }

    /// Revoke a peer monotonically in `TrustStore`, invalidate tokens in `SessionTokenManager`,
    /// and immediately disconnect all active QUIC/TCP sessions registered for that `DeviceId`.
    pub fn revoke_peer(
        &self,
        peer_device_id: DeviceId,
        reason: RevocationReason,
        now_unix: u64,
    ) -> Result<(RevocationOutcome, usize), NodeError> {
        let outcome = revoke_peer_and_sessions(
            self.trust_store.as_ref(),
            &self.session_mgr,
            peer_device_id,
            reason,
            now_unix,
        )?;
        let mut closed = 0usize;
        for act in &outcome.actions {
            closed = closed.saturating_add(self.registry.apply_security_action(act));
        }
        Ok((outcome, closed))
    }
}

/// Live authenticated session runtime uniting `OperationalConnection`, `SessionGrant`,
/// `ClockSyncTracker`, `LatencyPercentileTracker`, and live `authorize_action` checks.
pub struct ActiveNodeSession {
    node_identity: DeviceId,
    transport_kind: TransportKind,
    conn: OperationalConnection,
    info: NegotiatedSessionInfo,
    grant: SessionGrant,
    resume_token: Option<ResumeTokenSecret>,
    active_displays: Vec<ActiveDisplayConfig>,
    trust_store: Arc<InMemoryTrustStore>,
    session_mgr: Arc<SessionTokenManager>,
    policy_ctx: AuthorizationPolicyContext,
    clock_sync: ClockSyncTracker,
    telemetry: LatencyPercentileTracker,
    next_update_seq: u64,
}

impl ActiveNodeSession {
    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.grant.session_id
    }

    #[must_use]
    pub const fn node_identity(&self) -> DeviceId {
        self.node_identity
    }

    #[must_use]
    pub const fn transport_kind(&self) -> TransportKind {
        self.transport_kind
    }

    #[must_use]
    pub const fn negotiated_info(&self) -> &NegotiatedSessionInfo {
        &self.info
    }

    #[must_use]
    pub const fn grant(&self) -> &SessionGrant {
        &self.grant
    }

    #[must_use]
    pub const fn resume_token(&self) -> Option<&ResumeTokenSecret> {
        self.resume_token.as_ref()
    }

    #[must_use]
    pub fn active_displays(&self) -> &[ActiveDisplayConfig] {
        &self.active_displays
    }

    #[must_use]
    pub fn telemetry_summary(&self) -> SessionTelemetrySummary {
        self.telemetry.summary()
    }

    /// Transmit an encoded frame, updating TX telemetry and signaling `EnqueueOutcome`.
    pub async fn send_encoded_frame(
        &mut self,
        frame: OutboundVideoFrame,
    ) -> Result<EnqueueOutcome, NodeError> {
        let is_blank = matches!(frame.kind, FrameKind::ProtectedBlank);
        let outcome = self.conn.send_video_frame(frame).await?;
        if is_blank {
            self.telemetry.protected_blanks = self.telemetry.protected_blanks.saturating_add(1);
        } else if outcome.admitted {
            self.telemetry.frames_sent = self.telemetry.frames_sent.saturating_add(1);
        }
        self.telemetry.dropped_frames = self.telemetry.dropped_frames.saturating_add(
            u64::try_from(
                outcome
                    .dropped_stale_frames
                    .saturating_add(outcome.dropped_broken_gop_frames),
            )
            .unwrap_or(u64::MAX),
        );
        Ok(outcome)
    }

    /// Send mandatory reliable `ProtectedBlank` on `Channel 1`.
    pub async fn send_protected_blank(
        &mut self,
        display_id: u16,
        frame_id: u32,
        gop_id: u16,
        ts_us: u64,
    ) -> Result<EnqueueOutcome, NodeError> {
        self.send_encoded_frame(OutboundVideoFrame {
            session_id: self.grant.session_id,
            display_id,
            codec_id: lumabridge_protocol::version::CodecId::H264,
            frame_id,
            gop_id,
            capture_ts_us: ts_us,
            encode_done_ts_us: ts_us,
            kind: FrameKind::ProtectedBlank,
            has_codec_config: false,
            mirror_source: false,
            payload: Vec::new(),
        })
        .await
    }

    /// Poll `OperationalConnection::recv_media_event` and update receiver latency/loss counters.
    pub async fn poll_media_event(
        &mut self,
        timeout: Duration,
        local_now_us: u64,
    ) -> Result<Option<NodeMediaEvent>, NodeError> {
        match self.conn.recv_media_event(timeout).await? {
            None => Ok(None),
            Some(MediaRxEvent::Frame(f)) => {
                self.telemetry.frames_delivered = self.telemetry.frames_delivered.saturating_add(1);
                let encode_us = f.encode_done_ts_us.saturating_sub(f.capture_ts_us);
                let net_us = local_now_us.saturating_sub(f.encode_done_ts_us);
                self.telemetry
                    .record_stage_latencies(0, encode_us, net_us, 0, 0);
                Ok(Some(NodeMediaEvent::Frame(f)))
            }
            Some(MediaRxEvent::ProtectedBlank(b)) => {
                self.telemetry.protected_blanks = self.telemetry.protected_blanks.saturating_add(1);
                Ok(Some(NodeMediaEvent::ProtectedBlank(b)))
            }
            Some(MediaRxEvent::FeedbackRequested(fb)) => {
                if fb.request_idr {
                    self.telemetry.idr_requests = self.telemetry.idr_requests.saturating_add(1);
                }
                Ok(Some(NodeMediaEvent::ForceIdrRequested(fb)))
            }
            Some(MediaRxEvent::DroppedDependentFrames(n)) => {
                self.telemetry.dropped_frames = self
                    .telemetry
                    .dropped_frames
                    .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                Ok(Some(NodeMediaEvent::DroppedDependentFrames(n)))
            }
            Some(MediaRxEvent::SessionRenewalRequired) => {
                Ok(Some(NodeMediaEvent::SessionRenewalRequired))
            }
        }
    }

    /// Send a `ClockSyncPing` and record `t1_us` in `ClockSyncTracker`.
    pub async fn send_clock_sync_ping(&mut self, seq: u64, t1_us: u64) -> Result<(), NodeError> {
        self.clock_sync.record_ping(seq, t1_us);
        self.conn
            .send_feedback_message(&ControlMessage::ClockSyncPing(
                lumabridge_protocol::control::ClockSyncPing {
                    seq,
                    t1_client_mono_us: t1_us,
                },
            ))
            .await?;
        Ok(())
    }

    /// Send an authorized `InputBatch` only if live `TrustStore` peer is non-revoked (`trust_epoch`
    /// unchanged) AND current granted session permissions permit all event modalities.
    pub async fn send_input_batch(
        &mut self,
        batch: &InputBatch,
        now_unix: u64,
    ) -> Result<(), NodeError> {
        let mut required = Permissions::NONE;
        for ev in &batch.events {
            required = required.union(ev.required_permission());
        }
        let rec = self.trust_store.verify_trusted_peer(
            self.conn.tls_session().peer_identity(),
            self.grant.expected_role,
        )?;
        if rec.device_id != self.grant.peer_device_id || rec.trust_epoch != self.grant.trust_epoch {
            return Err(NodeError::Security(SecurityError::RevokedDevice));
        }
        if now_unix > self.grant.expires_at_unix {
            return Err(NodeError::Security(SecurityError::SessionTokenInvalid(
                "session grant expired",
            )));
        }
        let allowed = self
            .policy_ctx
            .local_policy
            .intersection(self.policy_ctx.negotiated_caps)
            .intersection(self.grant.session_granted_perms);
        if !allowed.contains(required) {
            return Err(NodeError::Security(SecurityError::AuthorizationDenied(
                "required input permission not granted for outbound session",
            )));
        }
        self.conn
            .send_input_message(&ControlMessage::InputBatch(batch.clone()))
            .await?;
        Ok(())
    }

    /// Evaluate and send a local `PermissionUpgradeRequest` response (`apply_input_elevation`)
    /// after local human consent (`consent_cb`).
    pub async fn handle_permission_upgrade_request<F>(
        &mut self,
        req: &PermissionUpgradeRequest,
        now_unix: u64,
        consent_cb: F,
    ) -> Result<Permissions, NodeError>
    where
        F: FnOnce(&PendingPermissionUpgrade) -> InputApprovalDecision,
    {
        if req.session_id != self.grant.session_id {
            return Err(NodeError::Protocol(
                "PermissionUpgradeRequest session_id mismatch",
            ));
        }
        let pending = begin_permission_upgrade(
            self.trust_store.as_ref(),
            self.conn.tls_session(),
            &self.grant,
            req.request_seq,
            req.requested_perms,
            now_unix,
        )?;
        let decision = consent_cb(&pending);
        let new_perms = apply_input_elevation(
            self.trust_store.as_ref(),
            self.conn.tls_session(),
            &mut self.grant,
            pending,
            decision,
            self.policy_ctx,
            now_unix,
        )?;
        self.conn.set_effective_perms(new_perms);
        let _ = self
            .session_mgr
            .update_session_permissions(self.grant.session_id, new_perms);
        let update_seq = self.next_update_seq;
        self.next_update_seq = self.next_update_seq.saturating_add(1);
        self.conn
            .send_control_message(&ControlMessage::PermissionUpdate(PermissionUpdate {
                session_id: self.grant.session_id,
                update_seq,
                effective_perms: new_perms,
            }))
            .await?;
        Ok(new_perms)
    }

    /// Process a received `InputBatch` with default-deny 5-factor live verification (`authorize_action`).
    pub fn evaluate_inbound_input(&mut self, batch: &InputBatch, now_unix: u64) -> NodeSignalEvent {
        if batch.session_id != self.grant.session_id {
            self.telemetry.unauthorized_input_drops = self
                .telemetry
                .unauthorized_input_drops
                .saturating_add(u64::try_from(batch.events.len()).unwrap_or(u64::MAX));
            return NodeSignalEvent::InputDenied {
                display_id: batch.display_id,
                input_seq: batch.input_seq,
                dropped_events: batch.events.len(),
            };
        }
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for ev in &batch.events {
            if authorize_action(
                self.trust_store.as_ref(),
                self.conn.tls_session(),
                &self.grant,
                self.policy_ctx,
                ev.required_permission(),
                now_unix,
            )
            .is_ok()
            {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        self.telemetry.unauthorized_input_drops = self
            .telemetry
            .unauthorized_input_drops
            .saturating_add(u64::try_from(rejected).unwrap_or(u64::MAX));
        if accepted > 0 && rejected == 0 {
            NodeSignalEvent::InputAccepted {
                display_id: batch.display_id,
                input_seq: batch.input_seq,
                accepted_events: accepted,
            }
        } else {
            NodeSignalEvent::InputDenied {
                display_id: batch.display_id,
                input_seq: batch.input_seq,
                dropped_events: rejected.max(batch.events.len()),
            }
        }
    }

    /// Apply a received `ControlMessage` (`MediaFeedback`, `ClockSyncPing/Pong`, `PermissionUpdate`, `SessionClose`).
    pub async fn handle_control_or_feedback(
        &mut self,
        msg: ControlMessage,
        now_us: u64,
        now_unix: u64,
    ) -> Result<Option<NodeSignalEvent>, NodeError> {
        match msg {
            ControlMessage::MediaFeedback(fb) => {
                let trigger = self.conn.on_remote_feedback(&fb);
                if trigger {
                    self.telemetry.idr_requests = self.telemetry.idr_requests.saturating_add(1);
                    return Ok(Some(NodeSignalEvent::RemoteForceIdr {
                        display_id: fb.display_id,
                        broken_gop_id: fb.broken_gop_id,
                    }));
                }
                Ok(None)
            }
            ControlMessage::ClockSyncPing(ping) => {
                self.conn
                    .send_feedback_message(&ControlMessage::ClockSyncPong(
                        lumabridge_protocol::control::ClockSyncPong {
                            seq: ping.seq,
                            t1_client_mono_us: ping.t1_client_mono_us,
                            t2_server_recv_us: now_us,
                            t3_server_send_us: now_us,
                        },
                    ))
                    .await?;
                Ok(Some(NodeSignalEvent::ClockSyncReplied { seq: ping.seq }))
            }
            ControlMessage::ClockSyncPong(pong) => {
                if let Some(sample) = self.clock_sync.process_pong(&pong, now_us) {
                    self.telemetry.last_clock_sync_rtt_us = sample.rtt_us;
                    return Ok(Some(NodeSignalEvent::ClockSyncUpdated {
                        rtt_us: sample.rtt_us,
                        offset_us: sample.clock_offset_us,
                    }));
                }
                self.telemetry.timestamp_measurement_errors = self
                    .telemetry
                    .timestamp_measurement_errors
                    .saturating_add(1);
                Ok(None)
            }
            ControlMessage::Heartbeat(hb) => Ok(Some(NodeSignalEvent::HeartbeatReceived {
                seq: hb.seq,
                uptime_ms: hb.uptime_ms,
            })),
            ControlMessage::InputBatch(batch) => {
                Ok(Some(self.evaluate_inbound_input(&batch, now_unix)))
            }
            ControlMessage::PermissionUpgradeRequest(req) => {
                Ok(Some(NodeSignalEvent::PermissionUpgradeRequested {
                    session_id: req.session_id,
                    request_seq: req.request_seq,
                    requested_perms: req.requested_perms,
                }))
            }
            ControlMessage::PermissionUpdate(upd) => {
                if self.grant.expected_role == PeerRole::Controller {
                    return Err(NodeError::Security(SecurityError::AuthorizationDenied(
                        "only Host may issue PermissionUpdate",
                    )));
                }
                if upd.session_id != self.grant.session_id {
                    return Err(NodeError::Protocol("PermissionUpdate session_id mismatch"));
                }
                if now_unix > self.grant.expires_at_unix {
                    return Err(NodeError::Security(SecurityError::SessionTokenInvalid(
                        "session grant expired",
                    )));
                }
                let rec = self.trust_store.verify_trusted_peer(
                    self.conn.tls_session().peer_identity(),
                    self.grant.expected_role,
                )?;
                if rec.device_id != self.grant.peer_device_id
                    || rec.trust_epoch != self.grant.trust_epoch
                {
                    return Err(NodeError::Security(SecurityError::RevokedDevice));
                }
                self.grant.session_granted_perms = upd
                    .effective_perms
                    .intersection(self.policy_ctx.local_policy)
                    .intersection(self.policy_ctx.negotiated_caps);
                self.conn
                    .set_effective_perms(self.grant.session_granted_perms);
                let _ = self.session_mgr.update_session_permissions(
                    self.grant.session_id,
                    self.grant.session_granted_perms,
                );
                Ok(Some(NodeSignalEvent::PermissionUpdated(upd)))
            }
            ControlMessage::SessionClose(close) => Ok(Some(NodeSignalEvent::SessionClosed(close))),
            _ => Ok(None),
        }
    }

    /// Receive the next Channel 2 Feedback message (`MediaFeedback`, `ClockSyncPing/Pong`, `Heartbeat`).
    pub async fn recv_feedback(&mut self) -> Result<ControlMessage, NodeError> {
        Ok(self.conn.recv_feedback_message().await?)
    }

    /// Non-blocking poll for queued Channel 2 Feedback messages (zero timer overhead).
    pub async fn try_recv_feedback(&mut self) -> Result<Option<ControlMessage>, NodeError> {
        Ok(self.conn.try_recv_feedback_message().await?)
    }

    /// Receive the next Channel 0 Control message.
    pub async fn recv_control(&mut self) -> Result<ControlMessage, NodeError> {
        Ok(self.conn.recv_control_message().await?)
    }

    /// Non-blocking poll for queued Channel 0 Control messages (zero timer overhead).
    pub async fn try_recv_control(&mut self) -> Result<Option<ControlMessage>, NodeError> {
        Ok(self.conn.try_recv_control_message().await?)
    }

    /// Receive the next Channel 3 Input message.
    pub async fn recv_input(&mut self) -> Result<ControlMessage, NodeError> {
        Ok(self.conn.recv_input_message().await?)
    }

    /// Expose live transport congestion/queue metrics.
    #[must_use]
    pub fn snapshot_transport_congestion(
        &self,
    ) -> lumabridge_transport::metrics::CongestionSnapshot {
        self.conn.snapshot_congestion()
    }

    /// Gracefully close the session sending `SessionClose`.
    pub async fn close(mut self, reason: CloseReasonCode) {
        self.conn.close_gracefully(reason).await;
    }
}
