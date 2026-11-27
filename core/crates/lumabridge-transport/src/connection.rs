// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Unified `QUIC` / `TCP+TLS 1.3` transport session driver, pairing channel isolation,
//! capability handshake, `SessionResume` channel binding, TX/RX GOP recovery, and
//! live peer-revocation teardown (`ConnectionRegistry`).

use crate::config::{TransportConfig, TransportKind};
use crate::error::TransportError;
use crate::metrics::{BitrateAdvisor, CongestionSnapshot};
use crate::mtu::compute_packet_budget;
use crate::queue::{EnqueueOutcome, MediaTxScheduler, OutboundVideoFrame, TokenBucketPacer};
use crate::quic::{QuicPeerLink, QuicTransportEndpoint};
use crate::tcp::{connect_tcp_tls, TcpPeerLink, TcpTlsServer};
use lumabridge_protocol::cbor::{CborDecodeMode, CborDecodeOptions, UnknownFieldPolicy};
use lumabridge_protocol::control::{
    CloseReasonCode, ControlMessage, DisplayFrameCursor, ErrorNotice, Hello, HelloAck,
    HelloAckStatus, MediaFeedback, MsgType, NodeCapabilities, Permissions, SessionClose,
    SessionResumeRequest, SessionResumeResponse,
};
use lumabridge_protocol::error::ErrorCode;
use lumabridge_protocol::framing::{ChannelId, FrameFlags, RawStreamFrame};
use lumabridge_protocol::media::fragmentation::{decode_media_stream_record, PacketBudget};
use lumabridge_protocol::media::header::decode_video_packet;
use lumabridge_protocol::media::reassembly::{
    ProtectedBlankEvent, ReassembledFrame, Reassembler, ReassemblyOutcome, ReassemblyReport,
};
use lumabridge_protocol::media::recovery::{
    GopRecoveryStateMachine, RecoveryActions, RecoveryState,
};
use lumabridge_protocol::validation::{
    validate_frame_context, validate_message_context, ConnectionPhase, Direction,
    FrameContextDecision, SequenceTracker, ValidationContext,
};
use lumabridge_protocol::version::{
    negotiate_version, Alpn, ProtocolVersion, LBWP_PROTOCOL_MAJOR, LBWP_PROTOCOL_MINOR,
};
use lumabridge_security::certificate::GeneratedDeviceCertificate;
use lumabridge_security::identity::{DeviceId, PeerRole};
use lumabridge_security::secret::{CheckedOsCryptoRng, ResumeTokenSecret};
use lumabridge_security::session_token::{SessionTokenManager, ValidatedResumeResult};
use lumabridge_security::tls::{
    AuthenticatedTlsSession, TlsPeerTrustPolicy, LUMABRIDGE_ALPN_V1, LUMABRIDGE_PAIR_ALPN_V1,
};
use lumabridge_security::transcript::derive_resume_channel_proof;
use lumabridge_security::trust_store::{SecurityAction, TrustStore};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub enum PeerTransportLink {
    Quic {
        link: Arc<QuicPeerLink>,
        kind: TransportKind,
    },
    Tcp(Arc<TcpPeerLink>),
}

impl PeerTransportLink {
    #[must_use]
    pub fn tls_session(&self) -> &AuthenticatedTlsSession {
        match self {
            Self::Quic { link, .. } => link.tls_session(),
            Self::Tcp(link) => link.tls_session(),
        }
    }

    #[must_use]
    pub const fn transport_kind(&self) -> TransportKind {
        match self {
            Self::Quic { kind, .. } => *kind,
            Self::Tcp(_) => TransportKind::TcpTls,
        }
    }

    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        match self {
            Self::Quic { link, .. } => link.max_datagram_size(),
            Self::Tcp(_) => None,
        }
    }

    pub async fn send_stream_frame(
        &self,
        channel: ChannelId,
        msg_type: u16,
        flags: FrameFlags,
        payload: &[u8],
        is_protected_blank: bool,
    ) -> Result<(), TransportError> {
        match self {
            Self::Quic { link, .. } => {
                link.send_stream_frame(channel, msg_type, flags, payload)
                    .await
            }
            Self::Tcp(link) => {
                link.send_stream_frame(channel, msg_type, flags, payload, is_protected_blank)
                    .await
            }
        }
    }

    pub async fn recv_stream_frame(
        &self,
        channel: ChannelId,
    ) -> Result<RawStreamFrame, TransportError> {
        match self {
            Self::Quic { link, .. } => link.recv_stream_frame(channel).await,
            Self::Tcp(link) => link.recv_stream_frame(channel).await,
        }
    }

    pub async fn try_recv_stream_frame(
        &self,
        channel: ChannelId,
    ) -> Result<Option<RawStreamFrame>, TransportError> {
        match self {
            Self::Quic { link, .. } => link.try_recv_stream_frame(channel).await,
            Self::Tcp(link) => link.try_recv_stream_frame(channel).await,
        }
    }

    pub fn close_immediately(&self, reason: &[u8]) {
        match self {
            Self::Quic { link, .. } => {
                link.close_immediately(ErrorCode::UnauthorizedPeer as u32, reason);
            }
            Self::Tcp(link) => link.close_immediately(),
        }
    }

    pub async fn flush_tx(&self) {
        match self {
            Self::Quic { link, .. } => link.flush_control_and_finish().await,
            Self::Tcp(link) => link.flush_tx().await,
        }
    }
}

/// Bounded registry of active transport connections supporting immediate peer revocation teardown.
#[derive(Clone)]
pub struct ConnectionRegistry {
    max_connections: usize,
    entries: Arc<StdMutex<BTreeMap<u64, (DeviceId, PeerTransportLink)>>>,
    next_conn_id: Arc<StdMutex<u64>>,
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new(64)
    }
}

impl ConnectionRegistry {
    #[must_use]
    pub fn new(max_connections: usize) -> Self {
        Self {
            max_connections: max_connections.max(1),
            entries: Arc::new(StdMutex::new(BTreeMap::new())),
            next_conn_id: Arc::new(StdMutex::new(1)),
        }
    }

    pub fn register(
        &self,
        peer_device_id: DeviceId,
        link: PeerTransportLink,
    ) -> Result<u64, TransportError> {
        let mut id_guard = self
            .next_conn_id
            .lock()
            .map_err(|_| TransportError::LimitExceeded("registry id lock poisoned"))?;
        let conn_id = *id_guard;
        *id_guard = id_guard.saturating_add(1);
        drop(id_guard);

        let mut guard = self
            .entries
            .lock()
            .map_err(|_| TransportError::LimitExceeded("registry lock poisoned"))?;
        if guard.len() >= self.max_connections {
            return Err(TransportError::LimitExceeded(
                "max concurrent transport connections reached",
            ));
        }
        guard.insert(conn_id, (peer_device_id, link));
        Ok(conn_id)
    }

    pub fn unregister(&self, conn_id: u64) {
        if let Ok(mut guard) = self.entries.lock() {
            let _ = guard.remove(&conn_id);
        }
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.entries.lock().map_or(0, |g| g.len())
    }

    /// Close and drop all active transport handles for the revoked peer in `action`.
    #[must_use]
    pub fn apply_security_action(&self, action: &SecurityAction) -> usize {
        match action {
            SecurityAction::DisconnectPeerSessions { device_id, .. } => {
                let Ok(mut guard) = self.entries.lock() else {
                    return 0;
                };
                let doomed_ids: Vec<u64> = guard
                    .iter()
                    .filter_map(|(&cid, (did, _))| (*did == *device_id).then_some(cid))
                    .collect();
                let mut closed = 0usize;
                for cid in doomed_ids {
                    if let Some((_, link)) = guard.remove(&cid) {
                        link.close_immediately(b"peer_revoked");
                        closed += 1;
                    }
                }
                closed
            }
        }
    }
}

/// Server wrapper accepting authenticated pairing or operational connections over QUIC or TCP/TLS.
pub enum TransportServer {
    Quic(QuicTransportEndpoint),
    Tcp(TcpTlsServer),
}

impl TransportServer {
    pub async fn bind(
        kind: TransportKind,
        bind_addr: SocketAddr,
        local_cert: &GeneratedDeviceCertificate,
        policy: TlsPeerTrustPolicy,
        config: TransportConfig,
    ) -> Result<Self, TransportError> {
        match kind {
            TransportKind::QuicDatagram | TransportKind::QuicStream => Ok(Self::Quic(
                QuicTransportEndpoint::bind_server(bind_addr, local_cert, policy, config)?,
            )),
            TransportKind::TcpTls => Ok(Self::Tcp(
                TcpTlsServer::bind(bind_addr, local_cert, policy, config).await?,
            )),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        match self {
            Self::Quic(ep) => ep.local_addr(),
            Self::Tcp(srv) => srv.local_addr(),
        }
    }

    pub async fn accept_link(
        &self,
        expected_alpn: &[u8],
        now_unix_secs: u64,
    ) -> Result<PeerTransportLink, TransportError> {
        match self {
            Self::Quic(ep) => {
                let link = ep.accept(expected_alpn, now_unix_secs).await?;
                Ok(PeerTransportLink::Quic {
                    link: Arc::new(link),
                    kind: ep.kind(),
                })
            }
            Self::Tcp(srv) => {
                let link = srv.accept(expected_alpn, now_unix_secs).await?;
                Ok(PeerTransportLink::Tcp(Arc::new(link)))
            }
        }
    }

    pub fn close(&self) {
        if let Self::Quic(ep) = self {
            ep.close();
        }
    }
}

/// Connect client link for `kind` enforcing `policy` (`Pairing`, `Trusted`, or `PinnedPeer`).
#[allow(clippy::too_many_arguments)]
pub async fn connect_client_link(
    kind: TransportKind,
    remote: SocketAddr,
    local_cert: &GeneratedDeviceCertificate,
    policy: TlsPeerTrustPolicy,
    server_hint_device_id: DeviceId,
    expected_alpn: &[u8],
    now_unix_secs: u64,
    config: &TransportConfig,
) -> Result<PeerTransportLink, TransportError> {
    match kind {
        TransportKind::QuicDatagram | TransportKind::QuicStream => {
            let mut c = config.clone();
            c.kind = kind;
            let bind_addr: SocketAddr = if remote.is_ipv4() {
                SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0u16; 8], 0))
            };
            let ep = QuicTransportEndpoint::bind_client(bind_addr, local_cert, policy, c)?;
            let link = ep
                .connect(remote, server_hint_device_id, expected_alpn, now_unix_secs)
                .await?;
            Ok(PeerTransportLink::Quic {
                link: Arc::new(link),
                kind,
            })
        }
        TransportKind::TcpTls => {
            let link = connect_tcp_tls(
                remote,
                local_cert,
                policy,
                server_hint_device_id,
                expected_alpn,
                now_unix_secs,
                config,
            )
            .await?;
            Ok(PeerTransportLink::Tcp(Arc::new(link)))
        }
    }
}

/// Strictly isolated pairing transport wrapper enforcing `ALPN "lumabridge-pair/1"` and
/// `Channel 0` pairing-only messages (`PairHello`, `PairSpakeMsg`, `PairQrAuth`, `PairConfirm`, `PairCancel`).
pub struct PairingConnection {
    link: PeerTransportLink,
    config: TransportConfig,
    direction: Direction,
}

impl PairingConnection {
    pub fn from_link(
        link: PeerTransportLink,
        config: TransportConfig,
        is_initiator: bool,
    ) -> Result<Self, TransportError> {
        link.tls_session().require_pairing_alpn()?;
        config.validate()?;
        let direction = if is_initiator {
            Direction::InitiatorToAcceptor
        } else {
            Direction::AcceptorToInitiator
        };
        Ok(Self {
            link,
            config,
            direction,
        })
    }

    #[must_use]
    pub fn tls_session(&self) -> &AuthenticatedTlsSession {
        self.link.tls_session()
    }

    pub async fn send_pairing_message(&self, msg: &ControlMessage) -> Result<(), TransportError> {
        if !msg.msg_type().is_pairing() && msg.msg_type() != MsgType::ErrorNotice {
            return Err(TransportError::HandshakeFailed(
                "non-pairing message forbidden on lumabridge-pair/1",
            ));
        }
        let buf = msg.encode_cbor()?;
        self.link
            .send_stream_frame(
                ChannelId::Control,
                msg.msg_type().as_u16(),
                FrameFlags::MUST_UNDERSTAND,
                &buf,
                false,
            )
            .await
    }

    pub async fn recv_pairing_message(&self) -> Result<ControlMessage, TransportError> {
        let raw = self.link.recv_stream_frame(ChannelId::Control).await?;
        let ctx = ValidationContext {
            alpn: Alpn::Pairing,
            channel: ChannelId::Control,
            direction: opposite_dir(self.direction),
            phase: ConnectionPhase::PairingOpen,
            effective_perms: Permissions::NONE,
            active_session_id: None,
        };
        let msg_type = match validate_frame_context(&ctx, raw.header) {
            FrameContextDecision::AllowKnown(m) => m,
            FrameContextDecision::Reject(err) => return Err(err.into()),
            _ => {
                return Err(TransportError::HandshakeFailed(
                    "unexpected frame context on pairing channel",
                ));
            }
        };
        let unknown_fields = if msg_type == MsgType::PairCancel || msg_type == MsgType::ErrorNotice
        {
            UnknownFieldPolicy::SkipBounded
        } else {
            UnknownFieldPolicy::Reject
        };
        let msg = ControlMessage::decode_cbor(
            msg_type,
            &raw.payload,
            CborDecodeOptions {
                unknown_fields,
                mode: CborDecodeMode::StrictDeterministic,
                limits: self.config.cbor_limits,
            },
        )?;
        validate_message_context(&ctx, &msg)?;
        Ok(msg)
    }

    pub async fn flush(&self) {
        self.link.flush_tx().await;
    }

    pub fn close(self) {
        self.link.close_immediately(b"pairing_done");
    }
}

/// Output delivered by [`OperationalConnection::recv_media_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaRxEvent {
    Frame(ReassembledFrame),
    ProtectedBlank(ProtectedBlankEvent),
    FeedbackRequested(MediaFeedback),
    DroppedDependentFrames(usize),
    SessionRenewalRequired,
}

/// Negotiated operational parameters returned after `Hello` / `HelloAck` + `NodeCapabilities`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedSessionInfo {
    pub protocol_version: ProtocolVersion,
    pub peer_device_id: DeviceId,
    pub peer_capabilities: NodeCapabilities,
    pub granted_stored_perms: Permissions,
    pub max_control_bytes: u32,
    pub max_frame_bytes: u32,
    pub negotiated_mtu: u16,
}

/// Unified encrypted operational connection supporting `QUIC` datagrams/streams and `TCP/TLS 1.3`.
pub struct OperationalConnection {
    link: PeerTransportLink,
    config: TransportConfig,
    direction: Direction,
    phase: ConnectionPhase,
    active_session_id: Option<u64>,
    effective_perms: Permissions,
    negotiated_mtu: u16,
    scheduler: MediaTxScheduler,
    pacer: TokenBucketPacer,
    bitrate_advisor: BitrateAdvisor,
    reassembler: Reassembler,
    recovery_by_display: BTreeMap<(u64, u16), GopRecoveryStateMachine>,
    pending_rx_events: VecDeque<MediaRxEvent>,
    input_seq_tracker: SequenceTracker,
    update_seq_tracker: SequenceTracker,
    heartbeat_seq_tracker: SequenceTracker,
    perm_request_seq_tracker: SequenceTracker,
    perm_update_seq_tracker: SequenceTracker,
    clock_sync_ping_seq_tracker: SequenceTracker,
    clock_sync_pong_seq_tracker: SequenceTracker,
    next_heartbeat_seq: u64,
    last_rx_activity: Instant,
    started_at: Instant,
    tx_idr_requests_emitted: u64,
    tx_protected_blanks_sent: u64,
    registry: Option<ConnectionRegistry>,
    registry_conn_id: Option<u64>,
}

impl OperationalConnection {
    /// Wrap an authenticated operational TLS 1.3 connection (`ALPN "lumabridge/1"`).
    ///
    /// When `registry` is supplied, registration occurs BEFORE live `trust_store` verification
    /// when calling [`Self::from_link_verified`] to eliminate any revocation-vs-registration TOCTOU gap.
    pub fn from_link(
        link: PeerTransportLink,
        config: TransportConfig,
        is_initiator: bool,
        registry: Option<ConnectionRegistry>,
    ) -> Result<Self, TransportError> {
        link.tls_session().require_operational_alpn()?;
        config.validate()?;
        let direction = if is_initiator {
            Direction::InitiatorToAcceptor
        } else {
            Direction::AcceptorToInitiator
        };
        let scheduler =
            MediaTxScheduler::new(config.max_media_queue_frames, config.max_media_queue_bytes)?;
        let pacer_bps = config
            .pacing_target_bps
            .unwrap_or(config.initial_bitrate_bps);
        let pacer = TokenBucketPacer::new(pacer_bps, 64 * 1024);
        let bitrate_advisor = BitrateAdvisor::new(
            config.min_bitrate_bps,
            config.initial_bitrate_bps,
            config.max_bitrate_bps,
        );
        let reassembler = Reassembler::new(config.reassembly_config)?;

        let peer_did = link.tls_session().peer_identity().device_id();
        let registry_conn_id = match &registry {
            Some(reg) => Some(reg.register(peer_did, link.clone())?),
            None => None,
        };

        let now = Instant::now();
        Ok(Self {
            link,
            config,
            direction,
            phase: ConnectionPhase::OperationalHandshake,
            active_session_id: None,
            effective_perms: Permissions::NONE,
            negotiated_mtu: QUIC_SAFE_MTU_U16,
            scheduler,
            pacer,
            bitrate_advisor,
            reassembler,
            recovery_by_display: BTreeMap::new(),
            pending_rx_events: VecDeque::new(),
            input_seq_tracker: SequenceTracker::new(),
            update_seq_tracker: SequenceTracker::new(),
            heartbeat_seq_tracker: SequenceTracker::new(),
            perm_request_seq_tracker: SequenceTracker::new(),
            perm_update_seq_tracker: SequenceTracker::new(),
            clock_sync_ping_seq_tracker: SequenceTracker::new(),
            clock_sync_pong_seq_tracker: SequenceTracker::new(),
            next_heartbeat_seq: 1,
            last_rx_activity: now,
            started_at: now,
            tx_idr_requests_emitted: 0,
            tx_protected_blanks_sent: 0,
            registry,
            registry_conn_id,
        })
    }

    /// Construct an [`OperationalConnection`] while closing the registration-vs-revocation TOCTOU
    /// window: registers in `registry` FIRST, then validates live `TrustStore` state, unregistering
    /// and closing immediately on failure.
    pub fn from_link_verified(
        link: PeerTransportLink,
        config: TransportConfig,
        is_initiator: bool,
        registry: ConnectionRegistry,
        trust_store: &dyn TrustStore,
        expected_role: PeerRole,
    ) -> Result<Self, TransportError> {
        let conn = Self::from_link(link, config, is_initiator, Some(registry))?;
        if let Err(err) =
            trust_store.verify_trusted_peer(conn.link.tls_session().peer_identity(), expected_role)
        {
            conn.link.close_immediately(b"peer_revoked_or_untrusted");
            return Err(err.into());
        }
        Ok(conn)
    }

    #[must_use]
    pub fn tls_session(&self) -> &AuthenticatedTlsSession {
        self.link.tls_session()
    }

    #[must_use]
    pub const fn transport_kind(&self) -> TransportKind {
        self.link.transport_kind()
    }

    #[must_use]
    pub const fn phase(&self) -> ConnectionPhase {
        self.phase
    }

    #[must_use]
    pub const fn active_session_id(&self) -> Option<u64> {
        self.active_session_id
    }

    #[must_use]
    pub const fn effective_perms(&self) -> Permissions {
        self.effective_perms
    }

    #[must_use]
    pub const fn is_tx_chain_broken(&self) -> bool {
        self.scheduler.is_chain_broken()
    }

    pub fn take_tx_force_idr_request(&mut self) -> bool {
        self.scheduler.take_force_idr_request()
    }

    /// Manually activate session state (used after `SessionOpen` or `SessionResume` completion).
    pub fn set_active_session(&mut self, session_id: u64, effective_perms: Permissions) {
        self.active_session_id = Some(session_id);
        self.effective_perms = effective_perms;
        self.phase = ConnectionPhase::OperationalSessionActive;
    }

    /// Update active session permissions after `PermissionUpdate` or local elevation.
    pub fn set_effective_perms(&mut self, effective_perms: Permissions) {
        self.effective_perms = effective_perms;
    }

    /// Compute live MTU-aware [`PacketBudget`] for media packetization on this connection.
    pub fn current_packet_budget(&self) -> Result<PacketBudget, TransportError> {
        compute_packet_budget(
            self.link.transport_kind(),
            &self.config,
            self.link.max_datagram_size(),
            Some(self.negotiated_mtu),
        )
    }

    /// Execute the initiator side of `Hello` <-> `HelloAck` + `NodeCapabilities` handshake,
    /// verifying live `TrustStore` membership for `expected_role` and bounding stored permissions.
    pub async fn handshake_initiator(
        &mut self,
        local_device_id: DeviceId,
        trust_store: &dyn TrustStore,
        expected_role: PeerRole,
        app_version: &str,
        local_caps: NodeCapabilities,
    ) -> Result<NegotiatedSessionInfo, TransportError> {
        if self.direction != Direction::InitiatorToAcceptor {
            return Err(TransportError::HandshakeFailed(
                "handshake_initiator requires initiator link",
            ));
        }
        let record = trust_store
            .verify_trusted_peer(self.link.tls_session().peer_identity(), expected_role)?;
        let hello = ControlMessage::Hello(Hello {
            protocol_major: LBWP_PROTOCOL_MAJOR,
            protocol_minor: LBWP_PROTOCOL_MINOR,
            device_id: *local_device_id.as_bytes(),
            app_version: app_version.to_owned(),
            max_control_bytes: u32::try_from(self.config.framing_limits.max_control_bytes)
                .unwrap_or(65_536),
            max_frame_bytes: u32::try_from(self.config.max_frame_bytes).unwrap_or(8 * 1024 * 1024),
            preferred_mtu: self.config.max_mtu,
        });
        self.send_control_message(&hello).await?;

        let ack_msg = self.recv_control_message().await?;
        let ControlMessage::HelloAck(ack) = ack_msg else {
            return Err(TransportError::HandshakeFailed("expected HelloAck"));
        };
        if ack.device_id
            != *self
                .link
                .tls_session()
                .peer_identity()
                .device_id()
                .as_bytes()
        {
            return Err(TransportError::Security(
                lumabridge_security::error::SecurityError::IdentityMismatch(
                    "HelloAck device_id differs from mTLS identity",
                ),
            ));
        }
        if ack.status != HelloAckStatus::Accepted {
            return Err(TransportError::HandshakeFailed("peer rejected Hello"));
        }
        let version = negotiate_version(
            ProtocolVersion::CURRENT,
            ProtocolVersion::new(ack.negotiated_major, ack.negotiated_minor),
        )
        .map_err(|_| TransportError::HandshakeFailed("protocol version mismatch"))?;

        // Re-verify TrustStore and strictly intersect advertised wire perms with local TrustStore cap!
        let live_record = trust_store
            .verify_trusted_peer(self.link.tls_session().peer_identity(), expected_role)?;
        let bounded_perms = live_record
            .base_permissions
            .intersection(record.base_permissions)
            .intersection(ack.granted_stored_perms);
        self.negotiated_mtu = ack
            .negotiated_mtu
            .min(self.config.max_mtu)
            .max(crate::config::QUIC_MIN_INITIAL_MTU);
        self.effective_perms = bounded_perms;

        let caps_msg = ControlMessage::NodeCapabilities(local_caps);
        self.send_control_message(&caps_msg).await?;
        let peer_caps_msg = self.recv_control_message().await?;
        let ControlMessage::NodeCapabilities(peer_caps) = peer_caps_msg else {
            return Err(TransportError::HandshakeFailed(
                "expected peer NodeCapabilities",
            ));
        };
        self.phase = ConnectionPhase::OperationalAuthenticated;
        Ok(NegotiatedSessionInfo {
            protocol_version: version,
            peer_device_id: live_record.device_id,
            peer_capabilities: peer_caps,
            granted_stored_perms: bounded_perms,
            max_control_bytes: ack.max_control_bytes,
            max_frame_bytes: ack.max_frame_bytes,
            negotiated_mtu: self.negotiated_mtu,
        })
    }

    /// Execute the acceptor side of `Hello` <-> `HelloAck` + `NodeCapabilities` handshake,
    /// enforcing live `TrustStore` authorization for `expected_role`.
    pub async fn handshake_acceptor(
        &mut self,
        local_device_id: DeviceId,
        trust_store: &dyn TrustStore,
        expected_role: PeerRole,
        local_caps: NodeCapabilities,
    ) -> Result<NegotiatedSessionInfo, TransportError> {
        if self.direction != Direction::AcceptorToInitiator {
            return Err(TransportError::HandshakeFailed(
                "handshake_acceptor requires acceptor link",
            ));
        }
        let hello_msg = self.recv_control_message().await?;
        let ControlMessage::Hello(hello) = hello_msg else {
            return Err(TransportError::HandshakeFailed("expected Hello"));
        };
        if hello.device_id
            != *self
                .link
                .tls_session()
                .peer_identity()
                .device_id()
                .as_bytes()
        {
            return Err(TransportError::Security(
                lumabridge_security::error::SecurityError::IdentityMismatch(
                    "Hello device_id differs from mTLS identity",
                ),
            ));
        }
        let record = trust_store
            .verify_trusted_peer(self.link.tls_session().peer_identity(), expected_role)?;

        let negotiated_ver = negotiate_version(
            ProtocolVersion::CURRENT,
            ProtocolVersion::new(hello.protocol_major, hello.protocol_minor),
        );
        let (status, version) = match negotiated_ver {
            Ok(v) => (HelloAckStatus::Accepted, v),
            Err(_) => (HelloAckStatus::UnsupportedVersion, ProtocolVersion::CURRENT),
        };

        let negotiated_mtu = hello
            .preferred_mtu
            .min(self.config.max_mtu)
            .max(crate::config::QUIC_MIN_INITIAL_MTU);
        let max_ctrl = hello
            .max_control_bytes
            .min(u32::try_from(self.config.framing_limits.max_control_bytes).unwrap_or(65_536));
        let max_frame = hello
            .max_frame_bytes
            .min(u32::try_from(self.config.max_frame_bytes).unwrap_or(8 * 1024 * 1024));

        let ack = ControlMessage::HelloAck(HelloAck {
            negotiated_major: version.major,
            negotiated_minor: version.minor,
            device_id: *local_device_id.as_bytes(),
            granted_stored_perms: if status == HelloAckStatus::Accepted {
                record.base_permissions
            } else {
                Permissions::NONE
            },
            status,
            max_control_bytes: max_ctrl,
            max_frame_bytes: max_frame,
            negotiated_mtu,
        });
        self.send_control_message(&ack).await?;
        if status != HelloAckStatus::Accepted {
            return Err(TransportError::HandshakeFailed("unsupported peer version"));
        }
        self.negotiated_mtu = negotiated_mtu;
        self.effective_perms = record.base_permissions;

        let peer_caps_msg = self.recv_control_message().await?;
        let ControlMessage::NodeCapabilities(peer_caps) = peer_caps_msg else {
            return Err(TransportError::HandshakeFailed(
                "expected peer NodeCapabilities",
            ));
        };
        let caps_msg = ControlMessage::NodeCapabilities(local_caps);
        self.send_control_message(&caps_msg).await?;
        self.phase = ConnectionPhase::OperationalAuthenticated;

        Ok(NegotiatedSessionInfo {
            protocol_version: version,
            peer_device_id: record.device_id,
            peer_capabilities: peer_caps,
            granted_stored_perms: record.base_permissions,
            max_control_bytes: max_ctrl,
            max_frame_bytes: max_frame,
            negotiated_mtu,
        })
    }

    /// Initiator helper for channel-bound `SessionResumeRequest` (`ALPN "lumabridge/1"`).
    pub async fn resume_session_as_client(
        &mut self,
        local_device_id: DeviceId,
        session_id: u64,
        trust_epoch: u64,
        resume_token: &ResumeTokenSecret,
        last_good_frames: Vec<DisplayFrameCursor>,
    ) -> Result<SessionResumeResponse, TransportError> {
        let proof = derive_resume_channel_proof(
            resume_token,
            self.link.tls_session().channel_binding(),
            local_device_id,
            session_id,
            trust_epoch,
        )?;
        let req = ControlMessage::SessionResumeRequest(SessionResumeRequest {
            session_id,
            resume_token: resume_token.expose_secret().to_vec(),
            last_good_frames,
            channel_proof: Some(*proof),
        });
        self.send_control_message(&req).await?;
        match self.recv_control_message().await? {
            ControlMessage::SessionResumeResponse(resp) => Ok(resp),
            _ => Err(TransportError::HandshakeFailed(
                "expected SessionResumeResponse",
            )),
        }
    }

    /// Acceptor helper verifying `SessionResumeRequest` against `SessionTokenManager` + live `TrustStore`
    /// and sending `SessionResumeResponse` with rotated token.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_session_resume(
        &mut self,
        rng: &mut CheckedOsCryptoRng,
        trust_store: &dyn TrustStore,
        session_mgr: &SessionTokenManager,
        expected_role: PeerRole,
        req: &SessionResumeRequest,
        preserved_displays: Vec<lumabridge_protocol::control::ActiveDisplayConfig>,
        idr_requested_displays: Vec<u16>,
        now_unix: u64,
        new_resume_ttl_secs: u64,
    ) -> Result<Option<ValidatedResumeResult>, TransportError> {
        let Some(proof) = req.channel_proof else {
            let deny = ControlMessage::SessionResumeResponse(SessionResumeResponse {
                accepted: false,
                session_id: req.session_id,
                preserved_displays: Vec::new(),
                idr_requested_displays: Vec::new(),
                rotated_resume_token: None,
            });
            self.send_control_message(&deny).await?;
            return Ok(None);
        };

        if let Ok(res) = session_mgr.consume_and_rotate_resume_token(
            rng,
            trust_store,
            self.link.tls_session(),
            expected_role,
            req.session_id,
            &req.resume_token,
            &proof,
            now_unix,
            new_resume_ttl_secs,
        ) {
            let ok_msg = ControlMessage::SessionResumeResponse(SessionResumeResponse {
                accepted: true,
                session_id: res.session_id,
                preserved_displays,
                idr_requested_displays,
                rotated_resume_token: Some(res.rotated_resume_token.expose_secret().to_vec()),
            });
            self.send_control_message(&ok_msg).await?;
            self.set_active_session(res.session_id, res.effective_permissions);
            Ok(Some(res))
        } else {
            let deny = ControlMessage::SessionResumeResponse(SessionResumeResponse {
                accepted: false,
                session_id: req.session_id,
                preserved_displays: Vec::new(),
                idr_requested_displays: Vec::new(),
                rotated_resume_token: None,
            });
            self.send_control_message(&deny).await?;
            Ok(None)
        }
    }

    /// Encode and send a control/session/error message on `Channel 0` (`Control`).
    pub async fn send_control_message(&self, msg: &ControlMessage) -> Result<(), TransportError> {
        self.send_cbor_on_channel(ChannelId::Control, msg).await
    }

    /// Encode and send a feedback/sync/heartbeat message on `Channel 2` (`Feedback`).
    pub async fn send_feedback_message(&self, msg: &ControlMessage) -> Result<(), TransportError> {
        self.send_cbor_on_channel(ChannelId::Feedback, msg).await
    }

    /// Encode and send a remote input batch on `Channel 3` (`Input`).
    pub async fn send_input_message(&self, msg: &ControlMessage) -> Result<(), TransportError> {
        self.send_cbor_on_channel(ChannelId::Input, msg).await
    }

    async fn send_cbor_on_channel(
        &self,
        channel: ChannelId,
        msg: &ControlMessage,
    ) -> Result<(), TransportError> {
        if msg.msg_type().expected_channel() != channel {
            return Err(TransportError::InvalidConfig(
                "control message routed to wrong logical channel",
            ));
        }
        let payload = msg.encode_cbor()?;
        self.link
            .send_stream_frame(
                channel,
                msg.msg_type().as_u16(),
                FrameFlags::MUST_UNDERSTAND,
                &payload,
                false,
            )
            .await
    }

    pub async fn recv_control_message(&mut self) -> Result<ControlMessage, TransportError> {
        self.recv_cbor_on_channel(ChannelId::Control).await
    }

    pub async fn recv_feedback_message(&mut self) -> Result<ControlMessage, TransportError> {
        self.recv_cbor_on_channel(ChannelId::Feedback).await
    }

    pub async fn recv_input_message(&mut self) -> Result<ControlMessage, TransportError> {
        self.recv_cbor_on_channel(ChannelId::Input).await
    }

    /// Non-blocking poll for queued `Control` message without allocating an OS timer.
    pub async fn try_recv_control_message(
        &mut self,
    ) -> Result<Option<ControlMessage>, TransportError> {
        self.try_recv_cbor_on_channel(ChannelId::Control).await
    }

    /// Non-blocking poll for queued `Feedback` message without allocating an OS timer.
    pub async fn try_recv_feedback_message(
        &mut self,
    ) -> Result<Option<ControlMessage>, TransportError> {
        self.try_recv_cbor_on_channel(ChannelId::Feedback).await
    }

    async fn try_recv_cbor_on_channel(
        &mut self,
        channel: ChannelId,
    ) -> Result<Option<ControlMessage>, TransportError> {
        while let Some(raw) = self.link.try_recv_stream_frame(channel).await? {
            if let Some(msg) = self.validate_and_decode_cbor_frame(channel, raw).await? {
                return Ok(Some(msg));
            }
        }
        Ok(None)
    }

    async fn recv_cbor_on_channel(
        &mut self,
        channel: ChannelId,
    ) -> Result<ControlMessage, TransportError> {
        loop {
            let raw = tokio::time::timeout(
                Duration::from_millis(self.config.heartbeat_timeout_ms),
                self.link.recv_stream_frame(channel),
            )
            .await
            .map_err(|_| TransportError::Timeout("channel read exceeded heartbeat timeout"))??;
            if let Some(msg) = self.validate_and_decode_cbor_frame(channel, raw).await? {
                return Ok(msg);
            }
        }
    }

    async fn validate_and_decode_cbor_frame(
        &mut self,
        channel: ChannelId,
        raw: RawStreamFrame,
    ) -> Result<Option<ControlMessage>, TransportError> {
        self.last_rx_activity = Instant::now();

        let ctx = ValidationContext {
            alpn: Alpn::Operational,
            channel,
            direction: opposite_dir(self.direction),
            phase: self.phase,
            effective_perms: self.effective_perms,
            active_session_id: self.active_session_id,
        };
        let msg_type = match validate_frame_context(&ctx, raw.header) {
            FrameContextDecision::AllowKnown(m) => m,
            FrameContextDecision::IgnoreUnknownOptional => return Ok(None),
            FrameContextDecision::Reject(err) => {
                if err.fatal {
                    let _ = self
                        .send_control_message(&ControlMessage::ErrorNotice(ErrorNotice {
                            code: err.code,
                            fatal: true,
                            related_msg_type: raw.header.msg_type,
                            context_ascii: err.reason.to_owned(),
                        }))
                        .await;
                }
                return Err(err.into());
            }
            FrameContextDecision::AllowMediaFragment => {
                return Err(TransportError::InvalidConfig(
                    "unexpected media decision on CBOR channel",
                ));
            }
        };
        let msg = ControlMessage::decode_cbor(
            msg_type,
            &raw.payload,
            CborDecodeOptions {
                unknown_fields: UnknownFieldPolicy::SkipBounded,
                mode: CborDecodeMode::StrictDeterministic,
                limits: self.config.cbor_limits,
            },
        )?;
        validate_message_context(&ctx, &msg)?;
        self.verify_message_sequence(&msg)?;
        if let ControlMessage::ErrorNotice(notice) = &msg {
            if notice.fatal {
                return Err(TransportError::RemoteErrorNotice {
                    code: notice.code,
                    fatal: notice.fatal,
                });
            }
        }
        Ok(Some(msg))
    }

    fn verify_message_sequence(&mut self, msg: &ControlMessage) -> Result<(), TransportError> {
        match msg {
            ControlMessage::DisplayConfigUpdate(m) => {
                self.update_seq_tracker.accept(m.update_seq)?;
            }
            ControlMessage::InputBatch(m) => {
                self.input_seq_tracker.accept(m.input_seq)?;
            }
            ControlMessage::Heartbeat(m) => {
                self.heartbeat_seq_tracker.accept(m.seq)?;
            }
            ControlMessage::PermissionUpgradeRequest(m) => {
                self.perm_request_seq_tracker.accept(m.request_seq)?;
            }
            ControlMessage::PermissionUpdate(m) => {
                self.perm_update_seq_tracker.accept(m.update_seq)?;
            }
            ControlMessage::ClockSyncPing(m) => {
                self.clock_sync_ping_seq_tracker.accept(m.seq)?;
            }
            ControlMessage::ClockSyncPong(m) => {
                self.clock_sync_pong_seq_tracker.accept(m.seq)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Send an outbound encoded frame (or `ProtectedBlank`) applying `MediaTxScheduler`, pacing,
    /// and mandatory **reliable** delivery for `ProtectedBlank`.
    pub async fn send_video_frame(
        &mut self,
        frame: OutboundVideoFrame,
    ) -> Result<EnqueueOutcome, TransportError> {
        if self.phase != ConnectionPhase::OperationalSessionActive
            || self.active_session_id.is_none()
        {
            return Err(TransportError::InvalidConfig(
                "send_video_frame requires OperationalSessionActive",
            ));
        }

        let outcome = self.scheduler.enqueue(frame);
        if !outcome.admitted {
            return Ok(outcome);
        }

        let budget = self.current_packet_budget()?;
        while let Some(prepared) = self.scheduler.pop_ready(budget)? {
            if prepared.is_protected_blank {
                for pkt in &prepared.packets {
                    self.link
                        .send_stream_frame(
                            ChannelId::Media,
                            lumabridge_protocol::limits::MSG_TYPE_MEDIA_VIDEO_FRAGMENT,
                            FrameFlags::NONE,
                            pkt,
                            true,
                        )
                        .await?;
                }
                self.tx_protected_blanks_sent = self.tx_protected_blanks_sent.saturating_add(1);
                continue;
            }

            match self.link.transport_kind() {
                TransportKind::QuicDatagram => {
                    for pkt in &prepared.packets {
                        let delay = self.pacer.consume_or_delay(pkt.len(), self.elapsed_us());
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        if let PeerTransportLink::Quic { link, .. } = &self.link {
                            if let Err(err) = link.send_media_datagram(pkt) {
                                self.scheduler.notify_chain_broken(Some(prepared.gop_id));
                                return Err(err);
                            }
                        }
                    }
                }
                TransportKind::QuicStream | TransportKind::TcpTls => {
                    for pkt in &prepared.packets {
                        if let Err(err) = self
                            .link
                            .send_stream_frame(
                                ChannelId::Media,
                                lumabridge_protocol::limits::MSG_TYPE_MEDIA_VIDEO_FRAGMENT,
                                FrameFlags::NONE,
                                pkt,
                                false,
                            )
                            .await
                        {
                            if matches!(err, TransportError::QueueFull(_)) {
                                self.scheduler.notify_chain_broken(Some(prepared.gop_id));
                                return Ok(EnqueueOutcome {
                                    admitted: false,
                                    dropped_stale_frames: outcome.dropped_stale_frames,
                                    dropped_broken_gop_frames: 1,
                                    force_idr_required: true,
                                });
                            }
                            return Err(err);
                        }
                    }
                }
            }
        }
        let (_, _) = self.poll_congestion_and_advise_bitrate();
        Ok(outcome)
    }

    /// Apply remote `MediaFeedback` (updates TX `chain_broken` state on `request_idr`).
    pub fn on_remote_feedback(&mut self, fb: &MediaFeedback) -> bool {
        if fb.request_idr {
            self.scheduler.notify_chain_broken(fb.broken_gop_id);
            return true;
        }
        false
    }

    /// Poll RX media (`Channel 1` reliable stream prioritized over QUIC unreliable datagrams),
    /// validating session/phase context BEFORE allocating in [`Reassembler`], feeding
    /// [`GopRecoveryStateMachine`], and emitting rate-limited `MediaFeedback(request_idr = true)`.
    pub async fn recv_media_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<MediaRxEvent>, TransportError> {
        if let Some(queued) = self.pending_rx_events.pop_front() {
            return Ok(Some(queued));
        }
        let deadline = Instant::now() + timeout;
        loop {
            let expired_actions = self.poll_rx_timers();
            if let Some(ev) = self.consume_recovery_actions(expired_actions).await? {
                return Ok(Some(ev));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let remain = deadline - now;

            let media_ctx = ValidationContext {
                alpn: Alpn::Operational,
                channel: ChannelId::Media,
                direction: opposite_dir(self.direction),
                phase: self.phase,
                effective_perms: self.effective_perms,
                active_session_id: self.active_session_id,
            };

            let (packet_opt, from_stream) = match &self.link {
                PeerTransportLink::Quic { link, .. } => {
                    // Reliable Channel 1 stream (`ProtectedBlank`) ALWAYS precedes datagrams!
                    if let Some(raw) = link.try_recv_media_stream_frame().await {
                        Self::validate_media_stream_header(&media_ctx, &raw, &self.link).await?;
                        decode_media_stream_record(&raw, &self.config.framing_limits).map_err(
                            |_| TransportError::ConnectionClosed("bad media stream record"),
                        )?;
                        (Some(raw.payload), true)
                    } else {
                        tokio::select! {
                            biased;
                            res = tokio::time::timeout(remain, link.recv_stream_frame(ChannelId::Media)) => {
                                match res {
                                    Ok(Ok(raw)) => {
                                        Self::validate_media_stream_header(&media_ctx, &raw, &self.link).await?;
                                        decode_media_stream_record(&raw, &self.config.framing_limits)
                                            .map_err(|_| TransportError::ConnectionClosed("bad media stream record"))?;
                                        (Some(raw.payload), true)
                                    }
                                    Ok(Err(e)) => return Err(e),
                                    Err(_) => (None, false),
                                }
                            }
                            res = tokio::time::timeout(remain, link.recv_media_datagram()) => {
                                match res {
                                    Ok(Ok(pkt)) => (Some(pkt), false),
                                    Ok(Err(e)) => return Err(e),
                                    Err(_) => (None, false),
                                }
                            }
                        }
                    }
                }
                PeerTransportLink::Tcp(link) => {
                    match tokio::time::timeout(remain, link.recv_stream_frame(ChannelId::Media))
                        .await
                    {
                        Ok(Ok(raw)) => {
                            Self::validate_media_stream_header(&media_ctx, &raw, &self.link)
                                .await?;
                            decode_media_stream_record(&raw, &self.config.framing_limits).map_err(
                                |_| TransportError::ConnectionClosed("bad TCP media record"),
                            )?;
                            (Some(raw.payload), true)
                        }
                        Ok(Err(e)) => return Err(e),
                        Err(_) => (None, false),
                    }
                }
            };

            let Some(pkt) = packet_opt else {
                let expired_actions = self.poll_rx_timers();
                if let Some(ev) = self.consume_recovery_actions(expired_actions).await? {
                    return Ok(Some(ev));
                }
                return Ok(None);
            };
            self.last_rx_activity = Instant::now();

            // Enforce active session and session_id BEFORE allocating/modifying Reassembler state!
            let Some(active_sid) = self.active_session_id else {
                if !from_stream {
                    continue;
                }
                return Err(TransportError::InvalidConfig(
                    "media received without active session",
                ));
            };
            if self.phase != ConnectionPhase::OperationalSessionActive {
                continue;
            }

            let now_us = self.elapsed_us();
            let max_budget = match self.link.transport_kind() {
                TransportKind::QuicDatagram if !from_stream => self.config.max_packet_bytes,
                _ => self.config.framing_limits.max_media_stream_bytes,
            };
            let Ok((hdr, _)) = decode_video_packet(&pkt, max_budget) else {
                // `DropDatagram`: discard structurally invalid packet silently before Reassembler.
                continue;
            };
            if hdr.session_id != active_sid {
                // Reject foreign/spoofed session_id BEFORE inserting into Reassembler maps (`LBWP` §11).
                continue;
            }
            let Ok(report) = self.reassembler.ingest_packet(&pkt, max_budget, now_us) else {
                continue;
            };

            if let Some(ev) = self.process_reassembly_report(report, now_us).await? {
                return Ok(Some(ev));
            }
        }
    }

    async fn validate_media_stream_header(
        ctx: &ValidationContext,
        raw: &RawStreamFrame,
        link: &PeerTransportLink,
    ) -> Result<(), TransportError> {
        match validate_frame_context(ctx, raw.header) {
            FrameContextDecision::AllowMediaFragment => Ok(()),
            FrameContextDecision::Reject(err) => {
                if err.fatal {
                    if let Ok(payload) = ControlMessage::ErrorNotice(ErrorNotice {
                        code: err.code,
                        fatal: true,
                        related_msg_type: raw.header.msg_type,
                        context_ascii: err.reason.to_owned(),
                    })
                    .encode_cbor()
                    {
                        let _ = link
                            .send_stream_frame(
                                ChannelId::Control,
                                MsgType::ErrorNotice.as_u16(),
                                FrameFlags::MUST_UNDERSTAND,
                                &payload,
                                false,
                            )
                            .await;
                    }
                }
                Err(err.into())
            }
            _ => Err(TransportError::InvalidConfig(
                "unexpected context decision for Channel 1 media record",
            )),
        }
    }

    async fn process_reassembly_report(
        &mut self,
        report: ReassemblyReport,
        now_us: u64,
    ) -> Result<Option<MediaRxEvent>, TransportError> {
        let Some(active_sid) = self.active_session_id else {
            return Ok(None);
        };

        let target_key = match &report.outcome {
            ReassemblyOutcome::Completed(f) => Some((f.session_id, f.display_id)),
            ReassemblyOutcome::ProtectedBlank(ev) => Some((ev.session_id, ev.display_id)),
            _ => report
                .discarded
                .first()
                .map(|n| (n.session_id, n.display_id)),
        };

        if let Some((sid, did)) = target_key {
            if sid != active_sid {
                return Ok(None);
            }
            if !self.recovery_by_display.contains_key(&(sid, did)) {
                if self.recovery_by_display.len() >= 16 {
                    return Err(TransportError::LimitExceeded(
                        "too many tracked displays in GOP recovery",
                    ));
                }
                let sm = GopRecoveryStateMachine::new(sid, did, self.config.recovery_config)?;
                self.recovery_by_display.insert((sid, did), sm);
            }
            let outcome_clone_blank = match &report.outcome {
                ReassemblyOutcome::ProtectedBlank(ev) => Some(*ev),
                _ => None,
            };
            let sm = self
                .recovery_by_display
                .get_mut(&(sid, did))
                .expect("inserted display recovery SM");
            let mut actions = sm.on_reassembly_report(report, now_us, &self.reassembler);
            if actions.hide_content_for_protected_blank {
                if let Some(blank) = outcome_clone_blank {
                    // Queue ProtectedBlank with top priority while preserving session_renewal_required!
                    self.pending_rx_events
                        .push_back(MediaRxEvent::ProtectedBlank(blank));
                    if actions.session_renewal_required {
                        self.pending_rx_events
                            .push_back(MediaRxEvent::SessionRenewalRequired);
                        actions.session_renewal_required = false;
                    }
                    self.queue_recovery_actions_for(did, actions).await?;
                    return Ok(self.pending_rx_events.pop_front());
                }
            }
            return self.consume_recovery_actions_for(did, actions).await;
        }
        Ok(None)
    }

    fn poll_rx_timers(&mut self) -> Vec<(u16, RecoveryActions)> {
        let now_us = self.elapsed_us();
        let expired = self.reassembler.expire(now_us);
        let mut out = Vec::new();
        for ((sid, did), sm) in &mut self.recovery_by_display {
            let mut act = RecoveryActions::default();
            for n in &expired {
                if n.session_id == *sid && n.display_id == *did {
                    let lost =
                        sm.on_frame_lost(n.session_id, n.display_id, n.frame_id, n.gop_id, now_us);
                    if lost.request_idr {
                        act.request_idr = true;
                    }
                    act.dropped_dependent_frames = act
                        .dropped_dependent_frames
                        .saturating_add(lost.dropped_dependent_frames);
                }
            }
            let timers = sm.poll_timers(now_us);
            act.request_idr |= timers.request_idr;
            act.dropped_dependent_frames = act
                .dropped_dependent_frames
                .saturating_add(timers.dropped_dependent_frames);
            if act.request_idr || act.dropped_dependent_frames > 0 {
                out.push((*did, act));
            }
        }
        out
    }

    async fn consume_recovery_actions(
        &mut self,
        list: Vec<(u16, RecoveryActions)>,
    ) -> Result<Option<MediaRxEvent>, TransportError> {
        for (did, actions) in list {
            self.queue_recovery_actions_for(did, actions).await?;
        }
        Ok(self.pending_rx_events.pop_front())
    }

    async fn consume_recovery_actions_for(
        &mut self,
        display_id: u16,
        actions: RecoveryActions,
    ) -> Result<Option<MediaRxEvent>, TransportError> {
        self.queue_recovery_actions_for(display_id, actions).await?;
        Ok(self.pending_rx_events.pop_front())
    }

    async fn queue_recovery_actions_for(
        &mut self,
        display_id: u16,
        mut actions: RecoveryActions,
    ) -> Result<(), TransportError> {
        if actions.session_renewal_required {
            self.pending_rx_events
                .push_back(MediaRxEvent::SessionRenewalRequired);
        }
        if actions.request_idr {
            if let Some(sid) = self.active_session_id {
                let snap = self.snapshot_congestion();
                let (broken_gop_id, last_good) = self
                    .recovery_by_display
                    .get(&(sid, display_id))
                    .map_or((None, 0), |sm| match sm.state() {
                        RecoveryState::AwaitingIdr {
                            broken_gop_id,
                            last_good_frame_id,
                        } => (Some(broken_gop_id), last_good_frame_id),
                        RecoveryState::Healthy {
                            last_delivered_frame_id,
                            ..
                        } => (None, last_delivered_frame_id),
                        RecoveryState::ProtectedBlanked {
                            last_blank_frame_id,
                        } => (None, last_blank_frame_id),
                        RecoveryState::InitialAwaitingIdr => (None, 0),
                    });
                let fb = MediaFeedback {
                    session_id: sid,
                    display_id,
                    last_complete_frame_id: last_good,
                    last_displayed_frame_id: last_good,
                    broken_gop_id,
                    request_idr: true,
                    decode_p50_us: 0,
                    decode_p95_us: 0,
                    present_p95_us: 0,
                    rx_fps_milli: 0,
                    packet_loss_ppm: snap.packet_loss_ppm,
                    jitter_us: 0,
                    suggested_bitrate_bps: u32::try_from(
                        self.bitrate_advisor.current_bitrate_bps(),
                    )
                    .unwrap_or(u32::MAX),
                };
                self.tx_idr_requests_emitted = self.tx_idr_requests_emitted.saturating_add(1);
                let _ = self
                    .send_feedback_message(&ControlMessage::MediaFeedback(fb.clone()))
                    .await;
                self.pending_rx_events
                    .push_back(MediaRxEvent::FeedbackRequested(fb));
            }
        }
        for frame in actions.deliver_frames.drain(..) {
            self.pending_rx_events.push_back(MediaRxEvent::Frame(frame));
        }
        if actions.dropped_dependent_frames > 0 && self.pending_rx_events.is_empty() {
            self.pending_rx_events
                .push_back(MediaRxEvent::DroppedDependentFrames(
                    actions.dropped_dependent_frames,
                ));
        }
        Ok(())
    }

    /// Emit `Heartbeat` and advance monotonic heartbeat sequence.
    pub async fn send_heartbeat(&mut self) -> Result<(), TransportError> {
        let seq = self.next_heartbeat_seq;
        self.next_heartbeat_seq = self.next_heartbeat_seq.saturating_add(1);
        let msg = ControlMessage::Heartbeat(lumabridge_protocol::control::Heartbeat {
            session_id: self.active_session_id,
            seq,
            uptime_ms: self.elapsed_us() / 1_000,
        });
        self.send_feedback_message(&msg).await
    }

    /// Sample live transport congestion metrics and run [`BitrateAdvisor`].
    pub fn poll_congestion_and_advise_bitrate(&mut self) -> (CongestionSnapshot, Option<u64>) {
        let snap = self.snapshot_congestion();
        let suggested = self.bitrate_advisor.update(&snap, self.elapsed_us());
        if let Some(new_bps) = suggested {
            self.pacer.set_target_bps(new_bps);
        }
        (snap, suggested)
    }

    #[must_use]
    pub fn snapshot_congestion(&self) -> CongestionSnapshot {
        let effective_budget = self
            .current_packet_budget()
            .map_or(1140, |b| b.effective_lbwp_packet_budget);
        match &self.link {
            PeerTransportLink::Quic { link, .. } => {
                let qs = link.stats();
                let qc = link.counters();
                let total_sent = qs.path.sent_packets.max(1);
                let loss_ppm = u32::try_from(
                    (qs.path.lost_packets.saturating_mul(1_000_000) / total_sent).min(1_000_000),
                )
                .unwrap_or(1_000_000);
                CongestionSnapshot {
                    rtt_us: link.rtt_us(),
                    packet_loss_ppm: loss_ppm,
                    cwnd_bytes: qs.path.cwnd,
                    pacing_rate_bps: self.bitrate_advisor.current_bitrate_bps(),
                    effective_lbwp_packet_budget: effective_budget,
                    tx_queue_frames: self.scheduler.queued_frames(),
                    tx_queue_bytes: self.scheduler.queued_bytes(),
                    dropped_stale_frames: self.scheduler.total_dropped_stale(),
                    dropped_broken_gop_frames: self.scheduler.total_dropped_broken_gop(),
                    idr_requests_emitted: self.tx_idr_requests_emitted,
                    protected_blanks_sent: self.tx_protected_blanks_sent,
                    datagrams_sent: qc.datagrams_sent,
                    datagrams_received: qc.datagrams_received,
                    stream_media_records_sent: qc.stream_media_records_sent,
                    stream_media_records_received: qc.stream_media_records_received,
                }
            }
            PeerTransportLink::Tcp(link) => {
                let tc = link.counters();
                CongestionSnapshot {
                    rtt_us: 0,
                    packet_loss_ppm: 0,
                    cwnd_bytes: 0,
                    pacing_rate_bps: self.bitrate_advisor.current_bitrate_bps(),
                    effective_lbwp_packet_budget: effective_budget,
                    tx_queue_frames: self.scheduler.queued_frames(),
                    tx_queue_bytes: self.scheduler.queued_bytes(),
                    dropped_stale_frames: self
                        .scheduler
                        .total_dropped_stale()
                        .saturating_add(tc.media_pre_socket_drops),
                    dropped_broken_gop_frames: self.scheduler.total_dropped_broken_gop(),
                    idr_requests_emitted: self.tx_idr_requests_emitted,
                    protected_blanks_sent: self.tx_protected_blanks_sent,
                    datagrams_sent: 0,
                    datagrams_received: 0,
                    stream_media_records_sent: tc.stream_media_records_sent,
                    stream_media_records_received: tc.stream_media_records_received,
                }
            }
        }
    }

    /// Best-effort graceful session shutdown.
    pub async fn close_gracefully(&mut self, reason: CloseReasonCode) {
        if let Some(sid) = self.active_session_id {
            let msg = ControlMessage::SessionClose(SessionClose {
                session_id: sid,
                reason_code: reason,
                teardown_virtual_displays: true,
            });
            let _ = self.send_control_message(&msg).await;
            self.link.flush_tx().await;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        self.link.close_immediately(b"session_closed");
    }

    fn elapsed_us(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

impl Drop for OperationalConnection {
    fn drop(&mut self) {
        if let (Some(reg), Some(cid)) = (&self.registry, self.registry_conn_id) {
            reg.unregister(cid);
        }
    }
}

const QUIC_SAFE_MTU_U16: u16 = 1200;

const fn opposite_dir(dir: Direction) -> Direction {
    match dir {
        Direction::InitiatorToAcceptor => Direction::AcceptorToInitiator,
        Direction::AcceptorToInitiator => Direction::InitiatorToAcceptor,
    }
}

/// Helper keeping `ALPN_OPERATIONAL_V1` / `ALPN_PAIRING_V1` references centralized.
#[must_use]
pub const fn alpn_for_mode(pairing: bool) -> &'static [u8] {
    if pairing {
        LUMABRIDGE_PAIR_ALPN_V1
    } else {
        LUMABRIDGE_ALPN_V1
    }
}
