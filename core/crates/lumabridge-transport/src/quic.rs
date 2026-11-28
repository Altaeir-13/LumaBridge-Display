// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Encrypted `QUIC` (`RFC 9000` + `RFC 9221` datagrams & stream fallback) backed strictly
//! by `lumabridge-security` TLS 1.3 mTLS policies and channel-binding extraction.

use crate::config::TransportConfig;
use crate::error::{map_io_error, TransportError};
use crate::mtu::build_quic_mtu_discovery_config;
use lumabridge_protocol::framing::{
    encode_stream_frame, ChannelId, FrameFlags, RawStreamFrame, StreamBindingMode,
    StreamFrameDecoder,
};
use lumabridge_protocol::limits::FramingLimits;
use lumabridge_security::certificate::GeneratedDeviceCertificate;
use lumabridge_security::tls::{
    build_tls13_client_config, build_tls13_server_config, canonical_server_name_for_device,
    extract_authenticated_quic_session, AuthenticatedTlsSession, TlsPeerTrustPolicy,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

const MAX_INBOUND_UNI_STREAMS: usize = 8;

/// Wrapper holding a `quinn::Endpoint` and transport policy for QUIC client/server operation.
pub struct QuicTransportEndpoint {
    endpoint: quinn::Endpoint,
    config: TransportConfig,
}

impl QuicTransportEndpoint {
    /// Bind a server endpoint enforcing `policy` (`Pairing`, `Trusted`, or `PinnedPeer`),
    /// TLS 1.3 only, mTLS, zero 0-RTT/resumption, and `RFC 9221` datagrams.
    pub fn bind_server(
        bind_addr: SocketAddr,
        local_cert: &GeneratedDeviceCertificate,
        policy: TlsPeerTrustPolicy,
        config: TransportConfig,
    ) -> Result<Self, TransportError> {
        config.validate()?;
        let rustls_srv = build_tls13_server_config(local_cert, policy)?;
        let quic_srv = QuicServerConfig::try_from(rustls_srv)
            .map_err(|_| TransportError::HandshakeFailed("invalid QUIC server TLS config"))?;
        let mut srv_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_srv));
        srv_cfg.transport_config(build_quinn_transport_config(&config));
        let endpoint = quinn::Endpoint::server(srv_cfg, bind_addr).map_err(|e| map_io_error(&e))?;
        Ok(Self { endpoint, config })
    }

    /// Bind an ephemeral client endpoint configured for `lumabridge-security` mTLS policies.
    pub fn bind_client(
        bind_addr: SocketAddr,
        local_cert: &GeneratedDeviceCertificate,
        policy: TlsPeerTrustPolicy,
        config: TransportConfig,
    ) -> Result<Self, TransportError> {
        config.validate()?;
        let rustls_cli = build_tls13_client_config(local_cert, policy)?;
        let quic_cli = QuicClientConfig::try_from(rustls_cli)
            .map_err(|_| TransportError::HandshakeFailed("invalid QUIC client TLS config"))?;
        let mut cli_cfg = quinn::ClientConfig::new(Arc::new(quic_cli));
        cli_cfg.transport_config(build_quinn_transport_config(&config));
        let mut endpoint = quinn::Endpoint::client(bind_addr).map_err(|e| map_io_error(&e))?;
        endpoint.set_default_client_config(cli_cfg);
        Ok(Self { endpoint, config })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(|e| map_io_error(&e))
    }

    #[must_use]
    pub const fn kind(&self) -> crate::config::TransportKind {
        self.config.kind
    }

    /// Connect to `remote` expecting `expected_alpn` (`lumabridge/1` or `lumabridge-pair/1`).
    pub async fn connect(
        &self,
        remote: SocketAddr,
        server_hint_device_id: lumabridge_security::identity::DeviceId,
        expected_alpn: &[u8],
        now_unix_secs: u64,
    ) -> Result<QuicPeerLink, TransportError> {
        let sni = canonical_server_name_for_device(server_hint_device_id)?;
        let sni_str = sni.to_str().into_owned();
        let connecting = self
            .endpoint
            .connect(remote, &sni_str)
            .map_err(|_| TransportError::HandshakeFailed("invalid QUIC connect parameters"))?;
        let conn = tokio::time::timeout(
            Duration::from_millis(self.config.handshake_timeout_ms),
            connecting,
        )
        .await
        .map_err(|_| TransportError::Timeout("QUIC handshake timed out"))?
        .map_err(|_| TransportError::HandshakeFailed("QUIC handshake rejected"))?;

        let tls_session = extract_authenticated_quic_session(&conn, expected_alpn, now_unix_secs)?;
        Ok(QuicPeerLink::new(conn, tls_session, &self.config))
    }

    /// Accept the next authenticated QUIC peer connection matching `expected_alpn`.
    pub async fn accept(
        &self,
        expected_alpn: &[u8],
        now_unix_secs: u64,
    ) -> Result<QuicPeerLink, TransportError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(TransportError::ConnectionClosed("QUIC endpoint closed"))?;
        let connecting = incoming
            .accept()
            .map_err(|_| TransportError::HandshakeFailed("failed to accept QUIC incoming"))?;
        let conn = tokio::time::timeout(
            Duration::from_millis(self.config.handshake_timeout_ms),
            connecting,
        )
        .await
        .map_err(|_| TransportError::Timeout("QUIC server handshake timed out"))?
        .map_err(|_| TransportError::HandshakeFailed("QUIC server handshake rejected"))?;

        let tls_session = extract_authenticated_quic_session(&conn, expected_alpn, now_unix_secs)?;
        Ok(QuicPeerLink::new(conn, tls_session, &self.config))
    }

    /// Gracefully close endpoint sockets without panicking.
    pub fn close(&self) {
        self.endpoint.close(quinn::VarInt::from_u32(0), b"closed");
    }
}

fn build_quinn_transport_config(config: &TransportConfig) -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.initial_mtu(config.initial_mtu);
    let mut cubic = quinn::congestion::CubicConfig::default();
    cubic.initial_window(128 * 1024);
    t.congestion_controller_factory(Arc::new(cubic));
    t.initial_rtt(Duration::from_millis(10));
    t.packet_threshold(6);
    if let Some(mtu_cfg) = build_quic_mtu_discovery_config(config) {
        t.mtu_discovery_config(Some(mtu_cfg));
    } else {
        t.mtu_discovery_config(None);
    }
    t.max_concurrent_bidi_streams(4u32.into());
    t.max_concurrent_uni_streams(16u32.into());
    t.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    t.datagram_send_buffer_size(2 * 1024 * 1024);
    if let Ok(idle) =
        quinn::IdleTimeout::try_from(Duration::from_millis(config.heartbeat_timeout_ms))
    {
        t.max_idle_timeout(Some(idle));
    }
    t.keep_alive_interval(Some(Duration::from_millis(config.heartbeat_interval_ms)));
    Arc::new(t)
}

#[derive(Debug, Default)]
pub struct QuicCounters {
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub stream_media_records_sent: u64,
    pub stream_media_records_received: u64,
}

/// Active authenticated QUIC connection isolating logical LBWP channels `0..=3` onto dedicated
/// `BoundSingleChannel` unidirectional streams with independent per-channel TX locks (zero cross-channel HOL).
pub struct QuicPeerLink {
    conn: quinn::Connection,
    tls_session: AuthenticatedTlsSession,
    limits: FramingLimits,
    tx_control: AsyncMutex<Option<quinn::SendStream>>,
    tx_media: AsyncMutex<Option<quinn::SendStream>>,
    tx_feedback: AsyncMutex<Option<quinn::SendStream>>,
    tx_input: AsyncMutex<Option<quinn::SendStream>>,
    rx_control: AsyncMutex<mpsc::Receiver<RawStreamFrame>>,
    rx_media_stream: AsyncMutex<mpsc::Receiver<RawStreamFrame>>,
    rx_feedback: AsyncMutex<mpsc::Receiver<RawStreamFrame>>,
    rx_input: AsyncMutex<mpsc::Receiver<RawStreamFrame>>,
    counters: Arc<StdMutex<QuicCounters>>,
    close_tx: watch::Sender<bool>,
    accept_task: JoinHandle<()>,
}

impl QuicPeerLink {
    fn new(
        conn: quinn::Connection,
        tls_session: AuthenticatedTlsSession,
        config: &TransportConfig,
    ) -> Self {
        let (tx_ctrl, rx_ctrl) = mpsc::channel(config.max_control_queue);
        let (tx_media, rx_media) = mpsc::channel(config.max_media_queue_frames.saturating_mul(64));
        let (tx_fb, rx_fb) = mpsc::channel(config.max_feedback_queue);
        let (tx_inp, rx_inp) = mpsc::channel(config.max_input_queue);
        let (close_tx, mut close_rx) = watch::channel(false);

        let counters = Arc::new(StdMutex::new(QuicCounters::default()));
        let limits = config.framing_limits;
        let conn_clone = conn.clone();
        let counters_clone = Arc::clone(&counters);

        let accept_task = tokio::spawn(async move {
            let mut active_readers = 0usize;
            let mut reader_handles: Vec<JoinHandle<()>> = Vec::new();
            loop {
                tokio::select! {
                    changed = close_rx.changed() => {
                        if changed.is_err() || *close_rx.borrow() {
                            break;
                        }
                    }
                    incoming = conn_clone.accept_uni() => {
                        let Ok(mut stream) = incoming else {
                            break;
                        };
                        active_readers += 1;
                        if active_readers > MAX_INBOUND_UNI_STREAMS {
                            conn_clone.close(quinn::VarInt::from_u32(1), b"too_many_streams");
                            break;
                        }
                        let tx_ctrl_c = tx_ctrl.clone();
                        let tx_media_c = tx_media.clone();
                        let tx_fb_c = tx_fb.clone();
                        let tx_inp_c = tx_inp.clone();
                        let counters_c = Arc::clone(&counters_clone);
                        let conn_inner = conn_clone.clone();
                        let mut reader_close = close_rx.clone();
                        let h = tokio::spawn(async move {
                            let Ok(mut dec) = StreamFrameDecoder::new(
                                limits,
                                StreamBindingMode::UnboundSingleChannel,
                            ) else {
                                return;
                            };
                            let mut buf = vec![0u8; 8192];
                            loop {
                                tokio::select! {
                                    changed = reader_close.changed() => {
                                        if changed.is_err() || *reader_close.borrow() {
                                            break;
                                        }
                                    }
                                    res = stream.read(&mut buf) => {
                                        match res {
                                            Ok(Some(n)) => {
                                                if dec.feed(&buf[..n]).is_err() {
                                                    conn_inner.close(quinn::VarInt::from_u32(1), b"frame_error");
                                                    break;
                                                }
                                                loop {
                                                    match dec.next_frame() {
                                                        Ok(Some(frame)) => {
                                                            let ch = frame.header.channel_id;
                                                            let tx = match ch {
                                                                ChannelId::Control => &tx_ctrl_c,
                                                                ChannelId::Media => {
                                                                    if let Ok(mut c) = counters_c.lock() {
                                                                        c.stream_media_records_received =
                                                                            c.stream_media_records_received.saturating_add(1);
                                                                    }
                                                                    &tx_media_c
                                                                }
                                                                ChannelId::Feedback => &tx_fb_c,
                                                                ChannelId::Input => &tx_inp_c,
                                                            };
                                                            if tx.send(frame).await.is_err() {
                                                                return;
                                                            }
                                                        }
                                                        Ok(None) => break,
                                                        Err(_) => {
                                                            conn_inner.close(quinn::VarInt::from_u32(1), b"bad_stream_frame");
                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                            Ok(None) => {
                                                if dec.finish_eof().is_err() {
                                                    conn_inner.close(quinn::VarInt::from_u32(1), b"truncated_eof");
                                                }
                                                break;
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                }
                            }
                        });
                        reader_handles.push(h);
                    }
                }
            }
            for h in reader_handles {
                h.abort();
            }
        });

        Self {
            conn,
            tls_session,
            limits,
            tx_control: AsyncMutex::new(None),
            tx_media: AsyncMutex::new(None),
            tx_feedback: AsyncMutex::new(None),
            tx_input: AsyncMutex::new(None),
            rx_control: AsyncMutex::new(rx_ctrl),
            rx_media_stream: AsyncMutex::new(rx_media),
            rx_feedback: AsyncMutex::new(rx_fb),
            rx_input: AsyncMutex::new(rx_inp),
            counters,
            close_tx,
            accept_task,
        }
    }

    #[must_use]
    pub const fn tls_session(&self) -> &AuthenticatedTlsSession {
        &self.tls_session
    }

    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    #[must_use]
    pub fn rtt_us(&self) -> u64 {
        u64::try_from(self.conn.rtt().as_micros()).unwrap_or(u64::MAX)
    }

    #[must_use]
    pub fn stats(&self) -> quinn::ConnectionStats {
        self.conn.stats()
    }

    #[must_use]
    pub fn counters(&self) -> QuicCounters {
        self.counters
            .lock()
            .map_or_else(|_| QuicCounters::default(), |c| QuicCounters { ..*c })
    }

    /// Encode and transmit a reliable LBWP stream frame over the dedicated single-channel lock
    /// (independent mutex per logical `ChannelId` prevents cross-channel TX head-of-line stalling).
    pub async fn send_stream_frame(
        &self,
        channel: ChannelId,
        msg_type: u16,
        flags: FrameFlags,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        let encoded = encode_stream_frame(channel, msg_type, flags, payload, &self.limits)?;
        let tx_slot = match channel {
            ChannelId::Control => &self.tx_control,
            ChannelId::Media => &self.tx_media,
            ChannelId::Feedback => &self.tx_feedback,
            ChannelId::Input => &self.tx_input,
        };
        let mut guard = tx_slot.lock().await;
        if guard.is_none() {
            let stream =
                self.conn.open_uni().await.map_err(|_| {
                    TransportError::ConnectionClosed("failed opening QUIC uni stream")
                })?;
            *guard = Some(stream);
        }
        let stream = guard
            .as_mut()
            .ok_or(TransportError::ConnectionClosed("missing send stream"))?;
        if stream.write_all(&encoded).await.is_err() {
            *guard = None;
            return Err(TransportError::ConnectionClosed("QUIC stream write failed"));
        }
        drop(guard);
        if channel == ChannelId::Media {
            if let Ok(mut c) = self.counters.lock() {
                c.stream_media_records_sent = c.stream_media_records_sent.saturating_add(1);
            }
        }
        Ok(())
    }

    /// Transmit an unreliable `RFC 9221` media packet (`[44 B VideoPacketHeader | payload]`).
    pub fn send_media_datagram(&self, packet: &[u8]) -> Result<(), TransportError> {
        let max = self
            .conn
            .max_datagram_size()
            .ok_or(TransportError::InvalidConfig(
                "peer disabled QUIC datagrams",
            ))?;
        if packet.len() > max {
            return Err(TransportError::LimitExceeded(
                "media datagram exceeds live QUIC max_datagram_size",
            ));
        }
        self.conn
            .send_datagram(bytes::Bytes::copy_from_slice(packet))
            .map_err(|_| TransportError::ConnectionClosed("QUIC datagram send failed"))?;
        if let Ok(mut c) = self.counters.lock() {
            c.datagrams_sent = c.datagrams_sent.saturating_add(1);
        }
        Ok(())
    }

    /// Receive the next reliable frame arriving on `channel`.
    pub async fn recv_stream_frame(
        &self,
        channel: ChannelId,
    ) -> Result<RawStreamFrame, TransportError> {
        let mut rx = match channel {
            ChannelId::Control => self.rx_control.lock().await,
            ChannelId::Media => self.rx_media_stream.lock().await,
            ChannelId::Feedback => self.rx_feedback.lock().await,
            ChannelId::Input => self.rx_input.lock().await,
        };
        rx.recv().await.ok_or(TransportError::ConnectionClosed(
            "QUIC stream receiver closed",
        ))
    }

    /// Non-blocking poll for reliable stream records (used to prioritize `ProtectedBlank` over datagrams).
    pub async fn try_recv_media_stream_frame(&self) -> Option<RawStreamFrame> {
        self.rx_media_stream.lock().await.try_recv().ok()
    }

    /// Receive the next unreliable `RFC 9221` datagram from the QUIC peer.
    pub async fn recv_media_datagram(&self) -> Result<Vec<u8>, TransportError> {
        let bytes = self
            .conn
            .read_datagram()
            .await
            .map_err(|_| TransportError::ConnectionClosed("QUIC datagram channel closed"))?;
        if let Ok(mut c) = self.counters.lock() {
            c.datagrams_received = c.datagrams_received.saturating_add(1);
        }
        Ok(bytes.to_vec())
    }

    /// Close immediately (e.g., on peer revocation, fatal framing error, or drop).
    pub fn close_immediately(&self, reason_code: u32, reason: &[u8]) {
        let _ = self.close_tx.send(true);
        self.conn
            .close(quinn::VarInt::from_u32(reason_code), reason);
    }
}

impl Drop for QuicPeerLink {
    fn drop(&mut self) {
        let _ = self.close_tx.send(true);
        self.accept_task.abort();
    }
}
