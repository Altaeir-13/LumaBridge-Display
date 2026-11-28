// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mandatory `TCP / TLS 1.3` (`TCP_NODELAY`) transport fallback with strict channel priority
//! arbitration and non-stalling RX/TX pre-socket media drop on congestion (`ADR-0005` §1.1).

use crate::config::TransportConfig;
use crate::error::{map_io_error, TransportError};
use lumabridge_protocol::framing::{
    encode_stream_frame, ChannelId, FrameFlags, RawStreamFrame, StreamBindingMode,
    StreamFrameDecoder,
};
use lumabridge_protocol::limits::FramingLimits;
use lumabridge_protocol::media::header::{decode_video_packet, VideoFlags};
use lumabridge_security::certificate::GeneratedDeviceCertificate;
use lumabridge_security::tls::{
    build_tls13_client_config, build_tls13_server_config, canonical_server_name_for_device,
    extract_authenticated_session_with_alpn, AuthenticatedTlsSession, TlsPeerTrustPolicy,
};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex, Notify};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Debug, Default)]
pub struct TcpCounters {
    pub stream_media_records_sent: u64,
    pub stream_media_records_received: u64,
    pub media_pre_socket_drops: u64,
    pub media_rx_overflow_drops: u64,
}

fn is_protected_blank_record(frame: &RawStreamFrame) -> bool {
    decode_video_packet(&frame.payload, frame.payload.len())
        .is_ok_and(|(h, _)| h.flags.contains(VideoFlags::PROTECTED_BLANK))
}

#[derive(Default)]
struct BoundedMediaRxQueue {
    buf: VecDeque<RawStreamFrame>,
    closed: bool,
    cap: usize,
}

impl BoundedMediaRxQueue {
    fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(cap),
            closed: false,
            cap: cap.max(4),
        }
    }

    /// Push non-blocking: `ProtectedBlank` preempts oldest non-blank frames if full;
    /// ordinary video frames drop oldest non-blank on overflow so RX `Control`/`Feedback`/`Input`
    /// never block inside `read_task`. Returns `true` if pushed, `false` if overflow-dropped.
    fn push_non_blocking(&mut self, frame: RawStreamFrame) -> bool {
        if self.closed {
            return false;
        }
        let blank = is_protected_blank_record(&frame);
        if self.buf.len() >= self.cap {
            if let Some(pos) = self.buf.iter().position(|f| !is_protected_blank_record(f)) {
                let _ = self.buf.remove(pos);
                self.buf.push_back(frame);
                return !blank; // dropped an old non-blank record
            }
            if !blank {
                return false;
            }
            let _ = self.buf.pop_front();
        }
        self.buf.push_back(frame);
        true
    }
}

/// Server listener wrapping `tokio::net::TcpListener` + `tokio_rustls::TlsAcceptor`.
pub struct TcpTlsServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    config: TransportConfig,
}

impl TcpTlsServer {
    pub async fn bind(
        bind_addr: SocketAddr,
        local_cert: &GeneratedDeviceCertificate,
        policy: TlsPeerTrustPolicy,
        config: TransportConfig,
    ) -> Result<Self, TransportError> {
        config.validate()?;
        let rustls_cfg = build_tls13_server_config(local_cert, policy)?;
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| map_io_error(&e))?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(rustls_cfg),
            config,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.listener.local_addr().map_err(|e| map_io_error(&e))
    }

    pub async fn accept(
        &self,
        expected_alpn: &[u8],
        now_unix_secs: u64,
    ) -> Result<TcpPeerLink, TransportError> {
        let (stream, _) = self.listener.accept().await.map_err(|e| map_io_error(&e))?;
        stream
            .set_nodelay(self.config.tcp_nodelay)
            .map_err(|e| map_io_error(&e))?;
        let tls_stream = tokio::time::timeout(
            Duration::from_millis(self.config.handshake_timeout_ms),
            self.acceptor.accept(stream),
        )
        .await
        .map_err(|_| TransportError::Timeout("TCP TLS server handshake timed out"))?
        .map_err(|_| TransportError::HandshakeFailed("TCP TLS server handshake rejected"))?;

        let (_, server_conn) = tls_stream.get_ref();
        let tls_session =
            extract_authenticated_session_with_alpn(server_conn, expected_alpn, now_unix_secs)?;
        Ok(TcpPeerLink::spawn_from_tls(
            tokio_rustls::TlsStream::Server(tls_stream),
            tls_session,
            &self.config,
        ))
    }
}

/// Connect to a `TCP / TLS 1.3` peer enforcing `policy` and `TCP_NODELAY`.
pub async fn connect_tcp_tls(
    remote: SocketAddr,
    local_cert: &GeneratedDeviceCertificate,
    policy: TlsPeerTrustPolicy,
    server_hint_device_id: lumabridge_security::identity::DeviceId,
    expected_alpn: &[u8],
    now_unix_secs: u64,
    config: &TransportConfig,
) -> Result<TcpPeerLink, TransportError> {
    config.validate()?;
    let rustls_cfg = build_tls13_client_config(local_cert, policy)?;
    let connector = TlsConnector::from(rustls_cfg);
    let stream = tokio::time::timeout(
        Duration::from_millis(config.handshake_timeout_ms),
        TcpStream::connect(remote),
    )
    .await
    .map_err(|_| TransportError::Timeout("TCP connect timed out"))?
    .map_err(|e| map_io_error(&e))?;
    stream
        .set_nodelay(config.tcp_nodelay)
        .map_err(|e| map_io_error(&e))?;
    let sni = canonical_server_name_for_device(server_hint_device_id)?;
    let tls_stream = tokio::time::timeout(
        Duration::from_millis(config.handshake_timeout_ms),
        connector.connect(sni, stream),
    )
    .await
    .map_err(|_| TransportError::Timeout("TCP TLS client handshake timed out"))?
    .map_err(|_| TransportError::HandshakeFailed("TCP TLS client handshake rejected"))?;

    let (_, client_conn) = tls_stream.get_ref();
    let tls_session =
        extract_authenticated_session_with_alpn(client_conn, expected_alpn, now_unix_secs)?;
    Ok(TcpPeerLink::spawn_from_tls(
        tokio_rustls::TlsStream::Client(tls_stream),
        tls_session,
        config,
    ))
}

/// Multiplexed TLS 1.3 byte-stream connection with strict channel priority queues,
/// non-stalling RX media buffering, and pre-socket congestion drop on TX media (`Channel 1`).
pub struct TcpPeerLink {
    tls_session: AuthenticatedTlsSession,
    limits: FramingLimits,
    tx_control: mpsc::Sender<Vec<u8>>,
    tx_feedback: mpsc::Sender<Vec<u8>>,
    tx_input: mpsc::Sender<Vec<u8>>,
    tx_protected_blank: mpsc::Sender<Vec<u8>>,
    tx_media: mpsc::Sender<Vec<u8>>,
    rx_control: AsyncMutex<mpsc::Receiver<RawStreamFrame>>,
    rx_media_queue: Arc<StdMutex<BoundedMediaRxQueue>>,
    rx_media_notify: Arc<Notify>,
    rx_feedback: AsyncMutex<mpsc::Receiver<RawStreamFrame>>,
    rx_input: AsyncMutex<mpsc::Receiver<RawStreamFrame>>,
    counters: Arc<StdMutex<TcpCounters>>,
    close_tx: watch::Sender<bool>,
    io_tasks: Vec<JoinHandle<()>>,
}

impl TcpPeerLink {
    fn spawn_from_tls(
        tls_stream: tokio_rustls::TlsStream<TcpStream>,
        tls_session: AuthenticatedTlsSession,
        config: &TransportConfig,
    ) -> Self {
        let (mut reader, mut writer) = tokio::io::split(tls_stream);
        let media_queue_cap = config.max_media_queue_frames.saturating_mul(64).max(16);
        let (tx_ctrl_out, mut rx_ctrl_out) = mpsc::channel::<Vec<u8>>(config.max_control_queue);
        let (tx_fb_out, mut rx_fb_out) = mpsc::channel::<Vec<u8>>(config.max_feedback_queue);
        let (tx_inp_out, mut rx_inp_out) = mpsc::channel::<Vec<u8>>(config.max_input_queue);
        let (tx_blank_out, mut rx_blank_out) = mpsc::channel::<Vec<u8>>(16);
        let (tx_media_out, mut rx_media_out) = mpsc::channel::<Vec<u8>>(media_queue_cap);

        let (tx_ctrl_in, rx_ctrl_in) = mpsc::channel(config.max_control_queue);
        let (tx_fb_in, rx_fb_in) = mpsc::channel(config.max_feedback_queue);
        let (tx_inp_in, rx_inp_in) = mpsc::channel(config.max_input_queue);
        let rx_media_queue = Arc::new(StdMutex::new(BoundedMediaRxQueue::new(media_queue_cap)));
        let rx_media_notify = Arc::new(Notify::new());

        let (close_tx, mut close_rx_w) = watch::channel(false);
        let mut close_rx_r = close_tx.subscribe();
        let counters = Arc::new(StdMutex::new(TcpCounters::default()));
        let counters_r = Arc::clone(&counters);
        let counters_w = Arc::clone(&counters);
        let limits = config.framing_limits;
        let rx_media_q_w = Arc::clone(&rx_media_queue);
        let rx_media_n_w = Arc::clone(&rx_media_notify);

        let write_task = tokio::spawn(async move {
            loop {
                let next_buf = tokio::select! {
                    biased;
                    changed = close_rx_w.changed() => {
                        if changed.is_err() || *close_rx_w.borrow() {
                            break;
                        }
                        continue;
                    }
                    Some(b) = rx_ctrl_out.recv() => b,
                    Some(b) = rx_blank_out.recv() => {
                        if let Ok(mut c) = counters_w.lock() {
                            c.stream_media_records_sent = c.stream_media_records_sent.saturating_add(1);
                        }
                        b
                    }
                    Some(b) = rx_fb_out.recv() => b,
                    Some(b) = rx_inp_out.recv() => b,
                    Some(b) = rx_media_out.recv() => {
                        if let Ok(mut c) = counters_w.lock() {
                            c.stream_media_records_sent = c.stream_media_records_sent.saturating_add(1);
                        }
                        b
                    }
                    else => break,
                };
                if writer.write_all(&next_buf).await.is_err() || writer.flush().await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });

        let read_task = tokio::spawn(async move {
            let Ok(mut dec) = StreamFrameDecoder::new(limits, StreamBindingMode::Multiplexed)
            else {
                return;
            };
            let mut buf = vec![0u8; 8192];
            loop {
                tokio::select! {
                    changed = close_rx_r.changed() => {
                        if changed.is_err() || *close_rx_r.borrow() {
                            break;
                        }
                    }
                    res = reader.read(&mut buf) => {
                        match res {
                            Ok(0) => {
                                let _ = dec.finish_eof();
                                break;
                            }
                            Err(_) => break,
                            Ok(n) => {
                                if dec.feed(&buf[..n]).is_err() {
                                    break;
                                }
                                loop {
                                    match dec.next_frame() {
                                        Ok(Some(frame)) => {
                                            match frame.header.channel_id {
                                                ChannelId::Media => {
                                                    if let Ok(mut c) = counters_r.lock() {
                                                        c.stream_media_records_received =
                                                            c.stream_media_records_received.saturating_add(1);
                                                    }
                                                    let dropped_overflow = rx_media_q_w
                                                        .lock()
                                                        .map_or(true, |mut q| !q.push_non_blocking(frame));
                                                    if dropped_overflow {
                                                        if let Ok(mut c) = counters_r.lock() {
                                                            c.media_rx_overflow_drops =
                                                                c.media_rx_overflow_drops.saturating_add(1);
                                                        }
                                                    }
                                                    rx_media_n_w.notify_one();
                                                }
                                                ChannelId::Control => {
                                                    if tx_ctrl_in.send(frame).await.is_err() {
                                                        return;
                                                    }
                                                }
                                                ChannelId::Feedback => {
                                                    if tx_fb_in.send(frame).await.is_err() {
                                                        return;
                                                    }
                                                }
                                                ChannelId::Input => {
                                                    if tx_inp_in.send(frame).await.is_err() {
                                                        return;
                                                    }
                                                }
                                            }
                                        }
                                        Ok(None) => break,
                                        Err(_) => return,
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Ok(mut q) = rx_media_q_w.lock() {
                q.closed = true;
            }
            rx_media_n_w.notify_waiters();
        });

        Self {
            tls_session,
            limits,
            tx_control: tx_ctrl_out,
            tx_feedback: tx_fb_out,
            tx_input: tx_inp_out,
            tx_protected_blank: tx_blank_out,
            tx_media: tx_media_out,
            rx_control: AsyncMutex::new(rx_ctrl_in),
            rx_media_queue,
            rx_media_notify,
            rx_feedback: AsyncMutex::new(rx_fb_in),
            rx_input: AsyncMutex::new(rx_inp_in),
            counters,
            close_tx,
            io_tasks: vec![write_task, read_task],
        }
    }

    #[must_use]
    pub const fn tls_session(&self) -> &AuthenticatedTlsSession {
        &self.tls_session
    }

    #[must_use]
    pub fn counters(&self) -> TcpCounters {
        self.counters
            .lock()
            .map_or_else(|_| TcpCounters::default(), |c| TcpCounters { ..*c })
    }

    /// Encode and send a frame respecting channel priority (`ProtectedBlank` preempts normal media).
    pub async fn send_stream_frame(
        &self,
        channel: ChannelId,
        msg_type: u16,
        flags: FrameFlags,
        payload: &[u8],
        is_protected_blank: bool,
    ) -> Result<(), TransportError> {
        let encoded = encode_stream_frame(channel, msg_type, flags, payload, &self.limits)?;
        match channel {
            ChannelId::Control => self
                .tx_control
                .send(encoded)
                .await
                .map_err(|_| TransportError::ConnectionClosed("TCP control TX closed")),
            ChannelId::Feedback => self
                .tx_feedback
                .send(encoded)
                .await
                .map_err(|_| TransportError::ConnectionClosed("TCP feedback TX closed")),
            ChannelId::Input => self
                .tx_input
                .send(encoded)
                .await
                .map_err(|_| TransportError::ConnectionClosed("TCP input TX closed")),
            ChannelId::Media if is_protected_blank => self
                .tx_protected_blank
                .send(encoded)
                .await
                .map_err(|_| TransportError::ConnectionClosed("TCP ProtectedBlank TX closed")),
            ChannelId::Media => {
                // Pre-socket congestion drop (`ADR-0005` §1.1): never block waiting on saturated TCP window.
                match self.tx_media.try_send(encoded) {
                    Ok(()) => Ok(()),
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        if let Ok(mut c) = self.counters.lock() {
                            c.media_pre_socket_drops = c.media_pre_socket_drops.saturating_add(1);
                        }
                        Err(TransportError::QueueFull("TCP media TX queue saturated"))
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        Err(TransportError::ConnectionClosed("TCP media TX closed"))
                    }
                }
            }
        }
    }

    pub async fn recv_stream_frame(
        &self,
        channel: ChannelId,
    ) -> Result<RawStreamFrame, TransportError> {
        if channel == ChannelId::Media {
            loop {
                let notified = self.rx_media_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let Ok(mut q) = self.rx_media_queue.lock() else {
                        return Err(TransportError::ConnectionClosed("TCP media queue poisoned"));
                    };
                    if let Some(frame) = q.buf.pop_front() {
                        return Ok(frame);
                    }
                    if q.closed {
                        return Err(TransportError::ConnectionClosed("TCP media RX closed"));
                    }
                }
                notified.await;
            }
        }
        let mut rx = match channel {
            ChannelId::Control => self.rx_control.lock().await,
            ChannelId::Feedback => self.rx_feedback.lock().await,
            ChannelId::Input => self.rx_input.lock().await,
            ChannelId::Media => unreachable!(),
        };
        rx.recv()
            .await
            .ok_or(TransportError::ConnectionClosed("TCP stream RX closed"))
    }

    pub fn close_immediately(&self) {
        let _ = self.close_tx.send(true);
        if let Ok(mut q) = self.rx_media_queue.lock() {
            q.closed = true;
        }
        self.rx_media_notify.notify_waiters();
    }
}

impl Drop for TcpPeerLink {
    fn drop(&mut self) {
        self.close_immediately();
        for t in &self.io_tasks {
            t.abort();
        }
    }
}
