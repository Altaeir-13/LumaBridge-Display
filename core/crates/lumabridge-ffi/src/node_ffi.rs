// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Additive operational node FFI boundary (`lb_node_*`) exposing `LumaBridgeNode` over the
//! versioned C ABI (`ADR-0004` + `M1.5`) while preserving `lb_core_*` unchanged and isolated.

use crate::{
    alloc_rust_owned_buffer, read_and_validate_abi_input, validate_abi_output, LbAbiHeader,
    LbOwnedBuffer, LbStatus,
};
use lumabridge_core::node::{
    LumaBridgeNode, NodeConfig, NodeError, NodeMediaEvent, NodeSignalEvent,
};
use lumabridge_core::telemetry::SessionTelemetrySummary;
use lumabridge_protocol::control::{
    ActiveDisplayConfig, CaptureMode, CloseReasonCode, CodecCapability, ColorFormat,
    ControlMessage, DisplayMode, DisplayRequest, InputCapabilities, LatencyProfile,
    NodeCapabilities, OsGraphicsPlatform, Permissions, RoleFlags, RotationDeg,
};
use lumabridge_protocol::media::fragmentation::FrameKind;
use lumabridge_protocol::media::header::VideoFlags;
use lumabridge_protocol::version::CodecId;
use lumabridge_security::authorization::AuthorizationPolicyContext;
use lumabridge_security::identity::{DeviceId, PeerRole};
use lumabridge_security::pairing::{HumanApprovalDecision, PinPairingWindow};
use lumabridge_security::secret::{CheckedOsCryptoRng, PinSecret};
use lumabridge_security::tls::{LUMABRIDGE_ALPN_V1, LUMABRIDGE_PAIR_ALPN_V1};
use lumabridge_security::trust_store::{RevocationReason, TrustStore};
use lumabridge_transport::config::{TransportConfig, TransportKind};
use lumabridge_transport::error::TransportError;
use lumabridge_transport::queue::OutboundVideoFrame;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Operational node role across `lb_node_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LbNodeRole {
    Host = 1,
    Controller = 2,
}

/// Transport mode exposed across `lb_node_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LbNodeTransportKind {
    QuicDatagram = 1,
    QuicStream = 2,
    TcpTls = 3,
}

/// Configuration passed to `lb_node_create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LbNodeConfig {
    pub abi: LbAbiHeader,
    pub role: u32,
    pub transport_kind: u32,
    pub max_virtual_displays: u16,
    pub reserved0: u16,
    pub heartbeat_timeout_ms: u32,
    pub friendly_name: [u8; 48],
    pub friendly_name_len: u32,
    pub reserved1: u32,
}

/// Privacy-sanitized operational node telemetry output structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LbNodeTelemetry {
    pub abi: LbAbiHeader,
    pub frames_sent: u64,
    pub frames_delivered: u64,
    pub dropped_frames: u64,
    pub idr_requests: u64,
    pub protected_blanks: u64,
    pub unauthorized_input_drops: u64,
    pub clock_sync_rtt_us: u64,
    pub e2e_p50_us: u64,
    pub e2e_p95_us: u64,
    pub e2e_p99_us: u64,
}

/// Opaque native handle owning an isolated Tokio runtime and [`LumaBridgeNode`].
///
/// # Caller Contract
/// - Destroyed strictly once via `lb_node_destroy`.
pub struct LbNodeHandle {
    runtime: tokio::runtime::Runtime,
    node: Arc<LumaBridgeNode>,
}

fn node_panic_boundary(f: impl FnOnce() -> LbStatus) -> LbStatus {
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or(LbStatus::InternalPanic)
}

fn map_role(raw: u32) -> Result<PeerRole, LbStatus> {
    match raw {
        1 => Ok(PeerRole::Host),
        2 => Ok(PeerRole::Controller),
        _ => Err(LbStatus::InvalidArgument),
    }
}

fn map_transport(raw: u32) -> Result<TransportKind, LbStatus> {
    match raw {
        1 => Ok(TransportKind::QuicDatagram),
        2 => Ok(TransportKind::QuicStream),
        3 => Ok(TransportKind::TcpTls),
        _ => Err(LbStatus::InvalidArgument),
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1_700_000_000, |d| d.as_secs())
}

fn default_node_caps(max_virtual_displays: u8) -> NodeCapabilities {
    NodeCapabilities {
        roles_mask: RoleFlags::CAN_RECEIVE_VIDEO
            .union(RoleFlags::CAN_EXTEND_SESSION)
            .union(RoleFlags::CAN_SEND_INPUT)
            .union(RoleFlags::CAN_RECEIVE_INPUT),
        platform: OsGraphicsPlatform::Other,
        codecs: vec![CodecCapability {
            codec_id: CodecId::H264,
            can_encode: true,
            can_decode: true,
            hw_accelerated: false,
            max_width: 1920,
            max_height: 1080,
            max_fps_num: 60,
            max_fps_den: 1,
            max_b_frames: 0,
        }],
        max_virtual_displays,
        supports_scale: true,
        supports_rotation: true,
        input_caps_mask: InputCapabilities::POINTER.union(InputCapabilities::KEYBOARD),
    }
}

/// Create an operational [`LbNodeHandle`] with a freshly generated Ed25519 identity and certificate.
///
/// # Safety
/// - `config` must pass 16-byte `LbAbiHeader` + full `LbNodeConfig` validation.
/// - `out_handle` must be aligned, writable, and non-null.
#[no_mangle]
pub unsafe extern "C" fn lb_node_create(
    config: *const LbNodeConfig,
    out_handle: *mut *mut LbNodeHandle,
) -> LbStatus {
    node_panic_boundary(|| {
        if config.is_null() || out_handle.is_null() || !out_handle.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller contract guarantees aligned writable `*out_handle`.
        unsafe { ptr::write(out_handle, ptr::null_mut()) };

        // SAFETY: Validates 16-byte `LbAbiHeader` and alignment before reading `LbNodeConfig`.
        let raw_cfg = match unsafe { read_and_validate_abi_input(config) } {
            Ok(c) => c,
            Err(s) => return s,
        };
        if raw_cfg.reserved0 != 0 || raw_cfg.reserved1 != 0 {
            return LbStatus::InvalidArgument;
        }
        let Ok(role) = map_role(raw_cfg.role) else {
            return LbStatus::InvalidArgument;
        };
        let Ok(kind) = map_transport(raw_cfg.transport_kind) else {
            return LbStatus::InvalidArgument;
        };
        let name_len = usize::try_from(raw_cfg.friendly_name_len).unwrap_or(usize::MAX);
        if name_len == 0 || name_len > raw_cfg.friendly_name.len() {
            return LbStatus::InvalidArgument;
        }
        let Ok(friendly_name) = core::str::from_utf8(&raw_cfg.friendly_name[..name_len]) else {
            return LbStatus::InvalidArgument;
        };
        let mut transport_config = TransportConfig {
            kind,
            ..TransportConfig::default()
        };
        if raw_cfg.heartbeat_timeout_ms > 0 {
            transport_config.heartbeat_timeout_ms =
                u64::from(raw_cfg.heartbeat_timeout_ms).max(100);
        }
        let max_disp = u8::try_from(raw_cfg.max_virtual_displays)
            .unwrap_or(1)
            .max(1);
        let Ok(mut rng) = CheckedOsCryptoRng::preflight() else {
            return LbStatus::Faulted;
        };
        let Ok(node) = LumaBridgeNode::generate(
            NodeConfig {
                friendly_name: friendly_name.to_owned(),
                role,
                capabilities: default_node_caps(max_disp),
                transport_config,
                policy_ctx: AuthorizationPolicyContext::allow_all_v1(),
                session_ttl_secs: 3600,
                resume_ttl_secs: 600,
                max_connections: 16,
            },
            &mut rng,
            now_unix_secs().saturating_sub(300),
            7_200,
        ) else {
            return LbStatus::InvalidArgument;
        };
        let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        else {
            return LbStatus::Faulted;
        };
        let boxed = Box::new(LbNodeHandle {
            runtime,
            node: Arc::new(node),
        });
        // SAFETY: Validated non-null aligned `out_handle`.
        unsafe { ptr::write(out_handle, Box::into_raw(boxed)) };
        LbStatus::Ok
    })
}

/// Destroy an [`LbNodeHandle`], shutting down its Tokio runtime and clearing credentials.
///
/// # Safety
/// `handle` must be null or a valid pointer produced by [`lb_node_create`] with no concurrent use.
#[no_mangle]
pub unsafe extern "C" fn lb_node_destroy(handle: *mut LbNodeHandle) -> LbStatus {
    node_panic_boundary(|| {
        if handle.is_null() {
            return LbStatus::Ok;
        }
        if !handle.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Owned exclusive pointer from `lb_node_create`.
        let boxed = unsafe { Box::from_raw(handle) };
        drop(boxed);
        LbStatus::Ok
    })
}

/// Copy the node's 32-byte canonical `DeviceId` (`SHA-256(Ed25519 SPKI)`) into `out_id`.
///
/// # Safety
/// `out_id` must be valid for writing `out_len` bytes (requires `out_len >= 32`).
#[no_mangle]
pub unsafe extern "C" fn lb_node_local_device_id(
    handle: *const LbNodeHandle,
    out_id: *mut u8,
    out_len: usize,
) -> LbStatus {
    node_panic_boundary(|| {
        if handle.is_null() || !handle.is_aligned() || out_id.is_null() {
            return LbStatus::InvalidArgument;
        }
        if out_len < 32 {
            return LbStatus::BufferTooSmall;
        }
        // SAFETY: Caller guarantees valid aligned `handle`.
        let wrapper = unsafe { &*handle };
        // SAFETY: Caller guarantees writable `out_id` for `out_len >= 32` bytes.
        let dst = unsafe { slice::from_raw_parts_mut(out_id, 32) };
        dst.copy_from_slice(wrapper.node.device_id().as_bytes());
        LbStatus::Ok
    })
}

/// Revoke a peer by 32-byte `DeviceId`, terminating active connections via `ConnectionRegistry`.
///
/// # Safety
/// `peer_id` must point to at least 32 readable bytes (`id_len >= 32`).
#[no_mangle]
pub unsafe extern "C" fn lb_node_revoke_peer(
    handle: *mut LbNodeHandle,
    peer_id: *const u8,
    id_len: usize,
) -> LbStatus {
    node_panic_boundary(|| {
        if handle.is_null() || !handle.is_aligned() || peer_id.is_null() || id_len < 32 {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller guarantees readable 32 bytes at `peer_id`.
        let raw = unsafe { slice::from_raw_parts(peer_id, 32) };
        let Ok(arr) = <[u8; 32]>::try_from(raw) else {
            return LbStatus::InvalidArgument;
        };
        // SAFETY: Caller guarantees aligned live `handle`.
        let wrapper = unsafe { &*handle };
        match wrapper.node.revoke_peer(
            DeviceId::from_bytes(arr),
            RevocationReason::UserRemovedDevice,
            now_unix_secs(),
        ) {
            Ok(_) => LbStatus::Ok,
            Err(_) => LbStatus::Faulted,
        }
    })
}

/// Query whether `peer_id` is currently trusted and non-revoked in `handle`'s `TrustStore`.
///
/// # Safety
/// `peer_id` must point to 32 readable bytes; `out_trusted` must be aligned and writable.
#[no_mangle]
pub unsafe extern "C" fn lb_node_is_peer_trusted(
    handle: *const LbNodeHandle,
    peer_id: *const u8,
    id_len: usize,
    out_trusted: *mut u32,
) -> LbStatus {
    node_panic_boundary(|| {
        if handle.is_null()
            || !handle.is_aligned()
            || peer_id.is_null()
            || id_len < 32
            || out_trusted.is_null()
            || !out_trusted.is_aligned()
        {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller guarantees readable 32 bytes at `peer_id`.
        let raw = unsafe { slice::from_raw_parts(peer_id, 32) };
        let Ok(arr) = <[u8; 32]>::try_from(raw) else {
            return LbStatus::InvalidArgument;
        };
        let did = DeviceId::from_bytes(arr);
        // SAFETY: Caller guarantees aligned live `handle`.
        let wrapper = unsafe { &*handle };
        let store = wrapper.node.trust_store();
        let trusted = u32::from(!store.is_revoked(did) && store.get_peer(did).is_some());
        // SAFETY: Caller guarantees aligned writable `out_trusted`.
        unsafe { ptr::write(out_trusted, trusted) };
        LbStatus::Ok
    })
}

/// Execute an end-to-end encrypted loopback self-test (SPAKE2 pairing + mTLS `SessionOpen` +
/// `frame_count` synthetic 1080p60 frames + `ProtectedBlank`) between two initialized [`LbNodeHandle`]s.
///
/// # Safety
/// - `host` and `receiver` must be distinct, aligned, valid handles (`Host` and `Controller`).
/// - `out_telemetry` must satisfy `LbAbiHeader` validation before writing.
#[no_mangle]
pub unsafe extern "C" fn lb_node_run_loopback_selftest(
    host: *mut LbNodeHandle,
    receiver: *mut LbNodeHandle,
    transport_kind: u32,
    frame_count: u32,
    out_telemetry: *mut LbNodeTelemetry,
) -> LbStatus {
    node_panic_boundary(|| {
        if host.is_null()
            || !host.is_aligned()
            || receiver.is_null()
            || !receiver.is_aligned()
            || ptr::eq(host, receiver)
            || frame_count == 0
            || frame_count > 1024
        {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validates 16-byte `LbAbiHeader` and alignment of `out_telemetry`.
        if let Err(s) = unsafe { validate_abi_output(out_telemetry) } {
            return s;
        }
        let Ok(kind) = map_transport(transport_kind) else {
            return LbStatus::InvalidArgument;
        };
        // SAFETY: `host` and `receiver` are distinct aligned handles per preconditions above.
        let host_w = unsafe { &*host };
        // SAFETY: Verified distinct non-null aligned handle above.
        let rx_w = unsafe { &*receiver };
        if host_w.node.config().role != PeerRole::Host
            || rx_w.node.config().role != PeerRole::Controller
        {
            return LbStatus::InvalidArgument;
        }

        let res = host_w.runtime.block_on(run_ffi_loopback_session(
            &host_w.node,
            &rx_w.node,
            kind,
            frame_count,
        ));
        match res {
            Ok(summary) => {
                let raw = LbNodeTelemetry {
                    abi: LbAbiHeader::new::<LbNodeTelemetry>(),
                    frames_sent: summary.frames_sent,
                    frames_delivered: summary.frames_delivered,
                    dropped_frames: summary.dropped_frames,
                    idr_requests: summary.idr_requests,
                    protected_blanks: summary.protected_blanks,
                    unauthorized_input_drops: summary.unauthorized_input_drops,
                    clock_sync_rtt_us: summary.clock_sync_rtt_us,
                    e2e_p50_us: summary.end_to_end.p50_us,
                    e2e_p95_us: summary.end_to_end.p95_us,
                    e2e_p99_us: summary.end_to_end.p99_us,
                };
                // SAFETY: Validated non-null aligned `out_telemetry` above.
                unsafe { ptr::write(out_telemetry, raw) };
                LbStatus::Ok
            }
            Err(_) => LbStatus::Faulted,
        }
    })
}

#[allow(clippy::too_many_lines)]
async fn run_ffi_loopback_session(
    host: &LumaBridgeNode,
    rx: &LumaBridgeNode,
    kind: TransportKind,
    frame_count: u32,
) -> Result<lumabridge_core::telemetry::SessionTelemetrySummary, lumabridge_core::node::NodeError> {
    let now = now_unix_secs();
    let mut rng = CheckedOsCryptoRng::preflight()?;
    let pin_win = PinPairingWindow::new();
    let pin = pin_win.open_with_new_pin(&mut rng, now)?;
    let pair_srv = rx
        .bind_server(kind, SocketAddr::from(([127, 0, 0, 1], 0)), true)
        .await?;
    let op_srv = rx
        .bind_server(kind, SocketAddr::from(([127, 0, 0, 1], 0)), false)
        .await?;
    let pair_addr = pair_srv.local_addr()?;
    let op_addr = op_srv.local_addr()?;

    let accept_pair = async {
        let link = pair_srv.accept_link(LUMABRIDGE_PAIR_ALPN_V1, now).await?;
        rx.accept_pairing_over_link(link, Some(&pin_win), None, now, 100, |p| {
            HumanApprovalDecision::Approve {
                pairing_attempt_id: p.pairing_attempt_id,
                peer_device_id: p.peer_device_id,
                granted_base_perms: Permissions::EXTEND_DISPLAY,
            }
        })
        .await
    };
    let init_pair = host.pair_with_pin(kind, pair_addr, rx.device_id(), &pin, now, |p| {
        HumanApprovalDecision::Approve {
            pairing_attempt_id: p.pairing_attempt_id,
            peer_device_id: p.peer_device_id,
            granted_base_perms: Permissions::EXTEND_DISPLAY,
        }
    });
    let (r_pair, h_pair) = tokio::join!(accept_pair, init_pair);
    r_pair?;
    h_pair?;
    pair_srv.close();

    let (r_sess_res, h_sess_res) = tokio::join!(
        async {
            let link = op_srv.accept_link(LUMABRIDGE_ALPN_V1, now).await?;
            rx.accept_operational_session(
                link,
                |_req, _caps| {
                    vec![ActiveDisplayConfig {
                        display_id: 0,
                        mode: DisplayMode::Extend,
                        width: 1920,
                        height: 1080,
                        fps_num: 60,
                        fps_den: 1,
                        scale_milli: 1000,
                        rotation_deg: RotationDeg::Deg0,
                        codec_id: CodecId::H264,
                        color_format: ColorFormat::Nv12_8Bit,
                        initial_bitrate_bps: 10_000_000,
                        capture_mode: CaptureMode::WindowsIddVirtualMonitor,
                    }]
                },
                now,
            )
            .await
        },
        host.connect_operational_session(
            kind,
            op_addr,
            rx.device_id(),
            vec![DisplayRequest {
                display_id: 0,
                mode: DisplayMode::Extend,
                width: 1920,
                height: 1080,
                fps_num: 60,
                fps_den: 1,
                scale_milli: 1000,
                rotation_deg: RotationDeg::Deg0,
                codec_pref: vec![CodecId::H264],
                max_bitrate_bps: 10_000_000,
                latency_profile: LatencyProfile::LowLatency,
            }],
            Permissions::EXTEND_DISPLAY,
            now,
        )
    );
    let mut rx_sess = r_sess_res?;
    let mut host_sess = h_sess_res?;
    let start = Instant::now();
    let got_frame = std::sync::Arc::new(tokio::sync::Notify::new());
    let got_frame_tx = std::sync::Arc::clone(&got_frame);
    let got_frame_rx = std::sync::Arc::clone(&got_frame);

    let tx_fut = async {
        for fid in 1..=frame_count {
            let is_idr = fid == 1;
            host_sess
                .send_encoded_frame(OutboundVideoFrame {
                    session_id: host_sess.session_id(),
                    display_id: 0,
                    codec_id: CodecId::H264,
                    frame_id: fid,
                    gop_id: 1,
                    capture_ts_us: u64::from(fid) * 16_000,
                    encode_done_ts_us: u64::from(fid) * 16_000 + 250,
                    kind: if is_idr {
                        FrameKind::Keyframe { chain_reset: true }
                    } else {
                        FrameKind::InterFrame
                    },
                    has_codec_config: is_idr,
                    mirror_source: false,
                    payload: vec![0xAAu8; 2_048],
                })
                .await?;
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), got_frame_tx.notified()).await;
        host_sess
            .send_protected_blank(0, frame_count + 1, 1, u64::from(frame_count + 1) * 16_000)
            .await?;
        Ok::<(), lumabridge_core::node::NodeError>(())
    };
    let rx_fut = async {
        let mut saw_frame = false;
        let mut saw_blank = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !saw_blank {
            let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
            match rx_sess
                .poll_media_event(Duration::from_millis(50), now_us)
                .await?
            {
                Some(lumabridge_core::node::NodeMediaEvent::Frame(_)) => {
                    if !saw_frame {
                        saw_frame = true;
                        got_frame_rx.notify_one();
                    }
                }
                Some(lumabridge_core::node::NodeMediaEvent::ProtectedBlank(_)) => {
                    saw_blank = true;
                }
                _ => {}
            }
        }
        Ok::<bool, lumabridge_core::node::NodeError>(saw_blank)
    };
    let (tx_res, rx_res) = tokio::join!(tx_fut, rx_fut);
    tx_res?;
    let saw_blank = rx_res?;
    if !saw_blank {
        return Err(lumabridge_core::node::NodeError::Protocol(
            "loopback selftest did not receive ProtectedBlank",
        ));
    }
    let mut summary = rx_sess.telemetry_summary();
    summary.frames_sent = host_sess.telemetry_summary().frames_sent;
    host_sess.close(CloseReasonCode::UserRequested).await;
    op_srv.close();
    Ok(summary)
}

pub const LB_MAX_RX_BUFFERED_EVENTS: usize = 8;

/// Host connection configuration for `lb_node_host_connect` (M2 live LAN pipeline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LbHostConnectConfig {
    pub abi: LbAbiHeader,
    pub transport_kind: u32,
    pub reserved0: u32,
    pub pair_addr_utf8: [u8; 64],
    pub op_addr_utf8: [u8; 64],
    pub pin_ascii: [u8; 16],
    pub peer_device_id_hex: [u8; 64],
    pub pair_addr_len: u32,
    pub op_addr_len: u32,
    pub pin_len: u32,
    pub peer_device_id_len: u32,
    pub width: u16,
    pub height: u16,
    pub fps_num: u16,
    pub fps_den: u16,
    pub initial_bitrate_bps: u32,
    pub timeout_ms: u32,
}

/// Live network feedback signals exposed by `lb_node_host_get_telemetry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LbHostFeedback {
    pub abi: LbAbiHeader,
    pub recommended_bitrate_bps: u32,
    pub force_idr_requested: u8,
    pub session_closed: u8,
    pub reserved0: u16,
}

/// Receiver listener startup configuration for `lb_node_receiver_start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LbReceiverStartConfig {
    pub abi: LbAbiHeader,
    pub transport_kind: u32,
    pub bind_addr_len: u32,
    pub bind_addr_utf8: [u8; 64],
    pub width: u16,
    pub height: u16,
    pub fps_num: u16,
    pub fps_den: u16,
    pub enable_mdns: u8,
    pub reserved0: u8,
    pub reserved1: u16,
    pub reserved2: u32,
}

/// Bound listener endpoints and ephemeral pairing PIN emitted by `lb_node_receiver_get_endpoints`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LbReceiverEndpoints {
    pub abi: LbAbiHeader,
    pub pair_addr_utf8: [u8; 64],
    pub op_addr_utf8: [u8; 64],
    pub device_id_hex: [u8; 65],
    pub pin_ascii: [u8; 17],
    pub reserved0: [u8; 6],
}

/// Event discriminator for `LbReceiverMediaEvent::kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LbReceiverEventKind {
    None = 0,
    VideoFrame = 1,
    ProtectedBlank = 2,
    SessionClosed = 3,
}

/// Event delivered by `lb_node_receiver_poll_event`.
/// When `kind == LB_RECEIVER_EVENT_KIND_VIDEO_FRAME`, caller MUST release `payload`
/// exactly once via `lb_core_release_buffer(&evt.payload)`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LbReceiverMediaEvent {
    pub abi: LbAbiHeader,
    pub kind: u32,
    pub display_id: u16,
    pub gop_id: u16,
    pub frame_id: u32,
    pub video_flags: u32,
    pub capture_ts_us: u64,
    pub encode_done_ts_us: u64,
    pub session_id: u64,
    pub payload: LbOwnedBuffer,
    pub force_idr_requested: u8,
    pub padding_reserved: [u8; 7],
}

enum HostTxCommand {
    SubmitFrame {
        frame: OutboundVideoFrame,
        reply: std::sync::mpsc::SyncSender<Result<(), LbStatus>>,
    },
    SendProtectedBlank {
        display_id: u16,
        frame_id: u32,
        gop_id: u16,
        ts_us: u64,
        reply: std::sync::mpsc::SyncSender<Result<(), LbStatus>>,
    },
    Close,
}

#[derive(Default)]
struct HostSharedState {
    telemetry: Option<SessionTelemetrySummary>,
    recommended_bitrate_bps: u32,
    force_idr_latch: bool,
    session_closed: bool,
}

/// Opaque live streaming host session wrapping SPAKE2 + mTLS `ActiveNodeSession`.
pub struct LbHostSessionHandle {
    runtime_handle: tokio::runtime::Handle,
    cmd_tx: tokio::sync::mpsc::Sender<HostTxCommand>,
    shared: Arc<Mutex<HostSharedState>>,
    driver_join: Option<tokio::task::JoinHandle<()>>,
}

struct QueuedRxItem {
    kind: LbReceiverEventKind,
    display_id: u16,
    gop_id: u16,
    frame_id: u32,
    video_flags: u32,
    capture_ts_us: u64,
    encode_done_ts_us: u64,
    session_id: u64,
    payload: Vec<u8>,
    force_idr_requested: bool,
}

struct ReceiverSharedQueue {
    events: VecDeque<QueuedRxItem>,
    telemetry: Option<SessionTelemetrySummary>,
    stopped: bool,
}

/// Opaque live receiver session accepting pairing, operational frames, clock sync, and telemetry.
pub struct LbReceiverSessionHandle {
    runtime_handle: tokio::runtime::Handle,
    endpoints: LbReceiverEndpoints,
    queue: Arc<(Mutex<ReceiverSharedQueue>, Condvar)>,
    timing_tx: tokio::sync::mpsc::Sender<(u64, u64)>,
    stop_tx: tokio::sync::watch::Sender<bool>,
    driver_join: Option<tokio::task::JoinHandle<()>>,
}

fn summary_to_ffi(summary: &SessionTelemetrySummary) -> LbNodeTelemetry {
    LbNodeTelemetry {
        abi: LbAbiHeader::new::<LbNodeTelemetry>(),
        frames_sent: summary.frames_sent,
        frames_delivered: summary.frames_delivered,
        dropped_frames: summary.dropped_frames,
        idr_requests: summary.idr_requests,
        protected_blanks: summary.protected_blanks,
        unauthorized_input_drops: summary.unauthorized_input_drops,
        clock_sync_rtt_us: summary.clock_sync_rtt_us,
        e2e_p50_us: summary.end_to_end.p50_us,
        e2e_p95_us: summary.end_to_end.p95_us,
        e2e_p99_us: summary.end_to_end.p99_us,
    }
}

fn parse_fixed_utf8(buf: &[u8], len: u32) -> Result<&str, LbStatus> {
    let n = usize::try_from(len).map_err(|_| LbStatus::InvalidArgument)?;
    if n == 0 || n > buf.len() {
        return Err(LbStatus::InvalidArgument);
    }
    core::str::from_utf8(&buf[..n]).map_err(|_| LbStatus::InvalidArgument)
}

fn parse_device_hex(hex: &str) -> Result<DeviceId, LbStatus> {
    if hex.len() != 64 {
        return Err(LbStatus::InvalidArgument);
    }
    let mut raw = [0u8; 32];
    for (idx, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let s = core::str::from_utf8(pair).map_err(|_| LbStatus::InvalidArgument)?;
        raw[idx] = u8::from_str_radix(s, 16).map_err(|_| LbStatus::InvalidArgument)?;
    }
    Ok(DeviceId::from_bytes(raw))
}

fn write_fixed_cstr(dst: &mut [u8], src: &str) {
    dst.fill(0);
    let max_copy = dst.len().saturating_sub(1);
    let copy_len = src.len().min(max_copy);
    dst[..copy_len].copy_from_slice(&src.as_bytes()[..copy_len]);
}

fn push_rx_event(shared: &(Mutex<ReceiverSharedQueue>, Condvar), item: QueuedRxItem) {
    let Ok(mut guard) = shared.0.lock() else {
        return;
    };
    if matches!(item.kind, LbReceiverEventKind::VideoFrame)
        && guard.events.len() >= LB_MAX_RX_BUFFERED_EVENTS
    {
        if let Some(pos) = guard
            .events
            .iter()
            .position(|e| matches!(e.kind, LbReceiverEventKind::VideoFrame))
        {
            let _ = guard.events.remove(pos);
        }
    }
    guard.events.push_back(item);
    shared.1.notify_all();
}

/// Pair via SPAKE2 and open a live Phase 2 mTLS operational streaming session as `Host`.
///
/// # Safety
/// - `node` must be a valid `Host` [`LbNodeHandle`].
/// - `config` and `out_host` must be aligned, non-null pointers satisfying `LbAbiHeader`.
#[no_mangle]
#[allow(clippy::too_many_lines)]
pub unsafe extern "C" fn lb_node_host_connect(
    node: *mut LbNodeHandle,
    config: *const LbHostConnectConfig,
    out_host: *mut *mut LbHostSessionHandle,
) -> LbStatus {
    node_panic_boundary(|| {
        if node.is_null()
            || !node.is_aligned()
            || config.is_null()
            || out_host.is_null()
            || !out_host.is_aligned()
        {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller guarantees aligned writable `*out_host`.
        unsafe { ptr::write(out_host, ptr::null_mut()) };

        // SAFETY: Validates `LbAbiHeader` and alignment of `config`.
        let cfg = match unsafe { read_and_validate_abi_input(config) } {
            Ok(c) => c,
            Err(s) => return s,
        };
        if cfg.reserved0 != 0
            || !(320..=7680).contains(&cfg.width)
            || !(240..=4320).contains(&cfg.height)
            || cfg.fps_num == 0
            || cfg.fps_den == 0
            || cfg.fps_num < cfg.fps_den
            || (cfg.fps_num / cfg.fps_den) > 240
        {
            return LbStatus::InvalidArgument;
        }
        let Ok(kind) = map_transport(cfg.transport_kind) else {
            return LbStatus::InvalidArgument;
        };
        let Ok(pair_str) = parse_fixed_utf8(&cfg.pair_addr_utf8, cfg.pair_addr_len) else {
            return LbStatus::InvalidArgument;
        };
        let Ok(op_str) = parse_fixed_utf8(&cfg.op_addr_utf8, cfg.op_addr_len) else {
            return LbStatus::InvalidArgument;
        };
        let Ok(pair_addr) = pair_str.parse::<SocketAddr>() else {
            return LbStatus::InvalidArgument;
        };
        let Ok(op_addr) = op_str.parse::<SocketAddr>() else {
            return LbStatus::InvalidArgument;
        };
        let Ok(pin_str) = parse_fixed_utf8(&cfg.pin_ascii, cfg.pin_len) else {
            return LbStatus::InvalidArgument;
        };
        let Ok(pin_secret) = PinSecret::new(pin_str) else {
            return LbStatus::InvalidArgument;
        };
        let peer_hint = if cfg.peer_device_id_len == 0 {
            DeviceId::from_bytes([0u8; 32])
        } else {
            let Ok(hex) = parse_fixed_utf8(&cfg.peer_device_id_hex, cfg.peer_device_id_len) else {
                return LbStatus::InvalidArgument;
            };
            let Ok(did) = parse_device_hex(hex) else {
                return LbStatus::InvalidArgument;
            };
            did
        };

        // SAFETY: Validated non-null aligned `node`.
        let wrapper = unsafe { &*node };
        if wrapper.node.config().role != PeerRole::Host {
            return LbStatus::InvalidArgument;
        }
        let timeout_dur = Duration::from_millis(u64::from(cfg.timeout_ms.max(5_000)));
        let init_bitrate = cfg.initial_bitrate_bps.clamp(1_000_000, 100_000_000);

        let connect_res = wrapper.runtime.block_on(async {
            let fut = async {
                let rec = wrapper
                    .node
                    .pair_with_pin(
                        kind,
                        pair_addr,
                        peer_hint,
                        &pin_secret,
                        now_unix_secs(),
                        |p| HumanApprovalDecision::Approve {
                            pairing_attempt_id: p.pairing_attempt_id,
                            peer_device_id: p.peer_device_id,
                            granted_base_perms: Permissions::EXTEND_DISPLAY,
                        },
                    )
                    .await?;
                let mut session = wrapper
                    .node
                    .connect_operational_session(
                        kind,
                        op_addr,
                        rec.device_id,
                        vec![DisplayRequest {
                            display_id: 0,
                            mode: DisplayMode::Extend,
                            width: cfg.width,
                            height: cfg.height,
                            fps_num: cfg.fps_num,
                            fps_den: cfg.fps_den,
                            scale_milli: 1000,
                            rotation_deg: RotationDeg::Deg0,
                            codec_pref: vec![CodecId::H264],
                            max_bitrate_bps: init_bitrate,
                            latency_profile: LatencyProfile::LowLatency,
                        }],
                        Permissions::EXTEND_DISPLAY,
                        now_unix_secs(),
                    )
                    .await?;
                let _ = session.send_clock_sync_ping(1, 0).await;
                Ok::<lumabridge_core::node::ActiveNodeSession, NodeError>(session)
            };
            tokio::time::timeout(timeout_dur, fut)
                .await
                .map_err(|_| NodeError::InvalidConfig("host connect timed out"))?
        });

        let Ok(mut session) = connect_res else {
            return LbStatus::Faulted;
        };

        let shared = Arc::new(Mutex::new(HostSharedState {
            telemetry: Some(session.telemetry_summary()),
            recommended_bitrate_bps: init_bitrate,
            force_idr_latch: false,
            session_closed: false,
        }));
        let shared_bg = Arc::clone(&shared);
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<HostTxCommand>(32);

        let driver_join = wrapper.runtime.spawn(async move {
            let start = Instant::now();
            let mut next_ping_at = Instant::now() + Duration::from_secs(1);
            let mut ping_seq = 2u64;
            let mut tick = tokio::time::interval(Duration::from_millis(8));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    maybe_cmd = cmd_rx.recv() => {
                        let Some(cmd) = maybe_cmd else {
                            break;
                        };
                        match cmd {
                            HostTxCommand::SubmitFrame { mut frame, reply } => {
                                frame.session_id = session.session_id();
                                if let Ok(outcome) = session.send_encoded_frame(frame).await {
                                    if let Ok(mut g) = shared_bg.lock() {
                                        if outcome.force_idr_required {
                                            g.force_idr_latch = true;
                                        }
                                        g.telemetry = Some(session.telemetry_summary());
                                    }
                                    let _ = reply.send(Ok(()));
                                } else {
                                    if let Ok(mut g) = shared_bg.lock() {
                                        g.session_closed = true;
                                        g.telemetry = Some(session.telemetry_summary());
                                    }
                                    let _ = reply.send(Err(LbStatus::Faulted));
                                    break;
                                }
                            }
                            HostTxCommand::SendProtectedBlank { display_id, frame_id, gop_id, ts_us, reply } => {
                                if session
                                    .send_protected_blank(display_id, frame_id, gop_id, ts_us)
                                    .await
                                    .is_ok()
                                {
                                    if let Ok(mut g) = shared_bg.lock() {
                                        g.telemetry = Some(session.telemetry_summary());
                                    }
                                    let _ = reply.send(Ok(()));
                                } else {
                                    if let Ok(mut g) = shared_bg.lock() {
                                        g.session_closed = true;
                                    }
                                    let _ = reply.send(Err(LbStatus::Faulted));
                                    break;
                                }
                            }
                            HostTxCommand::Close => {
                                session.close(CloseReasonCode::UserRequested).await;
                                if let Ok(mut g) = shared_bg.lock() {
                                    g.session_closed = true;
                                }
                                return;
                            }
                        }
                    }
                    _ = tick.tick() => {
                        let now_u = now_unix_secs();
                        let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
                        if Instant::now() >= next_ping_at {
                            let _ = session.send_clock_sync_ping(ping_seq, now_us).await;
                            ping_seq = ping_seq.saturating_add(1);
                            next_ping_at = Instant::now() + Duration::from_secs(1);
                        }
                        while let Ok(Some(msg)) = session.try_recv_feedback().await {
                            let is_bitrate_hint = match &msg {
                                ControlMessage::MediaFeedback(fb) => Some(fb.suggested_bitrate_bps),
                                _ => None,
                            };
                            if let Ok(Some(ev)) = session.handle_control_or_feedback(msg, now_us, now_u).await {
                                if let Ok(mut g) = shared_bg.lock() {
                                    match ev {
                                        NodeSignalEvent::RemoteForceIdr { .. } => {
                                            g.force_idr_latch = true;
                                        }
                                        NodeSignalEvent::SessionClosed(_) => {
                                            g.session_closed = true;
                                        }
                                        _ => {}
                                    }
                                    if let Some(bps) = is_bitrate_hint {
                                        if bps >= 1_000_000 {
                                            g.recommended_bitrate_bps = bps;
                                        }
                                    }
                                }
                            }
                        }
                        match session.try_recv_control().await {
                            Ok(Some(ControlMessage::SessionClose(_))) | Err(NodeError::Transport(TransportError::ConnectionClosed(_))) => {
                                if let Ok(mut g) = shared_bg.lock() {
                                    g.session_closed = true;
                                    g.telemetry = Some(session.telemetry_summary());
                                }
                                break;
                            }
                            Ok(Some(cmsg)) => {
                                let _ = session.handle_control_or_feedback(cmsg, now_us, now_u).await;
                            }
                            Ok(None) | Err(_) => {}
                        }
                        if let Ok(mut g) = shared_bg.lock() {
                            g.telemetry = Some(session.telemetry_summary());
                        }
                    }
                }
            }
        });

        let handle = Box::new(LbHostSessionHandle {
            runtime_handle: wrapper.runtime.handle().clone(),
            cmd_tx,
            shared,
            driver_join: Some(driver_join),
        });
        // SAFETY: Validated aligned writable `out_host`.
        unsafe { ptr::write(out_host, Box::into_raw(handle)) };
        LbStatus::Ok
    })
}

/// Submit one encoded H.264 Annex-B access unit from native Windows host over the live network session.
///
/// `meta->flags & 0x01` marks IDR keyframe; `meta->flags & 0x02` marks `mirror_source`.
///
/// # Safety
/// - `host` must be a valid handle from [`lb_node_host_connect`].
/// - `meta` must pass `LbAbiHeader` validation; `data` must be valid for `data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn lb_node_host_submit_h264(
    host: *mut LbHostSessionHandle,
    meta: *const crate::LbEncodedFrameMeta,
    data: *const u8,
    data_len: usize,
) -> LbStatus {
    node_panic_boundary(|| {
        if host.is_null() || !host.is_aligned() || meta.is_null() {
            return LbStatus::InvalidArgument;
        }
        if data_len == 0 || data_len > crate::LB_FFI_MAX_FRAME_BYTES || data.is_null() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validates `LbAbiHeader` and alignment of `meta`.
        let raw_meta = match unsafe { read_and_validate_abi_input(meta) } {
            Ok(m) => m,
            Err(s) => return s,
        };
        if raw_meta.codec != crate::LbEncodedCodec::H264AnnexB as u32
            || raw_meta.display_id > lumabridge_core::MAX_VALID_DISPLAY_ID
            || (raw_meta.flags & !0x03) != 0
            || raw_meta.frame_id == 0
            || raw_meta.encode_done_ts_us < raw_meta.capture_ts_us
        {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validated non-null readable slice `[data; data_len]`.
        let payload = unsafe { slice::from_raw_parts(data, data_len) }.to_vec();
        let is_key = (raw_meta.flags & 0x01) != 0;
        let mirror_source = (raw_meta.flags & 0x02) != 0;
        let frame = OutboundVideoFrame {
            session_id: raw_meta.session_id,
            display_id: raw_meta.display_id,
            codec_id: CodecId::H264,
            frame_id: raw_meta.frame_id,
            gop_id: raw_meta.gop_id,
            capture_ts_us: raw_meta.capture_ts_us,
            encode_done_ts_us: raw_meta.encode_done_ts_us,
            kind: if is_key {
                FrameKind::Keyframe { chain_reset: true }
            } else {
                FrameKind::InterFrame
            },
            has_codec_config: is_key,
            mirror_source,
            payload,
        };

        // SAFETY: Validated aligned `host`.
        let wrapper = unsafe { &*host };
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        if wrapper
            .cmd_tx
            .blocking_send(HostTxCommand::SubmitFrame {
                frame,
                reply: reply_tx,
            })
            .is_err()
        {
            return LbStatus::InvalidState;
        }
        reply_rx
            .recv()
            .unwrap_or(Err(LbStatus::InvalidState))
            .err()
            .unwrap_or(LbStatus::Ok)
    })
}

/// Transmit reliable `ProtectedBlank` on `Channel 1` from native Windows host.
///
/// # Safety
/// `host` must be a valid handle from [`lb_node_host_connect`].
#[no_mangle]
pub unsafe extern "C" fn lb_node_host_send_protected_blank(
    host: *mut LbHostSessionHandle,
    display_id: u16,
    frame_id: u32,
    gop_id: u16,
    ts_us: u64,
) -> LbStatus {
    node_panic_boundary(|| {
        if host.is_null() || !host.is_aligned() || frame_id == 0 {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validated aligned `host`.
        let wrapper = unsafe { &*host };
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        if wrapper
            .cmd_tx
            .blocking_send(HostTxCommand::SendProtectedBlank {
                display_id,
                frame_id,
                gop_id,
                ts_us,
                reply: reply_tx,
            })
            .is_err()
        {
            return LbStatus::InvalidState;
        }
        reply_rx
            .recv()
            .unwrap_or(Err(LbStatus::InvalidState))
            .err()
            .unwrap_or(LbStatus::Ok)
    })
}

/// Snapshot sanitized host telemetry and consume latched remote `ForceIdr` / bitrate feedback.
///
/// # Safety
/// `host` must be valid; `out_telemetry` and optional `out_feedback` must satisfy `LbAbiHeader`.
#[no_mangle]
pub unsafe extern "C" fn lb_node_host_get_telemetry(
    host: *const LbHostSessionHandle,
    out_telemetry: *mut LbNodeTelemetry,
    out_feedback: *mut LbHostFeedback,
) -> LbStatus {
    node_panic_boundary(|| {
        if host.is_null() || !host.is_aligned() || out_telemetry.is_null() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validates `LbAbiHeader` of `out_telemetry`.
        if let Err(s) = unsafe { validate_abi_output(out_telemetry) } {
            return s;
        }
        if !out_feedback.is_null() {
            // SAFETY: Validates `LbAbiHeader` of optional `out_feedback`.
            if let Err(s) = unsafe { validate_abi_output(out_feedback) } {
                return s;
            }
        }
        // SAFETY: Validated aligned `host`.
        let wrapper = unsafe { &*host };
        let Ok(mut g) = wrapper.shared.lock() else {
            return LbStatus::Faulted;
        };
        let tel_snapshot = g.telemetry.as_ref().map_or_else(
            || summary_to_ffi(&SessionTelemetrySummary::default()),
            summary_to_ffi,
        );
        // SAFETY: Validated writable `out_telemetry`.
        unsafe { ptr::write(out_telemetry, tel_snapshot) };
        if !out_feedback.is_null() {
            let fb = LbHostFeedback {
                abi: LbAbiHeader::new::<LbHostFeedback>(),
                recommended_bitrate_bps: g.recommended_bitrate_bps,
                force_idr_requested: u8::from(g.force_idr_latch),
                session_closed: u8::from(g.session_closed),
                reserved0: 0,
            };
            g.force_idr_latch = false;
            // SAFETY: Validated writable `out_feedback`.
            unsafe { ptr::write(out_feedback, fb) };
        }
        LbStatus::Ok
    })
}

/// Gracefully close and destroy an [`LbHostSessionHandle`].
///
/// # Safety
/// `host` must be null or a valid exclusive handle from [`lb_node_host_connect`].
#[no_mangle]
pub unsafe extern "C" fn lb_node_host_close(host: *mut LbHostSessionHandle) -> LbStatus {
    node_panic_boundary(|| {
        if host.is_null() {
            return LbStatus::Ok;
        }
        if !host.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Exclusive owned handle from `lb_node_host_connect`.
        let mut boxed = unsafe { Box::from_raw(host) };
        let _ = boxed.cmd_tx.blocking_send(HostTxCommand::Close);
        if let Some(join) = boxed.driver_join.take() {
            boxed.runtime_handle.block_on(async {
                let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
            });
        }
        drop(boxed);
        LbStatus::Ok
    })
}

/// Start a live background receiver accepting pairing + mTLS video stream frames into a bounded queue.
///
/// # Safety
/// - `node` must be a valid `Controller` [`LbNodeHandle`].
/// - `config` and `out_rx` must be aligned, non-null, and satisfy `LbAbiHeader`.
#[no_mangle]
#[allow(clippy::too_many_lines)]
pub unsafe extern "C" fn lb_node_receiver_start(
    node: *mut LbNodeHandle,
    config: *const LbReceiverStartConfig,
    out_rx: *mut *mut LbReceiverSessionHandle,
) -> LbStatus {
    node_panic_boundary(|| {
        if node.is_null()
            || !node.is_aligned()
            || config.is_null()
            || out_rx.is_null()
            || !out_rx.is_aligned()
        {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller guarantees writable aligned `*out_rx`.
        unsafe { ptr::write(out_rx, ptr::null_mut()) };

        // SAFETY: Validates `LbAbiHeader` of `config`.
        let cfg = match unsafe { read_and_validate_abi_input(config) } {
            Ok(c) => c,
            Err(s) => return s,
        };
        if cfg.reserved0 != 0
            || cfg.reserved1 != 0
            || cfg.reserved2 != 0
            || !(320..=7680).contains(&cfg.width)
            || !(240..=4320).contains(&cfg.height)
            || cfg.fps_num == 0
            || cfg.fps_den == 0
            || cfg.fps_num < cfg.fps_den
            || (cfg.fps_num / cfg.fps_den) > 240
        {
            return LbStatus::InvalidArgument;
        }
        let Ok(kind) = map_transport(cfg.transport_kind) else {
            return LbStatus::InvalidArgument;
        };
        let Ok(bind_str) = parse_fixed_utf8(&cfg.bind_addr_utf8, cfg.bind_addr_len) else {
            return LbStatus::InvalidArgument;
        };
        let Ok(bind_addr) = bind_str.parse::<SocketAddr>() else {
            return LbStatus::InvalidArgument;
        };

        // SAFETY: Validated non-null aligned `node`.
        let wrapper = unsafe { &*node };
        if wrapper.node.config().role != PeerRole::Controller {
            return LbStatus::InvalidArgument;
        }

        let init_res = wrapper.runtime.block_on(async {
            let now = now_unix_secs();
            let mut rng = CheckedOsCryptoRng::preflight()?;
            let pin_win = PinPairingWindow::new();
            let pin = pin_win.open_with_new_pin(&mut rng, now)?;
            let pair_srv = wrapper.node.bind_server(kind, bind_addr, true).await?;
            let op_srv = wrapper.node.bind_server(kind, bind_addr, false).await?;
            let pair_addr = pair_srv.local_addr()?;
            let op_addr = op_srv.local_addr()?;
            Ok::<_, NodeError>((pin_win, pin, pair_srv, op_srv, pair_addr, op_addr))
        });

        let Ok((pin_win, pin, pair_srv, op_srv, pair_addr, op_addr)) = init_res else {
            return LbStatus::Faulted;
        };

        let Ok(pin_str) = core::str::from_utf8(pin.expose_bytes()) else {
            return LbStatus::Faulted;
        };
        let mut dev_hex = String::with_capacity(64);
        for b in wrapper.node.device_id().as_bytes() {
            use core::fmt::Write as _;
            let _ = write!(dev_hex, "{b:02x}");
        }
        let mut endpoints = LbReceiverEndpoints {
            abi: LbAbiHeader::new::<LbReceiverEndpoints>(),
            pair_addr_utf8: [0u8; 64],
            op_addr_utf8: [0u8; 64],
            device_id_hex: [0u8; 65],
            pin_ascii: [0u8; 17],
            reserved0: [0u8; 6],
        };
        write_fixed_cstr(&mut endpoints.pair_addr_utf8, &pair_addr.to_string());
        write_fixed_cstr(&mut endpoints.op_addr_utf8, &op_addr.to_string());
        write_fixed_cstr(&mut endpoints.device_id_hex, &dev_hex);
        write_fixed_cstr(&mut endpoints.pin_ascii, pin_str);

        let queue = Arc::new((
            Mutex::new(ReceiverSharedQueue {
                events: VecDeque::with_capacity(LB_MAX_RX_BUFFERED_EVENTS),
                telemetry: None,
                stopped: false,
            }),
            Condvar::new(),
        ));
        let queue_bg = Arc::clone(&queue);
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let (timing_tx, mut timing_rx) = tokio::sync::mpsc::channel::<(u64, u64)>(128);
        let node_ref = Arc::clone(&wrapper.node);
        let enable_mdns = cfg.enable_mdns != 0;
        let display_w = cfg.width;
        let display_h = cfg.height;
        let display_fps_num = cfg.fps_num;
        let display_fps_den = cfg.fps_den;

        let driver_join = wrapper.runtime.spawn(async move {
            let mdns_responder = if enable_mdns {
                lumabridge_transport::discovery::DiscoveryResponder::bind(
                    SocketAddr::from(([0, 0, 0, 0], 5353)),
                    wrapper_device_service_info(&node_ref, pair_addr, kind),
                    true,
                )
                .await
                .ok()
            } else {
                None
            };
            let accept_res = async {
                let pair_clock = Instant::now();
                loop {
                    if *stop_rx.borrow() || pin_win.remaining_attempts(now_unix_secs()) == 0 {
                        return Ok::<_, NodeError>(None);
                    }
                    let pair_link = tokio::select! {
                        _ = stop_rx.changed() => return Ok(None),
                        res = pair_srv.accept_link(LUMABRIDGE_PAIR_ALPN_V1, now_unix_secs()) => match res {
                            Ok(link) => link,
                            Err(_) => continue,
                        },
                    };
                    let now_ms = u64::try_from(pair_clock.elapsed().as_millis()).unwrap_or(u64::MAX);
                    if node_ref
                        .accept_pairing_over_link(
                            pair_link,
                            Some(&pin_win),
                            None,
                            now_unix_secs(),
                            now_ms,
                            |p| HumanApprovalDecision::Approve {
                                pairing_attempt_id: p.pairing_attempt_id,
                                peer_device_id: p.peer_device_id,
                                granted_base_perms: Permissions::EXTEND_DISPLAY,
                            },
                        )
                        .await
                        .is_ok()
                    {
                        break;
                    }
                }
                pair_srv.close();

                let op_link = tokio::select! {
                    _ = stop_rx.changed() => return Ok(None),
                    res = op_srv.accept_link(LUMABRIDGE_ALPN_V1, now_unix_secs()) => res?,
                };
                let session = node_ref
                    .accept_operational_session(
                        op_link,
                        |_req, _caps| {
                            vec![ActiveDisplayConfig {
                                display_id: 0,
                                mode: DisplayMode::Extend,
                                width: display_w,
                                height: display_h,
                                fps_num: display_fps_num,
                                fps_den: display_fps_den,
                                scale_milli: 1000,
                                rotation_deg: RotationDeg::Deg0,
                                codec_id: CodecId::H264,
                                color_format: ColorFormat::Nv12_8Bit,
                                initial_bitrate_bps: 15_000_000,
                                capture_mode: CaptureMode::WindowsIddVirtualMonitor,
                            }]
                        },
                        now_unix_secs(),
                    )
                    .await?;
                Ok(Some(session))
            }
            .await;

            let Ok(Some(mut session)) = accept_res else {
                pair_srv.close();
                op_srv.close();
                if let Ok(mut g) = queue_bg.0.lock() {
                    g.stopped = true;
                }
                queue_bg.1.notify_all();
                return;
            };

            let start = Instant::now();
            let push_media_event = |ev: NodeMediaEvent, session_id: u64, now_us: u64| match ev {
                NodeMediaEvent::Frame(f) => {
                    let mut vflags = 0u32;
                    if f.flags.contains(VideoFlags::KEYFRAME) {
                        vflags |= 0x01;
                    }
                    if f.flags.contains(VideoFlags::MIRROR_SOURCE) {
                        vflags |= 0x04;
                    }
                    push_rx_event(
                        &queue_bg,
                        QueuedRxItem {
                            kind: LbReceiverEventKind::VideoFrame,
                            display_id: f.display_id,
                            gop_id: f.gop_id,
                            frame_id: f.frame_id,
                            video_flags: vflags,
                            capture_ts_us: f.capture_ts_us,
                            encode_done_ts_us: f.encode_done_ts_us,
                            session_id: f.session_id,
                            payload: f.payload,
                            force_idr_requested: false,
                        },
                    );
                }
                NodeMediaEvent::ProtectedBlank(b) => {
                    push_rx_event(
                        &queue_bg,
                        QueuedRxItem {
                            kind: LbReceiverEventKind::ProtectedBlank,
                            display_id: b.display_id,
                            gop_id: 0,
                            frame_id: b.frame_id,
                            video_flags: VideoFlags::PROTECTED_BLANK.raw().into(),
                            capture_ts_us: now_us,
                            encode_done_ts_us: now_us,
                            session_id,
                            payload: Vec::new(),
                            force_idr_requested: false,
                        },
                    );
                }
                NodeMediaEvent::ForceIdrRequested(_)
                | NodeMediaEvent::DroppedDependentFrames(_)
                | NodeMediaEvent::SessionRenewalRequired => {}
            };
            loop {
                if *stop_rx.borrow() {
                    break;
                }
                while let Ok((dec_us, pres_us)) = timing_rx.try_recv() {
                    session.record_decode_present_latency(dec_us, pres_us);
                }
                let now_u = now_unix_secs();
                let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
                match session.try_recv_control().await {
                    Ok(Some(ControlMessage::SessionClose(_)))
                    | Err(NodeError::Transport(TransportError::ConnectionClosed(_))) => {
                        for _ in 0..16 {
                            let drain_us =
                                u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
                            match session
                                .poll_media_event(Duration::from_millis(2), drain_us)
                                .await
                            {
                                Ok(Some(ev)) => {
                                    push_media_event(ev, session.session_id(), drain_us);
                                }
                                Ok(None) | Err(_) => break,
                            }
                        }
                        if let Ok(mut g) = queue_bg.0.lock() {
                            g.telemetry = Some(session.telemetry_summary());
                        }
                        push_rx_event(
                            &queue_bg,
                            QueuedRxItem {
                                kind: LbReceiverEventKind::SessionClosed,
                                display_id: 0,
                                gop_id: 0,
                                frame_id: 0,
                                video_flags: 0,
                                capture_ts_us: 0,
                                encode_done_ts_us: 0,
                                session_id: session.session_id(),
                                payload: Vec::new(),
                                force_idr_requested: false,
                            },
                        );
                        break;
                    }
                    Ok(Some(msg)) => {
                        let _ = session.handle_control_or_feedback(msg, now_us, now_u).await;
                    }
                    Ok(None) | Err(_) => {}
                }
                while let Ok(Some(fb_msg)) = session.try_recv_feedback().await {
                    let fb_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
                    let _ = session
                        .handle_control_or_feedback(fb_msg, fb_us, now_u)
                        .await;
                }
                match session
                    .poll_media_event(Duration::from_millis(8), now_us)
                    .await
                {
                    Ok(Some(ev)) => push_media_event(ev, session.session_id(), now_us),
                    Ok(None) => {}
                    Err(NodeError::Transport(TransportError::ConnectionClosed(_))) => {
                        push_rx_event(
                            &queue_bg,
                            QueuedRxItem {
                                kind: LbReceiverEventKind::SessionClosed,
                                display_id: 0,
                                gop_id: 0,
                                frame_id: 0,
                                video_flags: 0,
                                capture_ts_us: 0,
                                encode_done_ts_us: 0,
                                session_id: session.session_id(),
                                payload: Vec::new(),
                                force_idr_requested: false,
                            },
                        );
                        break;
                    }
                    Err(_) => break,
                }
                if let Ok(mut g) = queue_bg.0.lock() {
                    g.telemetry = Some(session.telemetry_summary());
                }
            }
            while let Ok((dec_us, pres_us)) = timing_rx.try_recv() {
                session.record_decode_present_latency(dec_us, pres_us);
            }
            if let Ok(mut g) = queue_bg.0.lock() {
                g.telemetry = Some(session.telemetry_summary());
                g.stopped = true;
            }
            queue_bg.1.notify_all();
            if let Some(mdns) = mdns_responder {
                mdns.shutdown().await;
            }
            op_srv.close();
        });

        let handle = Box::new(LbReceiverSessionHandle {
            runtime_handle: wrapper.runtime.handle().clone(),
            endpoints,
            queue,
            timing_tx,
            stop_tx,
            driver_join: Some(driver_join),
        });
        // SAFETY: Validated aligned writable `*out_rx`.
        unsafe { ptr::write(out_rx, Box::into_raw(handle)) };
        LbStatus::Ok
    })
}

/// Copy bound endpoints, canonical device id hex, and ephemeral pairing PIN from [`LbReceiverSessionHandle`].
///
/// # Safety
/// `rx` and `out_endpoints` must be aligned non-null pointers satisfying `LbAbiHeader`.
#[no_mangle]
pub unsafe extern "C" fn lb_node_receiver_get_endpoints(
    rx: *const LbReceiverSessionHandle,
    out_endpoints: *mut LbReceiverEndpoints,
) -> LbStatus {
    node_panic_boundary(|| {
        if rx.is_null() || !rx.is_aligned() || out_endpoints.is_null() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validates `LbAbiHeader` of `out_endpoints`.
        if let Err(s) = unsafe { validate_abi_output(out_endpoints) } {
            return s;
        }
        // SAFETY: Validated aligned `rx`.
        let wrapper = unsafe { &*rx };
        // SAFETY: Validated writable `out_endpoints`.
        unsafe { ptr::write(out_endpoints, wrapper.endpoints) };
        LbStatus::Ok
    })
}

/// Poll the next decoded-ready compressed video frame, `ProtectedBlank`, or `SessionClosed` event.
///
/// # Safety
/// `rx` and `out_event` must be aligned non-null pointers satisfying `LbAbiHeader`.
#[no_mangle]
pub unsafe extern "C" fn lb_node_receiver_poll_event(
    rx: *mut LbReceiverSessionHandle,
    timeout_ms: u32,
    out_event: *mut LbReceiverMediaEvent,
) -> LbStatus {
    node_panic_boundary(|| {
        if rx.is_null() || !rx.is_aligned() || out_event.is_null() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validates `LbAbiHeader` of `out_event`.
        if let Err(s) = unsafe { validate_abi_output(out_event) } {
            return s;
        }
        // SAFETY: Validated aligned `rx`.
        let wrapper = unsafe { &*rx };
        let wait_dur = Duration::from_millis(u64::from(timeout_ms.min(5_000)));
        let deadline = Instant::now() + wait_dur;

        let Ok(mut guard) = wrapper.queue.0.lock() else {
            return LbStatus::Faulted;
        };
        while guard.events.is_empty() && !guard.stopped {
            let now_i = Instant::now();
            if now_i >= deadline {
                break;
            }
            let Ok((next_g, wait_res)) = wrapper.queue.1.wait_timeout(guard, deadline - now_i)
            else {
                return LbStatus::Faulted;
            };
            guard = next_g;
            if wait_res.timed_out() {
                break;
            }
        }

        let item_opt = guard.events.pop_front();
        drop(guard);

        let evt = if let Some(item) = item_opt {
            let payload = if item.payload.is_empty() {
                LbOwnedBuffer {
                    data: ptr::null(),
                    len: 0,
                    capacity: 0,
                    release: None,
                    user_ctx: ptr::null_mut(),
                }
            } else {
                alloc_rust_owned_buffer(item.payload)
            };
            LbReceiverMediaEvent {
                abi: LbAbiHeader::new::<LbReceiverMediaEvent>(),
                kind: item.kind as u32,
                display_id: item.display_id,
                gop_id: item.gop_id,
                frame_id: item.frame_id,
                video_flags: item.video_flags,
                capture_ts_us: item.capture_ts_us,
                encode_done_ts_us: item.encode_done_ts_us,
                session_id: item.session_id,
                payload,
                force_idr_requested: u8::from(item.force_idr_requested),
                padding_reserved: [0u8; 7],
            }
        } else {
            LbReceiverMediaEvent {
                abi: LbAbiHeader::new::<LbReceiverMediaEvent>(),
                kind: LbReceiverEventKind::None as u32,
                display_id: 0,
                gop_id: 0,
                frame_id: 0,
                video_flags: 0,
                capture_ts_us: 0,
                encode_done_ts_us: 0,
                session_id: 0,
                payload: LbOwnedBuffer {
                    data: ptr::null(),
                    len: 0,
                    capacity: 0,
                    release: None,
                    user_ctx: ptr::null_mut(),
                },
                force_idr_requested: 0,
                padding_reserved: [0u8; 7],
            }
        };
        // SAFETY: Validated writable `out_event`.
        unsafe { ptr::write(out_event, evt) };
        LbStatus::Ok
    })
}

/// Record platform decode & display present latency microseconds into receiver telemetry histograms.
///
/// # Safety
/// `rx` must be a valid [`LbReceiverSessionHandle`].
#[no_mangle]
pub unsafe extern "C" fn lb_node_receiver_record_timing(
    rx: *mut LbReceiverSessionHandle,
    decode_us: u64,
    present_us: u64,
) -> LbStatus {
    node_panic_boundary(|| {
        if rx.is_null() || !rx.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validated aligned `rx`.
        let wrapper = unsafe { &*rx };
        let _ = wrapper.timing_tx.try_send((decode_us, present_us));
        LbStatus::Ok
    })
}

/// Snapshot sanitized telemetry counters/percentiles from [`LbReceiverSessionHandle`].
///
/// # Safety
/// `rx` and `out_telemetry` must be aligned non-null pointers satisfying `LbAbiHeader`.
#[no_mangle]
pub unsafe extern "C" fn lb_node_receiver_get_telemetry(
    rx: *const LbReceiverSessionHandle,
    out_telemetry: *mut LbNodeTelemetry,
) -> LbStatus {
    node_panic_boundary(|| {
        if rx.is_null() || !rx.is_aligned() || out_telemetry.is_null() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validates `LbAbiHeader` of `out_telemetry`.
        if let Err(s) = unsafe { validate_abi_output(out_telemetry) } {
            return s;
        }
        // SAFETY: Validated aligned `rx`.
        let wrapper = unsafe { &*rx };
        let Ok(g) = wrapper.queue.0.lock() else {
            return LbStatus::Faulted;
        };
        let tel_snapshot = g.telemetry.as_ref().map_or_else(
            || summary_to_ffi(&SessionTelemetrySummary::default()),
            summary_to_ffi,
        );
        // SAFETY: Validated writable `out_telemetry`.
        unsafe { ptr::write(out_telemetry, tel_snapshot) };
        LbStatus::Ok
    })
}

/// Export privacy-sanitized JSON telemetry from [`LbReceiverSessionHandle`].
///
/// # Safety
/// `out_buf` must be writable for `out_cap` bytes; `out_written` must be aligned and writable.
#[no_mangle]
pub unsafe extern "C" fn lb_node_receiver_export_telemetry_json(
    rx: *const LbReceiverSessionHandle,
    out_buf: *mut u8,
    out_cap: usize,
    out_written: *mut usize,
) -> LbStatus {
    node_panic_boundary(|| {
        if rx.is_null() || !rx.is_aligned() || out_written.is_null() || !out_written.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validated aligned `rx`.
        let wrapper = unsafe { &*rx };
        let Ok(g) = wrapper.queue.0.lock() else {
            return LbStatus::Faulted;
        };
        let json = g.telemetry.as_ref().map_or_else(
            || String::from("{}"),
            SessionTelemetrySummary::to_sanitized_json,
        );
        let bytes = json.as_bytes();
        // SAFETY: Validated writable `out_written`.
        unsafe { ptr::write(out_written, bytes.len()) };
        if out_buf.is_null() || out_cap < bytes.len() {
            return LbStatus::BufferTooSmall;
        }
        // SAFETY: Caller guarantees writable `[out_buf; bytes.len()]`.
        let dst = unsafe { slice::from_raw_parts_mut(out_buf, bytes.len()) };
        dst.copy_from_slice(bytes);
        LbStatus::Ok
    })
}

/// Stop and destroy an [`LbReceiverSessionHandle`], releasing any queued unread buffers cleanly.
///
/// # Safety
/// `rx` must be null or a valid exclusive handle from [`lb_node_receiver_start`].
#[no_mangle]
pub unsafe extern "C" fn lb_node_receiver_stop(rx: *mut LbReceiverSessionHandle) -> LbStatus {
    node_panic_boundary(|| {
        if rx.is_null() {
            return LbStatus::Ok;
        }
        if !rx.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Exclusive owned handle from `lb_node_receiver_start`.
        let mut boxed = unsafe { Box::from_raw(rx) };
        let _ = boxed.stop_tx.send(true);
        if let Some(join) = boxed.driver_join.take() {
            boxed.runtime_handle.block_on(async {
                let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
            });
        }
        if let Ok(mut g) = boxed.queue.0.lock() {
            g.events.clear();
        }
        drop(boxed);
        LbStatus::Ok
    })
}

fn wrapper_device_service_info(
    node: &LumaBridgeNode,
    pair_addr: SocketAddr,
    kind: TransportKind,
) -> lumabridge_transport::discovery::DiscoveryAdvertisement {
    let mut short_hex = String::with_capacity(16);
    for b in &node.device_id().as_bytes()[..8] {
        use core::fmt::Write as _;
        let _ = write!(short_hex, "{b:02x}");
    }
    let host_ip = match pair_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => std::net::Ipv4Addr::LOCALHOST,
    };
    let (quic_port, tcp_port) = match kind {
        TransportKind::TcpTls => (0, Some(pair_addr.port())),
        TransportKind::QuicDatagram | TransportKind::QuicStream => (pair_addr.port(), None),
    };
    lumabridge_transport::discovery::DiscoveryAdvertisement {
        short_device_id_hex: short_hex,
        friendly_name: node.config().friendly_name.clone(),
        host_ip,
        quic_port,
        tcp_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cfg(role: LbNodeRole, name: &str) -> LbNodeConfig {
        let mut buf = [0u8; 48];
        let b = name.as_bytes();
        buf[..b.len()].copy_from_slice(b);
        LbNodeConfig {
            abi: LbAbiHeader::new::<LbNodeConfig>(),
            role: role as u32,
            transport_kind: LbNodeTransportKind::QuicDatagram as u32,
            max_virtual_displays: 1,
            reserved0: 0,
            heartbeat_timeout_ms: 4_000,
            friendly_name: buf,
            friendly_name_len: u32::try_from(b.len()).unwrap_or(0),
            reserved1: 0,
        }
    }

    #[test]
    fn ffi_node_abi_guards_and_loopback_roundtrip() {
        let mut h: *mut LbNodeHandle = ptr::null_mut();
        let mut r: *mut LbNodeHandle = ptr::null_mut();
        let h_cfg = make_cfg(LbNodeRole::Host, "FfiHost");
        let r_cfg = make_cfg(LbNodeRole::Controller, "FfiRx");
        assert_eq!(
            unsafe { lb_node_create(&raw const h_cfg, &raw mut h) },
            LbStatus::Ok
        );
        assert_eq!(
            unsafe { lb_node_create(&raw const r_cfg, &raw mut r) },
            LbStatus::Ok
        );

        let mut h_id = [0u8; 32];
        assert_eq!(
            unsafe { lb_node_local_device_id(h, h_id.as_mut_ptr(), 16) },
            LbStatus::BufferTooSmall
        );
        assert_eq!(
            unsafe { lb_node_local_device_id(h, h_id.as_mut_ptr(), 32) },
            LbStatus::Ok
        );

        let mut tel = LbNodeTelemetry {
            abi: LbAbiHeader::new::<LbNodeTelemetry>(),
            frames_sent: 0,
            frames_delivered: 0,
            dropped_frames: 0,
            idr_requests: 0,
            protected_blanks: 0,
            unauthorized_input_drops: 0,
            clock_sync_rtt_us: 0,
            e2e_p50_us: 0,
            e2e_p95_us: 0,
            e2e_p99_us: 0,
        };
        assert_eq!(
            unsafe {
                lb_node_run_loopback_selftest(
                    h,
                    r,
                    LbNodeTransportKind::QuicDatagram as u32,
                    12,
                    &raw mut tel,
                )
            },
            LbStatus::Ok
        );
        assert!(tel.frames_delivered >= 1);
        assert_eq!(tel.protected_blanks, 1);

        let mut trusted = 0u32;
        assert_eq!(
            unsafe { lb_node_is_peer_trusted(r, h_id.as_ptr(), 32, &raw mut trusted) },
            LbStatus::Ok
        );
        assert_eq!(trusted, 1);
        assert_eq!(
            unsafe { lb_node_revoke_peer(r, h_id.as_ptr(), 32) },
            LbStatus::Ok
        );
        assert_eq!(
            unsafe { lb_node_is_peer_trusted(r, h_id.as_ptr(), 32, &raw mut trusted) },
            LbStatus::Ok
        );
        assert_eq!(trusted, 0);

        assert_eq!(unsafe { lb_node_destroy(h) }, LbStatus::Ok);
        assert_eq!(unsafe { lb_node_destroy(r) }, LbStatus::Ok);
        assert_eq!(unsafe { lb_node_destroy(ptr::null_mut()) }, LbStatus::Ok);
    }

    #[test]
    fn ffi_node_rejects_invalid_configs_roles_and_frame_bounds() {
        let mut out: *mut LbNodeHandle = ptr::null_mut();
        let mut bad_res = make_cfg(LbNodeRole::Host, "BadRes");
        bad_res.reserved0 = 1;
        assert_eq!(
            unsafe { lb_node_create(&raw const bad_res, &raw mut out) },
            LbStatus::InvalidArgument
        );

        let mut bad_len = make_cfg(LbNodeRole::Host, "X");
        bad_len.friendly_name_len = 0;
        assert_eq!(
            unsafe { lb_node_create(&raw const bad_len, &raw mut out) },
            LbStatus::InvalidArgument
        );
        bad_len.friendly_name_len = 49;
        assert_eq!(
            unsafe { lb_node_create(&raw const bad_len, &raw mut out) },
            LbStatus::InvalidArgument
        );

        let mut bad_utf8 = make_cfg(LbNodeRole::Host, "Good");
        bad_utf8.friendly_name[0] = 0xFF;
        bad_utf8.friendly_name[1] = 0xFE;
        bad_utf8.friendly_name_len = 2;
        assert_eq!(
            unsafe { lb_node_create(&raw const bad_utf8, &raw mut out) },
            LbStatus::InvalidArgument
        );

        let first_host_cfg = make_cfg(LbNodeRole::Host, "HostA");
        let second_host_cfg = make_cfg(LbNodeRole::Host, "HostB");
        let ctrl_cfg = make_cfg(LbNodeRole::Controller, "CtrlA");
        let mut h1: *mut LbNodeHandle = ptr::null_mut();
        let mut h2: *mut LbNodeHandle = ptr::null_mut();
        let mut r1: *mut LbNodeHandle = ptr::null_mut();
        assert_eq!(
            unsafe { lb_node_create(&raw const first_host_cfg, &raw mut h1) },
            LbStatus::Ok
        );
        assert_eq!(
            unsafe { lb_node_create(&raw const second_host_cfg, &raw mut h2) },
            LbStatus::Ok
        );
        assert_eq!(
            unsafe { lb_node_create(&raw const ctrl_cfg, &raw mut r1) },
            LbStatus::Ok
        );

        let mut tel = LbNodeTelemetry {
            abi: LbAbiHeader::new::<LbNodeTelemetry>(),
            frames_sent: 0,
            frames_delivered: 0,
            dropped_frames: 0,
            idr_requests: 0,
            protected_blanks: 0,
            unauthorized_input_drops: 0,
            clock_sync_rtt_us: 0,
            e2e_p50_us: 0,
            e2e_p95_us: 0,
            e2e_p99_us: 0,
        };
        assert_eq!(
            unsafe { lb_node_run_loopback_selftest(h1, h1, 0, 4, &raw mut tel) },
            LbStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { lb_node_run_loopback_selftest(h1, h2, 0, 4, &raw mut tel) },
            LbStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { lb_node_run_loopback_selftest(r1, h1, 0, 4, &raw mut tel) },
            LbStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { lb_node_run_loopback_selftest(h1, r1, 0, 0, &raw mut tel) },
            LbStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { lb_node_run_loopback_selftest(h1, r1, 0, 1025, &raw mut tel) },
            LbStatus::InvalidArgument
        );

        assert_eq!(unsafe { lb_node_destroy(h1) }, LbStatus::Ok);
        assert_eq!(unsafe { lb_node_destroy(h2) }, LbStatus::Ok);
        assert_eq!(unsafe { lb_node_destroy(r1) }, LbStatus::Ok);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn ffi_live_host_and_receiver_streaming_blank_and_telemetry_json() {
        let host_cfg = make_cfg(LbNodeRole::Host, "LiveFfiHost");
        let rx_cfg = make_cfg(LbNodeRole::Controller, "LiveFfiRx");
        let mut host_node: *mut LbNodeHandle = ptr::null_mut();
        let mut rx_node: *mut LbNodeHandle = ptr::null_mut();
        assert_eq!(
            unsafe { lb_node_create(&raw const host_cfg, &raw mut host_node) },
            LbStatus::Ok
        );
        assert_eq!(
            unsafe { lb_node_create(&raw const rx_cfg, &raw mut rx_node) },
            LbStatus::Ok
        );

        let mut bind_buf = [0u8; 64];
        let bind_str = b"127.0.0.1:0";
        bind_buf[..bind_str.len()].copy_from_slice(bind_str);
        let rx_start_cfg = LbReceiverStartConfig {
            abi: LbAbiHeader::new::<LbReceiverStartConfig>(),
            transport_kind: LbNodeTransportKind::QuicDatagram as u32,
            bind_addr_len: u32::try_from(bind_str.len()).unwrap_or(0),
            bind_addr_utf8: bind_buf,
            width: 1920,
            height: 1080,
            fps_num: 60,
            fps_den: 1,
            enable_mdns: 0,
            reserved0: 0,
            reserved1: 0,
            reserved2: 0,
        };
        let mut rx_sess: *mut LbReceiverSessionHandle = ptr::null_mut();
        assert_eq!(
            unsafe { lb_node_receiver_start(rx_node, &raw const rx_start_cfg, &raw mut rx_sess) },
            LbStatus::Ok
        );

        let mut ep = LbReceiverEndpoints {
            abi: LbAbiHeader::new::<LbReceiverEndpoints>(),
            pair_addr_utf8: [0u8; 64],
            op_addr_utf8: [0u8; 64],
            device_id_hex: [0u8; 65],
            pin_ascii: [0u8; 17],
            reserved0: [0u8; 6],
        };
        assert_eq!(
            unsafe { lb_node_receiver_get_endpoints(rx_sess, &raw mut ep) },
            LbStatus::Ok
        );

        let cstr_len = |s: &[u8]| s.iter().position(|&b| b == 0).unwrap_or(s.len());
        let pair_len = cstr_len(&ep.pair_addr_utf8);
        let op_len = cstr_len(&ep.op_addr_utf8);
        let did_len = cstr_len(&ep.device_id_hex);
        let pin_len = cstr_len(&ep.pin_ascii);

        let mut pin_16 = [0u8; 16];
        pin_16[..pin_len].copy_from_slice(&ep.pin_ascii[..pin_len]);
        let mut did_64 = [0u8; 64];
        did_64[..did_len].copy_from_slice(&ep.device_id_hex[..did_len]);

        let host_conn_cfg = LbHostConnectConfig {
            abi: LbAbiHeader::new::<LbHostConnectConfig>(),
            transport_kind: LbNodeTransportKind::QuicDatagram as u32,
            reserved0: 0,
            pair_addr_utf8: ep.pair_addr_utf8,
            op_addr_utf8: ep.op_addr_utf8,
            pin_ascii: pin_16,
            peer_device_id_hex: did_64,
            pair_addr_len: u32::try_from(pair_len).unwrap_or(0),
            op_addr_len: u32::try_from(op_len).unwrap_or(0),
            pin_len: u32::try_from(pin_len).unwrap_or(0),
            peer_device_id_len: u32::try_from(did_len).unwrap_or(0),
            width: 1920,
            height: 1080,
            fps_num: 60,
            fps_den: 1,
            initial_bitrate_bps: 15_000_000,
            timeout_ms: 8_000,
        };
        let mut host_sess: *mut LbHostSessionHandle = ptr::null_mut();
        assert_eq!(
            unsafe {
                lb_node_host_connect(host_node, &raw const host_conn_cfg, &raw mut host_sess)
            },
            LbStatus::Ok
        );

        let payload_idr = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x29, 0xAA, 0xBB];
        let meta = crate::LbEncodedFrameMeta {
            abi: LbAbiHeader::new::<crate::LbEncodedFrameMeta>(),
            session_id: 1,
            capture_ts_us: 1_000,
            encode_done_ts_us: 1_400,
            submit_qpc_ticks: 10,
            codec: crate::LbEncodedCodec::H264AnnexB as u32,
            flags: 1,
            frame_id: 1,
            display_id: 0,
            gop_id: 1,
        };
        assert_eq!(
            unsafe {
                lb_node_host_submit_h264(
                    host_sess,
                    &raw const meta,
                    payload_idr.as_ptr(),
                    payload_idr.len(),
                )
            },
            LbStatus::Ok
        );

        let mut evt = LbReceiverMediaEvent {
            abi: LbAbiHeader::new::<LbReceiverMediaEvent>(),
            kind: 0,
            display_id: 0,
            gop_id: 0,
            frame_id: 0,
            video_flags: 0,
            capture_ts_us: 0,
            encode_done_ts_us: 0,
            session_id: 0,
            payload: LbOwnedBuffer {
                data: ptr::null(),
                len: 0,
                capacity: 0,
                release: None,
                user_ctx: ptr::null_mut(),
            },
            force_idr_requested: 0,
            padding_reserved: [0u8; 7],
        };
        let mut got_frame = false;
        for _ in 0..40 {
            assert_eq!(
                unsafe { lb_node_receiver_poll_event(rx_sess, 50, &raw mut evt) },
                LbStatus::Ok
            );
            if evt.kind == LbReceiverEventKind::VideoFrame as u32 {
                assert_eq!(evt.frame_id, 1);
                assert_eq!(evt.payload.len, payload_idr.len());
                assert_eq!(
                    unsafe { crate::lb_core_release_buffer(&raw mut evt.payload) },
                    LbStatus::Ok
                );
                assert_eq!(
                    unsafe { lb_node_receiver_record_timing(rx_sess, 250, 120) },
                    LbStatus::Ok
                );
                got_frame = true;
                break;
            }
        }
        assert!(got_frame, "receiver must receive live submitted H264 frame");

        assert_eq!(
            unsafe { lb_node_host_send_protected_blank(host_sess, 0, 2, 1, 2_000) },
            LbStatus::Ok
        );
        let mut got_blank = false;
        for _ in 0..40 {
            assert_eq!(
                unsafe { lb_node_receiver_poll_event(rx_sess, 50, &raw mut evt) },
                LbStatus::Ok
            );
            if evt.kind == LbReceiverEventKind::ProtectedBlank as u32 {
                got_blank = true;
                break;
            }
            if evt.payload.release.is_some() {
                let _ = unsafe { crate::lb_core_release_buffer(&raw mut evt.payload) };
            }
        }
        assert!(got_blank, "receiver must observe ProtectedBlank");

        let mut json_buf = vec![0u8; 4096];
        let mut written = 0usize;
        assert_eq!(
            unsafe {
                lb_node_receiver_export_telemetry_json(
                    rx_sess,
                    json_buf.as_mut_ptr(),
                    json_buf.len(),
                    &raw mut written,
                )
            },
            LbStatus::Ok
        );
        let json_str = core::str::from_utf8(&json_buf[..written]).expect("utf8 json");
        assert!(json_str.contains("\"frames_delivered\":"));
        assert!(json_str.contains("\"protected_blanks\": 1"));

        let mut host_tel = LbNodeTelemetry {
            abi: LbAbiHeader::new::<LbNodeTelemetry>(),
            frames_sent: 0,
            frames_delivered: 0,
            dropped_frames: 0,
            idr_requests: 0,
            protected_blanks: 0,
            unauthorized_input_drops: 0,
            clock_sync_rtt_us: 0,
            e2e_p50_us: 0,
            e2e_p95_us: 0,
            e2e_p99_us: 0,
        };
        let mut host_fb = LbHostFeedback {
            abi: LbAbiHeader::new::<LbHostFeedback>(),
            recommended_bitrate_bps: 0,
            force_idr_requested: 0,
            session_closed: 0,
            reserved0: 0,
        };
        assert_eq!(
            unsafe { lb_node_host_get_telemetry(host_sess, &raw mut host_tel, &raw mut host_fb) },
            LbStatus::Ok
        );
        assert_eq!(host_tel.frames_sent, 1);
        assert_eq!(host_tel.protected_blanks, 1);

        assert_eq!(unsafe { lb_node_host_close(host_sess) }, LbStatus::Ok);
        assert_eq!(unsafe { lb_node_receiver_stop(rx_sess) }, LbStatus::Ok);
        assert_eq!(unsafe { lb_node_destroy(host_node) }, LbStatus::Ok);
        assert_eq!(unsafe { lb_node_destroy(rx_node) }, LbStatus::Ok);
    }
}
