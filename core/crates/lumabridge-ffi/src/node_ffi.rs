// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Additive operational node FFI boundary (`lb_node_*`) exposing `LumaBridgeNode` over the
//! versioned C ABI (`ADR-0004` + `M1.5`) while preserving `lb_core_*` unchanged and isolated.

use crate::{read_and_validate_abi_input, validate_abi_output, LbAbiHeader, LbStatus};
use lumabridge_core::node::{LumaBridgeNode, NodeConfig};
use lumabridge_protocol::control::{
    ActiveDisplayConfig, CaptureMode, CloseReasonCode, CodecCapability, ColorFormat, DisplayMode,
    DisplayRequest, InputCapabilities, LatencyProfile, NodeCapabilities, OsGraphicsPlatform,
    Permissions, RoleFlags, RotationDeg,
};
use lumabridge_protocol::media::fragmentation::FrameKind;
use lumabridge_protocol::version::CodecId;
use lumabridge_security::authorization::AuthorizationPolicyContext;
use lumabridge_security::identity::{DeviceId, PeerRole};
use lumabridge_security::pairing::{HumanApprovalDecision, PinPairingWindow};
use lumabridge_security::secret::CheckedOsCryptoRng;
use lumabridge_security::tls::{LUMABRIDGE_ALPN_V1, LUMABRIDGE_PAIR_ALPN_V1};
use lumabridge_security::trust_store::{RevocationReason, TrustStore};
use lumabridge_transport::config::{TransportConfig, TransportKind};
use lumabridge_transport::queue::OutboundVideoFrame;
use std::net::SocketAddr;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::slice;
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
    node: LumaBridgeNode,
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
            now_unix_secs(),
            3600,
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
        let boxed = Box::new(LbNodeHandle { runtime, node });
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
}
