// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! Two-process M1.5 operational CLI runner validating real SPAKE2 pairing, mTLS `SessionOpen`,
//! synthetic 1080p60 H.264 Annex-B streaming over `QUIC`/`TCP+TLS 1.3`, `ClockSyncPing`/`Pong`,
//! IDR recovery, and privacy-sanitized JSON telemetry reports.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]

use lumabridge_core::node::{LumaBridgeNode, NodeConfig, NodeError, NodeMediaEvent};
use lumabridge_core::telemetry::SessionTelemetrySummary;
use lumabridge_protocol::control::{
    ActiveDisplayConfig, CaptureMode, CloseReasonCode, CodecCapability, ColorFormat,
    ControlMessage, DisplayMode, DisplayRequest, InputCapabilities, LatencyProfile,
    NodeCapabilities, OsGraphicsPlatform, Permissions, RoleFlags, RotationDeg,
};
use lumabridge_protocol::media::fragmentation::FrameKind;
use lumabridge_protocol::version::CodecId;
use lumabridge_security::authorization::AuthorizationPolicyContext;
use lumabridge_security::identity::{DeviceId, PeerRole};
use lumabridge_security::pairing::{HumanApprovalDecision, PinPairingWindow};
use lumabridge_security::secret::{CheckedOsCryptoRng, PinSecret};
use lumabridge_security::tls::{LUMABRIDGE_ALPN_V1, LUMABRIDGE_PAIR_ALPN_V1};
use lumabridge_transport::config::{TransportConfig, TransportKind};
use lumabridge_transport::queue::OutboundVideoFrame;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliMode {
    Host,
    Receiver,
}

#[derive(Debug, Clone)]
struct CliArgs {
    mode: CliMode,
    transport: TransportKind,
    bind_addr: SocketAddr,
    pair_port_out: Option<PathBuf>,
    rendezvous_in: Option<PathBuf>,
    pair_endpoint: Option<SocketAddr>,
    op_endpoint: Option<SocketAddr>,
    peer_device_hex: Option<String>,
    pin: Option<String>,
    synthetic_media: bool,
    frames: u32,
    fps: u32,
    h264_annexb_file: Option<PathBuf>,
    send_blank_end: bool,
    json_report: Option<PathBuf>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1_700_000_000, |d| d.as_secs())
}

fn default_caps() -> NodeCapabilities {
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
        max_virtual_displays: 1,
        supports_scale: true,
        supports_rotation: true,
        input_caps_mask: InputCapabilities::POINTER.union(InputCapabilities::KEYBOARD),
    }
}

fn parse_device_id_hex(hex: &str) -> Result<DeviceId, NodeError> {
    if hex.len() != 64 {
        return Err(NodeError::InvalidConfig(
            "peer-device-hex must be 64 hex chars",
        ));
    }
    let mut raw = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let s = core::str::from_utf8(chunk)
            .map_err(|_| NodeError::InvalidConfig("invalid UTF-8 in device id hex"))?;
        raw[idx] = u8::from_str_radix(s, 16)
            .map_err(|_| NodeError::InvalidConfig("invalid hex byte in device id"))?;
    }
    Ok(DeviceId::from_bytes(raw))
}

fn to_hex_lower(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use core::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[allow(clippy::too_many_lines)]
fn parse_args() -> Result<CliArgs, NodeError> {
    let mut mode: Option<CliMode> = None;
    let mut transport = TransportKind::QuicDatagram;
    let mut bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("valid loopback literal");
    let mut pair_port_out = None;
    let mut rendezvous_in = None;
    let mut pair_endpoint = None;
    let mut op_endpoint = None;
    let mut peer_device_hex = None;
    let mut pin: Option<String> = None;
    let mut frames = 180u32;
    let mut fps = 60u32;
    let mut h264_annexb_file = None;
    let mut send_blank_end = false;
    let mut json_report = None;

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        if flag == "--send-blank-end" {
            send_blank_end = true;
            continue;
        }
        if flag == "--pin-stdin" {
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|_| NodeError::InvalidConfig("failed reading PIN from stdin"))?;
            pin = Some(line.trim().to_owned());
            line.zeroize();
            continue;
        }
        let val = it
            .next()
            .ok_or(NodeError::InvalidConfig("missing value for CLI flag"))?;
        match flag.as_str() {
            "--mode" => {
                mode = match val.as_str() {
                    "host" => Some(CliMode::Host),
                    "receiver" => Some(CliMode::Receiver),
                    _ => return Err(NodeError::InvalidConfig("--mode must be host or receiver")),
                };
            }
            "--transport" => {
                transport = match val.as_str() {
                    "quic-datagram" => TransportKind::QuicDatagram,
                    "quic-stream" => TransportKind::QuicStream,
                    "tcp-tls" => TransportKind::TcpTls,
                    _ => return Err(NodeError::InvalidConfig("unsupported --transport")),
                };
            }
            "--bind" => {
                bind_addr = val
                    .parse()
                    .map_err(|_| NodeError::InvalidConfig("invalid --bind SocketAddr"))?;
            }
            "--endpoint-out" => pair_port_out = Some(PathBuf::from(val)),
            "--rendezvous-in" => rendezvous_in = Some(PathBuf::from(val)),
            "--connect" => {
                pair_endpoint = Some(
                    val.parse()
                        .map_err(|_| NodeError::InvalidConfig("invalid --connect SocketAddr"))?,
                );
            }
            "--op-connect" => {
                op_endpoint =
                    Some(val.parse().map_err(|_| {
                        NodeError::InvalidConfig("invalid --op-connect SocketAddr")
                    })?);
            }
            "--peer-device-hex" => peer_device_hex = Some(val),
            "--pin" => {
                eprintln!("[WARN] --pin exposes pairing secret on command line; prefer --pin-stdin or --rendezvous-in.");
                pin = Some(val);
            }
            "--ci-synthetic-pin" => pin = Some(val),
            "--frames" => {
                frames = val
                    .parse()
                    .map_err(|_| NodeError::InvalidConfig("invalid --frames u32"))?;
            }
            "--fps" => {
                fps = val
                    .parse()
                    .map_err(|_| NodeError::InvalidConfig("invalid --fps u32"))?;
            }
            "--h264-annexb-file" => h264_annexb_file = Some(PathBuf::from(val)),
            "--json-report" => json_report = Some(PathBuf::from(val)),
            _ => return Err(NodeError::InvalidConfig("unknown CLI argument")),
        }
    }

    let synthetic_media = true;
    Ok(CliArgs {
        mode: mode.ok_or(NodeError::InvalidConfig("--mode is required"))?,
        transport,
        bind_addr,
        pair_port_out,
        rendezvous_in,
        pair_endpoint,
        op_endpoint,
        peer_device_hex,
        pin,
        synthetic_media,
        frames,
        fps: fps.max(1),
        h264_annexb_file,
        send_blank_end,
        json_report,
    })
}

#[allow(clippy::too_many_lines)]
async fn run_receiver(args: CliArgs) -> Result<SessionTelemetrySummary, NodeError> {
    let startup_now = now_unix();
    let mut rng = CheckedOsCryptoRng::preflight()?;
    let node = LumaBridgeNode::generate(
        NodeConfig {
            friendly_name: String::from("M1.5 Synthetic Receiver"),
            role: PeerRole::Controller,
            capabilities: default_caps(),
            transport_config: TransportConfig {
                kind: args.transport,
                heartbeat_timeout_ms: 8_000,
                ..TransportConfig::default()
            },
            policy_ctx: AuthorizationPolicyContext::allow_all_v1(),
            session_ttl_secs: 3600,
            resume_ttl_secs: 600,
            max_connections: 8,
        },
        &mut rng,
        startup_now.saturating_sub(300),
        7_200,
    )?;

    let pin_window = PinPairingWindow::new();
    let generated_pin = pin_window.open_with_new_pin(&mut rng, now_unix())?;
    let pair_srv = node
        .bind_server(args.transport, args.bind_addr, true)
        .await?;
    let op_srv = node
        .bind_server(args.transport, args.bind_addr, false)
        .await?;
    let pair_addr = pair_srv.local_addr()?;
    let op_addr = op_srv.local_addr()?;
    let mut ready_line = {
        let pin_ascii = core::str::from_utf8(generated_pin.expose_bytes())
            .map_err(|_| NodeError::InvalidConfig("non-ASCII PIN"))?;
        format!(
            "{pair_addr}|{op_addr}|{}|{pin_ascii}",
            to_hex_lower(node.device_id().as_bytes()),
        )
    };
    if let Some(ref out_path) = args.pair_port_out {
        let tmp_path = out_path.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&tmp_path)
            .map_err(|_| NodeError::InvalidConfig("failed creating --endpoint-out temp file"))?;
        file.write_all(ready_line.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| NodeError::InvalidConfig("failed writing --endpoint-out temp file"))?;
        drop(file);
        std::fs::rename(&tmp_path, out_path)
            .map_err(|_| NodeError::InvalidConfig("failed finalizing --endpoint-out"))?;
    } else {
        println!("READY {ready_line}");
    }
    ready_line.zeroize();

    let pair_clock = Instant::now();
    loop {
        if pin_window.remaining_attempts(now_unix()) == 0 {
            return Err(NodeError::Security(
                lumabridge_security::error::SecurityError::PairingState(
                    "PIN pairing attempts exhausted",
                ),
            ));
        }
        let pair_now = now_unix();
        let Ok(pair_link) = pair_srv
            .accept_link(LUMABRIDGE_PAIR_ALPN_V1, pair_now)
            .await
        else {
            continue;
        };
        let now_ms = u64::try_from(pair_clock.elapsed().as_millis()).unwrap_or(u64::MAX);
        if node
            .accept_pairing_over_link(
                pair_link,
                Some(&pin_window),
                None,
                now_unix(),
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

    let op_now = now_unix();
    let op_link = op_srv.accept_link(LUMABRIDGE_ALPN_V1, op_now).await?;
    let mut session = node
        .accept_operational_session(
            op_link,
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
                    initial_bitrate_bps: 12_000_000,
                    capture_mode: CaptureMode::WindowsIddVirtualMonitor,
                }]
            },
            now_unix(),
        )
        .await?;

    session.set_media_origin_synthetic(args.synthetic_media);
    let _ = session.send_clock_sync_ping(1, 0).await;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(20);
    let mut last_seq = 0u32;
    while Instant::now() < deadline
        && session.telemetry_summary().frames_delivered < u64::from(args.frames)
    {
        let ctrl_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
        match session.try_recv_control().await {
            Ok(Some(ControlMessage::SessionClose(_))) => break,
            Ok(Some(msg)) => {
                let _ = session
                    .handle_control_or_feedback(msg, ctrl_us, now_unix())
                    .await?;
            }
            Ok(None) => {}
            Err(NodeError::Transport(
                lumabridge_transport::error::TransportError::ConnectionClosed(_),
            )) if last_seq > 0 => break,
            Err(e) => return Err(e),
        }
        while let Ok(Some(fb_msg)) = session.try_recv_feedback().await {
            let fb_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
            let _ = session
                .handle_control_or_feedback(fb_msg, fb_us, now_unix())
                .await?;
        }
        let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
        match session
            .poll_media_event(Duration::from_millis(20), now_us)
            .await
        {
            Ok(Some(NodeMediaEvent::Frame(f))) => {
                if f.frame_id <= last_seq {
                    return Err(NodeError::Protocol("non-monotonic delivered frame_id"));
                }
                last_seq = f.frame_id;
            }
            Ok(Some(_) | None) => {}
            Err(NodeError::Transport(
                lumabridge_transport::error::TransportError::ConnectionClosed(_),
            )) if last_seq > 0 => {
                break;
            }
            Err(e) => return Err(e),
        }
        loop {
            match session.try_recv_feedback().await {
                Ok(Some(msg)) => {
                    let fb_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
                    let _ = session
                        .handle_control_or_feedback(msg, fb_us, now_unix())
                        .await?;
                }
                Ok(None) => break,
                Err(NodeError::Transport(
                    lumabridge_transport::error::TransportError::ConnectionClosed(_),
                )) if last_seq > 0 => break,
                Err(e) => return Err(e),
            }
        }
    }

    let summary = session.telemetry_summary();
    op_srv.close();
    Ok(summary)
}

#[allow(clippy::too_many_lines)]
async fn run_host(args: CliArgs) -> Result<SessionTelemetrySummary, NodeError> {
    let startup_now = now_unix();
    let mut rng = CheckedOsCryptoRng::preflight()?;
    let node = LumaBridgeNode::generate(
        NodeConfig {
            friendly_name: String::from("M1.5 Synthetic Host"),
            role: PeerRole::Host,
            capabilities: default_caps(),
            transport_config: TransportConfig {
                kind: args.transport,
                heartbeat_timeout_ms: 8_000,
                ..TransportConfig::default()
            },
            policy_ctx: AuthorizationPolicyContext::allow_all_v1(),
            session_ttl_secs: 3600,
            resume_ttl_secs: 600,
            max_connections: 8,
        },
        &mut rng,
        startup_now.saturating_sub(300),
        7_200,
    )?;

    let rdv_path = args.rendezvous_in.as_ref().or(args.pair_port_out.as_ref());
    let (pair_addr, op_addr, rx_device_id, pin_str) = if let Some(ep_path) = rdv_path {
        let mut contents = String::new();
        for _ in 0..160 {
            if let Ok(raw) = std::fs::read_to_string(ep_path) {
                if raw.trim().split('|').count() == 4 {
                    contents = raw;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let parts: Vec<&str> = contents.trim().split('|').collect();
        if parts.len() != 4 {
            return Err(NodeError::InvalidConfig("malformed rendezvous file"));
        }
        (
            parts[0]
                .parse::<SocketAddr>()
                .map_err(|_| NodeError::InvalidConfig("bad pair addr"))?,
            parts[1]
                .parse::<SocketAddr>()
                .map_err(|_| NodeError::InvalidConfig("bad op addr"))?,
            parse_device_id_hex(parts[2])?,
            parts[3].to_owned(),
        )
    } else {
        let ep = args.pair_endpoint.ok_or(NodeError::InvalidConfig(
            "--connect, --rendezvous-in, or --endpoint-out required",
        ))?;
        let op_ep = args.op_endpoint.unwrap_or(ep);
        let hint_id = match args.peer_device_hex.as_deref() {
            Some(hex) => parse_device_id_hex(hex)?,
            None => DeviceId::from_bytes([0u8; 32]),
        };
        let explicit_pin = args.pin.clone().ok_or(NodeError::InvalidConfig(
            "host manual --connect requires --pin-stdin, --ci-synthetic-pin, or --rendezvous-in",
        ))?;
        (ep, op_ep, hint_id, explicit_pin)
    };

    let pin_secret = PinSecret::new(&pin_str)?;
    let mut pin_str = pin_str;
    pin_str.zeroize();
    let paired_rec = node
        .pair_with_pin(
            args.transport,
            pair_addr,
            rx_device_id,
            &pin_secret,
            now_unix(),
            |p| HumanApprovalDecision::Approve {
                pairing_attempt_id: p.pairing_attempt_id,
                peer_device_id: p.peer_device_id,
                granted_base_perms: Permissions::EXTEND_DISPLAY,
            },
        )
        .await?;

    let mut session = node
        .connect_operational_session(
            args.transport,
            op_addr,
            paired_rec.device_id,
            vec![DisplayRequest {
                display_id: 0,
                mode: DisplayMode::Extend,
                width: 1920,
                height: 1080,
                fps_num: u16::try_from(args.fps).unwrap_or(60),
                fps_den: 1,
                scale_milli: 1000,
                rotation_deg: RotationDeg::Deg0,
                codec_pref: vec![CodecId::H264],
                max_bitrate_bps: 12_000_000,
                latency_profile: LatencyProfile::LowLatency,
            }],
            Permissions::EXTEND_DISPLAY,
            now_unix(),
        )
        .await?;

    let annexb_access_units = if let Some(ref path) = args.h264_annexb_file {
        let bytes = std::fs::read(path)
            .map_err(|_| NodeError::InvalidConfig("failed reading --h264-annexb-file"))?;
        split_annexb_access_units(&bytes)?
    } else {
        Vec::new()
    };

    session.set_media_origin_synthetic(args.synthetic_media);
    let _ = session.send_clock_sync_ping(1, 0).await;
    let start = Instant::now();
    let interval = Duration::from_micros(1_000_000 / u64::from(args.fps));
    let mut next_tick = start;
    let mut gop_id = 1u16;
    let mut force_idr = false;

    for fid in 1..=args.frames {
        let (is_idr, payload) = if annexb_access_units.is_empty() {
            let key = fid == 1 || fid % 60 == 1 || force_idr;
            let mut buf = if key {
                vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x29]
            } else {
                vec![0x00, 0x00, 0x00, 0x01, 0x41, 0x9A]
            };
            buf.resize(
                if key { 6_144 } else { 2_400 },
                u8::try_from(fid & 0xFF).unwrap_or(0),
            );
            (key, buf)
        } else {
            let idx = usize::try_from(fid - 1).unwrap_or(0) % annexb_access_units.len();
            let (au_key, ref au_bytes) = annexb_access_units[idx];
            (au_key || fid == 1, au_bytes.clone())
        };
        if is_idr && fid > 1 {
            gop_id = gop_id.saturating_add(1).max(1);
        }
        force_idr = false;

        let cap_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
        let outcome = session
            .send_encoded_frame(OutboundVideoFrame {
                session_id: session.session_id(),
                display_id: 0,
                codec_id: CodecId::H264,
                frame_id: fid,
                gop_id,
                capture_ts_us: cap_us,
                encode_done_ts_us: cap_us.saturating_add(300),
                kind: if is_idr {
                    FrameKind::Keyframe { chain_reset: true }
                } else {
                    FrameKind::InterFrame
                },
                has_codec_config: is_idr,
                mirror_source: false,
                payload,
            })
            .await?;
        if outcome.force_idr_required {
            force_idr = true;
        }
        while let Some(msg) = session.try_recv_feedback().await? {
            let fb_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
            let _ = session
                .handle_control_or_feedback(msg, fb_us, now_unix())
                .await?;
        }
        next_tick += interval;
        let now_i = Instant::now();
        if next_tick > now_i {
            tokio::time::sleep(next_tick - now_i).await;
        }
    }

    if args.send_blank_end {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let blank_ts = u64::try_from(start.elapsed().as_micros()).unwrap_or(0);
        let _ = session
            .send_protected_blank(0, args.frames.saturating_add(1), gop_id, blank_ts)
            .await;
    }

    tokio::time::sleep(Duration::from_millis(120)).await;
    let summary = session.telemetry_summary();
    session.close(CloseReasonCode::UserRequested).await;
    Ok(summary)
}

fn find_nal_start(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i + 3 < bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 {
            if bytes[i + 2] == 1 {
                return Some((i, 3));
            }
            if i + 4 < bytes.len() && bytes[i + 2] == 0 && bytes[i + 3] == 1 {
                return Some((i, 4));
            }
        }
        i += 1;
    }
    None
}

fn split_annexb_access_units(bytes: &[u8]) -> Result<Vec<(bool, Vec<u8>)>, NodeError> {
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(NodeError::InvalidConfig("h264 Annex-B file exceeds 64 MiB"));
    }
    let mut nal_offsets = Vec::new();
    let mut pos = 0usize;
    while let Some((offset, sc_len)) = find_nal_start(bytes, pos) {
        nal_offsets.push((offset, sc_len));
        pos = offset + sc_len;
    }
    if nal_offsets.is_empty() {
        return Err(NodeError::InvalidConfig("no Annex-B NAL units found"));
    }

    let mut aus = Vec::new();
    let mut current_au = Vec::new();
    let mut current_key = false;
    let mut has_vcl = false;

    for idx in 0..nal_offsets.len() {
        let (start, sc_len) = nal_offsets[idx];
        let end = if idx + 1 < nal_offsets.len() {
            nal_offsets[idx + 1].0
        } else {
            bytes.len()
        };
        if start + sc_len >= end {
            continue;
        }
        let nal_type = bytes[start + sc_len] & 0x1F;
        let is_vcl = (1..=5).contains(&nal_type);
        let is_config_or_aud = matches!(nal_type, 6..=9);
        if has_vcl && (is_vcl || is_config_or_aud) {
            aus.push((current_key, core::mem::take(&mut current_au)));
            current_key = false;
            has_vcl = false;
        }
        if nal_type == 5 || nal_type == 7 {
            current_key = true;
        }
        if is_vcl {
            has_vcl = true;
        }
        current_au.extend_from_slice(&bytes[start..end]);
    }
    if !current_au.is_empty() {
        aus.push((current_key, current_au));
    }
    if aus.is_empty() {
        return Err(NodeError::InvalidConfig(
            "no access units produced from Annex-B file",
        ));
    }
    Ok(aus)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("lumabridge_node argument error: {e}");
            std::process::exit(2);
        }
    };
    let report_path = args.json_report.clone();
    let res = match args.mode {
        CliMode::Receiver => run_receiver(args).await,
        CliMode::Host => run_host(args).await,
    };
    match res {
        Ok(summary) => {
            let json = summary.to_sanitized_json();
            if let Some(path) = report_path {
                if let Err(e) = std::fs::write(&path, json.as_bytes()) {
                    eprintln!("failed writing json report: {e}");
                    std::process::exit(1);
                }
            } else {
                println!("{json}");
            }
        }
        Err(e) => {
            eprintln!("lumabridge_node failure: {e}");
            std::process::exit(1);
        }
    }
}
