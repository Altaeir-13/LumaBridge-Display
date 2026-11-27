//! Minimal `UniFFI` Kotlin/Android Proof-of-Concept bindings over `lumabridge-core`.

use std::fmt;
use std::sync::Arc;

use lumabridge_core::{
    CoreConfig, CoreError, CoreObserver, CoreSession, CoreState, EncodedCodec, EncodedFrameMeta,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiPocCodec {
    H264AnnexB,
    HevcAnnexB,
    Av1Obu,
}

impl From<FfiPocCodec> for EncodedCodec {
    fn from(value: FfiPocCodec) -> Self {
        match value {
            FfiPocCodec::H264AnnexB => Self::H264AnnexB,
            FfiPocCodec::HevcAnnexB => Self::HevcAnnexB,
            FfiPocCodec::Av1Obu => Self::Av1Obu,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiPocState {
    Created,
    Running,
    Stopping,
    Stopped,
    Faulted,
}

impl From<CoreState> for FfiPocState {
    fn from(value: CoreState) -> Self {
        match value {
            CoreState::Created => Self::Created,
            CoreState::Running => Self::Running,
            CoreState::Stopping => Self::Stopping,
            CoreState::Stopped => Self::Stopped,
            CoreState::Faulted => Self::Faulted,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum FfiPocError {
    InvalidArgument { reason: String },
    InvalidState,
    Backpressure,
    Faulted,
    InternalPanic,
    NotSupported,
}

impl fmt::Display for FfiPocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument { reason } => write!(f, "InvalidArgument: {reason}"),
            Self::InvalidState => write!(f, "InvalidState"),
            Self::Backpressure => write!(f, "Backpressure"),
            Self::Faulted => write!(f, "Faulted"),
            Self::InternalPanic => write!(f, "InternalPanic"),
            Self::NotSupported => write!(f, "NotSupported"),
        }
    }
}

impl std::error::Error for FfiPocError {}

impl From<CoreError> for FfiPocError {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::InvalidArgument(msg) => Self::InvalidArgument {
                reason: msg.to_owned(),
            },
            CoreError::InvalidState(_) => Self::InvalidState,
            CoreError::Backpressure => Self::Backpressure,
            CoreError::Faulted => Self::Faulted,
            CoreError::InternalPanic => Self::InternalPanic,
            CoreError::NotSupported => Self::NotSupported,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiPocMetrics {
    pub state: FfiPocState,
    pub queue_depth: u32,
    pub queue_peak_depth: u32,
    pub packets_submitted: u64,
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub backpressure_events: u64,
}

struct UniffiObserver;
impl CoreObserver for UniffiObserver {
    fn on_output_packet(&self, _meta: &EncodedFrameMeta, _payload: Vec<u8>) {}
    fn on_state_changed(&self, _new_state: CoreState, _status: Result<(), CoreError>) {}
}

#[derive(uniffi::Object)]
pub struct FfiPocSession {
    session: CoreSession,
}

#[must_use]
#[uniffi::export]
pub fn ffi_poc_abi_version_string() -> String {
    format!("{}.{}", crate::LB_FFI_ABI_MAJOR, crate::LB_FFI_ABI_MINOR)
}

#[uniffi::export]
impl FfiPocSession {
    #[uniffi::constructor]
    pub fn new(
        queue_capacity: u32,
        expected_frame_bytes_hint: u32,
    ) -> Result<Arc<Self>, FfiPocError> {
        let session = CoreSession::create(
            CoreConfig {
                queue_capacity: queue_capacity as usize,
                expected_frame_bytes_hint: expected_frame_bytes_hint as usize,
            },
            Arc::new(UniffiObserver),
        )?;
        Ok(Arc::new(Self { session }))
    }

    pub fn start(&self) -> Result<(), FfiPocError> {
        self.session.start().map_err(Into::into)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn submit_synthetic_encoded_frame(
        &self,
        session_id: u64,
        frame_id: u32,
        gop_id: u16,
        codec: FfiPocCodec,
        payload: Vec<u8>,
    ) -> Result<(), FfiPocError> {
        let meta = EncodedFrameMeta {
            session_id,
            display_id: 0,
            codec: codec.into(),
            flags: u32::from(frame_id == 1),
            frame_id,
            gop_id,
            capture_ts_us: u64::from(frame_id) * 16_667,
            encode_done_ts_us: u64::from(frame_id) * 16_667 + 50,
            submit_qpc_ticks: u64::from(frame_id),
        };
        self.session
            .submit_borrowed(&meta, &payload)
            .map_err(Into::into)
    }

    pub fn stop(&self) -> Result<(), FfiPocError> {
        self.session.stop().map_err(Into::into)
    }

    #[must_use]
    pub fn metrics(&self) -> FfiPocMetrics {
        let m = self.session.metrics();
        let state = match m.state {
            0 => FfiPocState::Created,
            1 => FfiPocState::Running,
            2 => FfiPocState::Stopping,
            3 => FfiPocState::Stopped,
            _ => FfiPocState::Faulted,
        };
        FfiPocMetrics {
            state,
            queue_depth: m.queue_depth,
            queue_peak_depth: m.queue_peak_depth,
            packets_submitted: m.packets_submitted,
            packets_processed: m.packets_processed,
            bytes_processed: m.bytes_processed,
            backpressure_events: m.backpressure_events,
        }
    }
}

/// Privacy-sanitized operational node telemetry record exposed over `UniFFI` (`M1.5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiNodeTelemetry {
    pub frames_sent: u64,
    pub frames_delivered: u64,
    pub dropped_frames: u64,
    pub protected_blanks: u64,
}

/// Supported wire protocol version advertised through `UniFFI`.
#[must_use]
#[uniffi::export]
pub fn ffi_node_protocol_version() -> String {
    format!(
        "{}.{}",
        lumabridge_protocol::version::LBWP_PROTOCOL_MAJOR,
        lumabridge_protocol::version::LBWP_PROTOCOL_MINOR
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniffi_session_roundtrip() {
        assert_eq!(ffi_poc_abi_version_string(), "1.0");
        assert_eq!(ffi_node_protocol_version(), "1.0");
        let session = FfiPocSession::new(8, 1024).expect("create");
        session.start().expect("start");
        session
            .submit_synthetic_encoded_frame(
                1,
                1,
                1,
                FfiPocCodec::H264AnnexB,
                vec![0, 0, 0, 1, 0x65],
            )
            .expect("submit");
        for _ in 0..100 {
            if session.metrics().packets_processed >= 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        session.stop().expect("stop");
        assert_eq!(session.metrics().packets_processed, 1);
    }
}
