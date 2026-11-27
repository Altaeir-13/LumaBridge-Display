#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

//! Versioned C ABI boundary (`M1.1` Proof of Concept per `ADR-0004`).
//!
//! Layout and version rules:
//! - Local C ABI version `(LB_FFI_ABI_MAJOR = 1, LB_FFI_ABI_MINOR = 0)` is strictly
//!   independent from the Windows local IPC (`LBIF`) and the remote network protocol (`LBWP v1`).
//! - Every versioned parameter/output struct starts with `LbAbiHeader`.
//! - Incompatible `abi_major` or unknown newer `abi_minor` returns `AbiVersionMismatch`.
//! - `struct_size` smaller than the minimum required for the version returns `InvalidStructSize`.
//! - Non-zero `reserved` fields return `InvalidArgument`.
//! - All exported `extern "C"` entry points wrap their body in `std::panic::catch_unwind`.
//!   `catch_unwind` prevents Rust panics from unwinding across the C ABI boundary, but cannot
//!   recover from fatal OS exceptions (access violations), process aborts, or undefined behavior
//!   caused by invalid caller pointers.

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi")]
pub mod uniffi_api;

pub mod node_ffi;
pub use node_ffi::*;

use std::ffi::c_void;
use std::mem::{align_of, offset_of, size_of};
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::Arc;

use lumabridge_core::{
    global_resource_snapshot, record_native_buffer_received, record_native_buffer_released,
    record_rust_buffer_allocated, record_rust_buffer_released, CoreConfig, CoreError, CoreObserver,
    CoreSession, CoreState, EncodedCodec, EncodedFrameMeta, OwnedByteSlice,
    TransactionalOwnedSlice, MAX_ENCODED_FRAME_BYTES, MAX_QUEUE_CAPACITY, MIN_QUEUE_CAPACITY,
};

pub const LB_FFI_ABI_MAJOR: u32 = 1;
pub const LB_FFI_ABI_MINOR: u32 = 0;
pub const LB_FFI_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const LB_FFI_MIN_QUEUE_CAPACITY: u32 = 1;
pub const LB_FFI_MAX_QUEUE_CAPACITY: u32 = 256;

/// cbindgen:ignore
const _: () = {
    assert!(LB_FFI_MAX_FRAME_BYTES == MAX_ENCODED_FRAME_BYTES);
    assert!(LB_FFI_MIN_QUEUE_CAPACITY as usize == MIN_QUEUE_CAPACITY);
    assert!(LB_FFI_MAX_QUEUE_CAPACITY as usize == MAX_QUEUE_CAPACITY);
};

/// Opaque native handle owning a `CoreSession`.
///
/// # Caller Contract & DLL/DSO Lifetime
/// - Must be destroyed exactly once via `lb_core_destroy` after all concurrent calls on `handle`
///   have returned (except cooperative `lb_core_stop` / `lb_core_simulate_disconnect`).
/// - Caller MUST keep the `lumabridge_ffi` shared library loaded in process memory while any
///   `LbCoreHandle` OR any Rust-allocated `LbOwnedBuffer` handed to native output callbacks
///   remains unreleased.
pub struct LbCoreHandle {
    session: CoreSession,
}

/// Deterministic `uint32_t` return status across the C ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LbStatus {
    Ok = 0,
    InvalidArgument = 1,
    AbiVersionMismatch = 2,
    InvalidStructSize = 3,
    InvalidState = 4,
    Backpressure = 5,
    Faulted = 6,
    InternalPanic = 7,
    NotSupported = 8,
    BufferTooSmall = 9,
}

/// Lifecycle state values matching `lumabridge_core::CoreState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LbCoreState {
    Created = 0,
    Running = 1,
    Stopping = 2,
    Stopped = 3,
    Faulted = 4,
}

/// Encoded bitstream container identifiers accepted by the FFI boundary.
/// Raw GPU textures, DXGI handles, DMA-BUF fds, `AHardwareBuffers`, and uncompressed RGB frames
/// are explicitly disallowed at this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LbEncodedCodec {
    H264AnnexB = 1,
    HevcAnnexB = 2,
    Av1Obu = 3,
}

/// Version and size header prefixed to all versioned C ABI structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LbAbiHeader {
    pub abi_major: u32,
    pub abi_minor: u32,
    pub struct_size: u32,
    pub reserved: u32,
}

impl LbAbiHeader {
    #[must_use]
    pub const fn new<T>() -> Self {
        Self {
            abi_major: LB_FFI_ABI_MAJOR,
            abi_minor: LB_FFI_ABI_MINOR,
            #[allow(clippy::cast_possible_truncation)]
            struct_size: size_of::<T>() as u32,
            reserved: 0,
        }
    }
}

/// Allocator-independent release callback matching `ADR-0004`.
/// Whoever allocates an `LbOwnedBuffer` supplies `release`; the receiving side
/// must invoke `release(user_ctx, data, len, capacity)` **noexcept** exactly once.
pub type LbBufferReleaseFn =
    Option<extern "C" fn(user_ctx: *mut c_void, data: *const u8, len: usize, capacity: usize)>;

/// Explicit ownership-transferring byte buffer descriptor (`ADR-0004`).
///
/// # Ownership & Lifetime Rules
/// - Native -> Rust (`lb_core_submit_owned_encoded_frame`): on `LB_STATUS_OK`, Rust zeros
///   `*buffer` (`release == NULL`) and guarantees `release` is invoked **noexcept** exactly once
///   outside internal mutexes.
/// - Rust -> Native (`LbOutputPacketCallback`): native consumer owns the delivered descriptor and
///   must call `lb_core_release_buffer(&owned)` (or `owned.release(...)`) once from any thread,
///   including after `lb_core_destroy`, while keeping `lumabridge_ffi` loaded.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LbOwnedBuffer {
    pub data: *const u8,
    pub len: usize,
    pub capacity: usize,
    pub release: LbBufferReleaseFn,
    pub user_ctx: *mut c_void,
}

/// Encoded bitstream metadata crossing the native/core boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LbEncodedFrameMeta {
    pub abi: LbAbiHeader,
    pub session_id: u64,
    pub capture_ts_us: u64,
    pub encode_done_ts_us: u64,
    pub submit_qpc_ticks: u64,
    pub codec: u32,
    pub flags: u32,
    pub frame_id: u32,
    pub display_id: u16,
    pub gop_id: u16,
}

/// Asynchronous packet callback transferring ownership of a Rust-allocated `LbOwnedBuffer`
/// to the native consumer. The consumer MUST call `buffer.release` exactly once (either
/// synchronously inside the callback or asynchronously later after decoder copy) and MUST NOT
/// throw C++ exceptions across this callback (`noexcept`).
pub type LbOutputPacketCallback = Option<
    extern "C" fn(
        user_ctx: *mut c_void,
        meta: *const LbEncodedFrameMeta,
        owned_buffer: LbOwnedBuffer,
    ),
>;

/// Cooperative lifecycle / fault notification callback (`noexcept` required on native side).
pub type LbStateChangeCallback =
    Option<extern "C" fn(user_ctx: *mut c_void, new_state: u32, status_code: u32)>;

/// Session configuration structure passed to `lb_core_create`.
///
/// # Memory Budget Note
/// `expected_frame_bytes_hint` guides bounded buffer recycling (eager preallocation capped at
/// 4 MiB total / 8 slots); individual queued encoded frames remain bounded by
/// `LB_FFI_MAX_FRAME_BYTES` (8 MiB), with an explicit total-byte admission cap planned for M1/M2.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LbCoreConfig {
    pub abi: LbAbiHeader,
    pub queue_capacity: u32,
    pub expected_frame_bytes_hint: u32,
    pub on_output_packet: LbOutputPacketCallback,
    pub on_state_change: LbStateChangeCallback,
    pub callback_user_ctx: *mut c_void,
}

/// Per-instance operational and drop counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LbCoreMetrics {
    pub abi: LbAbiHeader,
    pub state: u32,
    pub queue_depth: u32,
    pub queue_peak_depth: u32,
    pub reserved0: u32,
    pub packets_submitted: u64,
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub backpressure_events: u64,
    pub native_owned_submitted: u64,
    pub native_owned_dropped: u64,
    pub panic_faults: u64,
}

/// Process-wide lifecycle resource counters across instances, threads, buffers, and callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LbGlobalResourceCounters {
    pub abi: LbAbiHeader,
    pub active_instances: u64,
    pub active_worker_threads: u64,
    pub in_flight_buffers: u64,
    pub callbacks_in_progress: u64,
    pub callbacks_invoked_total: u64,
    pub rust_buffers_allocated: u64,
    pub rust_buffers_released: u64,
    pub native_buffers_received: u64,
    pub native_buffers_released: u64,
    pub disconnect_drains: u64,
}

/// ABI layout signature enabling automated cross-language `sizeof`/`alignof`/`offsetof` verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct LbAbiLayoutSignature {
    pub abi: LbAbiHeader,
    pub size_abi_header: u32,
    pub size_owned_buffer: u32,
    pub size_encoded_frame_meta: u32,
    pub size_core_config: u32,
    pub size_core_metrics: u32,
    pub size_global_counters: u32,
    pub offset_meta_codec: u32,
    pub offset_meta_gop_id: u32,
    pub offset_owned_release: u32,
    pub offset_config_on_output: u32,
}

fn validate_abi_header<T>(header: &LbAbiHeader) -> Result<(), LbStatus> {
    if header.abi_major != LB_FFI_ABI_MAJOR || header.abi_minor > LB_FFI_ABI_MINOR {
        return Err(LbStatus::AbiVersionMismatch);
    }
    let expected_size = u32::try_from(size_of::<T>()).unwrap_or(u32::MAX);
    if header.struct_size < expected_size {
        return Err(LbStatus::InvalidStructSize);
    }
    if header.abi_minor == LB_FFI_ABI_MINOR && header.struct_size != expected_size {
        return Err(LbStatus::InvalidStructSize);
    }
    if header.reserved != 0 {
        return Err(LbStatus::InvalidArgument);
    }
    Ok(())
}

/// Validates pointer non-nullness, 16-byte `LbAbiHeader` (before reading full `T`),
/// and full `T` alignment before reading `T` by value.
///
/// # Safety
/// - If `ptr` is non-null and aligned for `LbAbiHeader`, at least 16 bytes at `ptr` must be readable.
/// - If `validate_abi_header::<T>` succeeds and `ptr` is aligned for `T`, `size_of::<T>()` bytes
///   at `ptr` must be readable.
pub(crate) unsafe fn read_and_validate_abi_input<T: Copy>(ptr: *const T) -> Result<T, LbStatus> {
    if ptr.is_null() {
        return Err(LbStatus::InvalidArgument);
    }
    let hdr_ptr = ptr.cast::<LbAbiHeader>();
    if !hdr_ptr.is_aligned() {
        return Err(LbStatus::InvalidArgument);
    }
    // SAFETY: Caller guarantees 16 readable `LbAbiHeader` bytes when non-null & header-aligned.
    let header = unsafe { ptr::read(hdr_ptr) };
    validate_abi_header::<T>(&header)?;
    if !ptr.is_aligned() {
        return Err(LbStatus::InvalidArgument);
    }
    // SAFETY: Alignment and `struct_size == size_of::<T>()` were validated before full read.
    Ok(unsafe { ptr::read(ptr) })
}

/// Validates pointer non-nullness, 16-byte `LbAbiHeader` (before creating any `&mut T` or writing),
/// and full `T` alignment for an caller-initialized output structure.
///
/// # Safety
/// - If `ptr` is non-null and aligned for `LbAbiHeader`, the 16-byte `LbAbiHeader` prefix at `ptr`
///   must be readable.
/// - If `validate_abi_header::<T>` succeeds and `ptr` is aligned for `T`, `size_of::<T>()` bytes
///   at `ptr` must be writable.
pub(crate) unsafe fn validate_abi_output<T>(ptr: *mut T) -> Result<(), LbStatus> {
    if ptr.is_null() {
        return Err(LbStatus::InvalidArgument);
    }
    let hdr_ptr = ptr.cast_const().cast::<LbAbiHeader>();
    if !hdr_ptr.is_aligned() {
        return Err(LbStatus::InvalidArgument);
    }
    // SAFETY: Caller guarantees 16 readable `LbAbiHeader` bytes when non-null & header-aligned.
    let header = unsafe { ptr::read(hdr_ptr) };
    validate_abi_header::<T>(&header)?;
    if !ptr.is_aligned() {
        return Err(LbStatus::InvalidArgument);
    }
    Ok(())
}

fn map_core_error(err: CoreError) -> LbStatus {
    match err {
        CoreError::InvalidArgument(_) => LbStatus::InvalidArgument,
        CoreError::InvalidState(_) => LbStatus::InvalidState,
        CoreError::Backpressure => LbStatus::Backpressure,
        CoreError::Faulted => LbStatus::Faulted,
        CoreError::InternalPanic => LbStatus::InternalPanic,
        CoreError::NotSupported => LbStatus::NotSupported,
    }
}

fn map_meta_from_ffi(raw: &LbEncodedFrameMeta) -> Result<EncodedFrameMeta, LbStatus> {
    validate_abi_header::<LbEncodedFrameMeta>(&raw.abi)?;
    let Some(codec) = EncodedCodec::from_raw(raw.codec) else {
        return Err(LbStatus::NotSupported);
    };
    let meta = EncodedFrameMeta {
        session_id: raw.session_id,
        display_id: raw.display_id,
        codec,
        flags: raw.flags,
        frame_id: raw.frame_id,
        gop_id: raw.gop_id,
        capture_ts_us: raw.capture_ts_us,
        encode_done_ts_us: raw.encode_done_ts_us,
        submit_qpc_ticks: raw.submit_qpc_ticks,
    };
    meta.validate().map_err(map_core_error)?;
    Ok(meta)
}

fn map_meta_to_ffi(meta: &EncodedFrameMeta) -> LbEncodedFrameMeta {
    LbEncodedFrameMeta {
        abi: LbAbiHeader::new::<LbEncodedFrameMeta>(),
        session_id: meta.session_id,
        capture_ts_us: meta.capture_ts_us,
        encode_done_ts_us: meta.encode_done_ts_us,
        submit_qpc_ticks: meta.submit_qpc_ticks,
        codec: meta.codec as u32,
        flags: meta.flags,
        frame_id: meta.frame_id,
        display_id: meta.display_id,
        gop_id: meta.gop_id,
    }
}

struct RustOwnedVecPayload {
    _storage: Vec<u8>,
}

/// cbindgen:ignore
extern "C" fn lb_ffi_release_rust_vec(
    user_ctx: *mut c_void,
    _data: *const u8,
    _len: usize,
    _capacity: usize,
) {
    if user_ctx.is_null() {
        return;
    }
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `user_ctx` was created exclusively via `Box::into_raw(Box::new(RustOwnedVecPayload { .. }))`
        // in `alloc_rust_owned_buffer` and transfers ownership cleanly back to Rust on the first call.
        unsafe {
            let _reclaimed = Box::from_raw(user_ctx.cast::<RustOwnedVecPayload>());
        }
    }));
    record_rust_buffer_released();
}

fn alloc_rust_owned_buffer(bytes: Vec<u8>) -> LbOwnedBuffer {
    let data = bytes.as_ptr();
    let len = bytes.len();
    let capacity = bytes.capacity();
    let boxed = Box::new(RustOwnedVecPayload { _storage: bytes });
    let user_ctx = Box::into_raw(boxed).cast::<c_void>();
    record_rust_buffer_allocated();
    LbOwnedBuffer {
        data,
        len,
        capacity,
        release: Some(lb_ffi_release_rust_vec),
        user_ctx,
    }
}

/// cbindgen:ignore
type RawReleaseFn =
    extern "C" fn(user_ctx: *mut c_void, data: *const u8, len: usize, capacity: usize);

struct NativeOwnedBufferGuard {
    data: *const u8,
    len: usize,
    capacity: usize,
    release: RawReleaseFn,
    user_ctx_addr: usize,
    caller_desc: *mut LbOwnedBuffer,
    armed: bool,
}

// SAFETY: `LbBufferReleaseFn` and `user_ctx` are supplied under the C ABI contract that
// `release` may execute on the worker thread (strictly outside Rust locks) and `data[0..len]`
// remains immutable and valid until `release` is invoked. `caller_desc` is only accessed
// synchronously on the submitting thread during `commit_ownership()` inside `submit_owned_boxed`
// before returning to the FFI caller, then immediately cleared to null.
unsafe impl Send for NativeOwnedBufferGuard {}

impl OwnedByteSlice for NativeOwnedBufferGuard {
    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: `self.data` and `self.len` were validated non-null and `<= capacity` upon
        // submission, and native caller guarantees read validity until `self.release` runs on Drop.
        unsafe { slice::from_raw_parts(self.data, self.len) }
    }
}

impl TransactionalOwnedSlice for NativeOwnedBufferGuard {
    fn commit_ownership(&mut self) {
        self.armed = true;
        record_native_buffer_received();
        let desc = self.caller_desc;
        self.caller_desc = ptr::null_mut();
        if !desc.is_null() {
            // SAFETY: Still synchronously on the FFI caller thread before `submit_owned_boxed`
            // returns or triggers any post-commit unwind; zeroing `*desc` ensures the caller can
            // never mistakenly re-release an accepted buffer even after `LB_STATUS_INTERNAL_PANIC`.
            unsafe {
                ptr::write(
                    desc,
                    LbOwnedBuffer {
                        data: ptr::null(),
                        len: 0,
                        capacity: 0,
                        release: None,
                        user_ctx: ptr::null_mut(),
                    },
                );
            }
        }
    }
}

impl Drop for NativeOwnedBufferGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            (self.release)(
                self.user_ctx_addr as *mut c_void,
                self.data,
                self.len,
                self.capacity,
            );
        }));
        record_native_buffer_released();
    }
}

struct FfiObserver {
    on_output_packet: LbOutputPacketCallback,
    on_state_change: LbStateChangeCallback,
    user_ctx_addr: usize,
}

// SAFETY: `callback_user_ctx` synchronization/thread-affinity across worker and control calls is an
// explicit caller precondition documented in `lumabridge_ffi.h`.
unsafe impl Send for FfiObserver {}
// SAFETY: `FfiObserver` holds immutable function pointers and caller-synchronized user context.
unsafe impl Sync for FfiObserver {}

impl CoreObserver for FfiObserver {
    fn on_output_packet(&self, meta: &EncodedFrameMeta, payload: Vec<u8>) {
        let Some(cb) = self.on_output_packet else {
            return;
        };
        let ffi_meta = map_meta_to_ffi(meta);
        let owned = alloc_rust_owned_buffer(payload);
        cb(
            self.user_ctx_addr as *mut c_void,
            &raw const ffi_meta,
            owned,
        );
    }

    fn on_state_changed(&self, new_state: CoreState, status: Result<(), CoreError>) {
        let Some(cb) = self.on_state_change else {
            return;
        };
        let status_code = match status {
            Ok(()) => LbStatus::Ok as u32,
            Err(err) => map_core_error(err) as u32,
        };
        cb(
            self.user_ctx_addr as *mut c_void,
            new_state as u32,
            status_code,
        );
    }
}

fn run_with_panic_boundary(
    handle_opt: Option<*mut LbCoreHandle>,
    f: impl FnOnce() -> LbStatus,
) -> LbStatus {
    if let Ok(status) = panic::catch_unwind(AssertUnwindSafe(f)) {
        return status;
    }
    if let Some(raw) = handle_opt {
        if !raw.is_null() && raw.is_aligned() {
            let _ = panic::catch_unwind(AssertUnwindSafe(|| {
                // SAFETY: Called only when the handle pointer passed by caller was non-null and aligned.
                // Marks instance `Faulted` with sanitized reason without re-throwing across C ABI.
                let wrapper = unsafe { &*raw };
                wrapper
                    .session
                    .mark_faulted("Contained Rust panic at FFI boundary");
            }));
        }
    }
    LbStatus::InternalPanic
}

/// Query ABI major and minor version supported by this compiled binary.
///
/// # Safety
/// If `out_major` or `out_minor` is non-null, it must be properly aligned and valid for writing one `u32`.
#[no_mangle]
pub unsafe extern "C" fn lb_core_abi_version(out_major: *mut u32, out_minor: *mut u32) -> LbStatus {
    run_with_panic_boundary(None, || {
        if (out_major.is_null() && out_minor.is_null())
            || (!out_major.is_null() && !out_major.is_aligned())
            || (!out_minor.is_null() && !out_minor.is_aligned())
        {
            return LbStatus::InvalidArgument;
        }
        if !out_major.is_null() {
            // SAFETY: Caller contract guarantees writable aligned pointer for 1 `u32`.
            unsafe { ptr::write(out_major, LB_FFI_ABI_MAJOR) };
        }
        if !out_minor.is_null() {
            // SAFETY: Caller contract guarantees writable aligned pointer for 1 `u32`.
            unsafe { ptr::write(out_minor, LB_FFI_ABI_MINOR) };
        }
        LbStatus::Ok
    })
}

/// Create a new core handle in `LB_CORE_STATE_CREATED`.
///
/// # Safety
/// - `out_handle` must be a valid, properly aligned non-null pointer (`*out_handle` is zeroed on entry).
/// - `config` must be non-null, `LbAbiHeader`-aligned with at least 16 readable bytes; if
///   `config->abi.struct_size >= sizeof(LbCoreConfig)` and `config` is `LbCoreConfig`-aligned,
///   all `sizeof(LbCoreConfig)` bytes must be readable.
/// - If callbacks are supplied in `config`, `callback_user_ctx` must remain valid until
///   `lb_core_destroy` completes, callbacks must be `noexcept` and never invoke `lb_core_destroy`,
///   and the caller must keep `lumabridge_ffi` loaded while handles or Rust `LbOwnedBuffer`s exist.
#[no_mangle]
pub unsafe extern "C" fn lb_core_create(
    config: *const LbCoreConfig,
    out_handle: *mut *mut LbCoreHandle,
) -> LbStatus {
    run_with_panic_boundary(None, || {
        if config.is_null() || out_handle.is_null() || !out_handle.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller guarantees `out_handle` is aligned and writable for `*mut LbCoreHandle`.
        unsafe { ptr::write(out_handle, ptr::null_mut()) };

        // SAFETY: Validates 16-byte `LbAbiHeader` and alignment before reading `LbCoreConfig`.
        let cfg = match unsafe { read_and_validate_abi_input(config) } {
            Ok(c) => c,
            Err(err_status) => return err_status,
        };

        let core_cfg = CoreConfig {
            queue_capacity: cfg.queue_capacity as usize,
            expected_frame_bytes_hint: cfg.expected_frame_bytes_hint as usize,
        };
        let observer = Arc::new(FfiObserver {
            on_output_packet: cfg.on_output_packet,
            on_state_change: cfg.on_state_change,
            user_ctx_addr: cfg.callback_user_ctx as usize,
        });

        let session = match CoreSession::create(core_cfg, observer) {
            Ok(s) => s,
            Err(e) => return map_core_error(e),
        };

        let boxed = Box::new(LbCoreHandle { session });
        // SAFETY: Caller guarantees `out_handle` is aligned, writable, and receives unique ownership.
        unsafe { ptr::write(out_handle, Box::into_raw(boxed)) };
        LbStatus::Ok
    })
}

/// Start the core worker thread (`Created -> Running`).
///
/// # Safety
/// `handle` must be a valid aligned non-null handle returned by `lb_core_create` and not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn lb_core_start(handle: *mut LbCoreHandle) -> LbStatus {
    run_with_panic_boundary(Some(handle), || {
        if handle.is_null() || !handle.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: `handle` is non-null, aligned, and alive per caller precondition.
        let wrapper = unsafe { &*handle };
        match wrapper.session.start() {
            Ok(()) => LbStatus::Ok,
            Err(e) => map_core_error(e),
        }
    })
}

/// Synchronously enqueue a copy of a caller-borrowed encoded frame buffer without waiting on worker/network I/O.
/// Acquires an internal queue mutex briefly, copies `data[0..data_len]` into a bounded internal buffer before returning,
/// or returns `LB_STATUS_BACKPRESSURE` without retaining `data`.
///
/// # Safety
/// - `handle` must be a valid aligned non-null handle returned by `lb_core_create`.
/// - `meta` must have 16 readable `LbAbiHeader` bytes (and full `LbEncodedFrameMeta` readable once valid).
/// - `data` must be readable for `data_len` bytes during this call (`data_len` in `1..=8 MiB`).
#[no_mangle]
pub unsafe extern "C" fn lb_core_submit_encoded_frame(
    handle: *mut LbCoreHandle,
    meta: *const LbEncodedFrameMeta,
    data: *const u8,
    data_len: usize,
) -> LbStatus {
    run_with_panic_boundary(Some(handle), || {
        if handle.is_null() || !handle.is_aligned() || meta.is_null() || data.is_null() {
            return LbStatus::InvalidArgument;
        }
        if data_len == 0 || data_len > MAX_ENCODED_FRAME_BYTES {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validates 16-byte `LbAbiHeader` and alignment before reading `LbEncodedFrameMeta`.
        let raw_meta = match unsafe { read_and_validate_abi_input(meta) } {
            Ok(m) => m,
            Err(s) => return s,
        };
        let parsed_meta = match map_meta_from_ffi(&raw_meta) {
            Ok(m) => m,
            Err(s) => return s,
        };
        // SAFETY: Caller guarantees `handle` is aligned and valid during this call.
        let wrapper = unsafe { &*handle };
        // SAFETY: Caller guarantees `data` points to `data_len` valid immutable bytes for the call duration.
        let bytes = unsafe { slice::from_raw_parts(data, data_len) };
        match wrapper.session.submit_borrowed(&parsed_meta, bytes) {
            Ok(()) => LbStatus::Ok,
            Err(e) => map_core_error(e),
        }
    })
}

/// Enqueue transfer of ownership of a native-allocated `LbOwnedBuffer` into the core
/// using two-phase transactional commit without waiting on worker/network I/O (acquires an internal mutex briefly).
/// - On `LB_STATUS_OK`, Rust owns the buffer, zeroes `*buffer` (`release == NULL`), and
///   guarantees `release` is called **noexcept** exactly once outside internal mutexes.
/// - On any non-panic error status (`InvalidArgument`, `InvalidState`, `Backpressure`,
///   `Faulted`, etc.), ownership remains with the caller, `*buffer` is untouched, and
///   `release` is NOT called.
/// - On `LB_STATUS_INTERNAL_PANIC`, if a pre-commit panic occurred, `*buffer` remains intact
///   (`buffer->release != NULL`) and caller retains ownership; if a post-commit panic occurred,
///   `*buffer` is already zeroed (`buffer->release == NULL`) and Rust drains/releases it once.
///   Calling `lb_core_release_buffer(buffer)` on cleanup safely handles both outcomes without double-free.
///
/// # Safety
/// - `handle` and `buffer` must be valid aligned non-null pointers.
/// - `meta` must have 16 readable `LbAbiHeader` bytes (and full `LbEncodedFrameMeta` readable once valid).
/// - `buffer->data` must be valid and immutable for `buffer->len` bytes until `buffer->release` runs.
#[no_mangle]
pub unsafe extern "C" fn lb_core_submit_owned_encoded_frame(
    handle: *mut LbCoreHandle,
    meta: *const LbEncodedFrameMeta,
    buffer: *mut LbOwnedBuffer,
) -> LbStatus {
    run_with_panic_boundary(Some(handle), || {
        if handle.is_null()
            || !handle.is_aligned()
            || meta.is_null()
            || buffer.is_null()
            || !buffer.is_aligned()
        {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validates 16-byte `LbAbiHeader` and alignment before reading `LbEncodedFrameMeta`.
        let raw_meta = match unsafe { read_and_validate_abi_input(meta) } {
            Ok(m) => m,
            Err(s) => return s,
        };
        let parsed_meta = match map_meta_from_ffi(&raw_meta) {
            Ok(m) => m,
            Err(s) => return s,
        };
        // SAFETY: Caller guarantees aligned readable/writable `LbOwnedBuffer`.
        let owned = unsafe { ptr::read(buffer) };
        if owned.data.is_null()
            || owned.len == 0
            || owned.len > owned.capacity
            || owned.len > MAX_ENCODED_FRAME_BYTES
        {
            return LbStatus::InvalidArgument;
        }
        let Some(release_fn) = owned.release else {
            return LbStatus::InvalidArgument;
        };
        // SAFETY: Caller guarantees aligned live `handle`.
        let wrapper = unsafe { &*handle };

        let guard_box = Box::new(NativeOwnedBufferGuard {
            data: owned.data,
            len: owned.len,
            capacity: owned.capacity,
            release: release_fn,
            user_ctx_addr: owned.user_ctx as usize,
            caller_desc: buffer,
            armed: false,
        });

        match wrapper.session.submit_owned_boxed(&parsed_meta, guard_box) {
            Ok(()) => LbStatus::Ok,
            Err((err, _unaccepted_disarmed_guard)) => map_core_error(err),
        }
    })
}

/// Release a buffer via its embedded `release` callback and zero out the descriptor fields.
/// Convenience helper for native consumers holding a Rust-allocated `LbOwnedBuffer`.
/// May be called from any thread (including after `lb_core_destroy`), provided the `lumabridge_ffi`
/// shared library remains loaded in process memory.
///
/// # Safety
/// `buffer` must be null or point to a valid aligned writable `LbOwnedBuffer` owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn lb_core_release_buffer(buffer: *mut LbOwnedBuffer) -> LbStatus {
    run_with_panic_boundary(None, || {
        if buffer.is_null() || !buffer.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller guarantees aligned mutable ownership of one `LbOwnedBuffer`.
        let owned = unsafe { ptr::read(buffer) };
        let Some(rel) = owned.release else {
            return LbStatus::InvalidArgument;
        };
        // SAFETY: Zero descriptor BEFORE invoking `rel` so reentrant checks see empty descriptor.
        unsafe {
            ptr::write(
                buffer,
                LbOwnedBuffer {
                    data: ptr::null(),
                    len: 0,
                    capacity: 0,
                    release: None,
                    user_ctx: ptr::null_mut(),
                },
            );
        }
        rel(owned.user_ctx, owned.data, owned.len, owned.capacity);
        LbStatus::Ok
    })
}

/// Simulate an abrupt session disconnect, draining and releasing all queued buffers cleanly.
///
/// # Safety
/// `handle` must be a valid aligned non-null handle returned by `lb_core_create`.
#[no_mangle]
pub unsafe extern "C" fn lb_core_simulate_disconnect(handle: *mut LbCoreHandle) -> LbStatus {
    run_with_panic_boundary(Some(handle), || {
        if handle.is_null() || !handle.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller guarantees aligned live handle.
        let wrapper = unsafe { &*handle };
        match wrapper.session.simulate_disconnect() {
            Ok(()) => LbStatus::Ok,
            Err(e) => map_core_error(e),
        }
    })
}

/// Cooperatively stop the session (`Running/Created -> Stopping -> Stopped`).
/// Idempotent and reentrancy-safe from within callbacks (never self-joins the worker thread).
/// External callers block until any active worker callbacks finish, worker threads exit cleanly,
/// and all prior state notifications complete before returning.
///
/// # Safety
/// `handle` must be a valid aligned non-null handle returned by `lb_core_create`.
#[no_mangle]
pub unsafe extern "C" fn lb_core_stop(handle: *mut LbCoreHandle) -> LbStatus {
    run_with_panic_boundary(Some(handle), || {
        if handle.is_null() || !handle.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller guarantees aligned live handle.
        let wrapper = unsafe { &*handle };
        match wrapper.session.stop() {
            Ok(()) => LbStatus::Ok,
            Err(e) => map_core_error(e),
        }
    })
}

/// Destroy the handle and join all internal worker threads before returning.
/// Caller MUST ensure:
/// - `lb_core_destroy` is NOT called concurrently with other API calls on `handle`;
/// - `lb_core_destroy` is NOT called from inside a worker callback;
/// - `handle` is NEVER used again after `lb_core_destroy` returns (zero post-free guarantee
///   against stale opaque pointers cannot be provided in raw C without generation indirection);
/// - Keep `lumabridge_ffi` loaded while any Rust-allocated `LbOwnedBuffer` remains unreleased.
///
/// # Safety
/// `handle` must be a valid aligned live handle returned by `lb_core_create` or null (returns `InvalidArgument`).
#[no_mangle]
pub unsafe extern "C" fn lb_core_destroy(handle: *mut LbCoreHandle) -> LbStatus {
    run_with_panic_boundary(None, || {
        if handle.is_null() || !handle.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller guarantees exclusive teardown ownership on a live aligned handle.
        let wrapper = unsafe { &*handle };
        if wrapper.session.is_current_thread_worker() {
            return LbStatus::InvalidState;
        }
        // SAFETY: Reconstruct unique `Box` allocated in `lb_core_create` and drop it cleanly,
        // joining worker threads and draining remaining owned buffers outside locks.
        let owned_handle = unsafe { Box::from_raw(handle) };
        drop(owned_handle);
        LbStatus::Ok
    })
}

/// Query per-instance metrics and queue occupancy counters.
///
/// # Safety
/// - `handle` must be a valid aligned non-null pointer.
/// - `out_metrics` must have 16 readable `LbAbiHeader` bytes (and full `LbCoreMetrics` writable once valid).
#[no_mangle]
pub unsafe extern "C" fn lb_core_get_metrics(
    handle: *const LbCoreHandle,
    out_metrics: *mut LbCoreMetrics,
) -> LbStatus {
    run_with_panic_boundary(None, || {
        if handle.is_null() || !handle.is_aligned() || out_metrics.is_null() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Validates 16-byte `LbAbiHeader` and alignment before writing `LbCoreMetrics`.
        if let Err(s) = unsafe { validate_abi_output(out_metrics) } {
            return s;
        }
        // SAFETY: Caller guarantees aligned readable `LbCoreHandle`.
        let wrapper = unsafe { &*handle };
        let m = wrapper.session.metrics();
        // SAFETY: Header validation & `LbCoreMetrics` alignment succeeded above.
        unsafe {
            ptr::write(
                out_metrics,
                LbCoreMetrics {
                    abi: LbAbiHeader::new::<LbCoreMetrics>(),
                    state: m.state,
                    queue_depth: m.queue_depth,
                    queue_peak_depth: m.queue_peak_depth,
                    reserved0: 0,
                    packets_submitted: m.packets_submitted,
                    packets_processed: m.packets_processed,
                    bytes_processed: m.bytes_processed,
                    backpressure_events: m.backpressure_events,
                    native_owned_submitted: m.native_owned_submitted,
                    native_owned_dropped: m.native_owned_dropped,
                    panic_faults: m.panic_faults,
                },
            );
        }
        LbStatus::Ok
    })
}

/// Copy sanitized diagnostic error message (empty if none) into caller buffer (`NUL`-terminated).
///
/// # Safety
/// `handle` and `out_buf` must be valid aligned non-null pointers; `out_buf` must be writable for `buf_cap`.
/// If `out_len` is non-null, it must be aligned and writable for one `usize`.
#[no_mangle]
pub unsafe extern "C" fn lb_core_get_last_error(
    handle: *const LbCoreHandle,
    out_buf: *mut u8,
    buf_cap: usize,
    out_len: *mut usize,
) -> LbStatus {
    run_with_panic_boundary(None, || {
        if handle.is_null()
            || !handle.is_aligned()
            || out_buf.is_null()
            || buf_cap == 0
            || (!out_len.is_null() && !out_len.is_aligned())
        {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller guarantees aligned readable `LbCoreHandle`.
        let wrapper = unsafe { &*handle };
        let msg = wrapper.session.last_error();
        let bytes = msg.as_bytes();
        if !out_len.is_null() {
            // SAFETY: Caller guarantees aligned writable `out_len`.
            unsafe { ptr::write(out_len, bytes.len()) };
        }
        let max_copy = buf_cap.saturating_sub(1);
        let to_copy = bytes.len().min(max_copy);
        if to_copy > 0 {
            // SAFETY: Caller guarantees `out_buf` is writable for `buf_cap >= to_copy + 1`.
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, to_copy) };
        }
        // SAFETY: `buf_cap >= 1` checked above, so index `to_copy` is in-bounds.
        unsafe { ptr::write(out_buf.add(to_copy), 0u8) };
        if bytes.len() > max_copy {
            LbStatus::BufferTooSmall
        } else {
            LbStatus::Ok
        }
    })
}

/// Query process-wide resource counters (`active_instances`, `active_worker_threads`,
/// `in_flight_buffers`, Rust vs native buffer release balance).
///
/// # Safety
/// `out_counters` must have 16 readable `LbAbiHeader` bytes (and full `LbGlobalResourceCounters` writable once valid).
#[no_mangle]
pub unsafe extern "C" fn lb_core_get_global_resource_counters(
    out_counters: *mut LbGlobalResourceCounters,
) -> LbStatus {
    run_with_panic_boundary(None, || {
        // SAFETY: Validates 16-byte `LbAbiHeader` and alignment before writing `LbGlobalResourceCounters`.
        if let Err(s) = unsafe { validate_abi_output(out_counters) } {
            return s;
        }
        let snap = global_resource_snapshot();
        // SAFETY: Header validation & alignment succeeded above.
        unsafe {
            ptr::write(
                out_counters,
                LbGlobalResourceCounters {
                    abi: LbAbiHeader::new::<LbGlobalResourceCounters>(),
                    active_instances: snap.active_instances,
                    active_worker_threads: snap.active_worker_threads,
                    in_flight_buffers: snap.in_flight_buffers,
                    callbacks_in_progress: snap.callbacks_in_progress,
                    callbacks_invoked_total: snap.callbacks_invoked_total,
                    rust_buffers_allocated: snap.rust_buffers_allocated,
                    rust_buffers_released: snap.rust_buffers_released,
                    native_buffers_received: snap.native_buffers_received,
                    native_buffers_released: snap.native_buffers_released,
                    disconnect_drains: snap.disconnect_drains,
                },
            );
        }
        LbStatus::Ok
    })
}

/// Return Rust-computed structure sizes and key field offsets for cross-language verification.
///
/// # Safety
/// `out_sig` must have 16 readable `LbAbiHeader` bytes (and full `LbAbiLayoutSignature` writable once valid).
#[no_mangle]
pub unsafe extern "C" fn lb_core_layout_signature(out_sig: *mut LbAbiLayoutSignature) -> LbStatus {
    run_with_panic_boundary(None, || {
        // SAFETY: Validates 16-byte `LbAbiHeader` and alignment before writing `LbAbiLayoutSignature`.
        if let Err(s) = unsafe { validate_abi_output(out_sig) } {
            return s;
        }
        // SAFETY: Header validation & alignment succeeded above.
        unsafe {
            ptr::write(
                out_sig,
                LbAbiLayoutSignature {
                    abi: LbAbiHeader::new::<LbAbiLayoutSignature>(),
                    #[allow(clippy::cast_possible_truncation)]
                    size_abi_header: size_of::<LbAbiHeader>() as u32,
                    #[allow(clippy::cast_possible_truncation)]
                    size_owned_buffer: size_of::<LbOwnedBuffer>() as u32,
                    #[allow(clippy::cast_possible_truncation)]
                    size_encoded_frame_meta: size_of::<LbEncodedFrameMeta>() as u32,
                    #[allow(clippy::cast_possible_truncation)]
                    size_core_config: size_of::<LbCoreConfig>() as u32,
                    #[allow(clippy::cast_possible_truncation)]
                    size_core_metrics: size_of::<LbCoreMetrics>() as u32,
                    #[allow(clippy::cast_possible_truncation)]
                    size_global_counters: size_of::<LbGlobalResourceCounters>() as u32,
                    #[allow(clippy::cast_possible_truncation)]
                    offset_meta_codec: offset_of!(LbEncodedFrameMeta, codec) as u32,
                    #[allow(clippy::cast_possible_truncation)]
                    offset_meta_gop_id: offset_of!(LbEncodedFrameMeta, gop_id) as u32,
                    #[allow(clippy::cast_possible_truncation)]
                    offset_owned_release: offset_of!(LbOwnedBuffer, release) as u32,
                    #[allow(clippy::cast_possible_truncation)]
                    offset_config_on_output: offset_of!(LbCoreConfig, on_output_packet) as u32,
                },
            );
        }
        let _ = align_of::<LbEncodedFrameMeta>();
        LbStatus::Ok
    })
}

#[cfg(feature = "poc-fault-injection")]
/// Controlled fault-injection entry point compiled ONLY when `poc-fault-injection` feature is active.
/// - `mode = 1`: triggers an intentional panic directly inside the FFI call (`catch_unwind` -> `InternalPanic`, instance -> `Faulted`).
/// - `mode = 2`: arms an intentional panic on the core worker thread to verify worker panic containment & buffer drain.
/// - `mode = 3`: arms an intentional panic inside `submit_owned_boxed` BEFORE ownership commit.
/// - `mode = 4`: arms an intentional panic inside `submit_owned_boxed` AFTER ownership commit.
///
/// # Panics
/// When `mode == 1`, intentionally triggers a test panic inside the `catch_unwind` FFI boundary
/// (caught and mapped to `LB_STATUS_INTERNAL_PANIC`).
///
/// # Safety
/// `handle` must be a valid aligned non-null handle returned by `lb_core_create`.
#[no_mangle]
pub unsafe extern "C" fn lb_core_poc_trigger_panic(
    handle: *mut LbCoreHandle,
    mode: u32,
) -> LbStatus {
    run_with_panic_boundary(Some(handle), || {
        if handle.is_null() || !handle.is_aligned() {
            return LbStatus::InvalidArgument;
        }
        // SAFETY: Caller guarantees aligned live handle.
        let wrapper = unsafe { &*handle };
        match mode {
            1 => {
                panic!("Controlled PoC FFI boundary panic injection (mode 1)");
            }
            2 => match wrapper.session.poc_arm_worker_panic() {
                Ok(()) => LbStatus::Ok,
                Err(e) => map_core_error(e),
            },
            3 => match wrapper.session.poc_arm_submit_pre_commit_panic() {
                Ok(()) => LbStatus::Ok,
                Err(e) => map_core_error(e),
            },
            4 => match wrapper.session.poc_arm_submit_post_commit_panic() {
                Ok(()) => LbStatus::Ok,
                Err(e) => map_core_error(e),
            },
            _ => LbStatus::InvalidArgument,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestCtx {
        packets: AtomicUsize,
        rust_buffers_freed: AtomicUsize,
        native_buffers_freed: AtomicUsize,
        last_state: std::sync::atomic::AtomicU32,
        last_status: std::sync::atomic::AtomicU32,
    }

    extern "C" fn test_output_cb(
        user_ctx: *mut c_void,
        meta: *const LbEncodedFrameMeta,
        mut owned: LbOwnedBuffer,
    ) {
        assert!(!user_ctx.is_null());
        assert!(!meta.is_null());
        // SAFETY: Test context and meta pointers are valid for callback duration.
        let ctx = unsafe { &*(user_ctx.cast::<TestCtx>()) };
        ctx.packets.fetch_add(1, Ordering::SeqCst);
        let rc = unsafe { lb_core_release_buffer(&raw mut owned) };
        assert_eq!(rc, LbStatus::Ok);
        ctx.rust_buffers_freed.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn test_state_cb(user_ctx: *mut c_void, new_state: u32, status_code: u32) {
        if user_ctx.is_null() {
            return;
        }
        // SAFETY: Test context remains valid until after `lb_core_destroy`.
        let ctx = unsafe { &*(user_ctx.cast::<TestCtx>()) };
        ctx.last_state.store(new_state, Ordering::SeqCst);
        ctx.last_status.store(status_code, Ordering::SeqCst);
    }

    extern "C" fn test_native_release(
        user_ctx: *mut c_void,
        data: *const u8,
        len: usize,
        capacity: usize,
    ) {
        assert!(!user_ctx.is_null());
        assert!(!data.is_null());
        assert!(len > 0 && len <= capacity);
        // SAFETY: Allocated in test below via `Vec::into_raw_parts`-style Box<[u8]>.
        unsafe {
            let ctx = &*(user_ctx.cast::<TestCtx>());
            ctx.native_buffers_freed.fetch_add(1, Ordering::SeqCst);
            let slice_ptr = ptr::slice_from_raw_parts_mut(data.cast_mut(), capacity);
            drop(Box::from_raw(slice_ptr));
        }
    }

    #[test]
    fn c_abi_layout_and_version_validation() {
        let mut major = 0u32;
        let mut minor = 0u32;
        assert_eq!(
            unsafe { lb_core_abi_version(&raw mut major, &raw mut minor) },
            LbStatus::Ok
        );
        assert_eq!((major, minor), (LB_FFI_ABI_MAJOR, LB_FFI_ABI_MINOR));

        let mut bad_cfg = LbCoreConfig {
            abi: LbAbiHeader {
                abi_major: 99,
                abi_minor: 0,
                #[allow(clippy::cast_possible_truncation)]
                struct_size: size_of::<LbCoreConfig>() as u32,
                reserved: 0,
            },
            queue_capacity: 8,
            expected_frame_bytes_hint: 1024,
            on_output_packet: None,
            on_state_change: None,
            callback_user_ctx: ptr::null_mut(),
        };
        let mut handle: *mut LbCoreHandle = ptr::null_mut();
        assert_eq!(
            unsafe { lb_core_create(&raw const bad_cfg, &raw mut handle) },
            LbStatus::AbiVersionMismatch
        );

        bad_cfg.abi.abi_major = LB_FFI_ABI_MAJOR;
        bad_cfg.abi.struct_size = 4;
        assert_eq!(
            unsafe { lb_core_create(&raw const bad_cfg, &raw mut handle) },
            LbStatus::InvalidStructSize
        );
    }

    #[test]
    fn ffi_roundtrip_borrowed_and_native_owned_buffers() {
        let ctx = Box::new(TestCtx {
            packets: AtomicUsize::new(0),
            rust_buffers_freed: AtomicUsize::new(0),
            native_buffers_freed: AtomicUsize::new(0),
            last_state: std::sync::atomic::AtomicU32::new(99),
            last_status: std::sync::atomic::AtomicU32::new(99),
        });
        let ctx_ptr: *mut TestCtx = Box::into_raw(ctx);

        let cfg = LbCoreConfig {
            abi: LbAbiHeader::new::<LbCoreConfig>(),
            queue_capacity: 8,
            expected_frame_bytes_hint: 4096,
            on_output_packet: Some(test_output_cb),
            on_state_change: Some(test_state_cb),
            callback_user_ctx: ctx_ptr.cast::<c_void>(),
        };

        let mut handle: *mut LbCoreHandle = ptr::null_mut();
        assert_eq!(
            unsafe { lb_core_create(&raw const cfg, &raw mut handle) },
            LbStatus::Ok
        );
        assert_eq!(unsafe { lb_core_start(handle) }, LbStatus::Ok);

        let meta = LbEncodedFrameMeta {
            abi: LbAbiHeader::new::<LbEncodedFrameMeta>(),
            session_id: 42,
            capture_ts_us: 1000,
            encode_done_ts_us: 1500,
            submit_qpc_ticks: 9999,
            codec: LbEncodedCodec::H264AnnexB as u32,
            flags: 1,
            frame_id: 1,
            display_id: 0,
            gop_id: 1,
        };

        let borrowed = [0x00u8, 0x00, 0x00, 0x01, 0x65, 0xAA, 0xBB];
        assert_eq!(
            unsafe {
                lb_core_submit_encoded_frame(
                    handle,
                    &raw const meta,
                    borrowed.as_ptr(),
                    borrowed.len(),
                )
            },
            LbStatus::Ok
        );

        let boxed_slice: Box<[u8]> = vec![0x77u8; 256].into_boxed_slice();
        let cap = boxed_slice.len();
        let raw_data = Box::into_raw(boxed_slice).cast::<u8>();
        let mut native_owned = LbOwnedBuffer {
            data: raw_data,
            len: cap,
            capacity: cap,
            release: Some(test_native_release),
            user_ctx: ctx_ptr.cast::<c_void>(),
        };
        assert_eq!(
            unsafe {
                lb_core_submit_owned_encoded_frame(handle, &raw const meta, &raw mut native_owned)
            },
            LbStatus::Ok
        );
        // Transactional move semantics: accepted descriptor was zeroed by Rust commit point.
        assert!(native_owned.data.is_null());
        assert!(native_owned.release.is_none());
        assert_eq!(
            unsafe { lb_core_release_buffer(&raw mut native_owned) },
            LbStatus::InvalidArgument
        );

        for _ in 0..100 {
            // SAFETY: `ctx_ptr` outlives worker until `lb_core_destroy` below.
            let ctx_ref = unsafe { &*ctx_ptr };
            if ctx_ref.packets.load(Ordering::SeqCst) >= 2
                && ctx_ref.native_buffers_freed.load(Ordering::SeqCst) >= 1
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert_eq!(unsafe { lb_core_stop(handle) }, LbStatus::Ok);
        assert_eq!(unsafe { lb_core_destroy(handle) }, LbStatus::Ok);

        // SAFETY: Handle has been destroyed and all callbacks joined.
        let ctx_reclaimed = unsafe { Box::from_raw(ctx_ptr) };
        assert_eq!(ctx_reclaimed.packets.load(Ordering::SeqCst), 2);
        assert_eq!(ctx_reclaimed.rust_buffers_freed.load(Ordering::SeqCst), 2);
        assert_eq!(ctx_reclaimed.native_buffers_freed.load(Ordering::SeqCst), 1);
    }

    #[cfg(feature = "poc-fault-injection")]
    #[test]
    fn ffi_panic_boundary_and_worker_panic_are_contained() {
        let cfg = LbCoreConfig {
            abi: LbAbiHeader::new::<LbCoreConfig>(),
            queue_capacity: 4,
            expected_frame_bytes_hint: 512,
            on_output_packet: None,
            on_state_change: None,
            callback_user_ctx: ptr::null_mut(),
        };
        let mut handle: *mut LbCoreHandle = ptr::null_mut();
        assert_eq!(
            unsafe { lb_core_create(&raw const cfg, &raw mut handle) },
            LbStatus::Ok
        );
        assert_eq!(unsafe { lb_core_start(handle) }, LbStatus::Ok);

        // Mode 1: immediate FFI boundary panic must be contained cleanly.
        assert_eq!(
            unsafe { lb_core_poc_trigger_panic(handle, 1) },
            LbStatus::InternalPanic
        );
        let mut metrics = LbCoreMetrics {
            abi: LbAbiHeader::new::<LbCoreMetrics>(),
            state: 0,
            queue_depth: 0,
            queue_peak_depth: 0,
            reserved0: 0,
            packets_submitted: 0,
            packets_processed: 0,
            bytes_processed: 0,
            backpressure_events: 0,
            native_owned_submitted: 0,
            native_owned_dropped: 0,
            panic_faults: 0,
        };
        assert_eq!(
            unsafe { lb_core_get_metrics(handle, &raw mut metrics) },
            LbStatus::Ok
        );
        assert_eq!(metrics.state, LbCoreState::Faulted as u32);
        assert!(metrics.panic_faults >= 1);
        assert_eq!(unsafe { lb_core_destroy(handle) }, LbStatus::Ok);
    }

    #[cfg(feature = "poc-fault-injection")]
    struct ReentrantCtx {
        handle: *mut LbCoreHandle,
        freed: AtomicUsize,
    }

    #[cfg(feature = "poc-fault-injection")]
    extern "C" fn reentrant_metrics_release(
        user_ctx: *mut c_void,
        data: *const u8,
        _len: usize,
        capacity: usize,
    ) {
        let ctx = unsafe { &*(user_ctx.cast::<ReentrantCtx>()) };
        let mut m = LbCoreMetrics {
            abi: LbAbiHeader::new::<LbCoreMetrics>(),
            state: 0,
            queue_depth: 0,
            queue_peak_depth: 0,
            reserved0: 0,
            packets_submitted: 0,
            packets_processed: 0,
            bytes_processed: 0,
            backpressure_events: 0,
            native_owned_submitted: 0,
            native_owned_dropped: 0,
            panic_faults: 0,
        };
        let st = unsafe { lb_core_get_metrics(ctx.handle, &raw mut m) };
        assert_eq!(st, LbStatus::Ok);
        ctx.freed.fetch_add(1, Ordering::SeqCst);
        let slice_ptr = ptr::slice_from_raw_parts_mut(data.cast_mut(), capacity);
        unsafe { drop(Box::from_raw(slice_ptr)) };
    }

    #[cfg(feature = "poc-fault-injection")]
    fn run_transactional_panic_case(mode: u32, expect_committed: bool) {
        let cfg = LbCoreConfig {
            abi: LbAbiHeader::new::<LbCoreConfig>(),
            queue_capacity: 4,
            expected_frame_bytes_hint: 512,
            on_output_packet: None,
            on_state_change: None,
            callback_user_ctx: ptr::null_mut(),
        };
        let mut handle: *mut LbCoreHandle = ptr::null_mut();
        assert_eq!(
            unsafe { lb_core_create(&raw const cfg, &raw mut handle) },
            LbStatus::Ok
        );
        assert_eq!(unsafe { lb_core_start(handle) }, LbStatus::Ok);
        let rctx = Box::into_raw(Box::new(ReentrantCtx {
            handle,
            freed: AtomicUsize::new(0),
        }));

        let boxed_slice: Box<[u8]> = vec![0x55u8; 64].into_boxed_slice();
        let cap = boxed_slice.len();
        let mut native_owned = LbOwnedBuffer {
            data: Box::into_raw(boxed_slice).cast::<u8>(),
            len: cap,
            capacity: cap,
            release: Some(reentrant_metrics_release),
            user_ctx: rctx.cast::<c_void>(),
        };
        let valid_meta = LbEncodedFrameMeta {
            abi: LbAbiHeader::new::<LbEncodedFrameMeta>(),
            session_id: 99,
            capture_ts_us: 100,
            encode_done_ts_us: 120,
            submit_qpc_ticks: 1,
            codec: LbEncodedCodec::H264AnnexB as u32,
            flags: 1,
            frame_id: 1,
            display_id: 0,
            gop_id: 1,
        };

        assert_eq!(
            unsafe { lb_core_poc_trigger_panic(handle, mode) },
            LbStatus::Ok
        );
        assert_eq!(
            unsafe {
                lb_core_submit_owned_encoded_frame(
                    handle,
                    &raw const valid_meta,
                    &raw mut native_owned,
                )
            },
            LbStatus::InternalPanic
        );
        if expect_committed {
            assert!(native_owned.data.is_null() && native_owned.release.is_none());
            assert_eq!(unsafe { (&*rctx).freed.load(Ordering::SeqCst) }, 1);
            assert_eq!(
                unsafe { lb_core_release_buffer(&raw mut native_owned) },
                LbStatus::InvalidArgument
            );
        } else {
            assert!(!native_owned.data.is_null() && native_owned.release.is_some());
            assert_eq!(unsafe { (&*rctx).freed.load(Ordering::SeqCst) }, 0);
            assert_eq!(
                unsafe { lb_core_release_buffer(&raw mut native_owned) },
                LbStatus::Ok
            );
        }
        assert_eq!(unsafe { (&*rctx).freed.load(Ordering::SeqCst) }, 1);
        assert_eq!(unsafe { lb_core_destroy(handle) }, LbStatus::Ok);
        unsafe { drop(Box::from_raw(rctx)) };
    }

    #[cfg(feature = "poc-fault-injection")]
    #[test]
    fn transactional_ownership_pre_and_post_commit_panics_never_double_free() {
        run_transactional_panic_case(3, false);
        run_transactional_panic_case(4, true);
    }

    #[test]
    #[allow(clippy::cast_ptr_alignment)]
    fn abi_preread_rejects_smaller_legacy_buffers() {
        #[repr(C, align(8))]
        struct SmallLegacyStruct {
            abi: LbAbiHeader,
            sentinel_tail: u64,
        }

        let small_hdr = LbAbiHeader {
            abi_major: LB_FFI_ABI_MAJOR,
            abi_minor: LB_FFI_ABI_MINOR,
            #[allow(clippy::cast_possible_truncation)]
            struct_size: size_of::<LbAbiHeader>() as u32,
            reserved: 0,
        };
        let mut handle: *mut LbCoreHandle = ptr::null_mut();
        assert_eq!(
            unsafe {
                lb_core_create(
                    (&raw const small_hdr).cast::<LbCoreConfig>(),
                    &raw mut handle,
                )
            },
            LbStatus::InvalidStructSize
        );
        assert!(handle.is_null());

        let mut small_out = SmallLegacyStruct {
            abi: LbAbiHeader {
                abi_major: LB_FFI_ABI_MAJOR,
                abi_minor: LB_FFI_ABI_MINOR,
                #[allow(clippy::cast_possible_truncation)]
                struct_size: size_of::<SmallLegacyStruct>() as u32,
                reserved: 0,
            },
            sentinel_tail: 0xCCCC_CCCC_CCCC_CCCC,
        };
        assert_eq!(
            unsafe {
                lb_core_get_global_resource_counters(
                    (&raw mut small_out).cast::<LbGlobalResourceCounters>(),
                )
            },
            LbStatus::InvalidStructSize
        );
        assert_eq!(small_out.sentinel_tail, 0xCCCC_CCCC_CCCC_CCCC);

        assert_eq!(
            unsafe {
                lb_core_layout_signature((&raw mut small_out).cast::<LbAbiLayoutSignature>())
            },
            LbStatus::InvalidStructSize
        );
        assert_eq!(small_out.sentinel_tail, 0xCCCC_CCCC_CCCC_CCCC);

        let valid_cfg = LbCoreConfig {
            abi: LbAbiHeader::new::<LbCoreConfig>(),
            queue_capacity: 4,
            expected_frame_bytes_hint: 512,
            on_output_packet: None,
            on_state_change: None,
            callback_user_ctx: ptr::null_mut(),
        };
        assert_eq!(
            unsafe { lb_core_create(&raw const valid_cfg, &raw mut handle) },
            LbStatus::Ok
        );
        assert_eq!(unsafe { lb_core_start(handle) }, LbStatus::Ok);

        let bytes = [1u8, 2, 3, 4];
        assert_eq!(
            unsafe {
                lb_core_submit_encoded_frame(
                    handle,
                    (&raw const small_out).cast::<LbEncodedFrameMeta>(),
                    bytes.as_ptr(),
                    bytes.len(),
                )
            },
            LbStatus::InvalidStructSize
        );
        assert_eq!(
            unsafe { lb_core_get_metrics(handle, (&raw mut small_out).cast::<LbCoreMetrics>()) },
            LbStatus::InvalidStructSize
        );
        assert_eq!(small_out.sentinel_tail, 0xCCCC_CCCC_CCCC_CCCC);

        assert_eq!(unsafe { lb_core_stop(handle) }, LbStatus::Ok);
        assert_eq!(unsafe { lb_core_destroy(handle) }, LbStatus::Ok);
    }

    #[test]
    #[allow(clippy::cast_ptr_alignment)]
    fn abi_rejects_misaligned_pointers() {
        let valid_cfg = LbCoreConfig {
            abi: LbAbiHeader::new::<LbCoreConfig>(),
            queue_capacity: 4,
            expected_frame_bytes_hint: 512,
            on_output_packet: None,
            on_state_change: None,
            callback_user_ctx: ptr::null_mut(),
        };
        let mut handle: *mut LbCoreHandle = ptr::null_mut();
        let mut backing = [0xAAu8; 256];
        let base_ptr = backing.as_mut_ptr();
        let offset = base_ptr.align_offset(16) + 1;
        let unaligned_u8 = unsafe { base_ptr.add(offset) };

        assert_eq!(
            unsafe { lb_core_abi_version(unaligned_u8.cast::<u32>(), ptr::null_mut()) },
            LbStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { lb_core_create(unaligned_u8.cast::<LbCoreConfig>(), &raw mut handle) },
            LbStatus::InvalidArgument
        );
        assert_eq!(
            unsafe {
                lb_core_create(
                    &raw const valid_cfg,
                    unaligned_u8.cast::<*mut LbCoreHandle>(),
                )
            },
            LbStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { lb_core_start(unaligned_u8.cast::<LbCoreHandle>()) },
            LbStatus::InvalidArgument
        );
        assert_eq!(
            unsafe {
                lb_core_get_global_resource_counters(
                    unaligned_u8.cast::<LbGlobalResourceCounters>(),
                )
            },
            LbStatus::InvalidArgument
        );
        assert_eq!(
            unsafe { lb_core_release_buffer(unaligned_u8.cast::<LbOwnedBuffer>()) },
            LbStatus::InvalidArgument
        );
    }

    #[test]
    fn generated_c_header_has_clean_opaque_abi_surface() {
        let header = include_str!("../include/lumabridge_ffi.h");
        assert!(header.contains("typedef struct LbCoreHandle LbCoreHandle;"));
        assert!(header.contains("LUMABRIDGE_FFI_POC_FAULT_INJECTION"));
        assert!(!header.contains("Option_Lb"));
        assert!(!header.contains("CoreSession session"));
        assert!(!header.contains("MAX_ENCODED_FRAME_BYTES"));
    }
}
