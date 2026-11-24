#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

//! Minimal M1.1 core runtime validating lifecycle state transitions,
//! bounded FIFO buffering, deterministic backpressure, synchronous copy vs
//! explicit owned-buffer release, cooperative shutdown without self-join,
//! and panic containment boundaries (ADR-0004).

use std::collections::VecDeque;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle, ThreadId};

pub const MAX_ENCODED_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MIN_QUEUE_CAPACITY: usize = 1;
pub const MAX_QUEUE_CAPACITY: usize = 256;
pub const DEFAULT_QUEUE_CAPACITY: usize = 64;
pub const MAX_VALID_DISPLAY_ID: u16 = 0xFFFE;

/// Explicit lifecycle state of a core session instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CoreState {
    Created = 0,
    Running = 1,
    Stopping = 2,
    Stopped = 3,
    Faulted = 4,
}

/// Supported encoded bitstream container formats across the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EncodedCodec {
    H264AnnexB = 1,
    HevcAnnexB = 2,
    Av1Obu = 3,
}

impl EncodedCodec {
    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::H264AnnexB),
            2 => Some(Self::HevcAnnexB),
            3 => Some(Self::Av1Obu),
            _ => None,
        }
    }
}

/// Explicit operational error codes mapped cleanly onto `LbStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    InvalidArgument(&'static str),
    InvalidState(CoreState),
    Backpressure,
    Faulted,
    InternalPanic,
    NotSupported,
}

/// Metadata accompanying an already-encoded frame across the native/core boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedFrameMeta {
    pub session_id: u64,
    pub display_id: u16,
    pub codec: EncodedCodec,
    pub flags: u32,
    pub frame_id: u32,
    pub gop_id: u16,
    pub capture_ts_us: u64,
    pub encode_done_ts_us: u64,
    pub submit_qpc_ticks: u64,
}

impl EncodedFrameMeta {
    /// Validate non-pixel metadata invariants before queueing.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.session_id == 0 {
            return Err(CoreError::InvalidArgument("session_id must be non-zero"));
        }
        if self.display_id > MAX_VALID_DISPLAY_ID {
            return Err(CoreError::InvalidArgument(
                "display_id 0xFFFF is reserved and invalid for frame submission",
            ));
        }
        if self.encode_done_ts_us < self.capture_ts_us {
            return Err(CoreError::InvalidArgument(
                "encode_done_ts_us must be >= capture_ts_us",
            ));
        }
        Ok(())
    }
}

/// Configuration for a core `PoC` session instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreConfig {
    pub queue_capacity: usize,
    pub expected_frame_bytes_hint: usize,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            expected_frame_bytes_hint: 64 * 1024,
        }
    }
}

impl CoreConfig {
    pub fn validate(&self) -> Result<(), CoreError> {
        if !(MIN_QUEUE_CAPACITY..=MAX_QUEUE_CAPACITY).contains(&self.queue_capacity) {
            return Err(CoreError::InvalidArgument(
                "queue_capacity must be within 1..=256",
            ));
        }
        if self.expected_frame_bytes_hint > MAX_ENCODED_FRAME_BYTES {
            return Err(CoreError::InvalidArgument(
                "expected_frame_bytes_hint exceeds 8 MiB limit",
            ));
        }
        Ok(())
    }
}

/// Trait implemented by external-allocator buffer ownership guards so `lumabridge-core`
/// can safely hold and drop native buffers outside locks with zero `unsafe`.
pub trait OwnedByteSlice: Send {
    fn as_slice(&self) -> &[u8];
}

/// Payload held inside the bounded queue between submission and worker dispatch.
pub enum QueuedPayload {
    /// Synchronous borrowed submission copied into a bounded Rust-owned `Vec<u8>`.
    Copied(Vec<u8>),
    /// Asynchronous transferred native buffer released via `Drop` (`OwnedByteSlice`).
    External(Box<dyn OwnedByteSlice>),
}

impl QueuedPayload {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Copied(buf) => buf.as_slice(),
            Self::External(ext) => ext.as_slice(),
        }
    }
}

struct QueuedItem {
    meta: EncodedFrameMeta,
    payload: QueuedPayload,
}

/// Snapshot of per-instance counters and queue occupancy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InstanceMetrics {
    pub state: u32,
    pub queue_depth: u32,
    pub queue_peak_depth: u32,
    pub packets_submitted: u64,
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub backpressure_events: u64,
    pub native_owned_submitted: u64,
    pub native_owned_dropped: u64,
    pub panic_faults: u64,
}

/// Process-wide counters verifying balanced instance/thread/buffer/callback lifecycles.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GlobalResourceSnapshot {
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

#[derive(Default)]
struct GlobalCounters {
    active_instances: AtomicU64,
    active_worker_threads: AtomicU64,
    in_flight_buffers: AtomicU64,
    callbacks_in_progress: AtomicU64,
    callbacks_invoked_total: AtomicU64,
    rust_buffers_allocated: AtomicU64,
    rust_buffers_released: AtomicU64,
    native_buffers_received: AtomicU64,
    native_buffers_released: AtomicU64,
    disconnect_drains: AtomicU64,
}

static GLOBAL_COUNTERS: Mutex<Option<Arc<GlobalCounters>>> = Mutex::new(None);

fn global_counters() -> Arc<GlobalCounters> {
    let mut guard = GLOBAL_COUNTERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = guard.as_ref() {
        Arc::clone(existing)
    } else {
        let created = Arc::new(GlobalCounters::default());
        *guard = Some(Arc::clone(&created));
        created
    }
}

/// Read the process-wide resource lifecycle counters for leak and balance audits.
#[must_use]
pub fn global_resource_snapshot() -> GlobalResourceSnapshot {
    let g = global_counters();
    GlobalResourceSnapshot {
        active_instances: g.active_instances.load(Ordering::SeqCst),
        active_worker_threads: g.active_worker_threads.load(Ordering::SeqCst),
        in_flight_buffers: g.in_flight_buffers.load(Ordering::SeqCst),
        callbacks_in_progress: g.callbacks_in_progress.load(Ordering::SeqCst),
        callbacks_invoked_total: g.callbacks_invoked_total.load(Ordering::SeqCst),
        rust_buffers_allocated: g.rust_buffers_allocated.load(Ordering::SeqCst),
        rust_buffers_released: g.rust_buffers_released.load(Ordering::SeqCst),
        native_buffers_received: g.native_buffers_received.load(Ordering::SeqCst),
        native_buffers_released: g.native_buffers_released.load(Ordering::SeqCst),
        disconnect_drains: g.disconnect_drains.load(Ordering::SeqCst),
    }
}

/// Increment balanced Rust-owned buffer allocation tracking (called by FFI layer).
pub fn record_rust_buffer_allocated() {
    global_counters()
        .rust_buffers_allocated
        .fetch_add(1, Ordering::SeqCst);
}

/// Increment balanced Rust-owned buffer release tracking (called by FFI release function).
pub fn record_rust_buffer_released() {
    global_counters()
        .rust_buffers_released
        .fetch_add(1, Ordering::SeqCst);
}

/// Increment balanced native-owned buffer receipt tracking.
pub fn record_native_buffer_received() {
    global_counters()
        .native_buffers_received
        .fetch_add(1, Ordering::SeqCst);
}

/// Increment balanced native-owned buffer release tracking.
pub fn record_native_buffer_released() {
    global_counters()
        .native_buffers_released
        .fetch_add(1, Ordering::SeqCst);
}

/// Callback sink trait executed on the dedicated worker thread strictly outside internal mutexes.
pub trait CoreObserver: Send + Sync + 'static {
    fn on_output_packet(&self, meta: &EncodedFrameMeta, payload: Vec<u8>);
    fn on_state_changed(&self, new_state: CoreState, status: Result<(), CoreError>);
}

struct InstanceCounters {
    state: AtomicU32,
    queue_peak_depth: AtomicU32,
    packets_submitted: AtomicU64,
    packets_processed: AtomicU64,
    bytes_processed: AtomicU64,
    backpressure_events: AtomicU64,
    native_owned_submitted: AtomicU64,
    native_owned_dropped: AtomicU64,
    panic_faults: AtomicU64,
}

impl InstanceCounters {
    fn new(initial: CoreState) -> Self {
        Self {
            state: AtomicU32::new(initial as u32),
            queue_peak_depth: AtomicU32::new(0),
            packets_submitted: AtomicU64::new(0),
            packets_processed: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            backpressure_events: AtomicU64::new(0),
            native_owned_submitted: AtomicU64::new(0),
            native_owned_dropped: AtomicU64::new(0),
            panic_faults: AtomicU64::new(0),
        }
    }
}

struct SharedQueueState {
    state: CoreState,
    queue: VecDeque<QueuedItem>,
    recycle_pool: Vec<Vec<u8>>,
    queue_capacity: usize,
    stop_requested: bool,
    fault_triggered: bool,
    pending_worker_panic: bool,
    last_error: String,
    worker_thread_id: Option<ThreadId>,
}

impl SharedQueueState {
    fn new(config: CoreConfig) -> Self {
        let mut recycle_pool = Vec::with_capacity(config.queue_capacity);
        let prealloc_cap = config.expected_frame_bytes_hint;
        if prealloc_cap > 0 {
            for _ in 0..config.queue_capacity {
                recycle_pool.push(Vec::with_capacity(prealloc_cap));
            }
        }
        Self {
            state: CoreState::Created,
            queue: VecDeque::with_capacity(config.queue_capacity),
            recycle_pool,
            queue_capacity: config.queue_capacity,
            stop_requested: false,
            fault_triggered: false,
            pending_worker_panic: false,
            last_error: String::new(),
            worker_thread_id: None,
        }
    }
}

struct SharedRuntime {
    inner: Mutex<SharedQueueState>,
    cv: Condvar,
    counters: InstanceCounters,
    global: Arc<GlobalCounters>,
    observer: Arc<dyn CoreObserver>,
    has_active_thread: AtomicBool,
}

impl SharedRuntime {
    fn set_state_locked(&self, guard: &mut SharedQueueState, new_state: CoreState) {
        guard.state = new_state;
        self.counters
            .state
            .store(new_state as u32, Ordering::SeqCst);
    }
}

/// Safe owned core session managing lifecycle, bounded worker thread, and buffer ownership.
pub struct CoreSession {
    shared: Arc<SharedRuntime>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl CoreSession {
    /// Construct a new session in `CoreState::Created`.
    pub fn create(config: CoreConfig, observer: Arc<dyn CoreObserver>) -> Result<Self, CoreError> {
        config.validate()?;
        let global = global_counters();
        global.active_instances.fetch_add(1, Ordering::SeqCst);

        let shared = Arc::new(SharedRuntime {
            inner: Mutex::new(SharedQueueState::new(config)),
            cv: Condvar::new(),
            counters: InstanceCounters::new(CoreState::Created),
            global,
            observer,
            has_active_thread: AtomicBool::new(false),
        });

        Ok(Self {
            shared,
            worker: Mutex::new(None),
        })
    }

    /// Transition `Created -> Running` and spawn the dedicated worker thread.
    pub fn start(&self) -> Result<(), CoreError> {
        let mut worker_slot = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        match guard.state {
            CoreState::Created => {}
            CoreState::Faulted => return Err(CoreError::Faulted),
            other => return Err(CoreError::InvalidState(other)),
        }

        self.shared.set_state_locked(&mut guard, CoreState::Running);
        guard.stop_requested = false;
        drop(guard);

        let worker_shared = Arc::clone(&self.shared);
        let handle = thread::Builder::new()
            .name("lb-core-worker".to_owned())
            .spawn(move || {
                worker_thread_entry(&worker_shared);
            })
            .map_err(|_| {
                let mut err_guard = self
                    .shared
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                self.shared
                    .set_state_locked(&mut err_guard, CoreState::Faulted);
                "Failed to spawn worker thread".clone_into(&mut err_guard.last_error);
                CoreError::Faulted
            })?;

        self.shared.has_active_thread.store(true, Ordering::SeqCst);
        *worker_slot = Some(handle);
        drop(worker_slot);

        self.invoke_state_callback(CoreState::Running, Ok(()));
        Ok(())
    }

    /// Submit a caller-borrowed encoded frame buffer synchronously.
    /// Copies the bytes into a bounded pool buffer before returning, or returns
    /// `CoreError::Backpressure` if the bounded queue is already full.
    pub fn submit_borrowed(&self, meta: &EncodedFrameMeta, data: &[u8]) -> Result<(), CoreError> {
        meta.validate()?;
        if data.is_empty() || data.len() > MAX_ENCODED_FRAME_BYTES {
            return Err(CoreError::InvalidArgument(
                "payload length must be in 1..=8 MiB",
            ));
        }

        let mut guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        match guard.state {
            CoreState::Running => {}
            CoreState::Faulted => return Err(CoreError::Faulted),
            other => return Err(CoreError::InvalidState(other)),
        }

        if guard.queue.len() >= guard.queue_capacity {
            self.shared
                .counters
                .backpressure_events
                .fetch_add(1, Ordering::SeqCst);
            return Err(CoreError::Backpressure);
        }

        let mut buf = guard.recycle_pool.pop().unwrap_or_default();
        buf.clear();
        buf.extend_from_slice(data);

        guard.queue.push_back(QueuedItem {
            meta: *meta,
            payload: QueuedPayload::Copied(buf),
        });

        self.record_enqueue_metrics(guard.queue.len(), false);
        self.shared.cv.notify_one();
        Ok(())
    }

    /// Accept ownership of a caller-allocated external buffer for asynchronous processing.
    /// If this returns `Err`, the caller retains ownership of `payload` and its `release`
    /// callback is NOT invoked.
    pub fn submit_owned<T: OwnedByteSlice + 'static>(
        &self,
        meta: &EncodedFrameMeta,
        payload: T,
    ) -> Result<(), (CoreError, T)> {
        if let Err(err) = meta.validate() {
            return Err((err, payload));
        }
        let byte_len = payload.as_slice().len();
        if byte_len == 0 || byte_len > MAX_ENCODED_FRAME_BYTES {
            return Err((
                CoreError::InvalidArgument("owned payload length must be in 1..=8 MiB"),
                payload,
            ));
        }

        let mut guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        match guard.state {
            CoreState::Running => {}
            CoreState::Faulted => return Err((CoreError::Faulted, payload)),
            other => return Err((CoreError::InvalidState(other), payload)),
        }

        if guard.queue.len() >= guard.queue_capacity {
            self.shared
                .counters
                .backpressure_events
                .fetch_add(1, Ordering::SeqCst);
            return Err((CoreError::Backpressure, payload));
        }

        guard.queue.push_back(QueuedItem {
            meta: *meta,
            payload: QueuedPayload::External(Box::new(payload)),
        });

        self.record_enqueue_metrics(guard.queue.len(), true);
        self.shared.cv.notify_one();
        Ok(())
    }

    /// Simulate an abrupt session disconnect: cancels queueing, drains and releases
    /// all queued payloads cleanly outside locks, and joins worker if called externally.
    pub fn simulate_disconnect(&self) -> Result<(), CoreError> {
        self.shared
            .global
            .disconnect_drains
            .fetch_add(1, Ordering::SeqCst);
        self.stop_internal(Some(
            "Session disconnected abruptly; queued buffers drained",
        ))
    }

    /// Cooperatively stop the session. Safe and idempotent to call multiple times or
    /// reentrantly from within a worker callback (avoids self-join deadlock).
    pub fn stop(&self) -> Result<(), CoreError> {
        self.stop_internal(None)
    }

    fn stop_internal(&self, disconnect_reason: Option<&str>) -> Result<(), CoreError> {
        let current_tid = thread::current().id();
        let (is_worker_thread, drained_items) = {
            let mut guard = self
                .shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let is_worker = guard.worker_thread_id == Some(current_tid);
            guard.stop_requested = true;
            if let Some(reason) = disconnect_reason {
                if guard.last_error.is_empty() {
                    reason.clone_into(&mut guard.last_error);
                }
            }
            if guard.state == CoreState::Created || guard.state == CoreState::Running {
                self.shared
                    .set_state_locked(&mut guard, CoreState::Stopping);
            }
            let drained = drain_queue_locked(&mut guard, &self.shared);
            self.shared.cv.notify_all();
            (is_worker, drained)
        };

        // Drop drained buffers (triggering external `release` functions) strictly outside mutexes.
        drop(drained_items);

        if is_worker_thread {
            // Worker will observe `stop_requested` upon callback return and transition to Stopped/Faulted.
            return Ok(());
        }

        self.join_worker_if_external()?;

        let mut final_guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let drained_tail = drain_queue_locked(&mut final_guard, &self.shared);
        let notify_stopped = if matches!(final_guard.state, CoreState::Faulted) {
            false
        } else {
            let changed = final_guard.state != CoreState::Stopped;
            self.shared
                .set_state_locked(&mut final_guard, CoreState::Stopped);
            changed
        };
        drop(final_guard);
        drop(drained_tail);
        if notify_stopped {
            self.invoke_state_callback(CoreState::Stopped, Ok(()));
        }
        Ok(())
    }

    /// Fault the instance due to an external/FFI panic boundary event.
    pub fn mark_faulted(&self, sanitized_reason: &str) {
        self.shared
            .counters
            .panic_faults
            .fetch_add(1, Ordering::SeqCst);
        let current_tid = thread::current().id();
        let (is_worker, drained) = {
            let mut guard = self
                .shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.fault_triggered = true;
            guard.stop_requested = true;
            sanitized_reason.clone_into(&mut guard.last_error);
            self.shared.set_state_locked(&mut guard, CoreState::Faulted);
            let drained = drain_queue_locked(&mut guard, &self.shared);
            self.shared.cv.notify_all();
            (guard.worker_thread_id == Some(current_tid), drained)
        };
        drop(drained);
        self.invoke_state_callback(CoreState::Faulted, Err(CoreError::InternalPanic));
        if !is_worker {
            let _ = self.join_worker_if_external();
        }
    }

    #[cfg(feature = "poc-fault-injection")]
    /// Controlled `PoC` helper to trigger an intentional panic inside the worker thread.
    pub fn poc_arm_worker_panic(&self) -> Result<(), CoreError> {
        let mut guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.state != CoreState::Running {
            return Err(CoreError::InvalidState(guard.state));
        }
        guard.pending_worker_panic = true;
        self.shared.cv.notify_all();
        Ok(())
    }

    #[must_use]
    pub fn is_current_thread_worker(&self) -> bool {
        let current_tid = thread::current().id();
        let guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.worker_thread_id == Some(current_tid)
    }

    #[must_use]
    pub fn metrics(&self) -> InstanceMetrics {
        let queue_depth = {
            let guard = self
                .shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            u32::try_from(guard.queue.len()).unwrap_or(u32::MAX)
        };
        InstanceMetrics {
            state: self.shared.counters.state.load(Ordering::SeqCst),
            queue_depth,
            queue_peak_depth: self.shared.counters.queue_peak_depth.load(Ordering::SeqCst),
            packets_submitted: self
                .shared
                .counters
                .packets_submitted
                .load(Ordering::SeqCst),
            packets_processed: self
                .shared
                .counters
                .packets_processed
                .load(Ordering::SeqCst),
            bytes_processed: self.shared.counters.bytes_processed.load(Ordering::SeqCst),
            backpressure_events: self
                .shared
                .counters
                .backpressure_events
                .load(Ordering::SeqCst),
            native_owned_submitted: self
                .shared
                .counters
                .native_owned_submitted
                .load(Ordering::SeqCst),
            native_owned_dropped: self
                .shared
                .counters
                .native_owned_dropped
                .load(Ordering::SeqCst),
            panic_faults: self.shared.counters.panic_faults.load(Ordering::SeqCst),
        }
    }

    #[must_use]
    pub fn last_error(&self) -> String {
        let guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.last_error.clone()
    }

    fn join_worker_if_external(&self) -> Result<(), CoreError> {
        let handle = {
            let mut worker_slot = self
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            worker_slot.take()
        };
        if let Some(join_handle) = handle {
            if join_handle.thread().id() == thread::current().id() {
                return Ok(());
            }
            if join_handle.join().is_err() {
                return Err(CoreError::InternalPanic);
            }
        }
        Ok(())
    }

    fn record_enqueue_metrics(&self, depth: usize, is_native_owned: bool) {
        self.shared
            .counters
            .packets_submitted
            .fetch_add(1, Ordering::SeqCst);
        if is_native_owned {
            self.shared
                .counters
                .native_owned_submitted
                .fetch_add(1, Ordering::SeqCst);
        }
        self.shared
            .global
            .in_flight_buffers
            .fetch_add(1, Ordering::SeqCst);
        let depth_u32 = u32::try_from(depth).unwrap_or(u32::MAX);
        self.shared
            .counters
            .queue_peak_depth
            .fetch_max(depth_u32, Ordering::SeqCst);
    }

    fn invoke_state_callback(&self, new_state: CoreState, status: Result<(), CoreError>) {
        self.shared
            .global
            .callbacks_in_progress
            .fetch_add(1, Ordering::SeqCst);
        self.shared
            .global
            .callbacks_invoked_total
            .fetch_add(1, Ordering::SeqCst);
        self.shared.observer.on_state_changed(new_state, status);
        self.shared
            .global
            .callbacks_in_progress
            .fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for CoreSession {
    fn drop(&mut self) {
        let _ = self.stop();
        // Ensure queue and pool are cleanly cleared outside locks after worker exit.
        let (drained, _pool) = {
            let mut guard = self
                .shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let drained = drain_queue_locked(&mut guard, &self.shared);
            let pool = std::mem::take(&mut guard.recycle_pool);
            (drained, pool)
        };
        drop(drained);
        self.shared
            .global
            .active_instances
            .fetch_sub(1, Ordering::SeqCst);
    }
}

fn drain_queue_locked(guard: &mut SharedQueueState, shared: &SharedRuntime) -> Vec<QueuedItem> {
    let mut drained = Vec::with_capacity(guard.queue.len());
    while let Some(item) = guard.queue.pop_front() {
        shared
            .global
            .in_flight_buffers
            .fetch_sub(1, Ordering::SeqCst);
        if matches!(item.payload, QueuedPayload::External(_)) {
            shared
                .counters
                .native_owned_dropped
                .fetch_add(1, Ordering::SeqCst);
        }
        drained.push(item);
    }
    drained
}

struct ThreadBookkeeping {
    shared: Arc<SharedRuntime>,
}

impl Drop for ThreadBookkeeping {
    fn drop(&mut self) {
        let drained = {
            let mut guard = self
                .shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.worker_thread_id = None;
            let drained = drain_queue_locked(&mut guard, &self.shared);
            if guard.fault_triggered {
                self.shared.set_state_locked(&mut guard, CoreState::Faulted);
            } else {
                self.shared.set_state_locked(&mut guard, CoreState::Stopped);
            }
            self.shared.cv.notify_all();
            drained
        };
        drop(drained);
        self.shared.has_active_thread.store(false, Ordering::SeqCst);
        self.shared
            .global
            .active_worker_threads
            .fetch_sub(1, Ordering::SeqCst);
    }
}

fn worker_thread_entry(shared: &Arc<SharedRuntime>) {
    shared
        .global
        .active_worker_threads
        .fetch_add(1, Ordering::SeqCst);
    {
        let mut guard = shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.worker_thread_id = Some(thread::current().id());
    }
    let _bookkeeping = ThreadBookkeeping {
        shared: Arc::clone(shared),
    };

    let res = panic::catch_unwind(AssertUnwindSafe(|| worker_loop(shared)));
    if res.is_err() {
        shared.counters.panic_faults.fetch_add(1, Ordering::SeqCst);
        let drained = {
            let mut guard = shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.fault_triggered = true;
            guard.stop_requested = true;
            "Contained panic in core worker thread".clone_into(&mut guard.last_error);
            shared.set_state_locked(&mut guard, CoreState::Faulted);
            drain_queue_locked(&mut guard, shared)
        };
        drop(drained);
        shared
            .global
            .callbacks_in_progress
            .fetch_add(1, Ordering::SeqCst);
        shared
            .global
            .callbacks_invoked_total
            .fetch_add(1, Ordering::SeqCst);
        shared
            .observer
            .on_state_changed(CoreState::Faulted, Err(CoreError::InternalPanic));
        shared
            .global
            .callbacks_in_progress
            .fetch_sub(1, Ordering::SeqCst);
    }
}

fn worker_loop(shared: &Arc<SharedRuntime>) {
    loop {
        let maybe_item = {
            let mut guard = shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                if guard.pending_worker_panic {
                    guard.pending_worker_panic = false;
                    panic!("Simulated controlled worker panic (PoC fault injection)");
                }
                if guard.stop_requested {
                    return;
                }
                if let Some(item) = guard.queue.pop_front() {
                    break Some(item);
                }
                guard = shared
                    .cv
                    .wait(guard)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        };

        let Some(item) = maybe_item else {
            continue;
        };

        let QueuedItem { meta, payload } = item;
        let out_bytes = payload.as_slice().to_vec();
        let byte_len = out_bytes.len() as u64;

        // Return Copied buffer to bounded pool OR drop External buffer OUTSIDE mutex!
        match payload {
            QueuedPayload::Copied(mut vec_buf) => {
                vec_buf.clear();
                let mut guard = shared
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if guard.recycle_pool.len() < guard.queue_capacity {
                    guard.recycle_pool.push(vec_buf);
                }
            }
            QueuedPayload::External(ext_box) => {
                // Explicitly drop native buffer ownership BEFORE dispatching output callback,
                // strictly outside all mutex locks.
                drop(ext_box);
                shared
                    .counters
                    .native_owned_dropped
                    .fetch_add(1, Ordering::SeqCst);
            }
        }

        shared
            .global
            .in_flight_buffers
            .fetch_sub(1, Ordering::SeqCst);
        shared
            .counters
            .packets_processed
            .fetch_add(1, Ordering::SeqCst);
        shared
            .counters
            .bytes_processed
            .fetch_add(byte_len, Ordering::SeqCst);

        shared
            .global
            .callbacks_in_progress
            .fetch_add(1, Ordering::SeqCst);
        shared
            .global
            .callbacks_invoked_total
            .fetch_add(1, Ordering::SeqCst);
        shared.observer.on_output_packet(&meta, out_bytes);
        shared
            .global
            .callbacks_in_progress
            .fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct NoopObserver;
    impl CoreObserver for NoopObserver {
        fn on_output_packet(&self, _meta: &EncodedFrameMeta, _payload: Vec<u8>) {}
        fn on_state_changed(&self, _new_state: CoreState, _status: Result<(), CoreError>) {}
    }

    #[derive(Debug)]
    struct TrackingNativeBuf {
        bytes: Vec<u8>,
        releases: Arc<AtomicUsize>,
    }

    impl OwnedByteSlice for TrackingNativeBuf {
        fn as_slice(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for TrackingNativeBuf {
        fn drop(&mut self) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn lifecycle_backpressure_and_native_release_are_balanced() {
        struct CountingObserver {
            count: Arc<AtomicUsize>,
        }
        impl CoreObserver for CountingObserver {
            fn on_output_packet(&self, _meta: &EncodedFrameMeta, payload: Vec<u8>) {
                assert_ne!(payload.len(), 0);
                self.count.fetch_add(1, Ordering::SeqCst);
            }
            fn on_state_changed(&self, _new_state: CoreState, _status: Result<(), CoreError>) {}
        }

        let before = global_resource_snapshot();
        let releases = Arc::new(AtomicUsize::new(0));
        let received_packets = Arc::new(AtomicUsize::new(0));

        let session = CoreSession::create(
            CoreConfig {
                queue_capacity: 2,
                expected_frame_bytes_hint: 1024,
            },
            Arc::new(CountingObserver {
                count: Arc::clone(&received_packets),
            }),
        )
        .expect("create");

        let meta = EncodedFrameMeta {
            session_id: 1,
            display_id: 0,
            codec: EncodedCodec::H264AnnexB,
            flags: 1,
            frame_id: 1,
            gop_id: 1,
            capture_ts_us: 100,
            encode_done_ts_us: 120,
            submit_qpc_ticks: 1000,
        };

        // Submit before start must return InvalidState.
        assert_eq!(
            session.submit_borrowed(&meta, &[1, 2, 3]),
            Err(CoreError::InvalidState(CoreState::Created))
        );

        session.start().expect("start");
        session
            .submit_borrowed(&meta, &[0, 0, 0, 1, 0x65])
            .expect("borrowed");

        let owned = TrackingNativeBuf {
            bytes: vec![0xAA; 128],
            releases: Arc::clone(&releases),
        };
        session.submit_owned(&meta, owned).expect("owned");

        // Wait briefly for worker processing then stop idempotently.
        for _ in 0..100 {
            if received_packets.load(Ordering::SeqCst) >= 2 && releases.load(Ordering::SeqCst) >= 1
            {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }

        session.stop().expect("stop 1");
        session.stop().expect("stop 2");
        assert_eq!(releases.load(Ordering::SeqCst), 1);
        assert_eq!(received_packets.load(Ordering::SeqCst), 2);
        drop(session);

        let after = global_resource_snapshot();
        assert_eq!(after.active_instances, before.active_instances);
        assert_eq!(after.active_worker_threads, before.active_worker_threads);
        assert_eq!(after.in_flight_buffers, before.in_flight_buffers);
    }

    #[test]
    fn validation_rejects_invalid_inputs_and_preserves_unaccepted_owned_buffer() {
        let releases = Arc::new(AtomicUsize::new(0));
        let session =
            CoreSession::create(CoreConfig::default(), Arc::new(NoopObserver)).expect("create");

        let bad_meta = EncodedFrameMeta {
            session_id: 0,
            display_id: 0,
            codec: EncodedCodec::H264AnnexB,
            flags: 0,
            frame_id: 1,
            gop_id: 0,
            capture_ts_us: 10,
            encode_done_ts_us: 5,
            submit_qpc_ticks: 1,
        };
        let owned = TrackingNativeBuf {
            bytes: vec![1, 2, 3],
            releases: Arc::clone(&releases),
        };
        let (err, returned_owned) = session.submit_owned(&bad_meta, owned).unwrap_err();
        assert!(matches!(err, CoreError::InvalidArgument(_)));
        // Ownership remained with caller until caller drops `returned_owned`.
        assert_eq!(releases.load(Ordering::SeqCst), 0);
        drop(returned_owned);
        assert_eq!(releases.load(Ordering::SeqCst), 1);
    }
}
