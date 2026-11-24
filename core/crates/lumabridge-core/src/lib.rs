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
/// Hard cap on eager startup pre-allocation per session so `MAX_QUEUE_CAPACITY` x `MAX_ENCODED_FRAME_BYTES`
/// never allocates ~2 GiB eagerly on creation; per-session/display byte budgets will accompany M1 protocols.
pub const MAX_EAGER_PREALLOC_TOTAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EAGER_PREALLOC_SLOTS: usize = 8;
pub const MIN_RETAINED_POOL_SLAB_BYTES: usize = 256 * 1024;

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

/// Extension of `OwnedByteSlice` supporting two-phase transactional ownership transfer.
/// Implementations keep caller ownership disarmed until `commit_ownership()` runs at
/// the infallible enqueue point, preventing pre-commit panics from invoking native `release`.
pub trait TransactionalOwnedSlice: OwnedByteSlice {
    fn commit_ownership(&mut self);
}

struct PlainOwnedSliceAdapter<T: OwnedByteSlice>(T);

impl<T: OwnedByteSlice> OwnedByteSlice for PlainOwnedSliceAdapter<T> {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<T: OwnedByteSlice> TransactionalOwnedSlice for PlainOwnedSliceAdapter<T> {
    fn commit_ownership(&mut self) {}
}

struct InFlightToken(Arc<GlobalCounters>);

impl InFlightToken {
    fn new(global: Arc<GlobalCounters>) -> Self {
        global.in_flight_buffers.fetch_add(1, Ordering::SeqCst);
        Self(global)
    }
}

impl Drop for InFlightToken {
    fn drop(&mut self) {
        self.0.in_flight_buffers.fetch_sub(1, Ordering::SeqCst);
    }
}

struct CallbackInProgressGuard<'a>(&'a GlobalCounters);

impl<'a> CallbackInProgressGuard<'a> {
    fn enter(global: &'a GlobalCounters) -> Self {
        global.callbacks_in_progress.fetch_add(1, Ordering::SeqCst);
        global
            .callbacks_invoked_total
            .fetch_add(1, Ordering::SeqCst);
        Self(global)
    }
}

impl Drop for CallbackInProgressGuard<'_> {
    fn drop(&mut self) {
        self.0.callbacks_in_progress.fetch_sub(1, Ordering::SeqCst);
    }
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
    _in_flight: InFlightToken,
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

#[cfg(feature = "poc-fault-injection")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum SubmitFaultMode {
    None,
    PreCommitPanic,
    PostCommitPanic,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkerLifecycle {
    NotSpawned,
    Active,
    Joined,
}

#[derive(Clone, Copy)]
enum CallbackSlot {
    Running,
    Terminal,
}

struct SharedQueueState {
    state: CoreState,
    queue: VecDeque<QueuedItem>,
    recycle_pool: Vec<Vec<u8>>,
    queue_capacity: usize,
    retained_slab_cap_limit: usize,
    stop_requested: bool,
    fault_triggered: bool,
    pending_worker_panic: bool,
    #[cfg(feature = "poc-fault-injection")]
    pending_submit_fault: SubmitFaultMode,
    last_error: String,
    worker_thread_id: Option<ThreadId>,
    worker_lifecycle: WorkerLifecycle,
    notified_rank: u8,
    running_cb_tid: Option<ThreadId>,
    terminal_cb_tid: Option<ThreadId>,
}

impl SharedQueueState {
    fn new(config: CoreConfig) -> Self {
        let mut recycle_pool = Vec::with_capacity(config.queue_capacity);
        if config.expected_frame_bytes_hint > 0 {
            let slot_cap = config
                .expected_frame_bytes_hint
                .min(MAX_EAGER_PREALLOC_TOTAL_BYTES);
            let max_slots_by_bytes = MAX_EAGER_PREALLOC_TOTAL_BYTES / slot_cap;
            let eager_slots = config
                .queue_capacity
                .min(MAX_EAGER_PREALLOC_SLOTS)
                .min(max_slots_by_bytes);
            for _ in 0..eager_slots {
                recycle_pool.push(Vec::with_capacity(slot_cap));
            }
        }
        let retained_slab_cap_limit = config
            .expected_frame_bytes_hint
            .max(MIN_RETAINED_POOL_SLAB_BYTES)
            .saturating_mul(2)
            .min(MAX_ENCODED_FRAME_BYTES);
        Self {
            state: CoreState::Created,
            queue: VecDeque::with_capacity(config.queue_capacity),
            recycle_pool,
            queue_capacity: config.queue_capacity,
            retained_slab_cap_limit,
            stop_requested: false,
            fault_triggered: false,
            pending_worker_panic: false,
            #[cfg(feature = "poc-fault-injection")]
            pending_submit_fault: SubmitFaultMode::None,
            last_error: String::new(),
            worker_thread_id: None,
            worker_lifecycle: WorkerLifecycle::NotSpawned,
            notified_rank: 0,
            running_cb_tid: None,
            terminal_cb_tid: None,
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

    fn wait_callbacks_clear_locked<'a>(
        &self,
        mut guard: std::sync::MutexGuard<'a, SharedQueueState>,
        current_tid: ThreadId,
        wait_for_running: bool,
    ) -> std::sync::MutexGuard<'a, SharedQueueState> {
        loop {
            let blocked_by_running = wait_for_running
                && guard
                    .running_cb_tid
                    .is_some_and(|owner| owner != current_tid);
            let blocked_by_terminal = guard
                .terminal_cb_tid
                .is_some_and(|owner| owner != current_tid);
            if !blocked_by_running && !blocked_by_terminal {
                return guard;
            }
            guard = self
                .cv
                .wait(guard)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn dispatch_state_notification(
        &self,
        new_state: CoreState,
        status: Result<(), CoreError>,
        slot: CallbackSlot,
    ) {
        let _slot_guard = StateCallbackSlotGuard { shared: self, slot };
        let _cb_guard = CallbackInProgressGuard::enter(&self.global);
        if new_state == CoreState::Faulted {
            let _ = panic::catch_unwind(AssertUnwindSafe(|| {
                self.observer.on_state_changed(new_state, status);
            }));
        } else {
            self.observer.on_state_changed(new_state, status);
        }
    }
}

struct JoinCompletionGuard<'a> {
    shared: &'a SharedRuntime,
}

impl Drop for JoinCompletionGuard<'_> {
    fn drop(&mut self) {
        let mut guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.worker_lifecycle = WorkerLifecycle::Joined;
        self.shared.cv.notify_all();
    }
}

struct StateCallbackSlotGuard<'a> {
    shared: &'a SharedRuntime,
    slot: CallbackSlot,
}

impl Drop for StateCallbackSlotGuard<'_> {
    fn drop(&mut self) {
        let mut guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match self.slot {
            CallbackSlot::Running => guard.running_cb_tid = None,
            CallbackSlot::Terminal => guard.terminal_cb_tid = None,
        }
        self.shared.cv.notify_all();
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
        let queue_state = SharedQueueState::new(config);
        let shared = Arc::new(SharedRuntime {
            inner: Mutex::new(queue_state),
            cv: Condvar::new(),
            counters: InstanceCounters::new(CoreState::Created),
            global: Arc::clone(&global),
            observer,
            has_active_thread: AtomicBool::new(false),
        });
        let worker = Mutex::new(None);
        // Increment active_instances only after all startup allocations succeed so OOM/panic
        // during initialization cannot leak the instance counter.
        global.active_instances.fetch_add(1, Ordering::SeqCst);

        Ok(Self { shared, worker })
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
        guard.worker_lifecycle = WorkerLifecycle::Active;
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
                err_guard.worker_lifecycle = WorkerLifecycle::NotSpawned;
                self.shared
                    .set_state_locked(&mut err_guard, CoreState::Faulted);
                "Failed to spawn worker thread".clone_into(&mut err_guard.last_error);
                CoreError::Faulted
            })?;

        self.shared.has_active_thread.store(true, Ordering::SeqCst);
        *worker_slot = Some(handle);

        let current_tid = thread::current().id();
        let should_notify_running = {
            let mut notify_guard = self
                .shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !notify_guard.stop_requested
                && !notify_guard.fault_triggered
                && notify_guard.notified_rank < 1
                && notify_guard.state == CoreState::Running
            {
                notify_guard.notified_rank = 1;
                notify_guard.running_cb_tid = Some(current_tid);
                true
            } else {
                false
            }
        };
        drop(worker_slot);

        if should_notify_running {
            self.shared.dispatch_state_notification(
                CoreState::Running,
                Ok(()),
                CallbackSlot::Running,
            );
            let follow_up = {
                let guard = self
                    .shared
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut guard = self
                    .shared
                    .wait_callbacks_clear_locked(guard, current_tid, false);
                if guard.fault_triggered
                    && guard.notified_rank < 3
                    && guard.terminal_cb_tid.is_none()
                {
                    guard.notified_rank = 3;
                    guard.terminal_cb_tid = Some(current_tid);
                    Some((CoreState::Faulted, Err(CoreError::InternalPanic)))
                } else if guard.stop_requested
                    && !guard.fault_triggered
                    && guard.worker_thread_id.is_none()
                    && guard.notified_rank < 2
                    && guard.terminal_cb_tid.is_none()
                {
                    guard.notified_rank = 2;
                    guard.terminal_cb_tid = Some(current_tid);
                    self.shared.set_state_locked(&mut guard, CoreState::Stopped);
                    Some((CoreState::Stopped, Ok(())))
                } else {
                    None
                }
            };
            if let Some((state, status)) = follow_up {
                self.shared
                    .dispatch_state_notification(state, status, CallbackSlot::Terminal);
            }
        }
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

        let token = InFlightToken::new(Arc::clone(&self.shared.global));
        guard.queue.push_back(QueuedItem {
            meta: *meta,
            payload: QueuedPayload::Copied(buf),
            _in_flight: token,
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
        match self.submit_owned_boxed(meta, Box::new(PlainOwnedSliceAdapter(payload))) {
            Ok(()) => Ok(()),
            Err((err, boxed)) => Err((err, boxed.0)),
        }
    }

    /// Transactional variant of `submit_owned` keeping `payload` disarmed until the
    /// infallible enqueue commit point inside the queue lock.
    ///
    /// # Panics
    /// Under the optional `poc-fault-injection` feature, triggers an intentional armed
    /// test panic before or after ownership commit to verify transactional safety.
    pub fn submit_owned_boxed<T: TransactionalOwnedSlice + 'static>(
        &self,
        meta: &EncodedFrameMeta,
        mut payload: Box<T>,
    ) -> Result<(), (CoreError, Box<T>)> {
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

        guard.queue.reserve(1);

        #[cfg(feature = "poc-fault-injection")]
        let submit_fault =
            std::mem::replace(&mut guard.pending_submit_fault, SubmitFaultMode::None);
        #[cfg(feature = "poc-fault-injection")]
        assert!(
            submit_fault != SubmitFaultMode::PreCommitPanic,
            "Controlled PoC FFI panic before ownership commit"
        );
        #[cfg(feature = "poc-fault-injection")]
        let trigger_post_commit_panic = submit_fault == SubmitFaultMode::PostCommitPanic;

        let token = InFlightToken::new(Arc::clone(&self.shared.global));
        // Infallible commit point: all checks & reservations finished; commit ownership atomically.
        payload.commit_ownership();
        guard.queue.push_back(QueuedItem {
            meta: *meta,
            payload: QueuedPayload::External(payload),
            _in_flight: token,
        });

        self.record_enqueue_metrics(guard.queue.len(), true);
        self.shared.cv.notify_one();
        drop(guard);

        #[cfg(feature = "poc-fault-injection")]
        assert!(
            !trigger_post_commit_panic,
            "Controlled PoC FFI panic after ownership commit"
        );

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

        self.wait_and_join_worker_external()?;

        let (drained_tail, pending_notify) = {
            let guard = self
                .shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut guard = self
                .shared
                .wait_callbacks_clear_locked(guard, current_tid, true);
            let drained_tail = drain_queue_locked(&mut guard, &self.shared);
            let pending_notify = if guard.fault_triggered {
                if guard.notified_rank < 3 && guard.terminal_cb_tid.is_none() {
                    guard.notified_rank = 3;
                    guard.terminal_cb_tid = Some(current_tid);
                    Some((CoreState::Faulted, Err(CoreError::InternalPanic)))
                } else {
                    None
                }
            } else {
                self.shared.set_state_locked(&mut guard, CoreState::Stopped);
                if guard.notified_rank < 2 && guard.terminal_cb_tid.is_none() {
                    guard.notified_rank = 2;
                    guard.terminal_cb_tid = Some(current_tid);
                    Some((CoreState::Stopped, Ok(())))
                } else {
                    None
                }
            };
            (drained_tail, pending_notify)
        };

        drop(drained_tail);
        if let Some((state, status)) = pending_notify {
            self.shared
                .dispatch_state_notification(state, status, CallbackSlot::Terminal);
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

        let _ = panic::catch_unwind(AssertUnwindSafe(|| drop(drained)));
        if !is_worker {
            let _ = self.wait_and_join_worker_external();
        }

        let should_notify_fault = {
            let guard = self
                .shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut guard = self
                .shared
                .wait_callbacks_clear_locked(guard, current_tid, !is_worker);
            let can_emit = (!is_worker || guard.running_cb_tid.is_none())
                && guard.notified_rank < 3
                && guard.terminal_cb_tid.is_none();
            if can_emit {
                guard.notified_rank = 3;
                guard.terminal_cb_tid = Some(current_tid);
                true
            } else {
                false
            }
        };

        if should_notify_fault {
            self.shared.dispatch_state_notification(
                CoreState::Faulted,
                Err(CoreError::InternalPanic),
                CallbackSlot::Terminal,
            );
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

    #[cfg(feature = "poc-fault-injection")]
    /// Controlled `PoC` helper to arm a pre-commit panic inside `submit_owned_boxed`.
    pub fn poc_arm_submit_pre_commit_panic(&self) -> Result<(), CoreError> {
        let mut guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.state != CoreState::Running {
            return Err(CoreError::InvalidState(guard.state));
        }
        guard.pending_submit_fault = SubmitFaultMode::PreCommitPanic;
        Ok(())
    }

    #[cfg(feature = "poc-fault-injection")]
    /// Controlled `PoC` helper to arm a post-commit panic inside `submit_owned_boxed`.
    pub fn poc_arm_submit_post_commit_panic(&self) -> Result<(), CoreError> {
        let mut guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.state != CoreState::Running {
            return Err(CoreError::InvalidState(guard.state));
        }
        guard.pending_submit_fault = SubmitFaultMode::PostCommitPanic;
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

    fn wait_and_join_worker_external(&self) -> Result<(), CoreError> {
        let current_tid = thread::current().id();
        let handle = {
            let mut worker_slot = self
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            worker_slot.take()
        };
        if let Some(join_handle) = handle {
            if join_handle.thread().id() == current_tid {
                return Ok(());
            }
            let _join_guard = JoinCompletionGuard {
                shared: &self.shared,
            };
            if join_handle.join().is_err() {
                return Err(CoreError::InternalPanic);
            }
            return Ok(());
        }
        let mut guard = self
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while guard.worker_lifecycle == WorkerLifecycle::Active {
            guard = self
                .shared
                .cv
                .wait(guard)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let depth_u32 = u32::try_from(depth).unwrap_or(u32::MAX);
        self.shared
            .counters
            .queue_peak_depth
            .fetch_max(depth_u32, Ordering::SeqCst);
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

impl ThreadBookkeeping {
    fn enter(shared: Arc<SharedRuntime>) -> Self {
        shared
            .global
            .active_worker_threads
            .fetch_add(1, Ordering::SeqCst);
        Self { shared }
    }
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
    let _bookkeeping = ThreadBookkeeping::enter(Arc::clone(shared));
    let worker_tid = thread::current().id();
    {
        let mut guard = shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.worker_thread_id = Some(worker_tid);
    }

    let res = panic::catch_unwind(AssertUnwindSafe(|| worker_loop(shared)));
    if res.is_err() {
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            shared.counters.panic_faults.fetch_add(1, Ordering::SeqCst);
            let (drained, notify_fault) = {
                let mut guard = shared
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.fault_triggered = true;
                guard.stop_requested = true;
                "Contained panic in core worker thread".clone_into(&mut guard.last_error);
                shared.set_state_locked(&mut guard, CoreState::Faulted);
                let drained = drain_queue_locked(&mut guard, shared);
                let notify_fault = if guard.running_cb_tid.is_none()
                    && guard.terminal_cb_tid.is_none()
                    && guard.notified_rank < 3
                {
                    guard.notified_rank = 3;
                    guard.terminal_cb_tid = Some(worker_tid);
                    true
                } else {
                    false
                };
                (drained, notify_fault)
            };
            drop(drained);
            if notify_fault {
                shared.dispatch_state_notification(
                    CoreState::Faulted,
                    Err(CoreError::InternalPanic),
                    CallbackSlot::Terminal,
                );
            }
        }));
    } else {
        let (drained, notify_stopped) = {
            let mut guard = shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let drained = drain_queue_locked(&mut guard, shared);
            let notify_stopped = if !guard.fault_triggered
                && guard.running_cb_tid.is_none()
                && guard.terminal_cb_tid.is_none()
                && guard.notified_rank < 2
            {
                guard.notified_rank = 2;
                guard.terminal_cb_tid = Some(worker_tid);
                shared.set_state_locked(&mut guard, CoreState::Stopped);
                true
            } else {
                false
            };
            (drained, notify_stopped)
        };
        drop(drained);
        if notify_stopped {
            shared.dispatch_state_notification(CoreState::Stopped, Ok(()), CallbackSlot::Terminal);
        }
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

        let QueuedItem {
            meta,
            payload,
            _in_flight: in_flight,
        } = item;
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
                if guard.recycle_pool.len() < guard.queue_capacity
                    && vec_buf.capacity() <= guard.retained_slab_cap_limit
                {
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
        drop(in_flight);

        shared
            .counters
            .packets_processed
            .fetch_add(1, Ordering::SeqCst);
        shared
            .counters
            .bytes_processed
            .fetch_add(byte_len, Ordering::SeqCst);

        let _cb_guard = CallbackInProgressGuard::enter(&shared.global);
        shared.observer.on_output_packet(&meta, out_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::RwLock;

    // Serialize only tests asserting process-wide counters against other session-creating tests.
    static SESSION_TEST_RWLOCK: RwLock<()> = RwLock::new(());

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

        let _exclusive = SESSION_TEST_RWLOCK
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

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
        let _shared = SESSION_TEST_RWLOCK
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    #[test]
    fn memory_preallocation_is_bounded_for_max_config() {
        let _shared = SESSION_TEST_RWLOCK
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let session = CoreSession::create(
            CoreConfig {
                queue_capacity: MAX_QUEUE_CAPACITY,
                expected_frame_bytes_hint: MAX_ENCODED_FRAME_BYTES,
            },
            Arc::new(NoopObserver),
        )
        .expect("max config session must not eagerly allocate 2 GiB");
        let guard = session
            .shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let eager_total: usize = guard.recycle_pool.iter().map(Vec::capacity).sum();
        assert!(guard.recycle_pool.len() <= MAX_EAGER_PREALLOC_SLOTS);
        assert!(eager_total <= MAX_EAGER_PREALLOC_TOTAL_BYTES);
    }

    #[test]
    fn observer_panic_during_fault_recovery_is_contained_and_decrements_counters() {
        struct PanickingFaultObserver;
        impl CoreObserver for PanickingFaultObserver {
            fn on_output_packet(&self, _meta: &EncodedFrameMeta, _payload: Vec<u8>) {}
            fn on_state_changed(&self, new_state: CoreState, _status: Result<(), CoreError>) {
                assert!(
                    new_state != CoreState::Faulted,
                    "Simulated observer panic during fault notification"
                );
            }
        }

        let _shared = SESSION_TEST_RWLOCK
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let releases = Arc::new(AtomicUsize::new(0));
        let session = CoreSession::create(CoreConfig::default(), Arc::new(PanickingFaultObserver))
            .expect("create");
        session.start().expect("start");
        let meta = EncodedFrameMeta {
            session_id: 77,
            display_id: 0,
            codec: EncodedCodec::H264AnnexB,
            flags: 1,
            frame_id: 1,
            gop_id: 1,
            capture_ts_us: 100,
            encode_done_ts_us: 120,
            submit_qpc_ticks: 10,
        };
        let owned = TrackingNativeBuf {
            bytes: vec![0xAA; 64],
            releases: Arc::clone(&releases),
        };
        session.submit_owned(&meta, owned).expect("submit");
        // mark_faulted triggers PanickingFaultObserver inside worker/caller; panic must not escape.
        let res = panic::catch_unwind(AssertUnwindSafe(|| {
            session.mark_faulted("test fault");
        }));
        assert!(res.is_ok());
        session.mark_faulted("idempotent second fault");
        drop(session);
        assert_eq!(releases.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn concurrent_external_stops_wait_for_worker_and_emit_single_stopped() {
        use std::sync::Barrier;
        use std::time::Duration;

        struct GateObserver {
            entered: Barrier,
            release: Barrier,
            states: Mutex<Vec<CoreState>>,
        }
        impl CoreObserver for GateObserver {
            fn on_output_packet(&self, _meta: &EncodedFrameMeta, _payload: Vec<u8>) {
                self.entered.wait();
                self.release.wait();
            }
            fn on_state_changed(&self, new_state: CoreState, _status: Result<(), CoreError>) {
                self.states
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(new_state);
            }
        }

        let _shared = SESSION_TEST_RWLOCK
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let observer = Arc::new(GateObserver {
            entered: Barrier::new(2),
            release: Barrier::new(2),
            states: Mutex::new(Vec::new()),
        });
        let session =
            Arc::new(CoreSession::create(CoreConfig::default(), observer.clone()).expect("create"));
        session.start().expect("start");

        let meta = EncodedFrameMeta {
            session_id: 101,
            display_id: 0,
            codec: EncodedCodec::H264AnnexB,
            flags: 1,
            frame_id: 1,
            gop_id: 1,
            capture_ts_us: 100,
            encode_done_ts_us: 120,
            submit_qpc_ticks: 10,
        };
        session
            .submit_borrowed(&meta, &[1, 2, 3, 4])
            .expect("submit");
        observer.entered.wait();

        let stop_start = Arc::new(Barrier::new(3));
        let completed_stops = Arc::new(AtomicUsize::new(0));
        let mut stop_threads = Vec::new();
        for _ in 0..2 {
            let s = Arc::clone(&session);
            let b = Arc::clone(&stop_start);
            let done = Arc::clone(&completed_stops);
            stop_threads.push(thread::spawn(move || {
                b.wait();
                s.stop().expect("stop");
                done.fetch_add(1, Ordering::SeqCst);
            }));
        }

        stop_start.wait();
        thread::sleep(Duration::from_millis(25));
        assert_eq!(
            completed_stops.load(Ordering::SeqCst),
            0,
            "neither concurrent stop may return while worker callback is still active"
        );

        observer.release.wait();
        for t in stop_threads {
            t.join().expect("join stop thread");
        }
        assert_eq!(completed_stops.load(Ordering::SeqCst), 2);
        let recorded = observer
            .states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(recorded, vec![CoreState::Running, CoreState::Stopped]);
    }

    #[test]
    fn start_racing_stop_maintains_monotonic_state_order() {
        use std::sync::Barrier;
        use std::time::Duration;

        struct RunningGateObserver {
            running_entered: Barrier,
            running_release: Barrier,
            states: Mutex<Vec<CoreState>>,
        }
        impl CoreObserver for RunningGateObserver {
            fn on_output_packet(&self, _meta: &EncodedFrameMeta, _payload: Vec<u8>) {}
            fn on_state_changed(&self, new_state: CoreState, _status: Result<(), CoreError>) {
                self.states
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(new_state);
                if new_state == CoreState::Running {
                    self.running_entered.wait();
                    self.running_release.wait();
                }
            }
        }

        let _shared = SESSION_TEST_RWLOCK
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let observer = Arc::new(RunningGateObserver {
            running_entered: Barrier::new(2),
            running_release: Barrier::new(2),
            states: Mutex::new(Vec::new()),
        });
        let session =
            Arc::new(CoreSession::create(CoreConfig::default(), observer.clone()).expect("create"));

        let s_start = Arc::clone(&session);
        let start_thread = thread::spawn(move || {
            s_start.start().expect("start");
        });

        observer.running_entered.wait();
        let stop_done = Arc::new(AtomicUsize::new(0));
        let s_stop = Arc::clone(&session);
        let done_flag = Arc::clone(&stop_done);
        let stop_thread = thread::spawn(move || {
            s_stop.stop().expect("stop");
            done_flag.fetch_add(1, Ordering::SeqCst);
        });

        thread::sleep(Duration::from_millis(25));
        assert_eq!(
            stop_done.load(Ordering::SeqCst),
            0,
            "stop must not emit Stopped or return while Running callback is executing"
        );

        observer.running_release.wait();
        start_thread.join().expect("start join");
        stop_thread.join().expect("stop join");
        assert_eq!(stop_done.load(Ordering::SeqCst), 1);

        let recorded = observer
            .states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(recorded, vec![CoreState::Running, CoreState::Stopped]);
    }

    #[test]
    fn fault_racing_stop_emits_faulted_without_downgrade_to_stopped() {
        use std::sync::Barrier;

        struct FaultStopObserver {
            entered: Barrier,
            release: Barrier,
            states: Mutex<Vec<CoreState>>,
        }
        impl CoreObserver for FaultStopObserver {
            fn on_output_packet(&self, _meta: &EncodedFrameMeta, _payload: Vec<u8>) {
                self.entered.wait();
                self.release.wait();
            }
            fn on_state_changed(&self, new_state: CoreState, _status: Result<(), CoreError>) {
                self.states
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(new_state);
            }
        }

        let _shared = SESSION_TEST_RWLOCK
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let observer = Arc::new(FaultStopObserver {
            entered: Barrier::new(2),
            release: Barrier::new(2),
            states: Mutex::new(Vec::new()),
        });
        let session =
            Arc::new(CoreSession::create(CoreConfig::default(), observer.clone()).expect("create"));
        session.start().expect("start");
        let meta = EncodedFrameMeta {
            session_id: 202,
            display_id: 0,
            codec: EncodedCodec::H264AnnexB,
            flags: 1,
            frame_id: 1,
            gop_id: 1,
            capture_ts_us: 100,
            encode_done_ts_us: 120,
            submit_qpc_ticks: 10,
        };
        session.submit_borrowed(&meta, &[9, 8, 7]).expect("submit");
        observer.entered.wait();

        let s1 = Arc::clone(&session);
        let t_fault = thread::spawn(move || {
            s1.mark_faulted("concurrent fault");
        });
        while session.metrics().state != CoreState::Faulted as u32 {
            thread::yield_now();
        }

        let stop_gate = Arc::new(Barrier::new(2));
        let s2 = Arc::clone(&session);
        let g2 = Arc::clone(&stop_gate);
        let t_stop = thread::spawn(move || {
            g2.wait();
            let _ = s2.stop();
        });

        stop_gate.wait();
        thread::sleep(std::time::Duration::from_millis(15));
        observer.release.wait();
        t_fault.join().expect("fault join");
        t_stop.join().expect("stop join");

        assert_eq!(session.metrics().state, CoreState::Faulted as u32);
        let recorded = observer
            .states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(recorded, vec![CoreState::Running, CoreState::Faulted]);
    }
}
