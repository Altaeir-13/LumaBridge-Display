#pragma once

#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#define LUMABRIDGE_SWAPCHAIN_DEFINED_WIN32_NO_STATUS
#endif
#include <Windows.h>
#ifdef LUMABRIDGE_SWAPCHAIN_DEFINED_WIN32_NO_STATUS
#undef WIN32_NO_STATUS
#undef LUMABRIDGE_SWAPCHAIN_DEFINED_WIN32_NO_STATUS
#endif

#include <ntstatus.h>

#include <cstdint>

typedef LONG NTSTATUS;

namespace lumabridge::driver {

inline constexpr uint32_t kMaxConsecutiveTransientErrors = 3;
inline constexpr DWORD kTransientRetryBackoffMs = 2;
inline constexpr uint32_t kMaxConsecutiveSwapChainFailures = 5;

/// Explicit lifecycle states for SwapChainProcessor availability, suspension, teardown, and fault gating.
enum class SwapChainProcessorState : uint32_t
{
    Ready = 0,
    Active,
    Suspended,
    Stopping,
    Stopped,
    Faulted,
};

/// Returns a concise ASCII name for a SwapChainProcessorState value.
inline const char*
SwapChainProcessorStateToString(
    SwapChainProcessorState state
    ) noexcept
{
    switch (state)
    {
    case SwapChainProcessorState::Ready:
        return "Ready";
    case SwapChainProcessorState::Active:
        return "Active";
    case SwapChainProcessorState::Suspended:
        return "Suspended";
    case SwapChainProcessorState::Stopping:
        return "Stopping";
    case SwapChainProcessorState::Stopped:
        return "Stopped";
    case SwapChainProcessorState::Faulted:
        return "Faulted";
    default:
        return "Unknown";
    }
}

/// Per-frame metadata extracted from IDDCX_METADATA and optional D3D11 pixel extraction status.
struct SwapChainFrameMetadata
{
    uint32_t PresentationFrameNumber{0};
    uint32_t DirtyRectCount{0};
    uint32_t MoveRegionCount{0};
    bool HwProtectedSurface{false};
    uint64_t PresentDisplayQPCTime{0};
    bool HasValidSurface{false};
    bool ExtractionAttempted{false};
    bool ExtractionAccepted{false};
    bool PixelsCopied{false};
    bool ProtectedContentRejected{false};
    bool EvictedOldestByBackpressure{false};
    uint32_t ExtractedWidth{0};
    uint32_t ExtractedHeight{0};
    uint32_t ExtractedFormat{0};
    uint64_t FrameSequence{0};
    uint64_t CopyLatencyUs{0};
    HRESULT ExtractionHResult{S_OK};
};

/// Synchronized snapshot of swapchain lifecycle, errors, circuit breaker, and frame-processing metrics.
struct SwapChainMetricsSnapshot
{
    uint64_t AssignAttempts{0};
    uint64_t AssignCount{0};
    uint64_t AbandonedAssignCount{0};
    uint64_t UnassignCount{0};
    uint64_t StaleMonitorUnassignIgnoredCount{0};
    uint64_t FramesAcquired{0};
    uint64_t FramesProcessed{0};
    uint64_t FramesDropped{0};
    uint64_t EmptyAcquireWaits{0};
    uint64_t TransientErrors{0};
    uint64_t DeviceRemovedErrors{0};
    uint64_t FatalErrors{0};
    uint64_t CircuitBreakerRejections{0};
    uint64_t SwapChainDeletedCount{0};
    uint64_t LastFrameProcessingTimeUs{0};
    uint64_t TotalFrameProcessingTimeUs{0};
    uint64_t AvgFrameProcessingTimeUs{0};
    uint64_t MaxFrameProcessingTimeUs{0};
    double AcquireFps{0.0};
    double ProcessFps{0.0};
    uint32_t ConsecutiveFailures{0};
    uint32_t LastPresentationFrameNumber{0};
    HRESULT LastErrorHResult{S_OK};
    LUID ActiveRenderAdapterLuid{0, 0};
    SwapChainProcessorState State{SwapChainProcessorState::Ready};
    bool IsActive{false};
    bool FrameExtractionEnabled{false};
    uint64_t FramesExtractionAccepted{0};
    uint64_t FramesCopied{0};
    uint64_t FramesDelivered{0};
    uint64_t FramesDroppedByBackpressure{0};
    uint64_t ProtectedFramesRejected{0};
    uint64_t FrameCopyFailures{0};
    uint64_t FrameTransportFailures{0};
    uint32_t ActiveHostConnections{0};
    uint64_t LastFrameSequence{0};
    uint64_t FrameCopyLatencyUs{0};
    uint64_t TotalFrameCopyLatencyUs{0};
    uint64_t AvgFrameCopyLatencyUs{0};
    uint64_t MaxFrameCopyLatencyUs{0};
    uint64_t FrameDeliveryLatencyUs{0};
    uint64_t AvgFrameDeliveryLatencyUs{0};
    uint64_t MaxFrameDeliveryLatencyUs{0};
    uint32_t QueueDepth{0};
    uint32_t PeakQueueDepth{0};
    uint32_t LastExtractedWidth{0};
    uint32_t LastExtractedHeight{0};
    uint32_t LastExtractedFormat{0};
    HRESULT LastExtractionError{S_OK};
    HRESULT LastTransportError{S_OK};
};

/// Abstraction over D3D11/DXGI device setup and IddCx swapchain DDIs for testability.
class ISwapChainBackend
{
public:
    virtual ~ISwapChainBackend() = default;

    /// Selects the adapter matching renderAdapterLuid, creates a BGRA-capable D3D11 device,
    /// and binds it to swapChainHandle via IddCxSwapChainSetDevice.
    virtual HRESULT InitializeDeviceAndBindSwapChain(
        void* swapChainHandle,
        LUID renderAdapterLuid
        ) noexcept = 0;

    /// Acquires the next buffer via IddCxSwapChainReleaseAndAcquireBuffer, extracts metadata,
    /// validates the surface handle, and releases the transient COM surface reference.
    virtual HRESULT ReleaseAndAcquireBuffer(
        void* swapChainHandle,
        SwapChainFrameMetadata& outMetadata
        ) noexcept = 0;

    /// Notifies IddCx that processing for the current frame has completed.
    virtual HRESULT FinishProcessingFrame(
        void* swapChainHandle
        ) noexcept = 0;

    /// Deletes the driver-owned WDF/IddCx swapchain object exactly once after ownership transfer.
    virtual void DeleteSwapChainObject(
        void* swapChainHandle
        ) noexcept = 0;

    /// Populates transport/IPC delivery and backpressure metrics from the backend if supported.
    virtual void QueryFrameTransportMetrics(
        SwapChainMetricsSnapshot& inoutSnapshot
        ) const noexcept
    {
        (void)inoutSnapshot;
    }
};

/// RAII wrapper for driver-owned Win32 handles (e.g., internal events and worker thread).
class ScopedWin32Handle final
{
public:
    ScopedWin32Handle() noexcept = default;

    explicit ScopedWin32Handle(HANDLE handle) noexcept
        : m_handle(handle)
    {
    }

    ~ScopedWin32Handle()
    {
        Reset();
    }

    ScopedWin32Handle(const ScopedWin32Handle&) = delete;
    ScopedWin32Handle& operator=(const ScopedWin32Handle&) = delete;

    ScopedWin32Handle(ScopedWin32Handle&& other) noexcept
        : m_handle(other.Release())
    {
    }

    ScopedWin32Handle& operator=(ScopedWin32Handle&& other) noexcept
    {
        if (this != &other)
        {
            Reset(other.Release());
        }
        return *this;
    }

    bool IsValid() const noexcept
    {
        return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
    }

    HANDLE Get() const noexcept
    {
        return m_handle;
    }

    HANDLE Release() noexcept
    {
        HANDLE detached = m_handle;
        m_handle = nullptr;
        return detached;
    }

    void Reset(HANDLE newHandle = nullptr) noexcept
    {
        if (IsValid() && m_handle != newHandle)
        {
            CloseHandle(m_handle);
        }
        m_handle = newHandle;
    }

private:
    HANDLE m_handle{nullptr};
};

/// Manages the dedicated cooperative-cancellation swapchain processing loop and lifecycle.
/// Lock ordering: m_lifecycleLock -> m_metricsLock (worker thread only ever acquires m_metricsLock).
class SwapChainProcessor final
{
public:
    explicit SwapChainProcessor(ISwapChainBackend* backend) noexcept;
    ~SwapChainProcessor();

    SwapChainProcessor(const SwapChainProcessor&) = delete;
    SwapChainProcessor& operator=(const SwapChainProcessor&) = delete;

    /// Assigns a new swapchain, binds D3D11/DXGI via backend, and starts the worker thread.
    /// Pre-ownership failures return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN WITHOUT
    /// deleting swapChainHandle (OS/IddCx retains ownership on callback failure).
    NTSTATUS AssignSwapChain(
        void* swapChainHandle,
        HANDLE nextSurfaceAvailableEvent,
        LUID renderAdapterLuid,
        void* ownerMonitorHandle = nullptr
        ) noexcept;

    /// Cooperatively stops the worker thread, joins it, and deletes the driver-owned swapchain once.
    /// Idempotent and reentrancy-safe.
    NTSTATUS UnassignSwapChain() noexcept;

    /// Stops active swapchain processing only if it belongs to monitorHandle (ignoring stale monitors).
    NTSTATUS UnassignSwapChainForMonitor(
        void* monitorHandle
        ) noexcept;

    /// Suspends swapchain processing (D0Exit) and rejects new assignments until OnResume().
    NTSTATUS OnSuspend() noexcept;

    /// Resumes swapchain processing (D0Entry), resetting transient Faulted circuit breaker if not stopped.
    NTSTATUS OnResume() noexcept;

    /// Permanently tears down the processor (Stopping -> Stopped), rejecting all future assignments.
    NTSTATUS Shutdown() noexcept;

    /// Returns a thread-safe snapshot of swapchain processing metrics and state.
    SwapChainMetricsSnapshot GetMetricsSnapshot() const noexcept;

private:
    struct WorkerRunParams
    {
        SwapChainProcessor* Processor{nullptr};
        void* SwapChainHandle{nullptr};
        HANDLE NextSurfaceAvailableEvent{nullptr};
        HANDLE StopEvent{nullptr};
        HANDLE StartGateEvent{nullptr};
    };

    static DWORD WINAPI WorkerThreadProc(LPVOID context) noexcept;

    void WorkerLoop(
        void* swapChainHandle,
        HANDLE nextSurfaceAvailableEvent,
        HANDLE stopEvent,
        HANDLE startGateEvent
        ) noexcept;

    bool IsReentrantLifecycleCall() const noexcept;
    void StopAndCleanupActiveSessionLocked() noexcept;
    void RecordPreOwnershipFailureLocked(HRESULT hr, bool countFailureAgainstBreaker) noexcept;
    void RecordWaitOrSyncFailureLocked(HRESULT hr) noexcept;

    ISwapChainBackend* m_backend{nullptr};

    SRWLOCK m_lifecycleLock{SRWLOCK_INIT};
    mutable SRWLOCK m_metricsLock{SRWLOCK_INIT};

    volatile LONG m_lifecycleLockOwnerThreadId{0};
    volatile LONG m_workerThreadId{0};
    volatile LONG m_shutdownRequested{0};

    void* m_activeSwapChain{nullptr};
    void* m_ownerMonitorHandle{nullptr};
    HANDLE m_nextSurfaceAvailableEvent{nullptr}; // Owned by OS/IddCx; never closed by driver.
    ScopedWin32Handle m_stopEvent{};
    ScopedWin32Handle m_startGateEvent{};
    ScopedWin32Handle m_workerThread{};
    WorkerRunParams m_workerParams{};
    SwapChainMetricsSnapshot m_metrics{};
};

} // namespace lumabridge::driver
