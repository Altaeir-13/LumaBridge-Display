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

/// Per-frame metadata extracted from IDDCX_METADATA without copying desktop pixel contents.
struct SwapChainFrameMetadata
{
    uint32_t PresentationFrameNumber{0};
    uint32_t DirtyRectCount{0};
    uint32_t MoveRegionCount{0};
    bool HwProtectedSurface{false};
    uint64_t PresentDisplayQPCTime{0};
    bool HasValidSurface{false};
};

/// Atomic/synchronized snapshot of swapchain lifecycle and frame-processing metrics.
struct SwapChainMetricsSnapshot
{
    uint64_t FramesAcquired{0};
    uint64_t FramesProcessed{0};
    uint64_t FramesDropped{0};
    uint64_t EmptyAcquireWaits{0};
    uint64_t DeviceRemovedErrors{0};
    uint64_t FatalErrors{0};
    uint64_t AssignCount{0};
    uint64_t UnassignCount{0};
    uint64_t SwapChainDeletedCount{0};
    uint32_t LastPresentationFrameNumber{0};
    HRESULT LastErrorHResult{S_OK};
    LUID ActiveRenderAdapterLuid{0, 0};
    bool IsActive{false};
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

    /// Deletes the driver-owned WDF/IddCx swapchain object exactly once after worker exit.
    virtual void DeleteSwapChainObject(
        void* swapChainHandle
        ) noexcept = 0;
};

/// RAII wrapper for driver-owned Win32 handles (e.g., internal stop event and worker thread).
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
    /// Replaces any previously active swapchain cleanly. On failure, deletes driver-owned
    /// swapChainHandle (if non-null) and returns STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN.
    NTSTATUS AssignSwapChain(
        void* swapChainHandle,
        HANDLE nextSurfaceAvailableEvent,
        LUID renderAdapterLuid
        ) noexcept;

    /// Cooperatively stops the worker thread, joins it, and deletes the active swapchain once.
    /// Idempotent and safe under concurrent calls.
    NTSTATUS UnassignSwapChain() noexcept;

    /// Returns a thread-safe snapshot of swapchain processing metrics.
    SwapChainMetricsSnapshot GetMetricsSnapshot() const noexcept;

private:
    struct WorkerRunParams
    {
        SwapChainProcessor* Processor{nullptr};
        void* SwapChainHandle{nullptr};
        HANDLE NextSurfaceAvailableEvent{nullptr};
        HANDLE StopEvent{nullptr};
    };

    static DWORD WINAPI WorkerThreadProc(LPVOID context) noexcept;

    void WorkerLoop(
        void* swapChainHandle,
        HANDLE nextSurfaceAvailableEvent,
        HANDLE stopEvent
        ) noexcept;

    void StopAndCleanupActiveSessionLocked() noexcept;
    void RecordAssignmentErrorLocked(HRESULT hr) noexcept;

    ISwapChainBackend* m_backend{nullptr};

    SRWLOCK m_lifecycleLock{SRWLOCK_INIT};
    mutable SRWLOCK m_metricsLock{SRWLOCK_INIT};

    void* m_activeSwapChain{nullptr};
    HANDLE m_nextSurfaceAvailableEvent{nullptr}; // Owned by OS/IddCx; never closed by driver.
    ScopedWin32Handle m_stopEvent{};
    ScopedWin32Handle m_workerThread{};
    WorkerRunParams m_workerParams{};
    SwapChainMetricsSnapshot m_metrics{};
};

} // namespace lumabridge::driver
