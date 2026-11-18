#include "SwapChainProcessor.h"

namespace lumabridge::driver {

namespace {

class ExclusiveSrwLock final
{
public:
    explicit ExclusiveSrwLock(SRWLOCK* lock) noexcept
        : m_lock(lock)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockExclusive(m_lock);
        }
    }

    ~ExclusiveSrwLock()
    {
        if (m_lock != nullptr)
        {
            ReleaseSRWLockExclusive(m_lock);
        }
    }

    ExclusiveSrwLock(const ExclusiveSrwLock&) = delete;
    ExclusiveSrwLock& operator=(const ExclusiveSrwLock&) = delete;

private:
    SRWLOCK* m_lock;
};

class SharedSrwLock final
{
public:
    explicit SharedSrwLock(SRWLOCK* lock) noexcept
        : m_lock(lock)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockShared(m_lock);
        }
    }

    ~SharedSrwLock()
    {
        if (m_lock != nullptr)
        {
            ReleaseSRWLockShared(m_lock);
        }
    }

    SharedSrwLock(const SharedSrwLock&) = delete;
    SharedSrwLock& operator=(const SharedSrwLock&) = delete;

private:
    SRWLOCK* m_lock;
};

bool
IsDeviceRemovedOrResetError(
    HRESULT hr
    ) noexcept
{
    return hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET;
}

} // namespace

SwapChainProcessor::SwapChainProcessor(
    ISwapChainBackend* backend
    ) noexcept
    : m_backend(backend)
{
}

SwapChainProcessor::~SwapChainProcessor()
{
    (void)UnassignSwapChain();
}

NTSTATUS
SwapChainProcessor::AssignSwapChain(
    void* swapChainHandle,
    HANDLE nextSurfaceAvailableEvent,
    LUID renderAdapterLuid
    ) noexcept
{
    ExclusiveSrwLock lifecycleGuard(&m_lifecycleLock);

    // Ensure any previous swapchain and worker thread are completely torn down first.
    StopAndCleanupActiveSessionLocked();

    if (m_backend == nullptr ||
        swapChainHandle == nullptr ||
        nextSurfaceAvailableEvent == nullptr ||
        nextSurfaceAvailableEvent == INVALID_HANDLE_VALUE)
    {
        if (m_backend != nullptr && swapChainHandle != nullptr)
        {
            m_backend->DeleteSwapChainObject(swapChainHandle);
            ExclusiveSrwLock metricsGuard(&m_metricsLock);
            ++m_metrics.SwapChainDeletedCount;
        }
        RecordAssignmentErrorLocked(E_INVALIDARG);
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    const HRESULT initHr = m_backend->InitializeDeviceAndBindSwapChain(
        swapChainHandle,
        renderAdapterLuid);
    if (FAILED(initHr))
    {
        m_backend->DeleteSwapChainObject(swapChainHandle);
        {
            ExclusiveSrwLock metricsGuard(&m_metricsLock);
            ++m_metrics.SwapChainDeletedCount;
        }
        RecordAssignmentErrorLocked(initHr);
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    ScopedWin32Handle stopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stopEvent.IsValid())
    {
        const DWORD err = GetLastError();
        const HRESULT hr = (err != ERROR_SUCCESS) ? HRESULT_FROM_WIN32(err) : E_FAIL;
        m_backend->DeleteSwapChainObject(swapChainHandle);
        {
            ExclusiveSrwLock metricsGuard(&m_metricsLock);
            ++m_metrics.SwapChainDeletedCount;
        }
        RecordAssignmentErrorLocked(hr);
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    m_workerParams = WorkerRunParams{
        this,
        swapChainHandle,
        nextSurfaceAvailableEvent,
        stopEvent.Get()};

    m_activeSwapChain = swapChainHandle;
    m_nextSurfaceAvailableEvent = nextSurfaceAvailableEvent;
    m_stopEvent = static_cast<ScopedWin32Handle&&>(stopEvent);

    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        ++m_metrics.AssignCount;
        m_metrics.ActiveRenderAdapterLuid = renderAdapterLuid;
        m_metrics.IsActive = true;
    }

    ScopedWin32Handle workerThread(CreateThread(
        nullptr,
        0,
        &SwapChainProcessor::WorkerThreadProc,
        &m_workerParams,
        0,
        nullptr));
    if (!workerThread.IsValid())
    {
        const DWORD err = GetLastError();
        const HRESULT hr = (err != ERROR_SUCCESS) ? HRESULT_FROM_WIN32(err) : E_FAIL;
        StopAndCleanupActiveSessionLocked();
        RecordAssignmentErrorLocked(hr);
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    m_workerThread = static_cast<ScopedWin32Handle&&>(workerThread);
    return STATUS_SUCCESS;
}

NTSTATUS
SwapChainProcessor::UnassignSwapChain() noexcept
{
    ExclusiveSrwLock lifecycleGuard(&m_lifecycleLock);

    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        ++m_metrics.UnassignCount;
    }

    StopAndCleanupActiveSessionLocked();
    return STATUS_SUCCESS;
}

SwapChainMetricsSnapshot
SwapChainProcessor::GetMetricsSnapshot() const noexcept
{
    SharedSrwLock metricsGuard(&m_metricsLock);
    return m_metrics;
}

DWORD WINAPI
SwapChainProcessor::WorkerThreadProc(
    LPVOID context
    ) noexcept
{
    const auto* params = static_cast<const WorkerRunParams*>(context);
    if (params == nullptr || params->Processor == nullptr)
    {
        return ERROR_INVALID_PARAMETER;
    }

    params->Processor->WorkerLoop(
        params->SwapChainHandle,
        params->NextSurfaceAvailableEvent,
        params->StopEvent);
    return 0;
}

void
SwapChainProcessor::WorkerLoop(
    void* swapChainHandle,
    HANDLE nextSurfaceAvailableEvent,
    HANDLE stopEvent
    ) noexcept
{
    if (m_backend == nullptr ||
        swapChainHandle == nullptr ||
        nextSurfaceAvailableEvent == nullptr ||
        stopEvent == nullptr)
    {
        return;
    }

    const HANDLE waitHandles[2] = {nextSurfaceAvailableEvent, stopEvent};

    while (WaitForSingleObject(stopEvent, 0) != WAIT_OBJECT_0)
    {
        SwapChainFrameMetadata frameMeta{};
        const HRESULT acquireHr = m_backend->ReleaseAndAcquireBuffer(swapChainHandle, frameMeta);

        if (acquireHr == E_PENDING)
        {
            {
                ExclusiveSrwLock metricsGuard(&m_metricsLock);
                ++m_metrics.EmptyAcquireWaits;
            }

            const DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
            if (waitResult == WAIT_OBJECT_0)
            {
                // Re-check stopEvent explicitly in case both events were signaled simultaneously.
                if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
                {
                    break;
                }
                continue;
            }

            // Stop signaled (WAIT_OBJECT_0 + 1) or invalid handle wait failure.
            break;
        }

        if (FAILED(acquireHr))
        {
            ExclusiveSrwLock metricsGuard(&m_metricsLock);
            if (IsDeviceRemovedOrResetError(acquireHr))
            {
                ++m_metrics.DeviceRemovedErrors;
            }
            else
            {
                ++m_metrics.FatalErrors;
            }
            m_metrics.LastErrorHResult = acquireHr;
            break;
        }

        {
            ExclusiveSrwLock metricsGuard(&m_metricsLock);
            ++m_metrics.FramesAcquired;
            if (!frameMeta.HasValidSurface)
            {
                ++m_metrics.FramesDropped;
            }
        }

        const HRESULT finishHr = m_backend->FinishProcessingFrame(swapChainHandle);
        if (FAILED(finishHr))
        {
            ExclusiveSrwLock metricsGuard(&m_metricsLock);
            if (frameMeta.HasValidSurface)
            {
                ++m_metrics.FramesDropped;
            }
            if (IsDeviceRemovedOrResetError(finishHr))
            {
                ++m_metrics.DeviceRemovedErrors;
            }
            else
            {
                ++m_metrics.FatalErrors;
            }
            m_metrics.LastErrorHResult = finishHr;
            break;
        }

        if (frameMeta.HasValidSurface)
        {
            ExclusiveSrwLock metricsGuard(&m_metricsLock);
            ++m_metrics.FramesProcessed;
            m_metrics.LastPresentationFrameNumber = frameMeta.PresentationFrameNumber;
        }
    }

    // IddCx contract: delete the swapchain object when the worker exits (including spontaneous
    // errors such as DXGI_ERROR_DEVICE_REMOVED) so the OS is notified to re-evaluate/re-create.
    void* swapChainToDelete = nullptr;
    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        if (m_activeSwapChain == swapChainHandle)
        {
            swapChainToDelete = m_activeSwapChain;
            m_activeSwapChain = nullptr;
            m_metrics.IsActive = false;
            m_metrics.ActiveRenderAdapterLuid = LUID{0, 0};
            ++m_metrics.SwapChainDeletedCount;
        }
    }

    if (swapChainToDelete != nullptr)
    {
        m_backend->DeleteSwapChainObject(swapChainToDelete);
    }
}

void
SwapChainProcessor::StopAndCleanupActiveSessionLocked() noexcept
{
    if (m_stopEvent.IsValid())
    {
        (void)SetEvent(m_stopEvent.Get());
    }

    if (m_workerThread.IsValid())
    {
        (void)WaitForSingleObject(m_workerThread.Get(), INFINITE);
        m_workerThread.Reset();
    }

    m_stopEvent.Reset();

    void* swapChainToDelete = nullptr;
    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        if (m_activeSwapChain != nullptr)
        {
            swapChainToDelete = m_activeSwapChain;
            m_activeSwapChain = nullptr;
            if (m_backend != nullptr)
            {
                ++m_metrics.SwapChainDeletedCount;
            }
        }
        m_metrics.IsActive = false;
        m_metrics.ActiveRenderAdapterLuid = LUID{0, 0};
    }

    if (swapChainToDelete != nullptr && m_backend != nullptr)
    {
        m_backend->DeleteSwapChainObject(swapChainToDelete);
    }

    // Never close m_nextSurfaceAvailableEvent; it belongs to IddCx / OS.
    m_nextSurfaceAvailableEvent = nullptr;
}

void
SwapChainProcessor::RecordAssignmentErrorLocked(
    HRESULT hr
    ) noexcept
{
    ExclusiveSrwLock metricsGuard(&m_metricsLock);
    if (IsDeviceRemovedOrResetError(hr))
    {
        ++m_metrics.DeviceRemovedErrors;
    }
    else
    {
        ++m_metrics.FatalErrors;
    }
    m_metrics.LastErrorHResult = hr;
}

} // namespace lumabridge::driver
