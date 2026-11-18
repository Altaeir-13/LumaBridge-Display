#include "SwapChainProcessor.h"

namespace lumabridge::driver {

namespace {

class OwnedLifecycleLockGuard final
{
public:
    OwnedLifecycleLockGuard(SRWLOCK* lock, volatile LONG* ownerThreadId) noexcept
        : m_lock(lock), m_ownerThreadId(ownerThreadId)
    {
        if (m_lock != nullptr)
        {
            AcquireSRWLockExclusive(m_lock);
            if (m_ownerThreadId != nullptr)
            {
                InterlockedExchange(m_ownerThreadId, static_cast<LONG>(GetCurrentThreadId()));
            }
        }
    }

    ~OwnedLifecycleLockGuard()
    {
        if (m_ownerThreadId != nullptr)
        {
            InterlockedExchange(m_ownerThreadId, 0);
        }
        if (m_lock != nullptr)
        {
            ReleaseSRWLockExclusive(m_lock);
        }
    }

    OwnedLifecycleLockGuard(const OwnedLifecycleLockGuard&) = delete;
    OwnedLifecycleLockGuard& operator=(const OwnedLifecycleLockGuard&) = delete;

private:
    SRWLOCK* m_lock;
    volatile LONG* m_ownerThreadId;
};

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

bool
IsTransientFrameError(
    HRESULT hr
    ) noexcept
{
    return hr == DXGI_ERROR_WAS_STILL_DRAWING ||
           hr == HRESULT_FROM_WIN32(ERROR_BUSY);
}

HRESULT
LastWin32ErrorAsHResult() noexcept
{
    const DWORD err = GetLastError();
    return (err != ERROR_SUCCESS) ? HRESULT_FROM_WIN32(err) : E_FAIL;
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
    (void)Shutdown();
}

bool
SwapChainProcessor::IsReentrantLifecycleCall() const noexcept
{
    const LONG currentTid = static_cast<LONG>(GetCurrentThreadId());
    return InterlockedCompareExchange(const_cast<volatile LONG*>(&m_lifecycleLockOwnerThreadId), 0, 0) == currentTid ||
           InterlockedCompareExchange(const_cast<volatile LONG*>(&m_workerThreadId), 0, 0) == currentTid;
}

NTSTATUS
SwapChainProcessor::AssignSwapChain(
    void* swapChainHandle,
    HANDLE nextSurfaceAvailableEvent,
    LUID renderAdapterLuid,
    void* ownerMonitorHandle
    ) noexcept
{
    if (IsReentrantLifecycleCall() || InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0)
    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        ++m_metrics.AssignAttempts;
        ++m_metrics.AbandonedAssignCount;
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    OwnedLifecycleLockGuard lifecycleGuard(&m_lifecycleLock, &m_lifecycleLockOwnerThreadId);

    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        ++m_metrics.AssignAttempts;
    }

    // Ensure any previous swapchain and worker thread are completely torn down first.
    StopAndCleanupActiveSessionLocked();

    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0 ||
            m_metrics.State == SwapChainProcessorState::Stopping ||
            m_metrics.State == SwapChainProcessorState::Stopped)
        {
            m_metrics.State = SwapChainProcessorState::Stopped;
            ++m_metrics.AbandonedAssignCount;
            return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
        }

        if (m_metrics.State == SwapChainProcessorState::Suspended)
        {
            ++m_metrics.AbandonedAssignCount;
            return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
        }

        if (m_metrics.State == SwapChainProcessorState::Faulted ||
            m_metrics.ConsecutiveFailures >= kMaxConsecutiveSwapChainFailures)
        {
            m_metrics.State = SwapChainProcessorState::Faulted;
            ++m_metrics.AbandonedAssignCount;
            ++m_metrics.CircuitBreakerRejections;
            return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
        }
    }

    // Pre-ownership validation: IddCx retains ownership of swapChainHandle when
    // EvtIddCxMonitorAssignSwapChain returns STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN.
    if (m_backend == nullptr ||
        swapChainHandle == nullptr ||
        nextSurfaceAvailableEvent == nullptr ||
        nextSurfaceAvailableEvent == INVALID_HANDLE_VALUE)
    {
        RecordPreOwnershipFailureLocked(E_INVALIDARG, true);
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    const HRESULT initHr = m_backend->InitializeDeviceAndBindSwapChain(
        swapChainHandle,
        renderAdapterLuid);
    if (FAILED(initHr))
    {
        RecordPreOwnershipFailureLocked(initHr, true);
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    ScopedWin32Handle stopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stopEvent.IsValid())
    {
        RecordPreOwnershipFailureLocked(LastWin32ErrorAsHResult(), true);
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    ScopedWin32Handle startGateEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!startGateEvent.IsValid())
    {
        RecordPreOwnershipFailureLocked(LastWin32ErrorAsHResult(), true);
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    m_workerParams = WorkerRunParams{
        this,
        swapChainHandle,
        nextSurfaceAvailableEvent,
        stopEvent.Get(),
        startGateEvent.Get()};

    DWORD createdThreadId = 0;
    ScopedWin32Handle workerThread(CreateThread(
        nullptr,
        0,
        &SwapChainProcessor::WorkerThreadProc,
        &m_workerParams,
        0,
        &createdThreadId));
    if (!workerThread.IsValid())
    {
        m_workerParams = {};
        RecordPreOwnershipFailureLocked(LastWin32ErrorAsHResult(), true);
        return STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN;
    }

    // Ownership of swapChainHandle is now committed to SwapChainProcessor.
    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        m_activeSwapChain = swapChainHandle;
        m_ownerMonitorHandle = ownerMonitorHandle;
        m_nextSurfaceAvailableEvent = nextSurfaceAvailableEvent;
        m_stopEvent = static_cast<ScopedWin32Handle&&>(stopEvent);
        m_startGateEvent = static_cast<ScopedWin32Handle&&>(startGateEvent);
        m_workerThread = static_cast<ScopedWin32Handle&&>(workerThread);
        InterlockedExchange(&m_workerThreadId, static_cast<LONG>(createdThreadId));

        ++m_metrics.AssignCount;
        m_metrics.ActiveRenderAdapterLuid = renderAdapterLuid;
        m_metrics.IsActive = true;
        m_metrics.State = SwapChainProcessorState::Active;
    }

    if (SetEvent(m_startGateEvent.Get()) == FALSE)
    {
        const HRESULT hr = LastWin32ErrorAsHResult();
        StopAndCleanupActiveSessionLocked();
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        ++m_metrics.FatalErrors;
        m_metrics.LastErrorHResult = hr;
        return STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SwapChainProcessor::UnassignSwapChain() noexcept
{
    if (IsReentrantLifecycleCall())
    {
        // Reentrant call from inside DeleteSwapChainObject or worker thread:
        // signal cooperative stop if an active stop event exists without re-acquiring m_lifecycleLock.
        if (m_stopEvent.IsValid())
        {
            (void)SetEvent(m_stopEvent.Get());
        }
        return STATUS_SUCCESS;
    }

    OwnedLifecycleLockGuard lifecycleGuard(&m_lifecycleLock, &m_lifecycleLockOwnerThreadId);

    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        ++m_metrics.UnassignCount;
    }

    StopAndCleanupActiveSessionLocked();

    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0)
        {
            m_metrics.State = SwapChainProcessorState::Stopped;
        }
        else if (m_metrics.State == SwapChainProcessorState::Active)
        {
            m_metrics.State = SwapChainProcessorState::Ready;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SwapChainProcessor::UnassignSwapChainForMonitor(
    void* monitorHandle
    ) noexcept
{
    if (monitorHandle == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (IsReentrantLifecycleCall())
    {
        bool shouldSignalStop = false;
        {
            ExclusiveSrwLock metricsGuard(&m_metricsLock);
            if (m_activeSwapChain != nullptr)
            {
                if (m_ownerMonitorHandle == monitorHandle)
                {
                    shouldSignalStop = true;
                }
                else
                {
                    ++m_metrics.StaleMonitorUnassignIgnoredCount;
                }
            }
        }
        if (shouldSignalStop && m_stopEvent.IsValid())
        {
            (void)SetEvent(m_stopEvent.Get());
        }
        return STATUS_SUCCESS;
    }

    OwnedLifecycleLockGuard lifecycleGuard(&m_lifecycleLock, &m_lifecycleLockOwnerThreadId);

    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        if (m_activeSwapChain == nullptr)
        {
            return STATUS_SUCCESS;
        }
        if (m_ownerMonitorHandle != monitorHandle)
        {
            ++m_metrics.StaleMonitorUnassignIgnoredCount;
            return STATUS_SUCCESS;
        }
        ++m_metrics.UnassignCount;
    }

    StopAndCleanupActiveSessionLocked();

    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0)
        {
            m_metrics.State = SwapChainProcessorState::Stopped;
        }
        else if (m_metrics.State == SwapChainProcessorState::Active)
        {
            m_metrics.State = SwapChainProcessorState::Ready;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SwapChainProcessor::OnSuspend() noexcept
{
    if (IsReentrantLifecycleCall())
    {
        if (m_stopEvent.IsValid())
        {
            (void)SetEvent(m_stopEvent.Get());
        }
        return STATUS_SUCCESS;
    }

    OwnedLifecycleLockGuard lifecycleGuard(&m_lifecycleLock, &m_lifecycleLockOwnerThreadId);

    StopAndCleanupActiveSessionLocked();

    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0 ||
            m_metrics.State == SwapChainProcessorState::Stopping ||
            m_metrics.State == SwapChainProcessorState::Stopped)
        {
            m_metrics.State = SwapChainProcessorState::Stopped;
        }
        else
        {
            m_metrics.State = SwapChainProcessorState::Suspended;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SwapChainProcessor::OnResume() noexcept
{
    if (IsReentrantLifecycleCall())
    {
        return STATUS_SUCCESS;
    }

    OwnedLifecycleLockGuard lifecycleGuard(&m_lifecycleLock, &m_lifecycleLockOwnerThreadId);
    ExclusiveSrwLock metricsGuard(&m_metricsLock);

    if (InterlockedCompareExchange(&m_shutdownRequested, 0, 0) != 0 ||
        m_metrics.State == SwapChainProcessorState::Stopping ||
        m_metrics.State == SwapChainProcessorState::Stopped)
    {
        m_metrics.State = SwapChainProcessorState::Stopped;
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (m_metrics.State == SwapChainProcessorState::Suspended ||
        m_metrics.State == SwapChainProcessorState::Faulted ||
        m_metrics.State == SwapChainProcessorState::Ready)
    {
        m_metrics.ConsecutiveFailures = 0;
        m_metrics.State = SwapChainProcessorState::Ready;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SwapChainProcessor::Shutdown() noexcept
{
    InterlockedExchange(&m_shutdownRequested, 1);

    if (IsReentrantLifecycleCall())
    {
        if (m_stopEvent.IsValid())
        {
            (void)SetEvent(m_stopEvent.Get());
        }
        return STATUS_SUCCESS;
    }

    OwnedLifecycleLockGuard lifecycleGuard(&m_lifecycleLock, &m_lifecycleLockOwnerThreadId);

    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        m_metrics.State = SwapChainProcessorState::Stopping;
    }

    StopAndCleanupActiveSessionLocked();

    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        m_metrics.State = SwapChainProcessorState::Stopped;
    }

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
        params->StopEvent,
        params->StartGateEvent);
    return 0;
}

void
SwapChainProcessor::WorkerLoop(
    void* swapChainHandle,
    HANDLE nextSurfaceAvailableEvent,
    HANDLE stopEvent,
    HANDLE startGateEvent
    ) noexcept
{
    if (m_backend == nullptr ||
        swapChainHandle == nullptr ||
        nextSurfaceAvailableEvent == nullptr ||
        stopEvent == nullptr ||
        startGateEvent == nullptr)
    {
        return;
    }

    const HANDLE gateHandles[2] = {startGateEvent, stopEvent};
    const DWORD gateWait = WaitForMultipleObjects(2, gateHandles, FALSE, INFINITE);
    if (gateWait != WAIT_OBJECT_0)
    {
        if (gateWait == WAIT_FAILED)
        {
            RecordWaitOrSyncFailureLocked(LastWin32ErrorAsHResult());
        }
        return;
    }

    LARGE_INTEGER qpcFreqLi{};
    (void)QueryPerformanceFrequency(&qpcFreqLi);
    const uint64_t qpcFreq = (qpcFreqLi.QuadPart > 0) ? static_cast<uint64_t>(qpcFreqLi.QuadPart) : 10000000ULL;

    const HANDLE waitHandles[2] = {nextSurfaceAvailableEvent, stopEvent};
    uint32_t consecutiveTransientErrors = 0;
    bool processedAnyFrameInSession = false;
    bool exitedDueToPermanentFailure = false;
    bool windowInitialized = false;
    bool hasCompletedWindow = false;
    uint64_t windowStartQpc = 0;
    uint64_t windowAcquired = 0;
    uint64_t windowProcessed = 0;
    uint64_t timedFrames = 0;
    double latchedAcquireFps = 0.0;
    double latchedProcessFps = 0.0;

    for (;;)
    {
        const DWORD stopCheck = WaitForSingleObject(stopEvent, 0);
        if (stopCheck == WAIT_OBJECT_0)
        {
            break;
        }
        if (stopCheck == WAIT_FAILED)
        {
            RecordWaitOrSyncFailureLocked(LastWin32ErrorAsHResult());
            exitedDueToPermanentFailure = true;
            break;
        }

        LARGE_INTEGER frameStartQpcLi{};
        (void)QueryPerformanceCounter(&frameStartQpcLi);

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
                continue;
            }
            if (waitResult == WAIT_OBJECT_0 + 1)
            {
                break;
            }

            RecordWaitOrSyncFailureLocked(LastWin32ErrorAsHResult());
            exitedDueToPermanentFailure = true;
            break;
        }

        if (FAILED(acquireHr))
        {
            if (IsTransientFrameError(acquireHr))
            {
                ++consecutiveTransientErrors;
                {
                    ExclusiveSrwLock metricsGuard(&m_metricsLock);
                    ++m_metrics.TransientErrors;
                    m_metrics.LastErrorHResult = acquireHr;
                }

                if (consecutiveTransientErrors < kMaxConsecutiveTransientErrors)
                {
                    const DWORD backoffWait = WaitForSingleObject(stopEvent, kTransientRetryBackoffMs);
                    if (backoffWait == WAIT_TIMEOUT)
                    {
                        continue;
                    }
                    if (backoffWait == WAIT_OBJECT_0)
                    {
                        break;
                    }
                    RecordWaitOrSyncFailureLocked(LastWin32ErrorAsHResult());
                    exitedDueToPermanentFailure = true;
                    break;
                }
            }

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
            }
            exitedDueToPermanentFailure = true;
            break;
        }

        if (!windowInitialized)
        {
            windowStartQpc = static_cast<uint64_t>(frameStartQpcLi.QuadPart);
            windowInitialized = true;
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
            if (IsTransientFrameError(finishHr))
            {
                ++consecutiveTransientErrors;
                {
                    ExclusiveSrwLock metricsGuard(&m_metricsLock);
                    if (frameMeta.HasValidSurface)
                    {
                        ++m_metrics.FramesDropped;
                    }
                    ++m_metrics.TransientErrors;
                    m_metrics.LastErrorHResult = finishHr;
                }

                if (consecutiveTransientErrors < kMaxConsecutiveTransientErrors)
                {
                    const DWORD backoffWait = WaitForSingleObject(stopEvent, kTransientRetryBackoffMs);
                    if (backoffWait == WAIT_TIMEOUT)
                    {
                        continue;
                    }
                    if (backoffWait == WAIT_OBJECT_0)
                    {
                        break;
                    }
                    RecordWaitOrSyncFailureLocked(LastWin32ErrorAsHResult());
                    exitedDueToPermanentFailure = true;
                    break;
                }
            }

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
            }
            exitedDueToPermanentFailure = true;
            break;
        }

        LARGE_INTEGER frameEndQpcLi{};
        (void)QueryPerformanceCounter(&frameEndQpcLi);
        const uint64_t startQpc = static_cast<uint64_t>(frameStartQpcLi.QuadPart);
        const uint64_t endQpc = static_cast<uint64_t>(frameEndQpcLi.QuadPart);
        const uint64_t frameTicks = (endQpc >= startQpc) ? (endQpc - startQpc) : 0ULL;
        const uint64_t frameTimeUs = (frameTicks * 1000000ULL) / qpcFreq;

        ++timedFrames;
        ++windowAcquired;
        if (frameMeta.HasValidSurface)
        {
            ++windowProcessed;
            consecutiveTransientErrors = 0;
            processedAnyFrameInSession = true;
        }

        const uint64_t windowTicks = (endQpc > windowStartQpc) ? (endQpc - windowStartQpc) : 1ULL;
        const double elapsedSec = static_cast<double>(windowTicks) / static_cast<double>(qpcFreq);

        {
            ExclusiveSrwLock metricsGuard(&m_metricsLock);
            if (frameMeta.HasValidSurface)
            {
                ++m_metrics.FramesProcessed;
                m_metrics.ConsecutiveFailures = 0;
                m_metrics.LastPresentationFrameNumber = frameMeta.PresentationFrameNumber;
            }

            m_metrics.LastFrameProcessingTimeUs = frameTimeUs;
            m_metrics.TotalFrameProcessingTimeUs += frameTimeUs;
            if (frameTimeUs > m_metrics.MaxFrameProcessingTimeUs)
            {
                m_metrics.MaxFrameProcessingTimeUs = frameTimeUs;
            }
            m_metrics.AvgFrameProcessingTimeUs = m_metrics.TotalFrameProcessingTimeUs / timedFrames;

            if (elapsedSec >= 1.0)
            {
                latchedAcquireFps = static_cast<double>(windowAcquired) / elapsedSec;
                latchedProcessFps = static_cast<double>(windowProcessed) / elapsedSec;
                hasCompletedWindow = true;
                m_metrics.AcquireFps = latchedAcquireFps;
                m_metrics.ProcessFps = latchedProcessFps;
                windowStartQpc = endQpc;
                windowAcquired = 0;
                windowProcessed = 0;
            }
            else if (!hasCompletedWindow || elapsedSec >= 0.25)
            {
                m_metrics.AcquireFps = static_cast<double>(windowAcquired) / elapsedSec;
                m_metrics.ProcessFps = static_cast<double>(windowProcessed) / elapsedSec;
            }
            else
            {
                m_metrics.AcquireFps = latchedAcquireFps;
                m_metrics.ProcessFps = latchedProcessFps;
            }
        }
    }

    // IddCx contract: delete the owned swapchain object when the worker exits spontaneously
    // or during teardown, releasing it exactly once.
    void* swapChainToDelete = nullptr;
    {
        ExclusiveSrwLock metricsGuard(&m_metricsLock);
        if (m_activeSwapChain == swapChainHandle)
        {
            swapChainToDelete = m_activeSwapChain;
            m_activeSwapChain = nullptr;
            m_ownerMonitorHandle = nullptr;
            m_metrics.IsActive = false;
            m_metrics.ActiveRenderAdapterLuid = LUID{0, 0};
            ++m_metrics.SwapChainDeletedCount;

            if (exitedDueToPermanentFailure && !processedAnyFrameInSession)
            {
                ++m_metrics.ConsecutiveFailures;
            }

            if (m_metrics.State == SwapChainProcessorState::Active)
            {
                if (m_metrics.ConsecutiveFailures >= kMaxConsecutiveSwapChainFailures)
                {
                    m_metrics.State = SwapChainProcessorState::Faulted;
                }
                else
                {
                    m_metrics.State = SwapChainProcessorState::Ready;
                }
            }
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
        if (SetEvent(m_stopEvent.Get()) == FALSE)
        {
            RecordWaitOrSyncFailureLocked(LastWin32ErrorAsHResult());
        }
    }

    if (m_workerThread.IsValid())
    {
        const DWORD joinResult = WaitForSingleObject(m_workerThread.Get(), INFINITE);
        if (joinResult != WAIT_OBJECT_0)
        {
            // Thread termination was not confirmed: do NOT release shared event handles or
            // delete m_activeSwapChain while the thread may still be touching them.
            RecordWaitOrSyncFailureLocked(LastWin32ErrorAsHResult());
            return;
        }
        InterlockedExchange(&m_workerThreadId, 0);
        m_workerThread.Reset();
    }

    m_stopEvent.Reset();
    m_startGateEvent.Reset();

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
        m_ownerMonitorHandle = nullptr;
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
SwapChainProcessor::RecordPreOwnershipFailureLocked(
    HRESULT hr,
    bool countFailureAgainstBreaker
    ) noexcept
{
    ExclusiveSrwLock metricsGuard(&m_metricsLock);
    ++m_metrics.AbandonedAssignCount;
    if (IsDeviceRemovedOrResetError(hr))
    {
        ++m_metrics.DeviceRemovedErrors;
    }
    else
    {
        ++m_metrics.FatalErrors;
    }
    m_metrics.LastErrorHResult = hr;

    if (countFailureAgainstBreaker)
    {
        ++m_metrics.ConsecutiveFailures;
        if (m_metrics.ConsecutiveFailures >= kMaxConsecutiveSwapChainFailures &&
            m_metrics.State != SwapChainProcessorState::Stopping &&
            m_metrics.State != SwapChainProcessorState::Stopped &&
            m_metrics.State != SwapChainProcessorState::Suspended)
        {
            m_metrics.State = SwapChainProcessorState::Faulted;
        }
    }
}

void
SwapChainProcessor::RecordWaitOrSyncFailureLocked(
    HRESULT hr
    ) noexcept
{
    ExclusiveSrwLock metricsGuard(&m_metricsLock);
    ++m_metrics.FatalErrors;
    m_metrics.LastErrorHResult = hr;
}

} // namespace lumabridge::driver
