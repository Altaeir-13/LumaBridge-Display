#include "../LumaBridgeIddDriver/SwapChainProcessor.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <vector>

namespace {

int g_TestsRun = 0;
int g_TestsFailed = 0;

void
CheckCondition(
    bool condition,
    const char* expression,
    int line
    ) noexcept
{
    if (!condition)
    {
        ++g_TestsFailed;
        std::printf("[FAIL] line %d: %s\n", line, expression);
    }
}

#define EXPECT_TRUE(expr) CheckCondition((expr), #expr, __LINE__)
#define EXPECT_EQ(actual, expected) CheckCondition(((actual) == (expected)), #actual " == " #expected, __LINE__)

using namespace lumabridge::driver;

struct AcquireAction
{
    HRESULT Result{S_OK};
    SwapChainFrameMetadata Metadata{};
};

class MockSwapChainBackend final : public ISwapChainBackend
{
public:
    MockSwapChainBackend() noexcept
    {
        InitializeSRWLock(&m_lock);
        m_activityEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }

    ~MockSwapChainBackend() override
    {
        if (m_activityEvent != nullptr)
        {
            CloseHandle(m_activityEvent);
        }
    }

    void SetInitResult(HRESULT hr) noexcept
    {
        AcquireSRWLockExclusive(&m_lock);
        m_initResult = hr;
        ReleaseSRWLockExclusive(&m_lock);
    }

    void SetFinishResult(HRESULT hr) noexcept
    {
        AcquireSRWLockExclusive(&m_lock);
        m_finishResult = hr;
        ReleaseSRWLockExclusive(&m_lock);
    }

    void EnqueueAcquireAction(const AcquireAction& action)
    {
        AcquireSRWLockExclusive(&m_lock);
        m_actions.push_back(action);
        ReleaseSRWLockExclusive(&m_lock);
    }

    bool WaitForActivityCount(uint32_t targetCalls, DWORD timeoutMs = 3000) noexcept
    {
        const ULONGLONG deadline = GetTickCount64() + timeoutMs;
        for (;;)
        {
            AcquireSRWLockExclusive(&m_lock);
            const uint32_t current = m_totalBackendCalls;
            if (current >= targetCalls)
            {
                ReleaseSRWLockExclusive(&m_lock);
                return true;
            }
            ResetEvent(m_activityEvent);
            ReleaseSRWLockExclusive(&m_lock);

            const ULONGLONG now = GetTickCount64();
            if (now >= deadline)
            {
                return false;
            }
            const DWORD remaining = static_cast<DWORD>(deadline - now);
            (void)WaitForSingleObject(m_activityEvent, remaining);
        }
    }

    bool WaitForDeleteCount(uint32_t targetDeletes, DWORD timeoutMs = 3000) noexcept
    {
        const ULONGLONG deadline = GetTickCount64() + timeoutMs;
        for (;;)
        {
            AcquireSRWLockExclusive(&m_lock);
            const uint32_t current = static_cast<uint32_t>(m_deletedHandles.size());
            if (current >= targetDeletes)
            {
                ReleaseSRWLockExclusive(&m_lock);
                return true;
            }
            ResetEvent(m_activityEvent);
            ReleaseSRWLockExclusive(&m_lock);

            const ULONGLONG now = GetTickCount64();
            if (now >= deadline)
            {
                return false;
            }
            const DWORD remaining = static_cast<DWORD>(deadline - now);
            (void)WaitForSingleObject(m_activityEvent, remaining);
        }
    }

    HRESULT InitializeDeviceAndBindSwapChain(
        void* swapChainHandle,
        LUID renderAdapterLuid
        ) noexcept override
    {
        AcquireSRWLockExclusive(&m_lock);
        ++m_initCalls;
        ++m_totalBackendCalls;
        m_lastInitHandle = swapChainHandle;
        m_lastLuid = renderAdapterLuid;
        const HRESULT hr = m_initResult;
        SetEvent(m_activityEvent);
        ReleaseSRWLockExclusive(&m_lock);
        return hr;
    }

    HRESULT ReleaseAndAcquireBuffer(
        void* swapChainHandle,
        SwapChainFrameMetadata& outMetadata
        ) noexcept override
    {
        AcquireSRWLockExclusive(&m_lock);
        ++m_acquireCalls;
        ++m_totalBackendCalls;
        m_lastAcquireHandle = swapChainHandle;
        HRESULT hr = E_PENDING;
        if (!m_actions.empty())
        {
            const AcquireAction next = m_actions.front();
            m_actions.pop_front();
            hr = next.Result;
            outMetadata = next.Metadata;
        }
        SetEvent(m_activityEvent);
        ReleaseSRWLockExclusive(&m_lock);
        return hr;
    }

    HRESULT FinishProcessingFrame(
        void* swapChainHandle
        ) noexcept override
    {
        AcquireSRWLockExclusive(&m_lock);
        ++m_finishCalls;
        ++m_totalBackendCalls;
        m_lastFinishHandle = swapChainHandle;
        const HRESULT hr = m_finishResult;
        SetEvent(m_activityEvent);
        ReleaseSRWLockExclusive(&m_lock);
        return hr;
    }

    void DeleteSwapChainObject(
        void* swapChainHandle
        ) noexcept override
    {
        AcquireSRWLockExclusive(&m_lock);
        ++m_totalBackendCalls;
        m_deletedHandles.push_back(swapChainHandle);
        SetEvent(m_activityEvent);
        ReleaseSRWLockExclusive(&m_lock);
    }

    uint32_t InitCalls() noexcept
    {
        AcquireSRWLockExclusive(&m_lock);
        const uint32_t val = m_initCalls;
        ReleaseSRWLockExclusive(&m_lock);
        return val;
    }

    uint32_t AcquireCalls() noexcept
    {
        AcquireSRWLockExclusive(&m_lock);
        const uint32_t val = m_acquireCalls;
        ReleaseSRWLockExclusive(&m_lock);
        return val;
    }

    uint32_t FinishCalls() noexcept
    {
        AcquireSRWLockExclusive(&m_lock);
        const uint32_t val = m_finishCalls;
        ReleaseSRWLockExclusive(&m_lock);
        return val;
    }

    std::vector<void*> DeletedHandles()
    {
        AcquireSRWLockExclusive(&m_lock);
        const auto copy = m_deletedHandles;
        ReleaseSRWLockExclusive(&m_lock);
        return copy;
    }

    LUID LastLuid() noexcept
    {
        AcquireSRWLockExclusive(&m_lock);
        const LUID val = m_lastLuid;
        ReleaseSRWLockExclusive(&m_lock);
        return val;
    }

private:
    SRWLOCK m_lock{SRWLOCK_INIT};
    HANDLE m_activityEvent{nullptr};
    HRESULT m_initResult{S_OK};
    HRESULT m_finishResult{S_OK};
    std::deque<AcquireAction> m_actions{};
    uint32_t m_initCalls{0};
    uint32_t m_acquireCalls{0};
    uint32_t m_finishCalls{0};
    uint32_t m_totalBackendCalls{0};
    void* m_lastInitHandle{nullptr};
    void* m_lastAcquireHandle{nullptr};
    void* m_lastFinishHandle{nullptr};
    LUID m_lastLuid{0, 0};
    std::vector<void*> m_deletedHandles{};
};

SwapChainFrameMetadata
MakeValidFrameMeta(uint32_t frameNumber) noexcept
{
    SwapChainFrameMetadata meta{};
    meta.PresentationFrameNumber = frameNumber;
    meta.DirtyRectCount = 1;
    meta.MoveRegionCount = 0;
    meta.HwProtectedSurface = false;
    meta.PresentDisplayQPCTime = 1000ULL + frameNumber;
    meta.HasValidSurface = true;
    return meta;
}

void
TestAssignProcessFramesAndUnassignLifecycle()
{
    MockSwapChainBackend backend;
    SwapChainProcessor processor(&backend);
    ScopedWin32Handle surfaceEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    EXPECT_TRUE(surfaceEvent.IsValid());

    backend.EnqueueAcquireAction({S_OK, MakeValidFrameMeta(1)});
    backend.EnqueueAcquireAction({S_OK, MakeValidFrameMeta(2)});
    backend.EnqueueAcquireAction({E_PENDING, {}});

    void* const fakeSwapChain = reinterpret_cast<void*>(0x1001);
    const LUID expectedLuid{0x1234, 0x5678};

    const NTSTATUS assignStatus = processor.AssignSwapChain(
        fakeSwapChain,
        surfaceEvent.Get(),
        expectedLuid);
    EXPECT_EQ(assignStatus, STATUS_SUCCESS);
    EXPECT_TRUE(backend.WaitForActivityCount(6)); // 1 init + 3 acquire + 2 finish

    const auto midMetrics = processor.GetMetricsSnapshot();
    EXPECT_TRUE(midMetrics.IsActive);
    EXPECT_EQ(midMetrics.ActiveRenderAdapterLuid.LowPart, expectedLuid.LowPart);
    EXPECT_EQ(midMetrics.ActiveRenderAdapterLuid.HighPart, expectedLuid.HighPart);
    EXPECT_EQ(midMetrics.FramesAcquired, static_cast<uint64_t>(2));
    EXPECT_EQ(midMetrics.FramesProcessed, static_cast<uint64_t>(2));
    EXPECT_EQ(midMetrics.FramesDropped, static_cast<uint64_t>(0));
    EXPECT_EQ(midMetrics.LastPresentationFrameNumber, static_cast<uint32_t>(2));

    EXPECT_EQ(processor.UnassignSwapChain(), STATUS_SUCCESS);

    const auto endMetrics = processor.GetMetricsSnapshot();
    EXPECT_TRUE(!endMetrics.IsActive);
    EXPECT_EQ(endMetrics.AssignCount, static_cast<uint64_t>(1));
    EXPECT_EQ(endMetrics.UnassignCount, static_cast<uint64_t>(1));
    EXPECT_EQ(endMetrics.SwapChainDeletedCount, static_cast<uint64_t>(1));

    const auto deleted = backend.DeletedHandles();
    EXPECT_EQ(deleted.size(), static_cast<size_t>(1));
    EXPECT_EQ(deleted[0], fakeSwapChain);

    // Ensure OS-owned surfaceEvent handle was NOT closed by SwapChainProcessor.
    EXPECT_TRUE(WaitForSingleObject(surfaceEvent.Get(), 0) != WAIT_FAILED);
}

void
TestPendingAcquireWaitsOnSurfaceEventWithoutBusyWaiting()
{
    MockSwapChainBackend backend;
    SwapChainProcessor processor(&backend);
    ScopedWin32Handle surfaceEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    EXPECT_TRUE(surfaceEvent.IsValid());

    void* const fakeSwapChain = reinterpret_cast<void*>(0x2001);
    EXPECT_EQ(
        processor.AssignSwapChain(fakeSwapChain, surfaceEvent.Get(), LUID{1, 0}),
        STATUS_SUCCESS);

    // Wait for initial E_PENDING acquire (1 init + 1 acquire = 2).
    EXPECT_TRUE(backend.WaitForActivityCount(2));
    Sleep(40);
    // Worker must stay blocked on WaitForMultipleObjects rather than spinning acquire calls.
    EXPECT_EQ(backend.AcquireCalls(), static_cast<uint32_t>(1));

    // Enqueue a valid frame and signal hNextSurfaceAvailable.
    backend.EnqueueAcquireAction({S_OK, MakeValidFrameMeta(7)});
    EXPECT_TRUE(SetEvent(surfaceEvent.Get()) != FALSE);
    EXPECT_TRUE(backend.WaitForActivityCount(5)); // +1 acquire(S_OK) +1 finish +1 acquire(E_PENDING)

    const auto metrics = processor.GetMetricsSnapshot();
    EXPECT_EQ(metrics.FramesProcessed, static_cast<uint64_t>(1));
    EXPECT_EQ(metrics.LastPresentationFrameNumber, static_cast<uint32_t>(7));
    EXPECT_TRUE(metrics.EmptyAcquireWaits >= 1);

    EXPECT_EQ(processor.UnassignSwapChain(), STATUS_SUCCESS);
}

void
TestInitializationFailureAbandonsSwapChainAndDeletesHandleOnce()
{
    MockSwapChainBackend backend;
    backend.SetInitResult(DXGI_ERROR_UNSUPPORTED);
    SwapChainProcessor processor(&backend);
    ScopedWin32Handle surfaceEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    EXPECT_TRUE(surfaceEvent.IsValid());

    void* const fakeSwapChain = reinterpret_cast<void*>(0x3001);
    const NTSTATUS status = processor.AssignSwapChain(
        fakeSwapChain,
        surfaceEvent.Get(),
        LUID{9, 0});
    EXPECT_EQ(status, STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN);

    const auto metrics = processor.GetMetricsSnapshot();
    EXPECT_TRUE(!metrics.IsActive);
    EXPECT_EQ(metrics.FatalErrors, static_cast<uint64_t>(1));
    EXPECT_EQ(metrics.LastErrorHResult, DXGI_ERROR_UNSUPPORTED);
    EXPECT_EQ(metrics.SwapChainDeletedCount, static_cast<uint64_t>(1));
    EXPECT_EQ(backend.AcquireCalls(), static_cast<uint32_t>(0));

    const auto deleted = backend.DeletedHandles();
    EXPECT_EQ(deleted.size(), static_cast<size_t>(1));
    EXPECT_EQ(deleted[0], fakeSwapChain);
}

void
TestDeviceRemovedStopsWorkerAndRecordsMetric()
{
    MockSwapChainBackend backend;
    SwapChainProcessor processor(&backend);
    ScopedWin32Handle surfaceEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    EXPECT_TRUE(surfaceEvent.IsValid());

    backend.EnqueueAcquireAction({DXGI_ERROR_DEVICE_REMOVED, {}});

    void* const fakeSwapChain = reinterpret_cast<void*>(0x4001);
    EXPECT_EQ(
        processor.AssignSwapChain(fakeSwapChain, surfaceEvent.Get(), LUID{2, 0}),
        STATUS_SUCCESS);

    // Worker exits spontaneously and deletes swapchain handle in its epilogue.
    EXPECT_TRUE(backend.WaitForDeleteCount(1));

    const auto metrics = processor.GetMetricsSnapshot();
    EXPECT_TRUE(!metrics.IsActive);
    EXPECT_EQ(metrics.DeviceRemovedErrors, static_cast<uint64_t>(1));
    EXPECT_EQ(metrics.LastErrorHResult, DXGI_ERROR_DEVICE_REMOVED);
    EXPECT_EQ(metrics.SwapChainDeletedCount, static_cast<uint64_t>(1));

    // Subsequent UnassignSwapChain must succeed without deleting the handle a second time.
    EXPECT_EQ(processor.UnassignSwapChain(), STATUS_SUCCESS);
    EXPECT_EQ(backend.DeletedHandles().size(), static_cast<size_t>(1));
}

void
TestFinishFrameFailureStopsWorkerAndCountsDroppedFrame()
{
    MockSwapChainBackend backend;
    backend.SetFinishResult(E_FAIL);
    SwapChainProcessor processor(&backend);
    ScopedWin32Handle surfaceEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    EXPECT_TRUE(surfaceEvent.IsValid());

    backend.EnqueueAcquireAction({S_OK, MakeValidFrameMeta(3)});

    void* const fakeSwapChain = reinterpret_cast<void*>(0x5001);
    EXPECT_EQ(
        processor.AssignSwapChain(fakeSwapChain, surfaceEvent.Get(), LUID{3, 0}),
        STATUS_SUCCESS);

    EXPECT_TRUE(backend.WaitForDeleteCount(1));

    const auto metrics = processor.GetMetricsSnapshot();
    EXPECT_TRUE(!metrics.IsActive);
    EXPECT_EQ(metrics.FramesAcquired, static_cast<uint64_t>(1));
    EXPECT_EQ(metrics.FramesProcessed, static_cast<uint64_t>(0));
    EXPECT_EQ(metrics.FramesDropped, static_cast<uint64_t>(1));
    EXPECT_EQ(metrics.FatalErrors, static_cast<uint64_t>(1));
    EXPECT_EQ(metrics.LastErrorHResult, E_FAIL);
    EXPECT_EQ(metrics.SwapChainDeletedCount, static_cast<uint64_t>(1));
}

void
TestInvalidSurfaceCountsAsDroppedFrame()
{
    MockSwapChainBackend backend;
    SwapChainProcessor processor(&backend);
    ScopedWin32Handle surfaceEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    EXPECT_TRUE(surfaceEvent.IsValid());

    SwapChainFrameMetadata invalidMeta = MakeValidFrameMeta(11);
    invalidMeta.HasValidSurface = false;
    backend.EnqueueAcquireAction({S_OK, invalidMeta});

    void* const fakeSwapChain = reinterpret_cast<void*>(0x6001);
    EXPECT_EQ(
        processor.AssignSwapChain(fakeSwapChain, surfaceEvent.Get(), LUID{4, 0}),
        STATUS_SUCCESS);

    EXPECT_TRUE(backend.WaitForActivityCount(4)); // init + acquire(S_OK) + finish + acquire(E_PENDING)
    EXPECT_EQ(processor.UnassignSwapChain(), STATUS_SUCCESS);

    const auto metrics = processor.GetMetricsSnapshot();
    EXPECT_EQ(metrics.FramesAcquired, static_cast<uint64_t>(1));
    EXPECT_EQ(metrics.FramesProcessed, static_cast<uint64_t>(0));
    EXPECT_EQ(metrics.FramesDropped, static_cast<uint64_t>(1));
}

void
TestRepeatedAssignReplacesPreviousSwapChainCleanly()
{
    MockSwapChainBackend backend;
    SwapChainProcessor processor(&backend);
    ScopedWin32Handle surfaceEvent1(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    ScopedWin32Handle surfaceEvent2(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    EXPECT_TRUE(surfaceEvent1.IsValid());
    EXPECT_TRUE(surfaceEvent2.IsValid());

    void* const firstSwapChain = reinterpret_cast<void*>(0x7001);
    void* const secondSwapChain = reinterpret_cast<void*>(0x7002);

    backend.EnqueueAcquireAction({S_OK, MakeValidFrameMeta(1)});
    EXPECT_EQ(
        processor.AssignSwapChain(firstSwapChain, surfaceEvent1.Get(), LUID{10, 0}),
        STATUS_SUCCESS);
    EXPECT_TRUE(backend.WaitForActivityCount(3));

    backend.EnqueueAcquireAction({S_OK, MakeValidFrameMeta(2)});
    EXPECT_EQ(
        processor.AssignSwapChain(secondSwapChain, surfaceEvent2.Get(), LUID{20, 0}),
        STATUS_SUCCESS);
    EXPECT_TRUE(backend.WaitForActivityCount(6));

    const auto midMetrics = processor.GetMetricsSnapshot();
    EXPECT_TRUE(midMetrics.IsActive);
    EXPECT_EQ(midMetrics.ActiveRenderAdapterLuid.LowPart, static_cast<DWORD>(20));
    EXPECT_EQ(midMetrics.AssignCount, static_cast<uint64_t>(2));
    EXPECT_EQ(midMetrics.SwapChainDeletedCount, static_cast<uint64_t>(1));

    EXPECT_EQ(processor.UnassignSwapChain(), STATUS_SUCCESS);

    const auto deleted = backend.DeletedHandles();
    EXPECT_EQ(deleted.size(), static_cast<size_t>(2));
    EXPECT_EQ(deleted[0], firstSwapChain);
    EXPECT_EQ(deleted[1], secondSwapChain);
}

struct ConcurrentUnassignArgs
{
    SwapChainProcessor* Processor{nullptr};
    HANDLE StartGate{nullptr};
    std::atomic<uint32_t>* SuccessCount{nullptr};
};

DWORD WINAPI
ConcurrentUnassignWorker(LPVOID context) noexcept
{
    auto* args = static_cast<ConcurrentUnassignArgs*>(context);
    (void)WaitForSingleObject(args->StartGate, INFINITE);
    if (args->Processor->UnassignSwapChain() == STATUS_SUCCESS)
    {
        args->SuccessCount->fetch_add(1);
    }
    return 0;
}

void
TestConcurrentUnassignIsIdempotentAndFreeOfRaces()
{
    MockSwapChainBackend backend;
    SwapChainProcessor processor(&backend);
    ScopedWin32Handle surfaceEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    EXPECT_TRUE(surfaceEvent.IsValid());

    void* const fakeSwapChain = reinterpret_cast<void*>(0x8001);
    EXPECT_EQ(
        processor.AssignSwapChain(fakeSwapChain, surfaceEvent.Get(), LUID{5, 0}),
        STATUS_SUCCESS);
    EXPECT_TRUE(backend.WaitForActivityCount(2));

    ScopedWin32Handle startGate(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    EXPECT_TRUE(startGate.IsValid());

    std::atomic<uint32_t> successCount{0};
    ConcurrentUnassignArgs args{&processor, startGate.Get(), &successCount};

    HANDLE threads[4]{};
    for (int i = 0; i < 4; ++i)
    {
        threads[i] = CreateThread(nullptr, 0, &ConcurrentUnassignWorker, &args, 0, nullptr);
        EXPECT_TRUE(threads[i] != nullptr);
    }

    EXPECT_TRUE(SetEvent(startGate.Get()) != FALSE);
    EXPECT_EQ(WaitForMultipleObjects(4, threads, TRUE, 5000), WAIT_OBJECT_0);
    for (HANDLE thread : threads)
    {
        if (thread != nullptr)
        {
            CloseHandle(thread);
        }
    }

    EXPECT_EQ(successCount.load(), static_cast<uint32_t>(4));
    const auto metrics = processor.GetMetricsSnapshot();
    EXPECT_TRUE(!metrics.IsActive);
    EXPECT_EQ(metrics.SwapChainDeletedCount, static_cast<uint64_t>(1));
    EXPECT_EQ(backend.DeletedHandles().size(), static_cast<size_t>(1));
}

void
TestRejectsNullHandlesWithAbandonSwapChainStatus()
{
    MockSwapChainBackend backend;
    SwapChainProcessor processor(&backend);
    ScopedWin32Handle surfaceEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    EXPECT_TRUE(surfaceEvent.IsValid());

    // Null swapChainHandle: nothing to delete, abandon returned.
    EXPECT_EQ(
        processor.AssignSwapChain(nullptr, surfaceEvent.Get(), LUID{1, 0}),
        STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN);
    EXPECT_EQ(backend.DeletedHandles().size(), static_cast<size_t>(0));

    // Valid swapChainHandle with null surfaceEvent: swapChainHandle must be deleted once and abandoned.
    void* const fakeSwapChain = reinterpret_cast<void*>(0x9001);
    EXPECT_EQ(
        processor.AssignSwapChain(fakeSwapChain, nullptr, LUID{1, 0}),
        STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN);

    const auto deleted = backend.DeletedHandles();
    EXPECT_EQ(deleted.size(), static_cast<size_t>(1));
    EXPECT_EQ(deleted[0], fakeSwapChain);
}

template <typename Fn>
void
RunTest(
    const char* name,
    Fn fn
    )
{
    ++g_TestsRun;
    const int failuresBefore = g_TestsFailed;
    fn();
    if (g_TestsFailed == failuresBefore)
    {
        std::printf("[PASS] %s\n", name);
    }
    else
    {
        std::printf("[FAIL] %s\n", name);
    }
}

} // namespace

int
main()
{
    RunTest("AssignProcessFramesAndUnassignLifecycle", TestAssignProcessFramesAndUnassignLifecycle);
    RunTest("PendingAcquireWaitsOnSurfaceEventWithoutBusyWaiting", TestPendingAcquireWaitsOnSurfaceEventWithoutBusyWaiting);
    RunTest("InitializationFailureAbandonsSwapChainAndDeletesHandleOnce", TestInitializationFailureAbandonsSwapChainAndDeletesHandleOnce);
    RunTest("DeviceRemovedStopsWorkerAndRecordsMetric", TestDeviceRemovedStopsWorkerAndRecordsMetric);
    RunTest("FinishFrameFailureStopsWorkerAndCountsDroppedFrame", TestFinishFrameFailureStopsWorkerAndCountsDroppedFrame);
    RunTest("InvalidSurfaceCountsAsDroppedFrame", TestInvalidSurfaceCountsAsDroppedFrame);
    RunTest("RepeatedAssignReplacesPreviousSwapChainCleanly", TestRepeatedAssignReplacesPreviousSwapChainCleanly);
    RunTest("ConcurrentUnassignIsIdempotentAndFreeOfRaces", TestConcurrentUnassignIsIdempotentAndFreeOfRaces);
    RunTest("RejectsNullHandlesWithAbandonSwapChainStatus", TestRejectsNullHandlesWithAbandonSwapChainStatus);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
