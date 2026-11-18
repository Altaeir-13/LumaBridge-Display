#include "../LumaBridgeIddDriver/VirtualMonitor.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <string>
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

class MockVirtualMonitorBackend final : public IVirtualMonitorBackend
{
public:
    NTSTATUS CreateStatus{STATUS_SUCCESS};
    NTSTATUS ArriveStatus{STATUS_SUCCESS};
    NTSTATUS DepartStatus{STATUS_SUCCESS};
    bool ReturnNullHandleOnCreate{false};
    LUID NextOsAdapterLuid{0x4444, 0x1};
    uint32_t NextOsTargetId{0x100};

    uint32_t CreateCalls{0};
    uint32_t ArriveCalls{0};
    uint32_t DepartCalls{0};
    uint32_t DeleteUnarrivedCalls{0};
    uint32_t StopSwapChainCalls{0};

    std::vector<uint32_t> SeenConnectors{};
    std::vector<GUID> SeenContainerIds{};
    std::vector<void*> DeletedUnarrivedHandles{};
    std::vector<void*> DepartedHandles{};
    std::vector<void*> StoppedSwapChainMonitorHandles{};
    std::vector<std::string> CallOrder{};

    std::function<void(void*)> OnCreateHook{};
    std::function<void(void*)> OnArriveHook{};
    std::function<void(void*)> OnDepartHook{};
    bool NegativeRefDetected{false};
    std::map<void*, int> HandleRefCounts{};

    int OutstandingRefCount() const noexcept
    {
        int total = 0;
        for (const auto& entry : HandleRefCounts)
        {
            total += entry.second;
        }
        return total;
    }

    NTSTATUS CreateMonitor(
        void* adapterHandle,
        uint32_t connectorIndex,
        const GUID& containerId,
        void*& outMonitorHandle
        ) noexcept override
    {
        ++CreateCalls;
        CallOrder.push_back("Create");
        SeenConnectors.push_back(connectorIndex);
        SeenContainerIds.push_back(containerId);
        if (!NT_SUCCESS(CreateStatus) || ReturnNullHandleOnCreate)
        {
            outMonitorHandle = nullptr;
            return CreateStatus;
        }

        m_nextHandleValue += 0x10;
        outMonitorHandle = reinterpret_cast<void*>(static_cast<uintptr_t>(m_nextHandleValue));
        HandleRefCounts[outMonitorHandle] += 1;
        if (OnCreateHook)
        {
            OnCreateHook(outMonitorHandle);
        }
        (void)adapterHandle;
        return STATUS_SUCCESS;
    }

    NTSTATUS ArriveMonitor(
        void* monitorHandle,
        LUID& outOsAdapterLuid,
        uint32_t& outOsTargetId
        ) noexcept override
    {
        ++ArriveCalls;
        CallOrder.push_back("Arrive");
        if (OnArriveHook)
        {
            OnArriveHook(monitorHandle);
        }
        if (!NT_SUCCESS(ArriveStatus))
        {
            return ArriveStatus;
        }
        outOsAdapterLuid = NextOsAdapterLuid;
        outOsTargetId = NextOsTargetId++;
        return STATUS_SUCCESS;
    }

    NTSTATUS DepartMonitor(
        void* monitorHandle
        ) noexcept override
    {
        ++DepartCalls;
        CallOrder.push_back("Depart");
        DepartedHandles.push_back(monitorHandle);
        if (OnDepartHook)
        {
            OnDepartHook(monitorHandle);
        }
        return DepartStatus;
    }

    void DeleteUnarrivedMonitorObject(
        void* monitorHandle
        ) noexcept override
    {
        ++DeleteUnarrivedCalls;
        CallOrder.push_back("DeleteUnarrived");
        DeletedUnarrivedHandles.push_back(monitorHandle);
    }

    void StopMonitorSwapChain(
        void* monitorHandle
        ) noexcept override
    {
        ++StopSwapChainCalls;
        CallOrder.push_back("StopSwapChain");
        StoppedSwapChainMonitorHandles.push_back(monitorHandle);
    }

    void AcquireMonitorReference(
        void* monitorHandle
        ) noexcept override
    {
        if (monitorHandle != nullptr)
        {
            HandleRefCounts[monitorHandle] += 1;
        }
    }

    void ReleaseMonitorReference(
        void* monitorHandle
        ) noexcept override
    {
        if (monitorHandle != nullptr)
        {
            int& ref = HandleRefCounts[monitorHandle];
            --ref;
            if (ref < 0)
            {
                NegativeRefDetected = true;
            }
        }
    }

private:
    uintptr_t m_nextHandleValue{0xA000};
};

bool
GuidsEqual(const GUID& lhs, const GUID& rhs) noexcept
{
    return std::memcmp(&lhs, &rhs, sizeof(GUID)) == 0;
}

void
TestDisabledByDefaultSkipsMonitorCreationAndArrival()
{
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager manager(&backend);

    EXPECT_TRUE(!manager.IsActivationEnabled());

    void* const fakeAdapter = reinterpret_cast<void*>(0x1111);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);

    const auto snap = manager.GetSnapshot();
    EXPECT_EQ(snap.State, VirtualMonitorState::NotCreated);
    EXPECT_TRUE(!snap.ActivationEnabled);
    EXPECT_TRUE(!snap.HasMonitorHandle);
    EXPECT_EQ(snap.SkippedDisabledCount, static_cast<uint64_t>(1));
    EXPECT_EQ(backend.CreateCalls, static_cast<uint32_t>(0));
    EXPECT_EQ(backend.ArriveCalls, static_cast<uint32_t>(0));
}

void
TestControlledActivationCreatesAndArrivesSingleMonitorWithPersistentIdentity()
{
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager manager(&backend);

    manager.SetActivationEnabled(true);
    EXPECT_TRUE(manager.IsActivationEnabled());

    void* const fakeAdapter = reinterpret_cast<void*>(0x1111);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);

    const auto snap = manager.GetSnapshot();
    EXPECT_EQ(snap.State, VirtualMonitorState::Arrived);
    EXPECT_TRUE(snap.HasMonitorHandle);
    EXPECT_EQ(snap.ConnectorIndex, kMvpVirtualMonitorConnectorIndex);
    EXPECT_TRUE(GuidsEqual(snap.ContainerId, kMvpVirtualMonitorContainerId));
    EXPECT_EQ(snap.OsAdapterLuid.LowPart, backend.NextOsAdapterLuid.LowPart);
    EXPECT_EQ(snap.OsAdapterLuid.HighPart, backend.NextOsAdapterLuid.HighPart);
    EXPECT_EQ(snap.OsTargetId, static_cast<uint32_t>(0x100));
    EXPECT_EQ(snap.CreateCount, static_cast<uint64_t>(1));
    EXPECT_EQ(snap.ArrivalCount, static_cast<uint64_t>(1));
    EXPECT_EQ(backend.CreateCalls, static_cast<uint32_t>(1));
    EXPECT_EQ(backend.ArriveCalls, static_cast<uint32_t>(1));
    EXPECT_EQ(backend.SeenConnectors[0], static_cast<uint32_t>(0));
    EXPECT_TRUE(GuidsEqual(backend.SeenContainerIds[0], kMvpVirtualMonitorContainerId));
}

void
TestDuplicateArrivalRequestIsPreventedWhileMonitorIsActive()
{
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager manager(&backend);
    manager.SetActivationEnabled(true);

    void* const fakeAdapter = reinterpret_cast<void*>(0x1111);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);

    const auto snap = manager.GetSnapshot();
    EXPECT_EQ(snap.State, VirtualMonitorState::Arrived);
    EXPECT_EQ(snap.CreateCount, static_cast<uint64_t>(1));
    EXPECT_EQ(snap.ArrivalCount, static_cast<uint64_t>(1));
    EXPECT_EQ(snap.DuplicateArrivalPreventedCount, static_cast<uint64_t>(1));
    EXPECT_EQ(backend.CreateCalls, static_cast<uint32_t>(1));
    EXPECT_EQ(backend.ArriveCalls, static_cast<uint32_t>(1));
}

void
TestCreateMonitorFailureTransitionsToFaultedWithoutOrphanHandle()
{
    MockVirtualMonitorBackend backend;
    backend.CreateStatus = STATUS_INSUFFICIENT_RESOURCES;
    VirtualMonitorManager manager(&backend);
    manager.SetActivationEnabled(true);

    void* const fakeAdapter = reinterpret_cast<void*>(0x1111);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_INSUFFICIENT_RESOURCES);

    const auto snap = manager.GetSnapshot();
    EXPECT_EQ(snap.State, VirtualMonitorState::Faulted);
    EXPECT_TRUE(!snap.HasMonitorHandle);
    EXPECT_EQ(snap.LastErrorStatus, STATUS_INSUFFICIENT_RESOURCES);
    EXPECT_EQ(snap.CreateCount, static_cast<uint64_t>(0));
    EXPECT_EQ(backend.ArriveCalls, static_cast<uint32_t>(0));
    EXPECT_EQ(backend.DeleteUnarrivedCalls, static_cast<uint32_t>(0));
}

void
TestPartialInitFailureOnArrivalDeletesUnarrivedMonitorObject()
{
    MockVirtualMonitorBackend backend;
    backend.ArriveStatus = STATUS_GRAPHICS_MONITOR_NOT_CONNECTED;
    VirtualMonitorManager manager(&backend);
    manager.SetActivationEnabled(true);

    void* const fakeAdapter = reinterpret_cast<void*>(0x1111);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_GRAPHICS_MONITOR_NOT_CONNECTED);

    const auto snap = manager.GetSnapshot();
    EXPECT_EQ(snap.State, VirtualMonitorState::Faulted);
    EXPECT_TRUE(!snap.HasMonitorHandle);
    EXPECT_EQ(snap.CreateCount, static_cast<uint64_t>(1));
    EXPECT_EQ(snap.ArrivalCount, static_cast<uint64_t>(0));
    EXPECT_EQ(snap.PartialInitFailures, static_cast<uint64_t>(1));
    EXPECT_EQ(snap.UnarrivedDeletions, static_cast<uint64_t>(1));
    EXPECT_EQ(snap.LastErrorStatus, STATUS_GRAPHICS_MONITOR_NOT_CONNECTED);
    EXPECT_EQ(backend.DeleteUnarrivedCalls, static_cast<uint32_t>(1));
    EXPECT_EQ(backend.DepartCalls, static_cast<uint32_t>(0));
}

void
TestSafeDepartureStopsSwapChainAndAllowsCleanRecreation()
{
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager manager(&backend);
    manager.SetActivationEnabled(true);

    void* const fakeAdapter = reinterpret_cast<void*>(0x1111);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);
    EXPECT_EQ(manager.DepartMonitor(), STATUS_SUCCESS);

    const auto departedSnap = manager.GetSnapshot();
    EXPECT_EQ(departedSnap.State, VirtualMonitorState::Departed);
    EXPECT_TRUE(!departedSnap.HasMonitorHandle);
    EXPECT_EQ(departedSnap.DepartureCount, static_cast<uint64_t>(1));
    EXPECT_EQ(departedSnap.OsTargetId, static_cast<uint32_t>(0));
    EXPECT_EQ(backend.StopSwapChainCalls, static_cast<uint32_t>(1));
    EXPECT_EQ(backend.DepartCalls, static_cast<uint32_t>(1));

    // Verify StopSwapChain runs before Depart.
    EXPECT_EQ(backend.CallOrder.size(), static_cast<size_t>(4));
    EXPECT_EQ(backend.CallOrder[2], std::string("StopSwapChain"));
    EXPECT_EQ(backend.CallOrder[3], std::string("Depart"));

    // Recreate after disconnection with same persistent ConnectorIndex and ContainerId.
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);
    const auto recreatedSnap = manager.GetSnapshot();
    EXPECT_EQ(recreatedSnap.State, VirtualMonitorState::Arrived);
    EXPECT_EQ(recreatedSnap.CreateCount, static_cast<uint64_t>(2));
    EXPECT_EQ(recreatedSnap.ArrivalCount, static_cast<uint64_t>(2));
    EXPECT_EQ(backend.SeenConnectors[1], kMvpVirtualMonitorConnectorIndex);
    EXPECT_TRUE(GuidsEqual(backend.SeenContainerIds[1], kMvpVirtualMonitorContainerId));
}

void
TestDepartureIsIdempotentWhenMonitorNotActive()
{
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager manager(&backend);

    EXPECT_EQ(manager.DepartMonitor(), STATUS_SUCCESS);
    EXPECT_EQ(manager.DepartMonitor(), STATUS_SUCCESS);
    EXPECT_EQ(backend.DepartCalls, static_cast<uint32_t>(0));
    EXPECT_EQ(backend.StopSwapChainCalls, static_cast<uint32_t>(0));
}

void
TestDisablingActivationAfterDeparturePreventsSubsequentArrival()
{
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager manager(&backend);
    manager.SetActivationEnabled(true);

    void* const fakeAdapter = reinterpret_cast<void*>(0x1111);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);
    EXPECT_EQ(manager.DepartMonitor(), STATUS_SUCCESS);

    manager.SetActivationEnabled(false);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);

    const auto snap = manager.GetSnapshot();
    EXPECT_EQ(snap.State, VirtualMonitorState::Departed);
    EXPECT_EQ(snap.ArrivalCount, static_cast<uint64_t>(1));
    EXPECT_EQ(snap.SkippedDisabledCount, static_cast<uint64_t>(1));
}

void
TestNotifyMonitorObjectCleanedUpResetsActiveHandleSafely()
{
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager manager(&backend);
    manager.SetActivationEnabled(true);

    void* const fakeAdapter = reinterpret_cast<void*>(0x1111);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);

    void* const activeHandle = reinterpret_cast<void*>(0xA010);
    // Unrelated handle does not clear active state.
    manager.NotifyMonitorObjectCleanedUp(reinterpret_cast<void*>(0xDEAD));
    EXPECT_TRUE(manager.GetSnapshot().HasMonitorHandle);

    // Matching handle clears handle and marks Departed; subsequent DepartMonitor is a safe no-op.
    manager.NotifyMonitorObjectCleanedUp(activeHandle);
    const auto snap = manager.GetSnapshot();
    EXPECT_TRUE(!snap.HasMonitorHandle);
    EXPECT_EQ(snap.State, VirtualMonitorState::Departed);
    EXPECT_EQ(manager.DepartMonitor(), STATUS_SUCCESS);
    EXPECT_EQ(backend.DepartCalls, static_cast<uint32_t>(0));
}

void
TestRejectsNullAdapterHandleWhenEnabled()
{
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager manager(&backend);
    manager.SetActivationEnabled(true);

    EXPECT_EQ(manager.EnsureMonitorArrived(nullptr), STATUS_INVALID_PARAMETER);
    EXPECT_EQ(manager.GetSnapshot().LastErrorStatus, STATUS_INVALID_PARAMETER);
    EXPECT_EQ(backend.CreateCalls, static_cast<uint32_t>(0));
}

void
TestFailedDeparturePreservesHandleBlocksRecreationAndRecovers()
{
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager manager(&backend);
    manager.SetActivationEnabled(true);

    void* const fakeAdapter = reinterpret_cast<void*>(0x1111);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);
    void* const firstHandle = manager.GetActiveMonitorHandle();
    EXPECT_TRUE(firstHandle != nullptr);

    // Failed IddCxMonitorDeparture must preserve m_monitorHandle and block duplicate creation.
    backend.DepartStatus = STATUS_UNSUCCESSFUL;
    EXPECT_EQ(manager.DepartMonitor(), STATUS_UNSUCCESSFUL);

    const auto failedSnap = manager.GetSnapshot();
    EXPECT_EQ(failedSnap.State, VirtualMonitorState::Faulted);
    EXPECT_TRUE(failedSnap.HasMonitorHandle);
    EXPECT_EQ(manager.GetActiveMonitorHandle(), firstHandle);
    EXPECT_EQ(failedSnap.DepartureFailures, static_cast<uint64_t>(1));
    EXPECT_EQ(failedSnap.LastDepartureStatus, STATUS_UNSUCCESSFUL);
    EXPECT_EQ(failedSnap.DepartureCount, static_cast<uint64_t>(0));

    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_DEVICE_BUSY);
    EXPECT_EQ(backend.CreateCalls, static_cast<uint32_t>(1));
    EXPECT_EQ(manager.GetSnapshot().UnconfirmedRemovalBlockedCount, static_cast<uint64_t>(1));

    // Retry succeeds -> clears handle and unlocks recreation.
    backend.DepartStatus = STATUS_SUCCESS;
    EXPECT_EQ(manager.DepartMonitor(), STATUS_SUCCESS);
    const auto recoveredSnap = manager.GetSnapshot();
    EXPECT_EQ(recoveredSnap.State, VirtualMonitorState::Departed);
    EXPECT_TRUE(!recoveredSnap.HasMonitorHandle);
    EXPECT_EQ(recoveredSnap.DepartureCount, static_cast<uint64_t>(1));
    EXPECT_EQ(recoveredSnap.LastDepartureStatus, STATUS_SUCCESS);
    EXPECT_TRUE(!backend.NegativeRefDetected);
    EXPECT_EQ(backend.OutstandingRefCount(), 0);

    // Recreate M2, fail DepartMonitor again, and recover via WDF NotifyMonitorObjectCleanedUp.
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);
    void* const secondHandle = manager.GetActiveMonitorHandle();
    EXPECT_TRUE(secondHandle != nullptr && secondHandle != firstHandle);

    backend.DepartStatus = STATUS_UNSUCCESSFUL;
    EXPECT_EQ(manager.DepartMonitor(), STATUS_UNSUCCESSFUL);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_DEVICE_BUSY);

    manager.NotifyMonitorObjectCleanedUp(secondHandle);
    const auto cleanedSnap = manager.GetSnapshot();
    EXPECT_EQ(cleanedSnap.State, VirtualMonitorState::Departed);
    EXPECT_TRUE(!cleanedSnap.HasMonitorHandle);
    EXPECT_TRUE(!backend.NegativeRefDetected);
    EXPECT_EQ(backend.OutstandingRefCount(), 0);

    // M3 can now be created cleanly.
    backend.DepartStatus = STATUS_SUCCESS;
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);
    EXPECT_EQ(manager.DepartMonitor(), STATUS_SUCCESS);
    EXPECT_EQ(backend.CreateCalls, static_cast<uint32_t>(3));
    EXPECT_TRUE(!backend.NegativeRefDetected);
    EXPECT_EQ(backend.OutstandingRefCount(), 0);
}

void
TestSuspendResumeAndLateCreateCancellation()
{
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager manager(&backend);
    manager.SetActivationEnabled(true);
    void* const fakeAdapter = reinterpret_cast<void*>(0x2222);

    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);
    EXPECT_EQ(manager.OnSuspend(), STATUS_SUCCESS);

    const auto suspendedSnap = manager.GetSnapshot();
    EXPECT_EQ(suspendedSnap.State, VirtualMonitorState::Suspended);
    EXPECT_TRUE(!suspendedSnap.HasMonitorHandle);

    // Suspended state blocks new creation.
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_INVALID_DEVICE_STATE);
    EXPECT_EQ(manager.GetSnapshot().LateCreateRejectedCount, static_cast<uint64_t>(1));
    EXPECT_EQ(backend.CreateCalls, static_cast<uint32_t>(1));

    // Resume restores normal creation.
    EXPECT_EQ(manager.OnResume(), STATUS_SUCCESS);
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);
    EXPECT_EQ(manager.GetSnapshot().State, VirtualMonitorState::Arrived);
    EXPECT_EQ(manager.DepartMonitor(), STATUS_SUCCESS);

    // Late Suspend racing inside CreateMonitor deletes unarrived handle without calling ArriveMonitor.
    backend.OnCreateHook = [&](void*) {
        (void)manager.OnSuspend();
    };
    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_INVALID_DEVICE_STATE);
    backend.OnCreateHook = nullptr;

    const auto postRaceSnap = manager.GetSnapshot();
    EXPECT_EQ(postRaceSnap.State, VirtualMonitorState::Suspended);
    EXPECT_TRUE(!postRaceSnap.HasMonitorHandle);
    EXPECT_EQ(backend.ArriveCalls, static_cast<uint32_t>(2));
    EXPECT_EQ(backend.DeleteUnarrivedCalls, static_cast<uint32_t>(1));
    EXPECT_EQ(postRaceSnap.LateCreateRejectedCount, static_cast<uint64_t>(2));
    EXPECT_TRUE(!backend.NegativeRefDetected);
    EXPECT_EQ(backend.OutstandingRefCount(), 0);
}

void
TestIrreversibleShutdownAndInFlightTeardownCancellation()
{
    void* const fakeAdapter = reinterpret_cast<void*>(0x3333);

    // Case A: Normal Shutdown permanently blocks OnResume and EnsureMonitorArrived.
    {
        MockVirtualMonitorBackend backend;
        VirtualMonitorManager manager(&backend);
        manager.SetActivationEnabled(true);

        EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);
        EXPECT_EQ(manager.Shutdown(), STATUS_SUCCESS);
        EXPECT_EQ(manager.GetSnapshot().State, VirtualMonitorState::Stopped);
        EXPECT_TRUE(!manager.GetSnapshot().HasMonitorHandle);
        EXPECT_EQ(manager.OnResume(), STATUS_INVALID_DEVICE_STATE);
        EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_INVALID_DEVICE_STATE);
        EXPECT_EQ(backend.CreateCalls, static_cast<uint32_t>(1));
        EXPECT_TRUE(!backend.NegativeRefDetected);
        EXPECT_EQ(backend.OutstandingRefCount(), 0);
    }

    // Case B: Shutdown triggered during ArriveMonitor immediately tears down arrived monitor.
    {
        MockVirtualMonitorBackend backend;
        VirtualMonitorManager manager(&backend);
        manager.SetActivationEnabled(true);

        backend.OnArriveHook = [&](void*) {
            (void)manager.Shutdown();
        };

        EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_INVALID_DEVICE_STATE);
        backend.OnArriveHook = nullptr;

        const auto snap = manager.GetSnapshot();
        EXPECT_EQ(snap.State, VirtualMonitorState::Stopped);
        EXPECT_TRUE(!snap.HasMonitorHandle);
        EXPECT_EQ(backend.StopSwapChainCalls, static_cast<uint32_t>(1));
        EXPECT_EQ(backend.DepartCalls, static_cast<uint32_t>(1));
        EXPECT_TRUE(!backend.NegativeRefDetected);
        EXPECT_EQ(backend.OutstandingRefCount(), 0);
    }
}

void
TestReentrantBackendCallbacksDoNotDeadlockOrLeakReferences()
{
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager manager(&backend);
    manager.SetActivationEnabled(true);
    void* const fakeAdapter = reinterpret_cast<void*>(0x4444);

    NTSTATUS reentrantEnsure = STATUS_SUCCESS;
    NTSTATUS reentrantDepart = STATUS_SUCCESS;
    void* observedHandle = nullptr;
    backend.OnArriveHook = [&](void* monitorHandle) {
        observedHandle = manager.GetActiveMonitorHandle();
        (void)manager.GetSnapshot();
        reentrantEnsure = manager.EnsureMonitorArrived(fakeAdapter);
        reentrantDepart = manager.DepartMonitor();
        EXPECT_EQ(observedHandle, monitorHandle);
    };

    EXPECT_EQ(manager.EnsureMonitorArrived(fakeAdapter), STATUS_SUCCESS);
    backend.OnArriveHook = nullptr;
    EXPECT_EQ(reentrantEnsure, STATUS_DEVICE_BUSY);
    EXPECT_EQ(reentrantDepart, STATUS_DEVICE_BUSY);

    // Reentrant NotifyMonitorObjectCleanedUp + DepartMonitor from inside DepartMonitor.
    NTSTATUS nestedDepart = STATUS_SUCCESS;
    backend.OnDepartHook = [&](void* monitorHandle) {
        manager.NotifyMonitorObjectCleanedUp(monitorHandle);
        nestedDepart = manager.DepartMonitor();
    };
    EXPECT_EQ(manager.DepartMonitor(), STATUS_SUCCESS);
    backend.OnDepartHook = nullptr;
    EXPECT_EQ(nestedDepart, STATUS_DEVICE_BUSY);
    EXPECT_TRUE(!manager.GetSnapshot().HasMonitorHandle);
    EXPECT_EQ(manager.GetSnapshot().State, VirtualMonitorState::Departed);
    EXPECT_TRUE(!backend.NegativeRefDetected);
    EXPECT_EQ(backend.OutstandingRefCount(), 0);
}

void
TestDerivedContainerIdsAreUniqueAndRfc4122ValidPerInstance()
{
    const GUID g00 = DeriveMonitorContainerId(0U, 0U);
    const GUID g10 = DeriveMonitorContainerId(1U, 0U);
    const GUID g20 = DeriveMonitorContainerId(2U, 0U);
    const GUID g01 = DeriveMonitorContainerId(0U, 1U);
    const GUID g11 = DeriveMonitorContainerId(1U, 1U);

    EXPECT_TRUE(GuidsEqual(g00, kMvpVirtualMonitorContainerId));
    EXPECT_TRUE(!GuidsEqual(g10, g00));
    EXPECT_TRUE(!GuidsEqual(g20, g00));
    EXPECT_TRUE(!GuidsEqual(g10, g20));
    EXPECT_TRUE(!GuidsEqual(g01, g00));
    EXPECT_TRUE(!GuidsEqual(g11, g10));

    // Deterministic across repeated derivation calls.
    EXPECT_TRUE(GuidsEqual(g10, DeriveMonitorContainerId(1U, 0U)));

    // RFC 4122 version 5 + variant 10xxxxxx validation.
    for (const GUID& g : {g10, g20, g01, g11})
    {
        EXPECT_EQ((g.Data3 & 0xF000U), static_cast<unsigned short>(0x5000U));
        EXPECT_EQ((g.Data4[0] & 0xC0U), static_cast<unsigned char>(0x80U));
    }

    // VirtualMonitorManager instance 1 passes its unique ContainerId to backend.
    MockVirtualMonitorBackend backend;
    VirtualMonitorManager managerInstance1(&backend, 1U);
    managerInstance1.SetActivationEnabled(true);
    EXPECT_EQ(managerInstance1.EnsureMonitorArrived(reinterpret_cast<void*>(0x5555)), STATUS_SUCCESS);
    EXPECT_TRUE(GuidsEqual(backend.SeenContainerIds[0], g10));
    EXPECT_TRUE(GuidsEqual(managerInstance1.GetSnapshot().ContainerId, g10));
    EXPECT_EQ(managerInstance1.DepartMonitor(), STATUS_SUCCESS);
    EXPECT_EQ(backend.OutstandingRefCount(), 0);
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
    RunTest("DisabledByDefaultSkipsMonitorCreationAndArrival", TestDisabledByDefaultSkipsMonitorCreationAndArrival);
    RunTest("ControlledActivationCreatesAndArrivesSingleMonitorWithPersistentIdentity", TestControlledActivationCreatesAndArrivesSingleMonitorWithPersistentIdentity);
    RunTest("DuplicateArrivalRequestIsPreventedWhileMonitorIsActive", TestDuplicateArrivalRequestIsPreventedWhileMonitorIsActive);
    RunTest("CreateMonitorFailureTransitionsToFaultedWithoutOrphanHandle", TestCreateMonitorFailureTransitionsToFaultedWithoutOrphanHandle);
    RunTest("PartialInitFailureOnArrivalDeletesUnarrivedMonitorObject", TestPartialInitFailureOnArrivalDeletesUnarrivedMonitorObject);
    RunTest("SafeDepartureStopsSwapChainAndAllowsCleanRecreation", TestSafeDepartureStopsSwapChainAndAllowsCleanRecreation);
    RunTest("DepartureIsIdempotentWhenMonitorNotActive", TestDepartureIsIdempotentWhenMonitorNotActive);
    RunTest("DisablingActivationAfterDeparturePreventsSubsequentArrival", TestDisablingActivationAfterDeparturePreventsSubsequentArrival);
    RunTest("NotifyMonitorObjectCleanedUpResetsActiveHandleSafely", TestNotifyMonitorObjectCleanedUpResetsActiveHandleSafely);
    RunTest("RejectsNullAdapterHandleWhenEnabled", TestRejectsNullAdapterHandleWhenEnabled);
    RunTest("FailedDeparturePreservesHandleBlocksRecreationAndRecovers", TestFailedDeparturePreservesHandleBlocksRecreationAndRecovers);
    RunTest("SuspendResumeAndLateCreateCancellation", TestSuspendResumeAndLateCreateCancellation);
    RunTest("IrreversibleShutdownAndInFlightTeardownCancellation", TestIrreversibleShutdownAndInFlightTeardownCancellation);
    RunTest("ReentrantBackendCallbacksDoNotDeadlockOrLeakReferences", TestReentrantBackendCallbacksDoNotDeadlockOrLeakReferences);
    RunTest("DerivedContainerIdsAreUniqueAndRfc4122ValidPerInstance", TestDerivedContainerIdsAreUniqueAndRfc4122ValidPerInstance);

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
