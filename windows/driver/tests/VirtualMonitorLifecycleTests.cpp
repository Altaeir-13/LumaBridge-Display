#include "../LumaBridgeIddDriver/VirtualMonitor.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
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
    std::vector<std::string> CallOrder{};

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
        if (!NT_SUCCESS(ArriveStatus))
        {
            return ArriveStatus;
        }
        outOsAdapterLuid = NextOsAdapterLuid;
        outOsTargetId = NextOsTargetId++;
        (void)monitorHandle;
        return STATUS_SUCCESS;
    }

    NTSTATUS DepartMonitor(
        void* monitorHandle
        ) noexcept override
    {
        ++DepartCalls;
        CallOrder.push_back("Depart");
        DepartedHandles.push_back(monitorHandle);
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
        (void)monitorHandle;
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

    std::printf("Summary: %d tests run, %d assertion failures.\n", g_TestsRun, g_TestsFailed);
    return (g_TestsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
