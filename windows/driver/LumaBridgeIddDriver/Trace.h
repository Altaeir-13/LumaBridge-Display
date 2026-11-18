#pragma once

#include <stdio.h>
#include "AdapterStateMachine.h"

namespace lumabridge::driver {

/// Returns a concise ASCII name for an AdapterLifecycleState value.
inline const char*
AdapterLifecycleStateToString(
    AdapterLifecycleState state
    ) noexcept
{
    switch (state)
    {
    case AdapterLifecycleState::Uninitialized:
        return "Uninitialized";
    case AdapterLifecycleState::DeviceConfigured:
        return "DeviceConfigured";
    case AdapterLifecycleState::DeviceInitialized:
        return "DeviceInitialized";
    case AdapterLifecycleState::AdapterInitPending:
        return "AdapterInitPending";
    case AdapterLifecycleState::AdapterReady:
        return "AdapterReady";
    case AdapterLifecycleState::AdapterFailed:
        return "AdapterFailed";
    case AdapterLifecycleState::DeviceStopped:
        return "DeviceStopped";
    default:
        return "Unknown";
    }
}

/// Returns a concise ASCII name for a DriverDiagnosticStage value.
inline const char*
DriverDiagnosticStageToString(
    DriverDiagnosticStage stage
    ) noexcept
{
    switch (stage)
    {
    case DriverDiagnosticStage::None:
        return "None";
    case DriverDiagnosticStage::DriverEntry:
        return "DriverEntry";
    case DriverDiagnosticStage::DriverUnload:
        return "DriverUnload";
    case DriverDiagnosticStage::DeviceAdd:
        return "DeviceAdd";
    case DriverDiagnosticStage::DeviceInitConfig:
        return "DeviceInitConfig";
    case DriverDiagnosticStage::WdfDeviceCreate:
        return "WdfDeviceCreate";
    case DriverDiagnosticStage::IddCxDeviceInitialize:
        return "IddCxDeviceInitialize";
    case DriverDiagnosticStage::DeviceD0Entry:
        return "DeviceD0Entry";
    case DriverDiagnosticStage::AdapterInitAsync:
        return "AdapterInitAsync";
    case DriverDiagnosticStage::AdapterInitFinished:
        return "AdapterInitFinished";
    case DriverDiagnosticStage::AdapterCommitModes:
        return "AdapterCommitModes";
    case DriverDiagnosticStage::DeviceD0Exit:
        return "DeviceD0Exit";
    case DriverDiagnosticStage::AdapterContextCleanup:
        return "AdapterContextCleanup";
    case DriverDiagnosticStage::DeviceContextCleanup:
        return "DeviceContextCleanup";
    case DriverDiagnosticStage::MonitorParseDescription:
        return "MonitorParseDescription";
    case DriverDiagnosticStage::MonitorGetDefaultDescriptionModes:
        return "MonitorGetDefaultDescriptionModes";
    case DriverDiagnosticStage::MonitorQueryTargetModes:
        return "MonitorQueryTargetModes";
    case DriverDiagnosticStage::MonitorCreate:
        return "MonitorCreate";
    case DriverDiagnosticStage::MonitorArrival:
        return "MonitorArrival";
    case DriverDiagnosticStage::MonitorDeparture:
        return "MonitorDeparture";
    case DriverDiagnosticStage::MonitorContextCleanup:
        return "MonitorContextCleanup";
    case DriverDiagnosticStage::MonitorAssignSwapChain:
        return "MonitorAssignSwapChain";
    case DriverDiagnosticStage::MonitorUnassignSwapChain:
        return "MonitorUnassignSwapChain";
    case DriverDiagnosticStage::MonitorCallbackStub:
        return "MonitorCallbackStub";
    default:
        return "Unknown";
    }
}

/// Emits a structured UMDF diagnostic line using the [LB-DRIVER] log convention.
inline void
LumaBridgeTraceEmit(
    const char* level,
    DriverDiagnosticStage stage,
    NTSTATUS status,
    AdapterLifecycleState state,
    const char* message
    ) noexcept
{
    char buffer[256]{};
    _snprintf_s(
        buffer,
        sizeof(buffer),
        _TRUNCATE,
        "[LB-DRIVER] [%s] stage=%s status=0x%08lX state=%s msg=\"%s\"\n",
        (level != nullptr) ? level : "INFO",
        DriverDiagnosticStageToString(stage),
        static_cast<unsigned long>(status),
        AdapterLifecycleStateToString(state),
        (message != nullptr) ? message : "");
    OutputDebugStringA(buffer);
}

inline void
LumaBridgeTraceInfo(
    DriverDiagnosticStage stage,
    NTSTATUS status,
    AdapterLifecycleState state,
    const char* message
    ) noexcept
{
    LumaBridgeTraceEmit("INFO", stage, status, state, message);
}

inline void
LumaBridgeTraceWarn(
    DriverDiagnosticStage stage,
    NTSTATUS status,
    AdapterLifecycleState state,
    const char* message
    ) noexcept
{
    LumaBridgeTraceEmit("WARN", stage, status, state, message);
}

inline void
LumaBridgeTraceError(
    DriverDiagnosticStage stage,
    NTSTATUS status,
    AdapterLifecycleState state,
    const char* message
    ) noexcept
{
    LumaBridgeTraceEmit("ERROR", stage, status, state, message);
}

/// Emits a structured runtime metrics snapshot using the [LB-DRIVER] [METRICS] convention
/// without copying or storing any desktop pixel or visual surface contents.
inline void
LumaBridgeTraceMetrics(
    DriverDiagnosticStage stage,
    AdapterLifecycleState adapterState,
    const char* monitorStateName,
    unsigned long long monitorCreates,
    unsigned long long monitorArrivals,
    unsigned long long monitorDepartures,
    unsigned long long monitorDepartureFailures,
    const char* swapChainStateName,
    bool swapChainActive,
    unsigned long long swapChainsAssigned,
    unsigned long long swapChainsDeleted,
    unsigned long long framesAcquired,
    unsigned long long framesProcessed,
    unsigned long long framesDropped,
    double acquireFps,
    double processFps,
    unsigned long long lastFrameUs,
    unsigned long long avgFrameUs,
    unsigned long long maxFrameUs,
    unsigned long long dxgiDeviceRemovedErrors,
    unsigned long long transientErrors,
    unsigned long long fatalErrors,
    SIZE_T workingSetKb,
    SIZE_T privateUsageKb,
    DWORD handleCount
    ) noexcept
{
    char buffer[512]{};
    _snprintf_s(
        buffer,
        sizeof(buffer),
        _TRUNCATE,
        "[LB-DRIVER] [METRICS] stage=%s adapterState=%s monitorState=%s monCreate=%llu monArrive=%llu monDepart=%llu monDepartFail=%llu scState=%s scActive=%u scAssigned=%llu scDeleted=%llu framesAcq=%llu framesProc=%llu framesDrop=%llu acqFps=%.2f procFps=%.2f lastUs=%llu avgUs=%llu maxUs=%llu dxgiDevRem=%llu transientErr=%llu fatalErr=%llu wsKB=%llu privKB=%llu handles=%lu\n",
        DriverDiagnosticStageToString(stage),
        AdapterLifecycleStateToString(adapterState),
        (monitorStateName != nullptr) ? monitorStateName : "Unknown",
        monitorCreates,
        monitorArrivals,
        monitorDepartures,
        monitorDepartureFailures,
        (swapChainStateName != nullptr) ? swapChainStateName : "Unknown",
        swapChainActive ? 1U : 0U,
        swapChainsAssigned,
        swapChainsDeleted,
        framesAcquired,
        framesProcessed,
        framesDropped,
        acquireFps,
        processFps,
        lastFrameUs,
        avgFrameUs,
        maxFrameUs,
        dxgiDeviceRemovedErrors,
        transientErrors,
        fatalErrors,
        static_cast<unsigned long long>(workingSetKb),
        static_cast<unsigned long long>(privateUsageKb),
        static_cast<unsigned long>(handleCount));
    OutputDebugStringA(buffer);
}

} // namespace lumabridge::driver
