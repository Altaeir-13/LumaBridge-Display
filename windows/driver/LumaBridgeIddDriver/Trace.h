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

} // namespace lumabridge::driver
