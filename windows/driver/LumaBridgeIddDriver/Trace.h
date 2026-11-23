#pragma once

#include <stdio.h>
#include "AdapterStateMachine.h"
#include "DiagnosticStageConfig.h"

#if defined(LUMABRIDGE_ENABLE_TRACELOGGING)
#pragma warning(push)
#pragma warning(disable : 4201)
#include <TraceLoggingProvider.h>
#pragma warning(pop)

TRACELOGGING_DECLARE_PROVIDER(g_LumaBridgeTraceProvider);
#endif

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

struct StageNameEntry
{
    DriverDiagnosticStage Stage;
    const char* Ascii;
    const wchar_t* Wide;
};

inline const StageNameEntry&
FindDiagnosticStageEntry(
    DriverDiagnosticStage stage
    ) noexcept
{
    static constexpr StageNameEntry kStageNames[] = {
        {DriverDiagnosticStage::None, "None", L"None"},
        {DriverDiagnosticStage::DriverEntry, "DriverEntry", L"DriverEntry"},
        {DriverDiagnosticStage::DriverUnload, "DriverUnload", L"DriverUnload"},
        {DriverDiagnosticStage::DeviceAdd, "DeviceAdd", L"DeviceAdd"},
        {DriverDiagnosticStage::DeviceInitConfig, "DeviceInitConfig", L"DeviceInitConfig"},
        {DriverDiagnosticStage::WdfDeviceCreate, "WdfDeviceCreate", L"WdfDeviceCreate"},
        {DriverDiagnosticStage::IddCxDeviceInitialize, "IddCxDeviceInitialize", L"IddCxDeviceInitialize"},
        {DriverDiagnosticStage::DeviceD0Entry, "DeviceD0Entry", L"DeviceD0Entry"},
        {DriverDiagnosticStage::AdapterInitAsync, "AdapterInitAsync", L"AdapterInitAsync"},
        {DriverDiagnosticStage::AdapterInitFinished, "AdapterInitFinished", L"AdapterInitFinished"},
        {DriverDiagnosticStage::AdapterCommitModes, "AdapterCommitModes", L"AdapterCommitModes"},
        {DriverDiagnosticStage::DeviceD0Exit, "DeviceD0Exit", L"DeviceD0Exit"},
        {DriverDiagnosticStage::AdapterContextCleanup, "AdapterContextCleanup", L"AdapterContextCleanup"},
        {DriverDiagnosticStage::DeviceContextCleanup, "DeviceContextCleanup", L"DeviceContextCleanup"},
        {DriverDiagnosticStage::MonitorParseDescription, "MonitorParseDescription", L"MonitorParseDescription"},
        {DriverDiagnosticStage::MonitorGetDefaultDescriptionModes, "MonitorGetDefaultDescriptionModes", L"MonitorGetDefaultDescriptionModes"},
        {DriverDiagnosticStage::MonitorQueryTargetModes, "MonitorQueryTargetModes", L"MonitorQueryTargetModes"},
        {DriverDiagnosticStage::MonitorCreate, "MonitorCreate", L"MonitorCreate"},
        {DriverDiagnosticStage::MonitorArrival, "MonitorArrival", L"MonitorArrival"},
        {DriverDiagnosticStage::MonitorDeparture, "MonitorDeparture", L"MonitorDeparture"},
        {DriverDiagnosticStage::MonitorContextCleanup, "MonitorContextCleanup", L"MonitorContextCleanup"},
        {DriverDiagnosticStage::MonitorAssignSwapChain, "MonitorAssignSwapChain", L"MonitorAssignSwapChain"},
        {DriverDiagnosticStage::MonitorUnassignSwapChain, "MonitorUnassignSwapChain", L"MonitorUnassignSwapChain"},
        {DriverDiagnosticStage::MonitorCallbackStub, "MonitorCallbackStub", L"MonitorCallbackStub"},
        {DriverDiagnosticStage::DllProcessAttach, "DllProcessAttach", L"DllProcessAttach"},
        {DriverDiagnosticStage::IddCxGetVersion, "IddCxGetVersion", L"IddCxGetVersion"},
        {DriverDiagnosticStage::WdfDeviceSetFailed, "WdfDeviceSetFailed", L"WdfDeviceSetFailed"},
    };
    static constexpr StageNameEntry kUnknownStage{DriverDiagnosticStage::None, "Unknown", L"Unknown"};

    for (const auto& entry : kStageNames)
    {
        if (entry.Stage == stage)
        {
            return entry;
        }
    }
    return kUnknownStage;
}

/// Returns a concise ASCII name for a DriverDiagnosticStage value.
inline const char*
DriverDiagnosticStageToString(
    DriverDiagnosticStage stage
    ) noexcept
{
    return FindDiagnosticStageEntry(stage).Ascii;
}

/// Returns a concise wide-string name for a DriverDiagnosticStage value.
inline const wchar_t*
DriverDiagnosticStageToWideString(
    DriverDiagnosticStage stage
    ) noexcept
{
    return FindDiagnosticStageEntry(stage).Wide;
}

#if defined(LUMABRIDGE_ENABLE_TRACELOGGING)
template <UCHAR TraceLevel>
inline void
LumaBridgeWriteStageEtwEvent(
    const char* safeLevel,
    DWORD processId,
    DWORD threadId,
    const char* safeStage,
    NTSTATUS status,
    const char* safeState,
    const char* safeLastOk,
    const char* safeMessage
    ) noexcept
{
    TraceLoggingWrite(
        g_LumaBridgeTraceProvider,
        "DriverStage",
        TraceLoggingLevel(TraceLevel),
        TraceLoggingString(safeLevel, "Level"),
        TraceLoggingUInt32(processId, "ProcessId"),
        TraceLoggingUInt32(threadId, "ThreadId"),
        TraceLoggingString(safeStage, "Stage"),
        TraceLoggingNTStatus(status, "Status"),
        TraceLoggingString(safeState, "LifecycleState"),
        TraceLoggingString(safeLastOk, "LastSuccessfulStage"),
        TraceLoggingString(safeMessage, "Message"));
}
#endif

/// Emits a structured UMDF diagnostic line using the [LB-DRIVER] log convention
/// and, when enabled, mirrors the stage event to ETW TraceLogging.
inline void
LumaBridgeTraceEmit(
    const char* level,
    DriverDiagnosticStage stage,
    NTSTATUS status,
    AdapterLifecycleState state,
    const char* message,
    DriverDiagnosticStage lastSuccessfulStage = DriverDiagnosticStage::None
    ) noexcept
{
    if constexpr (!GetDiagnosticStageCapabilities(kActiveDiagnosticStage).EnableTraceLoggingAndRegistryBreadcrumbs)
    {
        UNREFERENCED_PARAMETER(level);
        UNREFERENCED_PARAMETER(stage);
        UNREFERENCED_PARAMETER(status);
        UNREFERENCED_PARAMETER(state);
        UNREFERENCED_PARAMETER(message);
        UNREFERENCED_PARAMETER(lastSuccessfulStage);
    }
    else
    {
        const DWORD processId = GetCurrentProcessId();
        const DWORD threadId = GetCurrentThreadId();
        const char* safeLevel = (level != nullptr) ? level : "INFO";
        const char* safeStage = DriverDiagnosticStageToString(stage);
        const char* safeState = AdapterLifecycleStateToString(state);
        const char* safeLastOk = DriverDiagnosticStageToString(lastSuccessfulStage);
        const char* safeMessage = (message != nullptr) ? message : "";

        char buffer[512]{};
        _snprintf_s(
            buffer,
            sizeof(buffer),
            _TRUNCATE,
            "[LB-DRIVER] [%s] pid=%lu tid=%lu stage=%s status=0x%08lX state=%s lastOk=%s msg=\"%s\"\n",
            safeLevel,
            static_cast<unsigned long>(processId),
            static_cast<unsigned long>(threadId),
            safeStage,
            static_cast<unsigned long>(status),
            safeState,
            safeLastOk,
            safeMessage);
        OutputDebugStringA(buffer);

#if defined(LUMABRIDGE_ENABLE_TRACELOGGING)
        if (safeLevel[0] == 'E')
        {
            LumaBridgeWriteStageEtwEvent<2U>(
                safeLevel, processId, threadId, safeStage, status, safeState, safeLastOk, safeMessage);
        }
        else if (safeLevel[0] == 'W')
        {
            LumaBridgeWriteStageEtwEvent<3U>(
                safeLevel, processId, threadId, safeStage, status, safeState, safeLastOk, safeMessage);
        }
        else
        {
            LumaBridgeWriteStageEtwEvent<4U>(
                safeLevel, processId, threadId, safeStage, status, safeState, safeLastOk, safeMessage);
        }
#endif
    }
}

inline void
LumaBridgeTraceInfo(
    DriverDiagnosticStage stage,
    NTSTATUS status,
    AdapterLifecycleState state,
    const char* message,
    DriverDiagnosticStage lastSuccessfulStage = DriverDiagnosticStage::None
    ) noexcept
{
    LumaBridgeTraceEmit("INFO", stage, status, state, message, lastSuccessfulStage);
}

inline void
LumaBridgeTraceWarn(
    DriverDiagnosticStage stage,
    NTSTATUS status,
    AdapterLifecycleState state,
    const char* message,
    DriverDiagnosticStage lastSuccessfulStage = DriverDiagnosticStage::None
    ) noexcept
{
    LumaBridgeTraceEmit("WARN", stage, status, state, message, lastSuccessfulStage);
}

inline void
LumaBridgeTraceError(
    DriverDiagnosticStage stage,
    NTSTATUS status,
    AdapterLifecycleState state,
    const char* message,
    DriverDiagnosticStage lastSuccessfulStage = DriverDiagnosticStage::None
    ) noexcept
{
    LumaBridgeTraceEmit("ERROR", stage, status, state, message, lastSuccessfulStage);
}

/// Emits a structured runtime metrics snapshot using the [LB-DRIVER] [METRICS] convention
/// and TraceLogging without copying or storing any desktop pixel or visual surface contents.
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
    DWORD handleCount,
    bool frameExtractionEnabled = false,
    unsigned long long framesExtractionAccepted = 0ULL,
    unsigned long long framesCopied = 0ULL,
    unsigned long long framesDelivered = 0ULL,
    unsigned long long framesDroppedByBackpressure = 0ULL,
    unsigned long long protectedFramesRejected = 0ULL,
    unsigned long long frameCopyFailures = 0ULL,
    unsigned long long frameTransportFailures = 0ULL,
    unsigned long activeHostConnections = 0UL,
    unsigned long long lastFrameSequence = 0ULL,
    unsigned long long frameCopyLatencyUs = 0ULL,
    unsigned long long frameDeliveryLatencyUs = 0ULL,
    unsigned long queueDepth = 0UL,
    unsigned long peakQueueDepth = 0UL,
    HRESULT lastExtractionError = S_OK,
    HRESULT lastTransportError = S_OK,
    unsigned long long gpuFramesShared = 0ULL,
    unsigned long long gpuFramesDropped = 0ULL,
    unsigned long long gpuSyncWaitUs = 0ULL,
    unsigned long sharedPoolSize = 0UL,
    unsigned long sharedPoolPeakUsage = 0UL
    ) noexcept
{
    if constexpr (!GetDiagnosticStageCapabilities(kActiveDiagnosticStage).EnableTraceLoggingAndRegistryBreadcrumbs)
    {
        UNREFERENCED_PARAMETER(stage);
        UNREFERENCED_PARAMETER(adapterState);
        UNREFERENCED_PARAMETER(monitorStateName);
        UNREFERENCED_PARAMETER(monitorCreates);
        UNREFERENCED_PARAMETER(monitorArrivals);
        UNREFERENCED_PARAMETER(monitorDepartures);
        UNREFERENCED_PARAMETER(monitorDepartureFailures);
        UNREFERENCED_PARAMETER(swapChainStateName);
        UNREFERENCED_PARAMETER(swapChainActive);
        UNREFERENCED_PARAMETER(swapChainsAssigned);
        UNREFERENCED_PARAMETER(swapChainsDeleted);
        UNREFERENCED_PARAMETER(framesAcquired);
        UNREFERENCED_PARAMETER(framesProcessed);
        UNREFERENCED_PARAMETER(framesDropped);
        UNREFERENCED_PARAMETER(acquireFps);
        UNREFERENCED_PARAMETER(processFps);
        UNREFERENCED_PARAMETER(lastFrameUs);
        UNREFERENCED_PARAMETER(avgFrameUs);
        UNREFERENCED_PARAMETER(maxFrameUs);
        UNREFERENCED_PARAMETER(dxgiDeviceRemovedErrors);
        UNREFERENCED_PARAMETER(transientErrors);
        UNREFERENCED_PARAMETER(fatalErrors);
        UNREFERENCED_PARAMETER(workingSetKb);
        UNREFERENCED_PARAMETER(privateUsageKb);
        UNREFERENCED_PARAMETER(handleCount);
        UNREFERENCED_PARAMETER(frameExtractionEnabled);
        UNREFERENCED_PARAMETER(framesExtractionAccepted);
        UNREFERENCED_PARAMETER(framesCopied);
        UNREFERENCED_PARAMETER(framesDelivered);
        UNREFERENCED_PARAMETER(framesDroppedByBackpressure);
        UNREFERENCED_PARAMETER(protectedFramesRejected);
        UNREFERENCED_PARAMETER(frameCopyFailures);
        UNREFERENCED_PARAMETER(frameTransportFailures);
        UNREFERENCED_PARAMETER(activeHostConnections);
        UNREFERENCED_PARAMETER(lastFrameSequence);
        UNREFERENCED_PARAMETER(frameCopyLatencyUs);
        UNREFERENCED_PARAMETER(frameDeliveryLatencyUs);
        UNREFERENCED_PARAMETER(queueDepth);
        UNREFERENCED_PARAMETER(peakQueueDepth);
        UNREFERENCED_PARAMETER(lastExtractionError);
        UNREFERENCED_PARAMETER(lastTransportError);
        UNREFERENCED_PARAMETER(gpuFramesShared);
        UNREFERENCED_PARAMETER(gpuFramesDropped);
        UNREFERENCED_PARAMETER(gpuSyncWaitUs);
        UNREFERENCED_PARAMETER(sharedPoolSize);
        UNREFERENCED_PARAMETER(sharedPoolPeakUsage);
    }
    else
    {
        const char* safeStage = DriverDiagnosticStageToString(stage);
        const char* safeAdapterState = AdapterLifecycleStateToString(adapterState);
        const char* safeMonitorState = (monitorStateName != nullptr) ? monitorStateName : "Unknown";
        const char* safeSwapChainState = (swapChainStateName != nullptr) ? swapChainStateName : "Unknown";

        char buffer[1024]{};
        _snprintf_s(
            buffer,
            sizeof(buffer),
            _TRUNCATE,
            "[LB-DRIVER] [METRICS] stage=%s adapterState=%s monitorState=%s monCreate=%llu monArrive=%llu monDepart=%llu monDepartFail=%llu scState=%s scActive=%u scAssigned=%llu scDeleted=%llu framesAcq=%llu framesProc=%llu framesDrop=%llu acqFps=%.2f procFps=%.2f lastUs=%llu avgUs=%llu maxUs=%llu dxgiDevRem=%llu transientErr=%llu fatalErr=%llu extractEn=%u framesExtAcc=%llu framesCopy=%llu framesDeliv=%llu backpressDrop=%llu protRej=%llu copyFail=%llu ipcFail=%llu hostConn=%lu lastSeq=%llu copyUs=%llu delivUs=%llu qDepth=%lu peakQ=%lu extErr=0x%08lX ipcErr=0x%08lX gpuShr=%llu gpuDrop=%llu gpuSyncUs=%llu gpuPool=%lu/%lu wsKB=%llu privKB=%llu handles=%lu\n",
            safeStage,
            safeAdapterState,
            safeMonitorState,
            monitorCreates,
            monitorArrivals,
            monitorDepartures,
            monitorDepartureFailures,
            safeSwapChainState,
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
            frameExtractionEnabled ? 1U : 0U,
            framesExtractionAccepted,
            framesCopied,
            framesDelivered,
            framesDroppedByBackpressure,
            protectedFramesRejected,
            frameCopyFailures,
            frameTransportFailures,
            activeHostConnections,
            lastFrameSequence,
            frameCopyLatencyUs,
            frameDeliveryLatencyUs,
            queueDepth,
            peakQueueDepth,
            static_cast<unsigned long>(lastExtractionError),
            static_cast<unsigned long>(lastTransportError),
            gpuFramesShared,
            gpuFramesDropped,
            gpuSyncWaitUs,
            sharedPoolPeakUsage,
            sharedPoolSize,
            static_cast<unsigned long long>(workingSetKb),
            static_cast<unsigned long long>(privateUsageKb),
            static_cast<unsigned long>(handleCount));
        OutputDebugStringA(buffer);

#if defined(LUMABRIDGE_ENABLE_TRACELOGGING)
        TraceLoggingWrite(
            g_LumaBridgeTraceProvider,
            "DriverMetrics",
            TraceLoggingLevel(4U),
            TraceLoggingString(safeStage, "Stage"),
            TraceLoggingString(safeAdapterState, "AdapterState"),
            TraceLoggingString(safeMonitorState, "MonitorState"),
            TraceLoggingString(safeSwapChainState, "SwapChainState"),
            TraceLoggingBoolean(static_cast<BOOLEAN>(swapChainActive ? TRUE : FALSE), "SwapChainActive"),
            TraceLoggingUInt64(framesAcquired, "FramesAcquired"),
            TraceLoggingUInt64(framesProcessed, "FramesProcessed"),
            TraceLoggingUInt64(framesDropped, "FramesDropped"),
            TraceLoggingFloat64(acquireFps, "AcquireFps"),
            TraceLoggingFloat64(processFps, "ProcessFps"),
            TraceLoggingBoolean(static_cast<BOOLEAN>(frameExtractionEnabled ? TRUE : FALSE), "FrameExtractionEnabled"),
            TraceLoggingUInt64(framesExtractionAccepted, "FramesExtractionAccepted"),
            TraceLoggingUInt64(framesCopied, "FramesCopied"),
            TraceLoggingUInt64(framesDelivered, "FramesDelivered"),
            TraceLoggingUInt64(framesDroppedByBackpressure, "FramesDroppedByBackpressure"),
            TraceLoggingUInt64(protectedFramesRejected, "ProtectedFramesRejected"),
            TraceLoggingUInt64(frameCopyFailures, "FrameCopyFailures"),
            TraceLoggingUInt64(frameTransportFailures, "FrameTransportFailures"),
            TraceLoggingUInt32(activeHostConnections, "ActiveHostConnections"),
            TraceLoggingUInt64(lastFrameSequence, "LastFrameSequence"),
            TraceLoggingUInt64(frameCopyLatencyUs, "FrameCopyLatencyUs"),
            TraceLoggingUInt64(frameDeliveryLatencyUs, "FrameDeliveryLatencyUs"),
            TraceLoggingUInt32(queueDepth, "QueueDepth"),
            TraceLoggingUInt32(peakQueueDepth, "PeakQueueDepth"),
            TraceLoggingHResult(lastExtractionError, "LastExtractionError"),
            TraceLoggingHResult(lastTransportError, "LastTransportError"),
            TraceLoggingUInt64(gpuFramesShared, "GpuFramesShared"),
            TraceLoggingUInt64(gpuFramesDropped, "GpuFramesDropped"),
            TraceLoggingUInt64(gpuSyncWaitUs, "GpuSyncWaitUs"),
            TraceLoggingUInt32(sharedPoolSize, "SharedTexturePoolSize"),
            TraceLoggingUInt32(sharedPoolPeakUsage, "SharedTexturePoolPeakUsage"),
            TraceLoggingUInt64(static_cast<unsigned long long>(workingSetKb), "WorkingSetKb"),
            TraceLoggingUInt64(static_cast<unsigned long long>(privateUsageKb), "PrivateUsageKb"),
            TraceLoggingUInt32(handleCount, "HandleCount"));
#endif
    }
}

} // namespace lumabridge::driver
