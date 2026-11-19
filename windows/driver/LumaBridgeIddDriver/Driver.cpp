#include "Driver.h"
#include "Adapter.h"

#if defined(LUMABRIDGE_ENABLE_TRACELOGGING)
TRACELOGGING_DEFINE_PROVIDER(
    g_LumaBridgeTraceProvider,
    "LumaBridgeIddDriver",
    (0xa7e4c910, 0x5b32, 0x4f8e, 0x9d, 0x21, 0x7c, 0x3a, 0x1b, 0x8e, 0x4f, 0x01));
#endif

namespace {

volatile LONG g_DllProcessAttachCount = 0;
HRESULT g_TraceLoggingRegisterHr = S_FALSE;
bool g_TraceLoggingRegistered = false;

} // namespace

using lumabridge::driver::AdapterLifecycleState;
using lumabridge::driver::DriverDiagnosticStage;
using lumabridge::driver::LumaBridgeTraceError;
using lumabridge::driver::LumaBridgeTraceInfo;

extern "C"
BOOL WINAPI
DllMain(
    _In_ HINSTANCE Instance,
    _In_ DWORD Reason,
    _In_opt_ LPVOID Reserved
    )
{
    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Reserved);

    // Strictly loader-lock-safe: avoid TraceLogging, OutputDebugString, or WDF calls inside DllMain.
    if (Reason == DLL_PROCESS_ATTACH)
    {
        InterlockedIncrement(&g_DllProcessAttachCount);
    }

    return TRUE;
}

ULONG
LumaBridgeGetDllProcessAttachCount() noexcept
{
    return static_cast<ULONG>(InterlockedCompareExchange(&g_DllProcessAttachCount, 0, 0));
}

HRESULT
LumaBridgeGetTraceLoggingRegisterResult() noexcept
{
    return g_TraceLoggingRegisterHr;
}

bool
LumaBridgeIsTraceLoggingEnabled() noexcept
{
#if defined(LUMABRIDGE_ENABLE_TRACELOGGING)
    return g_TraceLoggingRegistered && (TraceLoggingProviderEnabled(g_LumaBridgeTraceProvider, 0, 0) != FALSE);
#else
    return false;
#endif
}

extern "C"
_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    HRESULT tlRegHr = E_NOTIMPL;
    bool tlEnabled = false;
#if defined(LUMABRIDGE_ENABLE_TRACELOGGING)
    tlRegHr = TraceLoggingRegister(g_LumaBridgeTraceProvider);
    g_TraceLoggingRegisterHr = tlRegHr;
    g_TraceLoggingRegistered = SUCCEEDED(tlRegHr);
    tlEnabled = g_TraceLoggingRegistered && (TraceLoggingProviderEnabled(g_LumaBridgeTraceProvider, 0, 0) != FALSE);
#else
    g_TraceLoggingRegisterHr = tlRegHr;
    g_TraceLoggingRegistered = false;
#endif

    {
        char entryMsg[224]{};
        _snprintf_s(
            entryMsg,
            sizeof(entryMsg),
            _TRUNCATE,
            "DriverEntry entered (dllAttachCount=%lu tlRegHr=0x%08lX tlEnabled=%u)",
            static_cast<unsigned long>(LumaBridgeGetDllProcessAttachCount()),
            static_cast<unsigned long>(tlRegHr),
            tlEnabled ? 1U : 0U);
        LumaBridgeTraceInfo(
            DriverDiagnosticStage::DriverEntry,
            STATUS_SUCCESS,
            AdapterLifecycleState::Uninitialized,
            entryMsg,
            DriverDiagnosticStage::DllProcessAttach);
    }

    WDF_DRIVER_CONFIG config{};
    WDF_DRIVER_CONFIG_INIT(&config, LumaBridgeEvtDeviceAdd);
    config.EvtDriverUnload = LumaBridgeEvtDriverUnload;

    const NTSTATUS status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE);

    if (!NT_SUCCESS(status))
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::DriverEntry,
            status,
            AdapterLifecycleState::Uninitialized,
            "WdfDriverCreate failed",
            DriverDiagnosticStage::DllProcessAttach);
#if defined(LUMABRIDGE_ENABLE_TRACELOGGING)
        if (g_TraceLoggingRegistered)
        {
            TraceLoggingUnregister(g_LumaBridgeTraceProvider);
            g_TraceLoggingRegistered = false;
        }
#endif
        return status;
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::DriverEntry,
        status,
        AdapterLifecycleState::Uninitialized,
        "WdfDriverCreate succeeded",
        DriverDiagnosticStage::DriverEntry);
    return status;
}

_Use_decl_annotations_
VOID
LumaBridgeEvtDriverUnload(
    WDFDRIVER Driver
    )
{
    UNREFERENCED_PARAMETER(Driver);

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::DriverUnload,
        STATUS_SUCCESS,
        AdapterLifecycleState::Uninitialized,
        "Driver unloading");

#if defined(LUMABRIDGE_ENABLE_TRACELOGGING)
    if (g_TraceLoggingRegistered)
    {
        TraceLoggingUnregister(g_LumaBridgeTraceProvider);
        g_TraceLoggingRegistered = false;
    }
#endif
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtDeviceAdd(
    WDFDRIVER Driver,
    PWDFDEVICE_INIT DeviceInit
    )
{
    UNREFERENCED_PARAMETER(Driver);

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::DeviceAdd,
        STATUS_SUCCESS,
        AdapterLifecycleState::Uninitialized,
        "EvtDeviceAdd entered",
        DriverDiagnosticStage::DriverEntry);

    if (DeviceInit == nullptr)
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::DeviceAdd,
            STATUS_INVALID_PARAMETER,
            AdapterLifecycleState::Uninitialized,
            "EvtDeviceAdd received null DeviceInit",
            DriverDiagnosticStage::DriverEntry);
        return STATUS_INVALID_PARAMETER;
    }

    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks{};
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDeviceD0Entry = LumaBridgeEvtDeviceD0Entry;
    pnpPowerCallbacks.EvtDeviceD0Exit = LumaBridgeEvtDeviceD0Exit;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

    NTSTATUS status = LumaBridgeConfigureDeviceInit(DeviceInit);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::WdfDeviceCreate,
        STATUS_SUCCESS,
        AdapterLifecycleState::DeviceConfigured,
        "Calling WdfDeviceCreate",
        DriverDiagnosticStage::DeviceInitConfig);

    WDF_OBJECT_ATTRIBUTES deviceAttributes{};
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, LumaBridgeDeviceContext);
    deviceAttributes.EvtCleanupCallback = LumaBridgeEvtDeviceContextCleanup;

    WDFDEVICE device = nullptr;
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status))
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::WdfDeviceCreate,
            status,
            AdapterLifecycleState::DeviceConfigured,
            "WdfDeviceCreate failed",
            DriverDiagnosticStage::DeviceInitConfig);
        return status;
    }

    LumaBridgeTraceInfo(
        DriverDiagnosticStage::WdfDeviceCreate,
        status,
        AdapterLifecycleState::DeviceConfigured,
        "WdfDeviceCreate succeeded",
        DriverDiagnosticStage::WdfDeviceCreate);

    return LumaBridgeInitializeDeviceContext(device);
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtDeviceD0Entry(
    WDFDEVICE Device,
    WDF_POWER_DEVICE_STATE PreviousState
    )
{
    {
        char msg[160]{};
        _snprintf_s(
            msg,
            sizeof(msg),
            _TRUNCATE,
            "EvtDeviceD0Entry entered (previousPowerState=%d)",
            static_cast<int>(PreviousState));
        LumaBridgeTraceInfo(
            DriverDiagnosticStage::DeviceD0Entry,
            STATUS_SUCCESS,
            AdapterLifecycleState::DeviceInitialized,
            msg,
            DriverDiagnosticStage::IddCxDeviceInitialize);
    }

    const NTSTATUS status = LumaBridgeStartAdapter(Device);
    if (!NT_SUCCESS(status))
    {
        LumaBridgeTraceError(
            DriverDiagnosticStage::DeviceD0Entry,
            status,
            AdapterLifecycleState::AdapterFailed,
            "EvtDeviceD0Entry returning failure status from LumaBridgeStartAdapter",
            DriverDiagnosticStage::DeviceD0Entry);
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtDeviceD0Exit(
    WDFDEVICE Device,
    WDF_POWER_DEVICE_STATE TargetState
    )
{
    {
        char msg[160]{};
        _snprintf_s(
            msg,
            sizeof(msg),
            _TRUNCATE,
            "EvtDeviceD0Exit entered (targetPowerState=%d)",
            static_cast<int>(TargetState));
        LumaBridgeTraceInfo(
            DriverDiagnosticStage::DeviceD0Exit,
            STATUS_SUCCESS,
            AdapterLifecycleState::DeviceStopped,
            msg,
            DriverDiagnosticStage::DeviceD0Exit);
    }

    LumaBridgeStopAdapter(Device);
    return STATUS_SUCCESS;
}
