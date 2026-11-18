#pragma once

#include "Driver.h"
#include "AdapterStateMachine.h"
#include "Trace.h"

namespace lumabridge::driver {

inline constexpr UINT kMaxMonitorsSupported = 1;
inline constexpr UINT64 kMaxDisplayPipelineRate = 2560ULL * 1440ULL * 60ULL;
inline constexpr DWORD kAdapterInitSlotWaitTimeoutMs = 5000;
inline constexpr UINT kEndpointMajorVersion = 0;
inline constexpr UINT kEndpointMinorVersion = 1;
inline constexpr UINT kEndpointBuildVersion = 0;

inline constexpr wchar_t kEndpointFriendlyName[] = L"LumaBridge Virtual Display Adapter";
inline constexpr wchar_t kEndpointModelName[] = L"LumaBridge Indirect Display";
inline constexpr wchar_t kEndpointManufacturerName[] = L"LumaBridge";

/// Per-WDFDEVICE state tracking the associated IddCx adapter and lifecycle status.
struct DeviceContext
{
    SRWLOCK StateLock{SRWLOCK_INIT};
    WDFDEVICE WdfDevice{nullptr};
    IDDCX_ADAPTER AdapterObject{nullptr};
    ULONG IddCxRuntimeVersion{0};
    bool IsCleanedUp{false};
    AdapterLifecycleTracker Lifecycle{};
};

/// Per-IDDCX_ADAPTER context linking back to the parent WDFDEVICE.
struct AdapterContext
{
    WDFDEVICE WdfDevice{nullptr};
    IDDCX_ADAPTER AdapterObject{nullptr};
    bool IsCleanedUp{false};
    bool HasBoundDevice{false};
};

} // namespace lumabridge::driver

using LumaBridgeDeviceContext = lumabridge::driver::DeviceContext;
using LumaBridgeAdapterContext = lumabridge::driver::AdapterContext;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LumaBridgeDeviceContext, LumaBridgeGetDeviceContext)
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LumaBridgeAdapterContext, LumaBridgeGetAdapterContext)

/// Configures WDFDEVICE_INIT with IddCx callbacks prior to WdfDeviceCreate.
_Must_inspect_result_
NTSTATUS
LumaBridgeConfigureDeviceInit(
    _Inout_ PWDFDEVICE_INIT DeviceInit
    );

/// Initializes the DeviceContext and registers the WDFDEVICE with IddCx.
_Must_inspect_result_
NTSTATUS
LumaBridgeInitializeDeviceContext(
    _In_ WDFDEVICE Device
    );

/// Starts asynchronous indirect display adapter initialization on D0 entry.
_Must_inspect_result_
NTSTATUS
LumaBridgeStartAdapter(
    _In_ WDFDEVICE Device
    );

/// Transitions adapter lifecycle state when the device leaves D0.
VOID
LumaBridgeStopAdapter(
    _In_ WDFDEVICE Device
    );

EVT_WDF_OBJECT_CONTEXT_CLEANUP LumaBridgeEvtDeviceContextCleanup;
EVT_WDF_OBJECT_CONTEXT_CLEANUP LumaBridgeEvtAdapterContextCleanup;

EVT_IDD_CX_ADAPTER_INIT_FINISHED LumaBridgeEvtAdapterInitFinished;
EVT_IDD_CX_ADAPTER_COMMIT_MODES LumaBridgeEvtAdapterCommitModes;
EVT_IDD_CX_PARSE_MONITOR_DESCRIPTION LumaBridgeEvtParseMonitorDescription;
EVT_IDD_CX_MONITOR_GET_DEFAULT_DESCRIPTION_MODES LumaBridgeEvtMonitorGetDefaultDescriptionModes;
EVT_IDD_CX_MONITOR_QUERY_TARGET_MODES LumaBridgeEvtMonitorQueryTargetModes;
EVT_IDD_CX_MONITOR_ASSIGN_SWAPCHAIN LumaBridgeEvtMonitorAssignSwapChain;
EVT_IDD_CX_MONITOR_UNASSIGN_SWAPCHAIN LumaBridgeEvtMonitorUnassignSwapChain;
