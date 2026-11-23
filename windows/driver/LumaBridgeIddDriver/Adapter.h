#pragma once

#include "Driver.h"
#include "DiagnosticStageConfig.h"
#include "AdapterStateMachine.h"
#include "MonitorModes.h"
#include "SwapChainProcessor.h"
#include "Trace.h"
#include "VirtualMonitor.h"

namespace lumabridge::driver {

struct DeviceSwapChainHost;

inline constexpr UINT kMaxMonitorsSupported = 1;
inline constexpr DWORD kAdapterInitSlotWaitTimeoutMs = 5000;
inline constexpr bool kDefaultFrameExtractionEnabled = false;
inline constexpr UINT kEndpointMajorVersion = 1;
inline constexpr UINT kEndpointMinorVersion = 1;
inline constexpr UINT kEndpointBuildVersion = 0;

// Workaround for Windows 11 IddCx.dll (10.0.26100.9818) Validate(IDDCX_ADAPTER_CAPS)
// off-by-one check that rejects IDDCX_TRANSMISSION_TYPE_NETWORK_OTHER (9) with 0xC000000D.
inline constexpr IDDCX_TRANSMISSION_TYPE kAdapterTransmissionType = IDDCX_TRANSMISSION_TYPE_WIRED_OTHER;
static_assert(
    IsSupportedIddCxRuntimeTransmissionType(static_cast<uint32_t>(kAdapterTransmissionType)),
    "kAdapterTransmissionType must be accepted by IddCx.dll Validate(IDDCX_ADAPTER_CAPS).");

inline constexpr wchar_t kEndpointFriendlyName[] = L"LumaBridge Virtual Display Adapter";
inline constexpr wchar_t kEndpointModelName[] = L"LumaBridge Indirect Display";
inline constexpr wchar_t kEndpointManufacturerName[] = L"LumaBridge";

/// Per-WDFDEVICE state tracking the associated IddCx adapter and lifecycle status.
struct DeviceContext
{
    SRWLOCK StateLock{SRWLOCK_INIT};
    WDFDEVICE WdfDevice{nullptr};
    IDDCX_ADAPTER AdapterObject{nullptr};
    DeviceSwapChainHost* SwapChainHost{nullptr};
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

/// Per-IDDCX_MONITOR context linking back to the parent WDFDEVICE swapchain host.
struct MonitorContext
{
    WDFDEVICE WdfDevice{nullptr};
    UINT32 ConnectorIndex{0};
    bool IsCleanedUp{false};
};

} // namespace lumabridge::driver

using LumaBridgeDeviceContext = lumabridge::driver::DeviceContext;
using LumaBridgeAdapterContext = lumabridge::driver::AdapterContext;
using LumaBridgeMonitorContext = lumabridge::driver::MonitorContext;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LumaBridgeDeviceContext, LumaBridgeGetDeviceContext)
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LumaBridgeAdapterContext, LumaBridgeGetAdapterContext)
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LumaBridgeMonitorContext, LumaBridgeGetMonitorContext)

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
EVT_WDF_OBJECT_CONTEXT_CLEANUP LumaBridgeEvtMonitorContextCleanup;

EVT_IDD_CX_ADAPTER_INIT_FINISHED LumaBridgeEvtAdapterInitFinished;
EVT_IDD_CX_ADAPTER_COMMIT_MODES LumaBridgeEvtAdapterCommitModes;
EVT_IDD_CX_PARSE_MONITOR_DESCRIPTION LumaBridgeEvtParseMonitorDescription;
EVT_IDD_CX_MONITOR_GET_DEFAULT_DESCRIPTION_MODES LumaBridgeEvtMonitorGetDefaultDescriptionModes;
EVT_IDD_CX_MONITOR_QUERY_TARGET_MODES LumaBridgeEvtMonitorQueryTargetModes;
EVT_IDD_CX_MONITOR_ASSIGN_SWAPCHAIN LumaBridgeEvtMonitorAssignSwapChain;
EVT_IDD_CX_MONITOR_UNASSIGN_SWAPCHAIN LumaBridgeEvtMonitorUnassignSwapChain;
