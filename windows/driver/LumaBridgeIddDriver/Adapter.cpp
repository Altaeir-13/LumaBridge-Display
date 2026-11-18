#include "Adapter.h"

#include <new>

using lumabridge::driver::AdapterLifecycleState;

_Use_decl_annotations_
NTSTATUS
LumaBridgeConfigureDeviceInit(
    PWDFDEVICE_INIT DeviceInit
    )
{
    if (DeviceInit == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    IDD_CX_CLIENT_CONFIG iddConfig{};
    IDD_CX_CLIENT_CONFIG_INIT(&iddConfig);

    iddConfig.EvtIddCxAdapterInitFinished = LumaBridgeEvtAdapterInitFinished;
    iddConfig.EvtIddCxAdapterCommitModes = LumaBridgeEvtAdapterCommitModes;
    iddConfig.EvtIddCxParseMonitorDescription = LumaBridgeEvtParseMonitorDescription;
    iddConfig.EvtIddCxMonitorGetDefaultDescriptionModes = LumaBridgeEvtMonitorGetDefaultDescriptionModes;
    iddConfig.EvtIddCxMonitorQueryTargetModes = LumaBridgeEvtMonitorQueryTargetModes;
    iddConfig.EvtIddCxMonitorAssignSwapChain = LumaBridgeEvtMonitorAssignSwapChain;
    iddConfig.EvtIddCxMonitorUnassignSwapChain = LumaBridgeEvtMonitorUnassignSwapChain;

    return IddCxDeviceInitConfig(DeviceInit, &iddConfig);
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeInitializeDeviceContext(
    WDFDEVICE Device
    )
{
    if (Device == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    auto* deviceContext = LumaBridgeGetDeviceContext(Device);
    if (deviceContext == nullptr)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    new (deviceContext) LumaBridgeDeviceContext{};
    deviceContext->WdfDevice = Device;
    deviceContext->State = AdapterLifecycleState::DeviceConfigured;

    const NTSTATUS status = IddCxDeviceInitialize(Device);
    if (!NT_SUCCESS(status))
    {
        deviceContext->State = AdapterLifecycleState::AdapterFailed;
        deviceContext->LastAdapterInitStatus = status;
        return status;
    }

    deviceContext->State = AdapterLifecycleState::DeviceInitialized;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeStartAdapter(
    WDFDEVICE Device
    )
{
    if (Device == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    auto* deviceContext = LumaBridgeGetDeviceContext(Device);
    if (deviceContext == nullptr)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // D0 entry can occur multiple times across power transitions; keep adapter creation idempotent.
    if (deviceContext->AdapterObject != nullptr)
    {
        if (deviceContext->State == AdapterLifecycleState::DeviceStopped &&
            NT_SUCCESS(deviceContext->LastAdapterInitStatus))
        {
            deviceContext->State = AdapterLifecycleState::AdapterReady;
        }
        return STATUS_SUCCESS;
    }

    IDARG_OUT_GETVERSION versionOut{};
    if (NT_SUCCESS(IddCxGetVersion(&versionOut)))
    {
        deviceContext->IddCxRuntimeVersion = versionOut.IddCxVersion;
    }

    IDDCX_ENDPOINT_VERSION endpointVersion{};
    endpointVersion.Size = IDD_STRUCTURE_SIZE(IDDCX_ENDPOINT_VERSION);
    endpointVersion.MajorVer = lumabridge::driver::kEndpointMajorVersion;
    endpointVersion.MinorVer = lumabridge::driver::kEndpointMinorVersion;
    endpointVersion.Build = lumabridge::driver::kEndpointBuildVersion;
    endpointVersion.SKU = 0;

    IDDCX_ENDPOINT_VERSION firmwareVersion = endpointVersion;

    IDDCX_ADAPTER_CAPS adapterCaps{};
    adapterCaps.Size = IDD_STRUCTURE_SIZE(IDDCX_ADAPTER_CAPS);
    adapterCaps.Flags = IDDCX_ADAPTER_FLAGS_NONE;
    adapterCaps.MaxDisplayPipelineRate = lumabridge::driver::kMaxDisplayPipelineRate;
    adapterCaps.MaxMonitorsSupported = lumabridge::driver::kMaxMonitorsSupported;
    adapterCaps.EndPointDiagnostics.Size = IDD_STRUCTURE_SIZE(IDDCX_ENDPOINT_DIAGNOSTIC_INFO);
    adapterCaps.EndPointDiagnostics.TransmissionType = IDDCX_TRANSMISSION_TYPE_NETWORK_OTHER;
    adapterCaps.EndPointDiagnostics.pEndPointFriendlyName = lumabridge::driver::kEndpointFriendlyName;
    adapterCaps.EndPointDiagnostics.pEndPointModelName = lumabridge::driver::kEndpointModelName;
    adapterCaps.EndPointDiagnostics.pEndPointManufacturerName = lumabridge::driver::kEndpointManufacturerName;
    adapterCaps.EndPointDiagnostics.pHardwareVersion = &endpointVersion;
    adapterCaps.EndPointDiagnostics.pFirmwareVersion = &firmwareVersion;
    adapterCaps.EndPointDiagnostics.GammaSupport = IDDCX_FEATURE_IMPLEMENTATION_NONE;
    adapterCaps.StaticDesktopReencodeFrameCount = 0;

    WDF_OBJECT_ATTRIBUTES adapterAttributes{};
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&adapterAttributes, LumaBridgeAdapterContext);
    adapterAttributes.EvtCleanupCallback = LumaBridgeEvtAdapterContextCleanup;

    IDARG_IN_ADAPTER_INIT adapterInitIn{};
    adapterInitIn.WdfDevice = Device;
    adapterInitIn.pCaps = &adapterCaps;
    adapterInitIn.ObjectAttributes = &adapterAttributes;

    IDARG_OUT_ADAPTER_INIT adapterInitOut{};
    deviceContext->State = AdapterLifecycleState::AdapterInitPending;
    deviceContext->LastAdapterInitStatus = STATUS_PENDING;

    const NTSTATUS status = IddCxAdapterInitAsync(&adapterInitIn, &adapterInitOut);
    if (!NT_SUCCESS(status) || adapterInitOut.AdapterObject == nullptr)
    {
        const NTSTATUS failureStatus = NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
        deviceContext->State = AdapterLifecycleState::AdapterFailed;
        deviceContext->LastAdapterInitStatus = failureStatus;
        return failureStatus;
    }

    deviceContext->AdapterObject = adapterInitOut.AdapterObject;

    auto* adapterContext = LumaBridgeGetAdapterContext(adapterInitOut.AdapterObject);
    if (adapterContext == nullptr)
    {
        deviceContext->State = AdapterLifecycleState::AdapterFailed;
        deviceContext->LastAdapterInitStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_INVALID_DEVICE_STATE;
    }

    new (adapterContext) LumaBridgeAdapterContext{};
    adapterContext->WdfDevice = Device;
    adapterContext->AdapterObject = adapterInitOut.AdapterObject;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
LumaBridgeStopAdapter(
    WDFDEVICE Device
    )
{
    if (Device == nullptr)
    {
        return;
    }

    auto* deviceContext = LumaBridgeGetDeviceContext(Device);
    if (deviceContext == nullptr)
    {
        return;
    }

    deviceContext->State = AdapterLifecycleState::DeviceStopped;
}

_Use_decl_annotations_
VOID
LumaBridgeEvtDeviceContextCleanup(
    WDFOBJECT Object
    )
{
    if (Object == nullptr)
    {
        return;
    }

    auto* deviceContext = LumaBridgeGetDeviceContext(Object);
    if (deviceContext == nullptr)
    {
        return;
    }

    deviceContext->AdapterObject = nullptr;
    deviceContext->WdfDevice = nullptr;
    deviceContext->State = AdapterLifecycleState::Uninitialized;
}

_Use_decl_annotations_
VOID
LumaBridgeEvtAdapterContextCleanup(
    WDFOBJECT Object
    )
{
    if (Object == nullptr)
    {
        return;
    }

    auto* adapterContext = LumaBridgeGetAdapterContext(Object);
    if (adapterContext == nullptr)
    {
        return;
    }

    if (adapterContext->WdfDevice != nullptr)
    {
        auto* deviceContext = LumaBridgeGetDeviceContext(adapterContext->WdfDevice);
        if (deviceContext != nullptr && deviceContext->AdapterObject == adapterContext->AdapterObject)
        {
            deviceContext->AdapterObject = nullptr;
        }
    }

    adapterContext->AdapterObject = nullptr;
    adapterContext->WdfDevice = nullptr;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtAdapterInitFinished(
    IDDCX_ADAPTER AdapterObject,
    const IDARG_IN_ADAPTER_INIT_FINISHED* pInArgs
    )
{
    if (AdapterObject == nullptr || pInArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    auto* adapterContext = LumaBridgeGetAdapterContext(AdapterObject);
    if (adapterContext == nullptr || adapterContext->WdfDevice == nullptr)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    auto* deviceContext = LumaBridgeGetDeviceContext(adapterContext->WdfDevice);
    if (deviceContext == nullptr)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    deviceContext->LastAdapterInitStatus = pInArgs->AdapterInitStatus;

    if (!NT_SUCCESS(pInArgs->AdapterInitStatus))
    {
        deviceContext->State = AdapterLifecycleState::AdapterFailed;
        return pInArgs->AdapterInitStatus;
    }

    deviceContext->State = AdapterLifecycleState::AdapterReady;

    // Monitor creation and arrival are intentionally deferred to a dedicated issue.
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtAdapterCommitModes(
    IDDCX_ADAPTER AdapterObject,
    const IDARG_IN_COMMITMODES* pInArgs
    )
{
    if (AdapterObject == nullptr || pInArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pInArgs->PathCount > 0 && pInArgs->pPaths == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    auto* adapterContext = LumaBridgeGetAdapterContext(AdapterObject);
    if (adapterContext == nullptr || adapterContext->WdfDevice == nullptr)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    auto* deviceContext = LumaBridgeGetDeviceContext(adapterContext->WdfDevice);
    if (deviceContext == nullptr)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    deviceContext->CommittedPathCount = pInArgs->PathCount;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtParseMonitorDescription(
    const IDARG_IN_PARSEMONITORDESCRIPTION* pInArgs,
    IDARG_OUT_PARSEMONITORDESCRIPTION* pOutArgs
    )
{
    if (pInArgs == nullptr || pOutArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    pOutArgs->MonitorModeBufferOutputCount = 0;
    pOutArgs->PreferredMonitorModeIdx = NO_PREFERRED_MODE;
    return STATUS_NOT_IMPLEMENTED;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtMonitorGetDefaultDescriptionModes(
    IDDCX_MONITOR MonitorObject,
    const IDARG_IN_GETDEFAULTDESCRIPTIONMODES* pInArgs,
    IDARG_OUT_GETDEFAULTDESCRIPTIONMODES* pOutArgs
    )
{
    UNREFERENCED_PARAMETER(MonitorObject);

    if (pInArgs == nullptr || pOutArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    pOutArgs->DefaultMonitorModeBufferOutputCount = 0;
    pOutArgs->PreferredMonitorModeIdx = NO_PREFERRED_MODE;
    return STATUS_NOT_IMPLEMENTED;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtMonitorQueryTargetModes(
    IDDCX_MONITOR MonitorObject,
    const IDARG_IN_QUERYTARGETMODES* pInArgs,
    IDARG_OUT_QUERYTARGETMODES* pOutArgs
    )
{
    UNREFERENCED_PARAMETER(MonitorObject);

    if (pInArgs == nullptr || pOutArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    pOutArgs->TargetModeBufferOutputCount = 0;
    return STATUS_NOT_IMPLEMENTED;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtMonitorAssignSwapChain(
    IDDCX_MONITOR MonitorObject,
    const IDARG_IN_SETSWAPCHAIN* pInArgs
    )
{
    UNREFERENCED_PARAMETER(MonitorObject);

    if (pInArgs == nullptr)
    {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_NOT_IMPLEMENTED;
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtMonitorUnassignSwapChain(
    IDDCX_MONITOR MonitorObject
    )
{
    UNREFERENCED_PARAMETER(MonitorObject);

    return STATUS_NOT_IMPLEMENTED;
}
