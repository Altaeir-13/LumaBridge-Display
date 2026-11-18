#include "Driver.h"
#include "Adapter.h"

extern "C"
_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG config{};
    WDF_DRIVER_CONFIG_INIT(&config, LumaBridgeEvtDeviceAdd);
    config.EvtDriverUnload = LumaBridgeEvtDriverUnload;

    return WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE);
}

_Use_decl_annotations_
VOID
LumaBridgeEvtDriverUnload(
    WDFDRIVER Driver
    )
{
    UNREFERENCED_PARAMETER(Driver);
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtDeviceAdd(
    WDFDRIVER Driver,
    PWDFDEVICE_INIT DeviceInit
    )
{
    UNREFERENCED_PARAMETER(Driver);

    if (DeviceInit == nullptr)
    {
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

    WDF_OBJECT_ATTRIBUTES deviceAttributes{};
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, LumaBridgeDeviceContext);
    deviceAttributes.EvtCleanupCallback = LumaBridgeEvtDeviceContextCleanup;

    WDFDEVICE device = nullptr;
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return LumaBridgeInitializeDeviceContext(device);
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtDeviceD0Entry(
    WDFDEVICE Device,
    WDF_POWER_DEVICE_STATE PreviousState
    )
{
    UNREFERENCED_PARAMETER(PreviousState);

    return LumaBridgeStartAdapter(Device);
}

_Use_decl_annotations_
NTSTATUS
LumaBridgeEvtDeviceD0Exit(
    WDFDEVICE Device,
    WDF_POWER_DEVICE_STATE TargetState
    )
{
    UNREFERENCED_PARAMETER(TargetState);

    LumaBridgeStopAdapter(Device);
    return STATUS_SUCCESS;
}
