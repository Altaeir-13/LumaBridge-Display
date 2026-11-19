#pragma once

#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#define LUMABRIDGE_DEFINED_WIN32_NO_STATUS
#endif
#include <Windows.h>
#ifdef LUMABRIDGE_DEFINED_WIN32_NO_STATUS
#undef WIN32_NO_STATUS
#undef LUMABRIDGE_DEFINED_WIN32_NO_STATUS
#endif

// Scope C4471 strictly to WDK headers (wudfwdm.h forward-declares unscoped enum _DEVICE_RELATION_TYPE).
#pragma warning(push)
#pragma warning(disable : 4471)
#include <wdf.h>
#include <IddCx.h>
#pragma warning(pop)

extern "C" DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_UNLOAD LumaBridgeEvtDriverUnload;
EVT_WDF_DRIVER_DEVICE_ADD LumaBridgeEvtDeviceAdd;
EVT_WDF_DEVICE_D0_ENTRY LumaBridgeEvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT LumaBridgeEvtDeviceD0Exit;

/// Returns the number of DLL_PROCESS_ATTACH notifications observed by DllMain.
ULONG
LumaBridgeGetDllProcessAttachCount() noexcept;
