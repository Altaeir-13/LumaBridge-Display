# LumaBridge IDD Driver

## Objetivo do modulo

`windows/driver` e o modulo responsavel pelo driver virtual Indirect Display (`IddCx`) do LumaBridge Display no Windows.

Nesta etapa, o modulo implementa a inicializacao do dispositivo WDF/IddCx e a criacao assincrona do adaptador de display indireto (`IDDCX_ADAPTER`). A enumeracao de monitor virtual, a exposicao de modos de video e o processamento de swapchain serao entregues nas proximas issues incrementais.

## Escopo atual

Incluido agora:

- solucao Visual Studio/MSBuild (`Debug|x64` e `Release|x64`);
- projeto WDK UMDF x64 compatibilizado com Windows 11 host (`UMDF 2.31`, minimo `2.25`, `IddCx 1.4`);
- entrada `DriverEntry`, configuracao `WDF_DRIVER_CONFIG_INIT`, `WdfDriverCreate` e `LumaBridgeEvtDriverUnload`;
- `LumaBridgeEvtDeviceAdd` com callbacks PnP/Power (`EvtDeviceD0Entry`, `EvtDeviceD0Exit`), `IddCxDeviceInitConfig`, criacao de `WDFDEVICE` com `DeviceContext` e `IddCxDeviceInitialize`;
- modulo `Adapter.*` com `LumaBridgeStartAdapter` (`IddCxGetVersion` e `IddCxAdapterInitAsync` com `AdapterContext`), `LumaBridgeStopAdapter`, `LumaBridgeEvtAdapterInitFinished`, `LumaBridgeEvtAdapterCommitModes` e cleanup deterministico de contextos;
- stubs controlados (`STATUS_NOT_IMPLEMENTED`) para callbacks de monitor e swapchain na tabela `IDD_CX_CLIENT_CONFIG`;
- supressao de `C4471` restrita ao bloco de includes WDK em `Driver.h`;
- INF minimo de desenvolvimento (`LumaBridgeIddDriver.inf`);
- `.gitignore` local para artefatos de build.

Fora do escopo atual (issues dedicadas):

- criacao e chegada/saida de monitor virtual (`IddCxMonitorCreate`, `IddCxMonitorArrival`, `IddCxMonitorDeparture`);
- exposicao de modos de video (`720p60`, `1080p60`, `1440p60`);
- processamento de swapchain e recursos Direct3D 11;
- validacao completa do pacote INF (`IndirectKmd`, `UmdfExtensions`, `StampInf`, `InfVerif`, `Inf2Cat` — ver issue #21);
- habilitacao de mitigacao Spectre apos instalacao das libs MSVC Spectre (ver issue #20);
- estrategia de assinatura de teste e instalacao controlada;
- host, client, protocolo, streaming ou NVENC.

## Estrutura

```text
windows/
  driver/
    .gitignore
    README.md
    LumaBridgeIddDriver.sln
    LumaBridgeIddDriver/
      LumaBridgeIddDriver.vcxproj
      LumaBridgeIddDriver.vcxproj.filters
      Driver.h
      Driver.cpp
      Adapter.h
      Adapter.cpp
      LumaBridgeIddDriver.inf
```

## Requisitos

Ambiente validado em `docs/setup/windows-wdk-environment.md`:

- Visual Studio Build Tools 18.x / VS2026 (`18.7.3` / MSBuild `18.7.8`);
- MSVC `14.51.36231`;
- Windows SDK / WDK `10.0.28000.0`;
- `WindowsUserModeDriver10.0`;
- UMDF `2.31` com `UMDF_MINIMUM_VERSION_REQUIRED=25` (alinhado ao host Windows 11 build `26300` / `WUDFx02000.dll` `10.0.26100.9818`);
- IddCx `1.4` com `IDDCX_MINIMUM_VERSION_REQUIRED=4`;
- Developer Command Prompt ou Developer PowerShell com ambiente do Visual Studio carregado.

## Ciclo de vida implementado

```text
DriverEntry
  -> WDF_DRIVER_CONFIG_INIT + WdfDriverCreate
  -> LumaBridgeEvtDeviceAdd
       -> WdfDeviceInitSetPnpPowerEventCallbacks (D0Entry / D0Exit)
       -> LumaBridgeConfigureDeviceInit (IDD_CX_CLIENT_CONFIG_INIT + IddCxDeviceInitConfig)
       -> WdfDeviceCreate (LumaBridgeDeviceContext + EvtCleanupCallback)
       -> LumaBridgeInitializeDeviceContext (IddCxDeviceInitialize)
  -> LumaBridgeEvtDeviceD0Entry
       -> LumaBridgeStartAdapter (IddCxGetVersion + IddCxAdapterInitAsync + LumaBridgeAdapterContext)
  -> LumaBridgeEvtAdapterInitFinished
       -> AdapterReady ou AdapterFailed
```

## Como abrir e buildar

Comandos validados em `Debug|x64` e `Release|x64`:

```bat
msbuild windows\driver\LumaBridgeIddDriver.sln /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 /v:minimal
msbuild windows\driver\LumaBridgeIddDriver.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 /v:minimal
```

Artefatos locais esperados (ignorados por `windows/driver/.gitignore`):

```text
windows/driver/x64/Debug/LumaBridgeIddDriver.dll
windows/driver/x64/Release/LumaBridgeIddDriver.dll
```

Observacao: `Inf2Cat` e `DrvCat` permanecem ignorados enquanto o INF esta declarado como `<None>` no `.vcxproj` (escopo separado na issue #21).

## Decisoes de build e dividas tecnicas

- **Compatibilidade UMDF/IddCx com o SO alvo:** O WDK `10.0.28000.0` usa UMDF `2.35` por padrao, mas o Windows 11 host (`OsBuildNumber = 26300`, `WUDFx02000.dll` `10.0.26100.9818`) registra servicos UMDF entre `2.15` e `2.31`. O projeto foi ajustado para `UMDF_VERSION_MINOR=31` com `UMDF_MINIMUM_VERSION_REQUIRED=25` (e `UmdfLibraryVersion=2.31.0` no INF), mantendo `IddCx 1.4` (`IDDCX_MINIMUM_VERSION_REQUIRED=4`).
- **Supressao escopada de `C4471`:** O warning `C4471` emitido por `wudfwdm.h` (`typedef enum _DEVICE_RELATION_TYPE`) passou a ser suprimido apenas ao redor de `#include <wdf.h>` e `#include <IddCx.h>` em `Driver.h` (`#pragma warning(push/disable/pop)`), removendo `<DisableSpecificWarnings>4471` do `.vcxproj`.
- **Mitigacao Spectre (issue #20):** `Driver_SpectreMitigation=false` permanece temporariamente porque as bibliotecas MSVC Spectre (`lib\spectre`) nao estao instaladas no Build Tools local.
- **Empacotamento INF e assinatura (issue #21):** `EnableTestSign=false` e `SignMode=Off` mantem assinatura e empacotamento fora deste escopo ate a validacao dedicada do INF.

## Proximos passos

1. Validar pacote INF (`IndirectKmd`, `UmdfExtensions = IddCx0102`, `StampInf`, `InfVerif`, `Inf2Cat`) e estrategia segura de assinatura de teste (issue #21).
2. Implementar criacao, chegada e remocao do monitor virtual (`IddCxMonitorCreate`, `IddCxMonitorArrival`, `IddCxMonitorDeparture`).
3. Expor modos de video (`1280x720@60`, `1920x1080@60`, `2560x1440@60`) em `EvtIddCxMonitorGetDefaultDescriptionModes` e `EvtIddCxMonitorQueryTargetModes`.
4. Implementar processamento de swapchain Direct3D 11 e contrato de entrega de frames para `lumabridge-host`.
