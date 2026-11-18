# LumaBridge IDD Driver

## Objetivo do modulo

`windows/driver` e o modulo responsavel pelo driver virtual Indirect Display (`IddCx`) do LumaBridge Display no Windows.

Nesta etapa, o modulo implementa a inicializacao do dispositivo WDF/IddCx e a criacao assincrona do adaptador de display indireto (`IDDCX_ADAPTER`) com maquina de estados explicita, sincronizacao entre callbacks assincronos e diagnostico UMDF `[LB-DRIVER]`. A enumeracao de monitor virtual, a exposicao de modos de video e o processamento de swapchain serao entregues nas proximas issues incrementais.

## Escopo atual

Incluido agora:

- solucao Visual Studio/MSBuild (`Debug|x64` e `Release|x64`);
- projeto WDK UMDF x64 compatibilizado com Windows 11 host (`UMDF 2.31`, minimo `2.25`, `IddCx 1.4`, minimo `4`);
- entrada `DriverEntry`, configuracao `WDF_DRIVER_CONFIG_INIT`, `WdfDriverCreate` e `LumaBridgeEvtDriverUnload`;
- `LumaBridgeEvtDeviceAdd` com callbacks PnP/Power (`EvtDeviceD0Entry`, `EvtDeviceD0Exit`), `IddCxDeviceInitConfig`, criacao de `WDFDEVICE` com `LumaBridgeDeviceContext` e `IddCxDeviceInitialize`;
- modulo `Adapter.*` e `AdapterStateMachine.h` com estados deterministicos, sincronizacao multi-dispositivo (`g_AdapterInitGate` + `g_AdapterInitSlotCv` + `InFlightAdapterBindingSlot` -> `DeviceContext::StateLock`), `IddCxGetVersion`, `IddCxAdapterInitAsync` (`LumaBridgeAdapterContext`), retencao de handle com `WdfObjectReference`/`WdfObjectDereference` antes de `WdfDeviceSetFailed`, `LumaBridgeEvtAdapterInitFinished`, `LumaBridgeEvtAdapterCommitModes`, rejeicao de callbacks tardios apos cleanup (`IsCleanedUp`) e limpeza deterministica de contextos;
- tracing UMDF estruturado em `Trace.h` com prefixos `[LB-DRIVER]` e `[LB-DRIVER] [METRICS]` via `OutputDebugStringA`, registrando estado de adaptador/monitor/swapchain, FPS de aquisicao/processamento, latencia de processamento em microssegundos, erros DXGI/transitorios e consumo de memoria/handles sem armazenar conteudo de pixels;
- modulo `MonitorModes.*` com especificacao canonica CTA-861 dos modos SDR progressivos (`1280x720@60` e `1920x1080@60` preferencial), separacao explicita de `vSyncFreqDivider` (`0` para `IDDCX_MONITOR_MODE`, `1` para `IDDCX_TARGET_MODE` e paths ativos), validacao de timings/pixel rate sem overflow, correspondencia exata com modos anunciados, deduplicacao, limite unico `kMaxDisplayPipelineRate` e negociacao de buffers;
- callbacks IddCx de modos implementados em `Adapter.cpp`: `LumaBridgeEvtParseMonitorDescription` (recusa EDID com `STATUS_NOT_SUPPORTED` conforme estrategia `IDDCX_MONITOR_DESCRIPTION_TYPE_EDID` com `DataSize = 0` e `pData = nullptr`), `LumaBridgeEvtMonitorGetDefaultDescriptionModes`, `LumaBridgeEvtMonitorQueryTargetModes` e validacao estrita de paths ativos em `LumaBridgeEvtAdapterCommitModes`;
- pipeline minimo de swapchain Direct3D 11 / DXGI em `SwapChainProcessor.*` e `Adapter.cpp`: selecao de adaptador por `RenderAdapterLuid` (`EnumAdapterByLuid`), criacao de `ID3D11Device` com `D3D11_CREATE_DEVICE_BGRA_SUPPORT`, `IddCxSwapChainSetDevice`, `IddCxSwapChainReleaseAndAcquireBuffer`, `IddCxSwapChainFinishedProcessingFrame`, estados explicitos (`Ready`, `Active`, `Suspended`, `Stopping`, `Stopped`, `Faulted`), circuit breaker contra loops de recriacao, tratamento distinto de erros transitorios e permanentes, worker thread dedicada com cancelamento cooperativo sem busy-wait, protecao contra reentrancia, RAII (`ScopedWin32Handle`, `ComPtr::Attach`), transferencia estrita de ownership (sem chamar `WdfObjectDelete` em recusas `STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN`), `DeviceSwapChainHost` refcounted, acesso a `MonitorContext` sincronizado por `g_AdapterInitGate`, isolamento de callbacks obsoletos por `UnassignSwapChainForMonitor`, metricas QPC/FPS e telemetria sem armazenar pixels do desktop;
- callbacks `LumaBridgeEvtMonitorAssignSwapChain` (com checagem de monitor ativo e pinagem WDF) e `LumaBridgeEvtMonitorUnassignSwapChain` integrados ao `SwapChainProcessor` (`OnSuspend`/`OnResume`/`Shutdown` coordenados em `D0Exit`/`D0Entry` e cleanups);
- modulo `VirtualMonitor.*` (`VirtualMonitorManager` + `IddCxVirtualMonitorBackend`) implementando `IddCxMonitorCreate`, `IddCxMonitorArrival` e `IddCxMonitorDeparture` para 1 monitor virtual MVP (`ConnectorIndex = 0`, `ContainerId` unico deterministico via `DeriveMonitorContainerId`, configuracao sem EDID via `IDDCX_MONITOR_DESCRIPTION_TYPE_EDID` com `DataSize = 0`), estados explicitos (`Suspended`, `Stopping`, `Stopped`, `Faulted`), preservacao de handle caso `IddCxMonitorDeparture` falhe (bloqueando recriacao via `STATUS_DEVICE_BUSY` ate retry ou cleanup WDF), protecao RAII `ScopedWdfObjectRef`/`AcquireMonitorReference`/`ReleaseMonitorReference`, protecao contra callbacks reentrantes/tardios em teardown e **ativacao controlada desabilitada por padrao** (`EnableVirtualMonitor` `REG_DWORD = 1` na chave do dispositivo para habilitar);
- 15 testes unitarios deterministicos do ciclo de vida do monitor virtual em `windows/driver/tests/VirtualMonitorLifecycleTests.cpp`;
- 15 testes unitarios deterministicos do ciclo de vida da swapchain (independentes de GPU fisica) em `windows/driver/tests/SwapChainLifecycleTests.cpp`;
- 12 testes unitarios deterministicos de modos de video e negociacao de buffers em `windows/driver/tests/MonitorModesTests.cpp`;
- supressao de `C4471` restrita ao bloco de includes WDK em `Driver.h`;
- 16 testes unitarios deterministicos da maquina de estados e associacao multi-dispositivo em `windows/driver/tests/AdapterLifecycleTests.cpp` (escopo puramente de logica de estado/associacao, distinto de testes em runtime real WDF/IddCx);
- pacote INF estruturado (`LumaBridgeIddDriver.inf`) com `Include = wudfrd.inf`, `UmdfExtensions = IddCx0102`, `UpperFilters = IndirectKmd`, `ClassVer = 2.0`, `DeviceGroupId`, `UmdfHostProcessSharing = ProcessSharingDisabled` e decoracao `NT$ARCH$.10.0...22000` (politica explicita de suporte exclusivo ao Windows 11 x64), integrado ao `.vcxproj` com `StampInf`, `InfVerif`, `Inf2Cat` (`10_CO_X64;10_NI_X64;10_GE_X64`, cobrindo Windows 11 21H2, 22H2/23H2 e 24H2/25H2+) e `DrvCat` (mantendo `SignMode=Off` e `EnableTestSign=false`, gerando `.dll`, `.inf` e `.cat` nao assinados em `$(PackageDir)` e `$(OutDir)` — ver `docs/setup/windows-idd-driver-packaging.md`);
- 5 testes automatizados de consistencia estatica e integridade criptografica de catalogo (`CryptCAT*`, `CryptCATAdminCalcHashFromFileHandle2`, `CryptQueryObject`, `WinVerifyTrust` e cenarios negativos) em `windows/driver/tests/DriverPackageValidationTests.cpp`;
- `.gitignore` local para artefatos de build.

Fora do escopo atual (issues dedicadas):

- exposicao de `2560x1440@60` (avaliado, nao obrigatorio no MVP inicial) e modos HDR/VRR;
- copia de staging/leitura de pixels, encoder NVENC, protocolo e streaming para o cliente Linux;
- habilitacao de mitigacao Spectre apos instalacao das libs MSVC Spectre (ver issue #20);
- execucao efetiva de assinatura de teste, instalacao controlada e validacao em runtime no `WUDFHost.exe` (procedimento e plano documentados em `docs/setup/windows-idd-functional-validation.md`).

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
      AdapterStateMachine.h
      MonitorModes.h
      MonitorModes.cpp
      SwapChainProcessor.h
      SwapChainProcessor.cpp
      VirtualMonitor.h
      VirtualMonitor.cpp
      Trace.h
      LumaBridgeIddDriver.inf
    tests/
      README.md
      AdapterLifecycleTests.cpp
      DriverPackageValidationTests.cpp
      MonitorModesTests.cpp
      SwapChainLifecycleTests.cpp
      VirtualMonitorLifecycleTests.cpp
```

## Requisitos

Ambiente validado em `docs/setup/windows-wdk-environment.md`:

- Visual Studio Build Tools 18.x / VS2026 (`18.7.3` / MSBuild `18.7.8`);
- MSVC `14.51.36231`;
- Windows SDK / WDK `10.0.28000.0`;
- `WindowsUserModeDriver10.0`;
- UMDF `2.31` com `UMDF_MINIMUM_VERSION_REQUIRED=25` (validado contra `WUDFx02000.dll` `10.0.26100.9818` no host Windows 11 build `26300`, que expoe versao `2.35` / `287` funcoes);
- IddCx `1.4` com `IDDCX_MINIMUM_VERSION_REQUIRED=4` (validado contra `IddCx.dll` `10.0.26100.9818` no host, que expoe versao `1.12` / `42` funcoes);
- Developer Command Prompt ou Developer PowerShell com ambiente do Visual Studio carregado.

## Ciclo de vida e modelo de concorrencia

```text
DriverEntry
  -> WDF_DRIVER_CONFIG_INIT + WdfDriverCreate
  -> LumaBridgeEvtDeviceAdd
       -> WdfDeviceInitSetPnpPowerEventCallbacks (D0Entry / D0Exit)
       -> LumaBridgeConfigureDeviceInit (IDD_CX_CLIENT_CONFIG_INIT + IddCxDeviceInitConfig)
       -> WdfDeviceCreate (LumaBridgeDeviceContext + EvtCleanupCallback)
       -> LumaBridgeInitializeDeviceContext (IddCxDeviceInitialize)
  -> LumaBridgeEvtDeviceD0Entry
       -> LumaBridgeStartAdapter (TransitionOnD0EntryBegin -> IddCxGetVersion + IddCxAdapterInitAsync)
  -> LumaBridgeEvtAdapterInitFinished
       -> AdapterReady (se em D0) / DeviceStopped (se saiu de D0) / AdapterFailed + WdfDeviceSetFailed
```

Regras de sincronizacao e ownership:

- Ordem fixa de locks: `g_AdapterInitGate` -> `DeviceContext::StateLock` (nunca invertida).
- `IddCxAdapterInitAsync` e `WdfDeviceSetFailed` sao sempre executados **sem** locks mantidos, evitando deadlock em callbacks sincronos ou reentrantes.
- `InFlightAdapterBindingSlot` + `g_AdapterInitSlotCv` (sob `g_AdapterInitGate`) serializam a janela sem vinculo de `IddCxAdapterInitAsync` entre multiplos `WDFDEVICE` no processo host com espera limitada (`kAdapterInitSlotWaitTimeoutMs = 5000 ms`, falhando com `STATUS_IO_TIMEOUT` e transicionando para `AdapterFailed` em timeout para respeitar os limites de timeout PnP/Power do reflector UMDF).
- Em cleanup durante inicializacao em voo, `LumaBridgeEvtDeviceContextCleanup` e `LumaBridgeEvtAdapterContextCleanup` apenas sinalizam `MarkDeviceCleanedUp` (sem liberar o slot antes do retorno de `IddCxAdapterInitAsync`) e marcam `AdapterContext->IsCleanedUp = true` + `HasBoundDevice = true`, garantindo que callbacks tardios do adaptador antigo sejam rejeitados com `nullptr` e nunca se vinculem cruzadamente a outro dispositivo `B`.
- Antes de liberar os locks para chamar `WdfDeviceSetFailed`, `LumaBridgeEvtAdapterInitFinished` retem referencia publica via `WdfObjectReference`/`WdfObjectDereference` para garantir validade do handle `WDFDEVICE` ate o retorno da chamada.
- `DeviceStopped` nunca sobrescreve `AdapterFailed`, e `STATUS_PENDING` nunca e tratado como conclusao bem-sucedida (`IsSucceededNonPendingStatus`).
- Em destruicao do dispositivo ou adaptador, os ponteiros cruzados (`WdfDevice` / `AdapterObject`) e `IsCleanedUp` sao atualizados simetricamente sob `g_AdapterInitGate`.
- Garantia de compatibilidade com o SO apoia-se exclusivamente nos contratos publicos e documentados do WDF/IddCx, nunca em offsets internos de DLLs do Windows.

## Como buildar e testar

Builds do driver (`Debug|x64` e `Release|x64`):

```bat
msbuild windows\driver\LumaBridgeIddDriver.sln /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 /v:minimal
msbuild windows\driver\LumaBridgeIddDriver.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 /v:minimal
```

Testes unitarios deterministicos de maquina de estados e associacao multi-dispositivo (escopo isolado, sem substituir validacao futura em runtime real WDF/`WUDFHost.exe`) e validacao estatica dos pacotes `Debug|x64` e `Release|x64`:

```bat
cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\AdapterLifecycleTests.cpp /Fowindows\driver\x64\Debug\AdapterLifecycleTests.obj /Fe:windows\driver\x64\Debug\AdapterLifecycleTests.exe
windows\driver\x64\Debug\AdapterLifecycleTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\DriverPackageValidationTests.cpp /Fowindows\driver\x64\Debug\DriverPackageValidationTests.obj /Fe:windows\driver\x64\Debug\DriverPackageValidationTests.exe
windows\driver\x64\Debug\DriverPackageValidationTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\MonitorModesTests.cpp windows\driver\LumaBridgeIddDriver\MonitorModes.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\MonitorModesTests.exe
windows\driver\x64\Debug\MonitorModesTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\SwapChainLifecycleTests.cpp windows\driver\LumaBridgeIddDriver\SwapChainProcessor.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\SwapChainLifecycleTests.exe
windows\driver\x64\Debug\SwapChainLifecycleTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\VirtualMonitorLifecycleTests.cpp windows\driver\LumaBridgeIddDriver\VirtualMonitor.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\VirtualMonitorLifecycleTests.exe
windows\driver\x64\Debug\VirtualMonitorLifecycleTests.exe
```

Artefatos locais esperados (ignorados por `windows/driver/.gitignore`):

```text
windows/driver/x64/Debug/LumaBridgeIddDriver.dll
windows/driver/x64/Debug/LumaBridgeIddDriver.inf
windows/driver/x64/Debug/LumaBridgeIddDriver.cat
windows/driver/x64/Debug/LumaBridgeIddDriver/LumaBridgeIddDriver.{dll,inf} + lumabridgeidddriver.cat
windows/driver/x64/Debug/AdapterLifecycleTests.exe
windows/driver/x64/Debug/DriverPackageValidationTests.exe
windows/driver/x64/Release/LumaBridgeIddDriver.dll
windows/driver/x64/Release/LumaBridgeIddDriver.inf
windows/driver/x64/Release/LumaBridgeIddDriver.cat
windows/driver/x64/Release/LumaBridgeIddDriver/LumaBridgeIddDriver.{dll,inf} + lumabridgeidddriver.cat
```

Validacao direta de INF com `InfVerif` e detalhes de assinatura/recuperacao estao documentados em `docs/setup/windows-idd-driver-packaging.md`.

## Decisoes de build e dividas tecnicas

- **Compatibilidade UMDF/IddCx com o SO alvo:** O driver usa `UMDF_VERSION_MINOR=31`, `UMDF_MINIMUM_VERSION_REQUIRED=25` e `IDDCX_VERSION_MAJOR=1`, `IDDCX_VERSION_MINOR=4`, `IDDCX_MINIMUM_VERSION_REQUIRED=4`, com pacote INF direcionado exclusivamente a `NTamd64.10.0...22000` e catalogo `10_CO_X64;10_NI_X64;10_GE_X64` (Windows 11 21H2, 22H2/23H2 e 24H2/25H2+ x64, sem declarar suporte a Windows 10). Todas as funcoes usadas estao dentro de `WDF_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`268`) e `IDD_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`23`), garantindo compatibilidade binaria nas versoes Windows 11 x64 suportadas.
- **Supressao escopada de `C4471`:** O warning `C4471` emitido por `wudfwdm.h` (`typedef enum _DEVICE_RELATION_TYPE`) e suprimido apenas ao redor de `#include <wdf.h>` e `#include <IddCx.h>` em `Driver.h`.
- **Mitigacao Spectre (issue #20 resolvida):** compilacao e linkagem habilitadas com `<Driver_SpectreMitigation>Spectre</Driver_SpectreMitigation>` (`/Qspectre` + `MSVC\14.51.36231\lib\spectre\x64`) em `Debug|x64` e `Release|x64`, verificadas nos `.tlog`.
- **Catalogo ativo sem assinatura automatica (issue #21):** `EnableInf2cat=true` gera e valida o `.cat` no build enquanto `EnableTestSign=false` e `SignMode=Off` mantem assinatura digital e alteracao de certificados fora do build padrao ate uma etapa controlada dedicada.

## Proximos passos

1. Executar a validacao funcional controlada com os scripts e o guia de `docs/setup/windows-idd-functional-validation.md` (`EnableVirtualMonitor = 1`).
2. Implementar extracao/encaminhamento de frames para `lumabridge-host` e encoder NVENC.
