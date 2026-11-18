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
- tracing UMDF estruturado em `Trace.h` com prefixo `[LB-DRIVER]` via `OutputDebugStringA` e registro de estagio/erro em memoria;
- stubs defensivos para callbacks ainda nao implementados: `LumaBridgeEvtMonitorAssignSwapChain` retorna `STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN` apenas como protecao de contrato IddCx 1.4+ contra bugcheck (nao e implementacao funcional de swapchain, pois o Windows pode solicitar repetidamente nova swapchain se houver monitor ativo; por isso nenhum monitor virtual e criado ou anunciado ate a implementacao do pipeline de modos e swapchain) e `LumaBridgeEvtMonitorUnassignSwapChain` retorna `STATUS_SUCCESS`; callbacks de descricao/modos retornam `STATUS_NOT_SUPPORTED`;
- supressao de `C4471` restrita ao bloco de includes WDK em `Driver.h`;
- 16 testes unitarios deterministicos da maquina de estados e associacao multi-dispositivo em `windows/driver/tests/AdapterLifecycleTests.cpp` (escopo puramente de logica de estado/associacao, distinto de testes em runtime real WDF/IddCx);
- pacote INF estruturado (`LumaBridgeIddDriver.inf`) com `Include = wudfrd.inf`, `UmdfExtensions = IddCx0102`, `UpperFilters = IndirectKmd`, `ClassVer = 2.0`, `DeviceGroupId`, `UmdfHostProcessSharing = ProcessSharingDisabled` e decoracao `NT$ARCH$.10.0...18362`, integrado ao `.vcxproj` com `StampInf`, `InfVerif`, `Inf2Cat` (`10_19H1_X64`) e `DrvCat` (mantendo `SignMode=Off` e `EnableTestSign=false`, gerando `.dll`, `.inf` e `.cat` nao assinados em `$(PackageDir)` e `$(OutDir)` — ver `docs/setup/windows-idd-driver-packaging.md`);
- 4 testes automatizados de consistencia estatica do pacote INF/CAT/DLL em `windows/driver/tests/DriverPackageValidationTests.cpp`;
- `.gitignore` local para artefatos de build.

Fora do escopo atual (issues dedicadas):

- criacao e chegada/saida de monitor virtual (`IddCxMonitorCreate`, `IddCxMonitorArrival`, `IddCxMonitorDeparture`);
- exposicao de modos de video (`720p60`, `1080p60`, `1440p60`);
- processamento de swapchain e recursos Direct3D 11;
- habilitacao de mitigacao Spectre apos instalacao das libs MSVC Spectre (ver issue #20);
- assinatura de teste, instalacao controlada e execucao em runtime real dentro de `WUDFHost.exe`;
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
      AdapterStateMachine.h
      Trace.h
      LumaBridgeIddDriver.inf
    tests/
      README.md
      AdapterLifecycleTests.cpp
      DriverPackageValidationTests.cpp
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

- **Compatibilidade UMDF/IddCx com o SO alvo:** O driver usa `UMDF_VERSION_MINOR=31`, `UMDF_MINIMUM_VERSION_REQUIRED=25` e `IDDCX_VERSION_MAJOR=1`, `IDDCX_VERSION_MINOR=4`, `IDDCX_MINIMUM_VERSION_REQUIRED=4`, com pacote INF direcionado a `NTamd64.10.0...18362` e catalogo `10_19H1_X64`. Todas as funcoes usadas estao dentro de `WDF_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`268`) e `IDD_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`23`), garantindo compatibilidade binaria em Windows 10 1903+ e Windows 11.
- **Supressao escopada de `C4471`:** O warning `C4471` emitido por `wudfwdm.h` (`typedef enum _DEVICE_RELATION_TYPE`) e suprimido apenas ao redor de `#include <wdf.h>` e `#include <IddCx.h>` em `Driver.h`.
- **Mitigacao Spectre (issue #20):** `Driver_SpectreMitigation=false` permanece temporariamente porque as bibliotecas MSVC Spectre (`lib\spectre`) nao estao instaladas no Build Tools local.
- **Catalogo ativo sem assinatura automatica (issue #21):** `EnableInf2cat=true` gera e valida o `.cat` no build enquanto `EnableTestSign=false` e `SignMode=Off` mantem assinatura digital e alteracao de certificados fora do build padrao ate uma etapa controlada dedicada.

## Proximos passos

1. Reativar mitigacao Spectre apos instalacao das libs MSVC Spectre (issue #20).
2. Implementar criacao, chegada e remocao do monitor virtual (`IddCxMonitorCreate`, `IddCxMonitorArrival`, `IddCxMonitorDeparture`).
3. Expor modos de video (`1280x720@60`, `1920x1080@60`, `2560x1440@60`) em `EvtIddCxMonitorGetDefaultDescriptionModes` e `EvtIddCxMonitorQueryTargetModes`.
4. Implementar processamento de swapchain Direct3D 11 e contrato de entrega de frames para `lumabridge-host`.
5. Executar estrategia controlada de assinatura de teste e validacao em runtime no Windows (`WUDFHost.exe`).
