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
      AdapterStateMachine.h
      Trace.h
      LumaBridgeIddDriver.inf
    tests/
      README.md
      AdapterLifecycleTests.cpp
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

Testes unitarios deterministicos de maquina de estados e associacao multi-dispositivo (escopo isolado, sem substituir validacao futura em runtime real WDF/`WUDFHost.exe`):

```bat
cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\AdapterLifecycleTests.cpp /Fowindows\driver\x64\Debug\AdapterLifecycleTests.obj /Fe:windows\driver\x64\Debug\AdapterLifecycleTests.exe
windows\driver\x64\Debug\AdapterLifecycleTests.exe
```

Artefatos locais esperados (ignorados por `windows/driver/.gitignore`):

```text
windows/driver/x64/Debug/LumaBridgeIddDriver.dll
windows/driver/x64/Debug/AdapterLifecycleTests.exe
windows/driver/x64/Release/LumaBridgeIddDriver.dll
```

Observacao: `Inf2Cat` e `DrvCat` permanecem ignorados enquanto o INF esta declarado como `<None>` no `.vcxproj` (escopo separado na issue #21).

## Decisoes de build e dividas tecnicas

- **Compatibilidade UMDF/IddCx com o SO alvo:** O driver usa `UMDF_VERSION_MINOR=31`, `UMDF_MINIMUM_VERSION_REQUIRED=25` e `IDDCX_VERSION_MAJOR=1`, `IDDCX_VERSION_MINOR=4`, `IDDCX_MINIMUM_VERSION_REQUIRED=4`. Todas as funcoes usadas estao dentro de `WDF_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`268`) e `IDD_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`23`), garantindo compatibilidade binaria em Windows 10 1903+ e Windows 11.
- **Supressao escopada de `C4471`:** O warning `C4471` emitido por `wudfwdm.h` (`typedef enum _DEVICE_RELATION_TYPE`) e suprimido apenas ao redor de `#include <wdf.h>` e `#include <IddCx.h>` em `Driver.h`.
- **Mitigacao Spectre (issue #20):** `Driver_SpectreMitigation=false` permanece temporariamente porque as bibliotecas MSVC Spectre (`lib\spectre`) nao estao instaladas no Build Tools local.
- **Empacotamento INF e assinatura (issue #21):** `EnableTestSign=false` e `SignMode=Off` mantem assinatura e empacotamento fora deste escopo ate a validacao dedicada do INF.

## Proximos passos

1. Validar pacote INF (`IndirectKmd`, `UmdfExtensions = IddCx0102`, `StampInf`, `InfVerif`, `Inf2Cat`) e resolver issue #21.
2. Reativar mitigacao Spectre apos instalacao das libs MSVC Spectre (issue #20).
3. Implementar criacao, chegada e remocao do monitor virtual (`IddCxMonitorCreate`, `IddCxMonitorArrival`, `IddCxMonitorDeparture`).
4. Expor modos de video (`1280x720@60`, `1920x1080@60`, `2560x1440@60`) em `EvtIddCxMonitorGetDefaultDescriptionModes` e `EvtIddCxMonitorQueryTargetModes`.
5. Implementar processamento de swapchain Direct3D 11 e contrato de entrega de frames para `lumabridge-host`.
