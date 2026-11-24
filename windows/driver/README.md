# LumaBridge IDD Driver

## Objetivo do modulo

`windows/driver` e o modulo responsavel pelo driver virtual Indirect Display (`IddCx`) do LumaBridge Display no Windows.

Ao encerramento da etapa `M0` (`M0.3`), o modulo implementa a inicializacao WDF/IddCx com maquina de estados deterministica e diagnostico de estagios, monitor virtual opt-in, modos CTA-861, pipeline de swapchain Direct3D 11, extracao de quadros com pool limitado de texturas compartilhadas (`D3D11_RESOURCE_MISC_SHARED_NTHANDLE | SHARED_KEYEDMUTEX`), IPC local autenticado (`LBIF` v1.0/v1.1 via Named Pipe com `SessionSummary` ETW) e conjunto automatizado de empacotamento, validacao e rollback controlado em Windows 11 x64.

## Escopo atual

Incluido no fechamento da `M0`:

- solucao Visual Studio/MSBuild (`Debug|x64` e `Release|x64`);
- projeto WDK UMDF x64 compatibilizado com Windows 11 host (`UMDF 2.31`, minimo `2.25`, `IddCx 1.4`, minimo `4`);
- entrada `DriverEntry`, configuracao `WDF_DRIVER_CONFIG_INIT`, `WdfDriverCreate` e `LumaBridgeEvtDriverUnload`;
- `LumaBridgeEvtDeviceAdd` com callbacks PnP/Power (`EvtDeviceD0Entry`, `EvtDeviceD0Exit`), `IddCxDeviceInitConfig`, criacao de `WDFDEVICE` com `LumaBridgeDeviceContext` e `IddCxDeviceInitialize`;
- modulo `Adapter.*`, `AdapterStateMachine.h` e `DiagnosticStageConfig.h` com estados deterministicos, sincronizacao multi-dispositivo (`g_AdapterInitGate` + `g_AdapterInitSlotCv` + `InFlightAdapterBindingSlot` -> `DeviceContext::StateLock`), `IddCxGetVersion`, `IddCxAdapterInitAsync` (`LumaBridgeAdapterContext`), retencao de handle com `WdfObjectReference`/`WdfObjectDereference` antes de `WdfDeviceSetFailed`, `LumaBridgeEvtAdapterInitFinished`, `LumaBridgeEvtAdapterCommitModes`, rejeicao de callbacks tardios apos cleanup (`IsCleanedUp`), breadcrumbs de inicializacao e limpeza deterministica de contextos;
- tracing TraceLogging/UMDF estruturado em `Trace.h` (`DriverStage`, `DriverMetrics`, `SessionSummary` e prefixos `[LB-DRIVER]`), registrando estado de adaptador/monitor/swapchain, FPS, latencias em microssegundos, geracao de swapchain/sessao, conservacao de quadros e consumo de recursos sem armazenar pixels;
- modulo `MonitorModes.*` com especificacao canonica CTA-861 dos modos SDR progressivos (`1280x720@60` e `1920x1080@60` preferencial), separacao explicita de `vSyncFreqDivider` (`0` para `IDDCX_MONITOR_MODE`, `1` para `IDDCX_TARGET_MODE` e paths ativos), validacao de timings/pixel rate sem overflow, correspondencia exata com modos anunciados, deduplicacao, limite unico `kMaxDisplayPipelineRate` e negociacao de buffers;
- callbacks IddCx de modos implementados em `Adapter.cpp`: `LumaBridgeEvtParseMonitorDescription` (recusa EDID com `STATUS_NOT_SUPPORTED` conforme estrategia `IDDCX_MONITOR_DESCRIPTION_TYPE_EDID` com `DataSize = 0` e `pData = nullptr`), `LumaBridgeEvtMonitorGetDefaultDescriptionModes`, `LumaBridgeEvtMonitorQueryTargetModes` e validacao estrita de paths ativos em `LumaBridgeEvtAdapterCommitModes`;
- pipeline de swapchain Direct3D 11 / DXGI em `SwapChainProcessor.*` e `Adapter.cpp`: selecao de adaptador por `RenderAdapterLuid`, `ID3D11Device` com `D3D11_CREATE_DEVICE_BGRA_SUPPORT`, `IddCxSwapChainSetDevice`, normalizacao causal de `SwapChainAcquireQpcTime` vs `PresentDisplayQPCTime` futuro do DWM, circuit breaker contra loops de recriacao, worker thread dedicada sem busy-wait, protecao RAII/reentrancia e metricas QPC/FPS;
- modulo `VirtualMonitor.*` (`VirtualMonitorManager` + `IddCxVirtualMonitorBackend`) implementando `IddCxMonitorCreate`, `IddCxMonitorArrival` e `IddCxMonitorDeparture` para 1 monitor virtual MVP (`ConnectorIndex = 0`, `ContainerId` unico deterministico) com **ativacao controlada desabilitada por padrao** (`EnableVirtualMonitor` `REG_DWORD = 1` para habilitar);
- extracao e transporte local (`FrameExtractor.*`, `SharedTexturePool.*`, `FrameIpcProtocol.h`, `FrameTransport.*`): copia GPU sem bloqueio na thread IddCx (`kDefaultSharedTexturePoolSize = 4`), `IDXGIKeyedMutex` + `DuplicateHandle` autenticado por PID/SID/sessao/integridade (`AllowSameUserAccess = false`), dominio unico serializado de sequencia e transicoes de sessao em `FrameIpcServer`, fallback diagnostico CPU staging v1.0 opt-in e liberacao segura no teardown (`FramesFlushedOnSessionTransition`);
- suites automatizadas de teste descritas em [tests/README.md](tests/README.md): **157 testes C++ unitarios e de componentes**, **9 testes E2E multiprocesso** (integrando com `../host/lumabridge-host.exe` documentado em [../host/README.md](../host/README.md)) e **71 testes automatizados PowerShell**;
- pacote INF estruturado (`LumaBridgeIddDriver.inf`) validado por `StampInf`, `InfVerif`, `Inf2Cat` (`10_CO_X64;10_NI_X64;10_GE_X64`, Windows 11 x64 `NTamd64.10.0...22000`) e `DrvCat` mantendo `SignMode=Off` e `EnableTestSign=false` no build padrao (ver [windows-idd-driver-packaging.md](../../docs/setup/windows-idd-driver-packaging.md));
- ferramental completo em `windows/driver/scripts/` (`LumaBridgeDriverCommon.psm1`, `Test-LumaBridgePrerequisites.ps1`, `Invoke-LumaBridgePackageSigning.ps1`, `Install-LumaBridgeDriver.ps1`, `Set-LumaBridgeVirtualMonitor.ps1`, `Invoke-LumaBridgeEtwTrace.ps1`, `Invoke-LumaBridgeFunctionalValidation.ps1`, `Collect-LumaBridgeDiagnostics.ps1`, `Build-LumaBridgeDiagnosticStage.ps1`, `Prepare-IddSampleReference.ps1`, `Uninstall-LumaBridgeDriver.ps1`) com `-DryRun`, reuso criptografico de staging (`-SkipDriverInstall -ReuseSignedStaging`), diagnosticos sem pixels e rollback garantido em `finally` (ver [windows-idd-functional-validation.md](../../docs/setup/windows-idd-functional-validation.md));
- `.gitignore` local para artefatos de build.

Fora do escopo do driver e transferido para marcos posteriores (`M1`+):

- exposicao de `2560x1440@60` e modos HDR/VRR;
- protocolo de rede multiplataforma (`LBWP v1`), transporte QUIC/TLS, receptor Linux e medicao glass-to-glass;
- assinatura de producao (WHQL / EV) e empacotamento para distribuicao final;
- suporte a multiplos adaptadores / GPUs adicionais alem do emissor NVIDIA NVENC no host Windows.

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
      Adapter.h / Adapter.cpp
      AdapterStateMachine.h
      DiagnosticStageConfig.h
      Driver.h / Driver.cpp
      FrameExtractor.h / FrameExtractor.cpp
      FrameIpcProtocol.h
      FrameTransport.h / FrameTransport.cpp
      MonitorModes.h / MonitorModes.cpp
      SharedTexturePool.h / SharedTexturePool.cpp
      SwapChainProcessor.h / SwapChainProcessor.cpp
      Trace.h
      VirtualMonitor.h / VirtualMonitor.cpp
      LumaBridgeIddDriver.inf
    tests/
      README.md
      AdapterLifecycleTests.cpp
      DriverPackageValidationTests.cpp
      FrameEndToEndIntegrationTests.cpp
      FrameExtractionTests.cpp
      FrameIpcTests.cpp
      GpuSharedTextureTests.cpp
      HostValidationWorkerAndStimulusTests.cpp
      MonitorModesTests.cpp
      NvencEncoderTests.cpp
      SwapChainLifecycleTests.cpp
      VirtualMonitorLifecycleTests.cpp
      LumaBridgeFunctionalToolingTests.ps1
    scripts/
      LumaBridgeDriverCommon.psm1
      Build-LumaBridgeDiagnosticStage.ps1
      Collect-LumaBridgeDiagnostics.ps1
      Install-LumaBridgeDriver.ps1
      Invoke-LumaBridgeEtwTrace.ps1
      Invoke-LumaBridgeFunctionalValidation.ps1
      Invoke-LumaBridgePackageSigning.ps1
      Prepare-IddSampleReference.ps1
      Set-LumaBridgeVirtualMonitor.ps1
      Test-LumaBridgePrerequisites.ps1
      Uninstall-LumaBridgeDriver.ps1
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

Os comandos completos para compilar e executar os **157 testes C++ unitarios e de componentes**, os **9 testes E2E multiprocesso** (junto ao consumidor `lumabridge-host.exe` em `../host/`) e os **71 testes automatizados PowerShell** em `windows/driver/scripts/` estao consolidados em [tests/README.md](tests/README.md) e [../host/README.md](../host/README.md).

Suíte PowerShell dos scripts operacionais:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File windows\driver\tests\LumaBridgeFunctionalToolingTests.ps1
```

Artefatos locais esperados (ignorados por `windows/driver/.gitignore`):

```text
windows/driver/x64/Debug/LumaBridgeIddDriver.{dll,inf,cat}
windows/driver/x64/Debug/LumaBridgeIddDriver/LumaBridgeIddDriver.{dll,inf} + lumabridgeidddriver.cat
windows/driver/x64/Release/LumaBridgeIddDriver.{dll,inf,cat}
windows/driver/x64/Release/LumaBridgeIddDriver/LumaBridgeIddDriver.{dll,inf} + lumabridgeidddriver.cat
windows/driver/x64/{Debug,Release}/*.exe (executaveis de testes C++ e lumabridge-host.exe)
```

Validacao direta de INF com `InfVerif`, assinatura controlada e procedimento funcional estao documentados em [windows-idd-driver-packaging.md](../../docs/setup/windows-idd-driver-packaging.md) e [windows-idd-functional-validation.md](../../docs/setup/windows-idd-functional-validation.md).

## Decisoes de build e dividas tecnicas

- **Compatibilidade UMDF/IddCx com o SO alvo:** O driver usa `UMDF_VERSION_MINOR=31`, `UMDF_MINIMUM_VERSION_REQUIRED=25` e `IDDCX_VERSION_MAJOR=1`, `IDDCX_VERSION_MINOR=4`, `IDDCX_MINIMUM_VERSION_REQUIRED=4`, com pacote INF direcionado exclusivamente a `NTamd64.10.0...22000` e catalogo `10_CO_X64;10_NI_X64;10_GE_X64` (Windows 11 21H2, 22H2/23H2 e 24H2/25H2+ x64, sem declarar suporte a Windows 10). Todas as funcoes usadas estao dentro de `WDF_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`268`) e `IDD_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`23`), garantindo compatibilidade binaria nas versoes Windows 11 x64 suportadas.
- **Supressao escopada de `C4471`:** O warning `C4471` emitido por `wudfwdm.h` (`typedef enum _DEVICE_RELATION_TYPE`) e suprimido apenas ao redor de `#include <wdf.h>` e `#include <IddCx.h>` em `Driver.h`.
- **Mitigacao Spectre (issue #20 resolvida):** compilacao e linkagem habilitadas com `<Driver_SpectreMitigation>Spectre</Driver_SpectreMitigation>` (`/Qspectre` + `MSVC\14.51.36231\lib\spectre\x64`) em `Debug|x64` e `Release|x64`, verificadas nos `.tlog`.
- **Catalogo ativo sem assinatura automatica (issue #21):** `EnableInf2cat=true` gera e valida o `.cat` no build enquanto `EnableTestSign=false` e `SignMode=Off` mantem assinatura digital e alteracao de certificados fora do build padrao ate etapas controladas em `<StagingDir>`.

## Proximos passos (`Pos-M0`)

1. Publicar e integrar a branch consolidada `integration/m0-windows-closure` em `dev` remoto (`origin/dev`) preservando a ancestralidade do commit funcional validado (`6b297856`) e do commit documental `M0.3` (`f1d2565e`). **A `M0` encontra-se funcionalmente aprovada e consolidada localmente, porem ainda nao integrada em `dev` remoto.**
2. Iniciar a etapa `M1` *(ainda nao iniciada)* — contratos multiplataforma, nucleo compartilhado, seguranca Fase 1/Fase 2 e protocolo de rede `LBWP v1`, mantendo a fronteira IPC local `LBIF` privada entre `WUDFHost.exe` e o backend Windows.
