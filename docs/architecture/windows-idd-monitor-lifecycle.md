# Ciclo de Vida do Monitor Virtual (IddCx) no LumaBridgeIddDriver

Data: 2026-11-18
Branch: `feature/windows-idd-monitor-lifecycle`
Issue relacionada: #29 (Milestone M3 - Windows Virtual Display)

## 1. Objetivo e escopo

Implementar a criacao, chegada e remocao controlada do primeiro monitor virtual do LumaBridge Display (`IddCxMonitorCreate`, `IddCxMonitorArrival` e `IddCxMonitorDeparture`), integrando-o ao ciclo de vida do adaptador, aos modos de video (`720p60` e `1080p60` preferencial), ao `MonitorContext` e ao pipeline Direct3D 11 (`SwapChainProcessor`).

Caracteristicas obrigatorias desta entrega:

- **Escopo de 1 monitor no MVP:** `kMaxMonitorsSupported = 1`, `kMvpVirtualMonitorConnectorIndex = 0`.
- **Ativacao controlada, desabilitada por padrao:** `kDefaultVirtualMonitorActivationEnabled = false`. O driver so chama `IddCxMonitorCreate` / `IddCxMonitorArrival` quando o valor `EnableVirtualMonitor` (`REG_DWORD = 1`) esta configurado na chave de hardware do dispositivo (`PLUGPLAY_REGKEY_DEVICE`); caso contrario ou na ausencia da chave, o monitor nao e anunciado.
- **Configuracao sem EDID:** usa `IDDCX_MONITOR_DESCRIPTION_TYPE_EDID` com `DataSize = 0` e `pData = nullptr` (conforme contrato `IddCx.h` 1.4 para monitores sem bloco EDID), delegando os modos padrao a `EvtIddCxMonitorGetDefaultDescriptionModes` e `EvtIddCxMonitorQueryTargetModes`.
- **Identidade persistente e exclusiva por instancia:** conector fixo `ConnectorIndex = 0` e `ContainerId` deterministico gerado por `DeriveMonitorContainerId(DeviceInstanceIndex, ConnectorIndex)` — preservando `kMvpVirtualMonitorContainerId = {8E7B5F32-4C19-4E8A-9B7D-2F6C3D9A1001}` para a instancia primaria `(0, 0)` e derivando GUIDs RFC 4122 versao 5 distintos para instancias subsequentes.
- **Observabilidade estruturada sem captura de pixels:** `Trace.h` e `Adapter.cpp` emitem eventos `[LB-DRIVER] [METRICS]` em marcos de ciclo de vida com estados de adaptador/monitor/swapchain, taxas de aquisicao/processamento (`AcquireFps`, `ProcessFps`), tempos de processamento em microssegundos, falhas DXGI/transitorias e consumo de recursos do processo host (`wsKB`, `privKB`, `handles`).
- **Fora de escopo:** codificacao (NVENC), streaming, protocolo ou comunicacao com o cliente Linux.

## 2. Maquina de estados do monitor (`VirtualMonitorManager`)

Modulo `windows/driver/LumaBridgeIddDriver/VirtualMonitor.h` / `VirtualMonitor.cpp`:

```text
NotCreated
  |-- EnsureMonitorArrived (ActivationEnabled=false) --> NotCreated (SkippedDisabledCount++)
  |-- EnsureMonitorArrived (m_monitorHandle != nullptr && State != Arrived) --> rejeita STATUS_DEVICE_BUSY (UnconfirmedRemovalBlockedCount++)
  |-- EnsureMonitorArrived (ActivationEnabled=true)  --> Creating
        |-- CreateMonitor falha ----------------------> Faulted
        |-- OnSuspend / Shutdown durante Create -----> DeleteUnarrivedMonitorObject -> Suspended / Stopped (LateCreateRejectedCount++)
        |-- CreateMonitor OK ------------------------> Arriving
              |-- ArriveMonitor falha ---------------> DeleteUnarrivedMonitorObject -> Faulted (PartialInitFailures++)
              |-- ArriveMonitor OK ------------------> Arrived (OsAdapterLuid, OsTargetId)
                    |-- EnsureMonitorArrived --------> Arrived (DuplicateArrivalPreventedCount++)
                    |-- DepartMonitor() -------------> Departing -> StopMonitorSwapChain(handle) -> IddCxMonitorDeparture
                          |-- Sucesso ---------------> limpa m_monitorHandle -> Departed / Suspended / Stopped
                          |-- Falha -----------------> preserva m_monitorHandle -> Faulted (DepartureFailures++, bloqueia recriacao ate retry ou cleanup WDF)
                    |-- OnSuspend() (D0Exit) --------> Suspended (bloqueia EnsureMonitorArrived ate OnResume())
                    |-- Shutdown() (Cleanup) --------> Stopping -> Stopped (irreversivel; bloqueia EnsureMonitorArrived e OnResume())
```

## 3. Regras de sincronizacao, falhas parciais e prevencao de orfaos

- **Separacao de locks e prevencao de deadlock reentrante (`m_operationLock` -> `m_stateLock`):** `m_operationLock` serializa `EnsureMonitorArrived`, `DepartMonitor`, `OnSuspend`, `OnResume` e `Shutdown` com rastreamento de thread proprietaria (`m_operationLockOwnerThreadId`). `m_stateLock` protege exclusivamente o estado em memoria e **nunca** e mantido durante chamadas WDF/IddCx (`CreateMonitor`, `ArriveMonitor`, `DepartMonitor`, `DeleteUnarrivedMonitorObject`, `StopMonitorSwapChain`). Callbacks reentrantes na mesma thread (ou `NotifyMonitorObjectCleanedUp` dentro de `LumaBridgeEvtMonitorContextCleanup`) jamais causam deadlock.
- **Preservacao de handle em falha de remocao:** se `IddCxMonitorDeparture` falhar, `m_monitorHandle` e mantido (`HasMonitorHandle = true`, `DepartureFailures++`, `LastDepartureStatus`), impedindo nova criacao (`STATUS_DEVICE_BUSY`) ate que nova tentativa de `DepartMonitor()` tenha sucesso ou que o WDF finalize o objeto via `NotifyMonitorObjectCleanedUp(handle)`.
- **Protecao de handles WDF (`WdfObjectReference`/`WdfObjectDereference`):** `IddCxVirtualMonitorBackend` fixa referencia RAII (`ScopedWdfObjectRef`) em `WDFDEVICE` durante `IddCxMonitorCreate`, transfere `+1` referencia em `IDDCX_MONITOR` enquanto `m_monitorHandle` esta ativo e adquire referencias transitorias em `ArriveMonitor`, `DepartMonitor` e callbacks de swapchain.
- **Isolamento contra callbacks de monitores antigos:** `LumaBridgeEvtMonitorAssignSwapChain` confirma que `MonitorObject == MonitorManager.GetActiveMonitorHandle()` (antes e apos `Processor.AssignSwapChain`, abandonando ou desatribuindo caso contrario) e `SwapChainProcessor::UnassignSwapChainForMonitor(monitorHandle)` ignora unassign/cleanup de monitores obsoletos quando outro monitor detem a swapchain ativa.
- **Prevencao de monitor orfao em falha parcial ou cancelamento tardio:** se `IddCxMonitorCreate` suceder mas `IddCxMonitorArrival` falhar — ou se `OnSuspend()` / `Shutdown()` disparar durante `CreateMonitor` ou `ArriveMonitor` — o manager aciona `DeleteUnarrivedMonitorObject` (`WdfObjectDelete`) ou `DepartMonitorLocked` imediatamente.
- **Integracao com energia e cleanup do adaptador:**
  - `LumaBridgeEvtAdapterInitFinished` (`AdapterReady`): consulta `EnableVirtualMonitor`, aciona `EnsureMonitorArrived` e emite `[LB-DRIVER] [METRICS]`.
  - `LumaBridgeStartAdapter` (D0Entry): chama `MonitorManager.OnResume()` e `Processor.OnResume()`; em `ResumeReady`, reavalia `EnableVirtualMonitor` e garante chegada do monitor.
  - `LumaBridgeStopAdapter` (D0Exit): chama `MonitorManager.OnSuspend()` e `Processor.OnSuspend()` e emite metricas finais de D0.
  - `LumaBridgeEvtAdapterContextCleanup` e `LumaBridgeEvtDeviceContextCleanup`: acionam teardown irreversivel `MonitorManager.Shutdown()` e `Processor.Shutdown()` com emissao de metricas antes de liberar `DeviceSwapChainHost`.
  - `LumaBridgeEvtMonitorContextCleanup`: marca `MonitorContext->IsCleanedUp = true` sob `g_AdapterInitGate`, chama `Processor.UnassignSwapChainForMonitor(Object)` e `MonitorManager.NotifyMonitorObjectCleanedUp(Object)`.

## 4. Resolucao da issue #20 (Spectre Mitigation)

As bibliotecas MSVC Spectre foram instaladas para o toolset ativo `14.51.36231` em:

- `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\lib\spectre\x64`

O projeto `LumaBridgeIddDriver.vcxproj` foi restaurado para `<Driver_SpectreMitigation>Spectre</Driver_SpectreMitigation>` nas configuracoes `Debug|x64` e `Release|x64` (valor valido do `EnumProperty` em `drivercl.xml` do WDK `10.0.28000.0`). Os logs de build (`.tlog`) confirmam compilacao com `/Qspectre` e vinculacao de `libcmt.lib`, `libcpmt.lib`, `oldnames.lib` e `libvcruntime.lib` a partir de `lib\spectre\x64`, com rebuilds e empacotamento sem erros ou warnings.

## 5. Resultados dos testes unitarios

- `VirtualMonitorLifecycleTests.exe`: **15 testes deterministicos** aprovados (`0` falhas), incluindo falha em `DepartMonitor` com preservacao de handle e bloqueio de recriacao, recuperacao por retry/cleanup WDF, `OnSuspend`/`OnResume`/cancelamento tardio em `CreateMonitor`, `Shutdown` irreversivel em voo, reentrancia sem deadlock nem leak de referencias, `ContainerId` unico RFC 4122 por instancia e testes originais do monitor.
- `SwapChainLifecycleTests.exe`: **15 testes deterministicos** aprovados (`0` falhas), incluindo isolamento contra monitor antigo (`UnassignSwapChainForMonitor`) e gravacao de FPS/tempos QPC em microssegundos sem pixels.
- `AdapterLifecycleTests.exe`: **16/16** aprovados.
- `DriverPackageValidationTests.exe`: **5/5** aprovados.
- `MonitorModesTests.exe`: **12/12** aprovados.
