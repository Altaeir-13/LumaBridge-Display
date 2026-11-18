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
- **Identidade persistente:** conector fixo `ConnectorIndex = 0` e `ContainerId` dedicado (`kMvpVirtualMonitorContainerId = {8E7B5F32-4C19-4E8A-9B7D-2F6C3D9A1001}`).
- **Fora de escopo:** codificacao (NVENC), streaming, protocolo ou comunicacao com o cliente Linux.

## 2. Maquina de estados do monitor (`VirtualMonitorManager`)

Modulo `windows/driver/LumaBridgeIddDriver/VirtualMonitor.h` / `VirtualMonitor.cpp`:

```text
NotCreated
  |-- EnsureMonitorArrived (ActivationEnabled=false) --> NotCreated (SkippedDisabledCount++)
  |-- EnsureMonitorArrived (ActivationEnabled=true)  --> Creating
        |-- CreateMonitor falha ----------------------> Faulted
        |-- CreateMonitor OK ------------------------> Arriving
              |-- ArriveMonitor falha ---------------> DeleteUnarrivedMonitorObject -> Faulted (PartialInitFailures++)
              |-- ArriveMonitor OK ------------------> Arrived (OsAdapterLuid, OsTargetId)
                    |-- EnsureMonitorArrived --------> Arrived (DuplicateArrivalPreventedCount++)
                    |-- DepartMonitor() -------------> Departing -> StopMonitorSwapChain -> IddCxMonitorDeparture -> Departed
                          |-- EnsureMonitorArrived ---> Creating (recriacao segura apos desconexao)
```

## 3. Regras de sincronizacao, falhas parciais e prevencao de orfaos

- **Separacao de locks (`m_operationLock` -> `m_stateLock`):** `m_operationLock` serializa `EnsureMonitorArrived` e `DepartMonitor`, enquanto `m_stateLock` protege exclusivamente o estado em memoria e **nunca** e mantido durante chamadas WDF/IddCx (`CreateMonitor`, `ArriveMonitor`, `DepartMonitor`, `DeleteUnarrivedMonitorObject`, `StopMonitorSwapChain`). Assim, callbacks sincronos ou reentrantes (como `NotifyMonitorObjectCleanedUp` dentro de `LumaBridgeEvtMonitorContextCleanup`) jamais causam deadlock.
- **Prevencao de monitor orfao em falha parcial:** se `IddCxMonitorCreate` suceder mas `IddCxMonitorArrival` falhar, `EnsureMonitorArrived` chama imediatamente `DeleteUnarrivedMonitorObject` (`WdfObjectDelete`) para liberar o `IDDCX_MONITOR` recem-criado antes de retornar erro.
- **Ordem segura de desconexao (`DepartMonitor`):** interrompe a swapchain associada (`SwapChainProcessor::UnassignSwapChain`) antes de invocar `IddCxMonitorDeparture`, zerando `m_monitorHandle`, `OsAdapterLuid` e `OsTargetId` de forma idempotente.
- **Integracao com energia e cleanup do adaptador:**
  - `LumaBridgeEvtAdapterInitFinished` (`AdapterReady`): consulta `EnableVirtualMonitor` e aciona `EnsureMonitorArrived`.
  - `LumaBridgeStartAdapter` (`ResumeReady`): reavalia `EnableVirtualMonitor` e garante chegada do monitor ao retornar para D0.
  - `LumaBridgeStopAdapter` (`D0Exit`): chama `MonitorManager.DepartMonitor()` antes de `Processor.OnSuspend()`.
  - `LumaBridgeEvtAdapterContextCleanup` e `LumaBridgeEvtDeviceContextCleanup`: chamam `MonitorManager.DepartMonitor()` antes de `Processor.Shutdown()`.
  - `LumaBridgeEvtMonitorContextCleanup`: marca `MonitorContext->IsCleanedUp = true` sob `g_AdapterInitGate`, encerra a swapchain pendente e chama `MonitorManager.NotifyMonitorObjectCleanedUp(Object)`.

## 4. Pendencia da issue #20 (Spectre Mitigation)

A auditoria do catalogo local do Visual Studio 2026 BuildTools (`18.7.11925.98`, toolset MSVC `14.51.36231`) identificou os componentes ausentes:

- `Microsoft.VisualStudio.Component.VC.14.51.x86.x64.Spectre`
- `Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre`

Como a sessao atual nao possui privilegios administrativos (`IsInRole(Administrator) == False`), a instalacao via Visual Studio Installer requer execucao manual elevada pelo usuario (detalhada em `docs/setup/windows-wdk-environment.md`). `Driver_SpectreMitigation=false` e a issue #20 permanecem **abertos** ate que as bibliotecas Spectre sejam instaladas, `Driver_SpectreMitigation=true` seja restaurado e o build completo seja revalidado.

## 5. Resultados dos testes unitarios

- `VirtualMonitorLifecycleTests.exe`: **10 testes deterministicos** aprovados (`0` falhas), cobrindo desabilitacao padrao, ativacao controlada com identidade persistente, prevencao de duplicidade, falha de criacao, falha parcial no arrival com limpeza do objeto nao chegado, partida segura + recriacao, idempotencia de `DepartMonitor`, cleanup WDF e parametros nulos.
- `AdapterLifecycleTests.exe`: **16/16** aprovados.
- `DriverPackageValidationTests.exe`: **5/5** aprovados.
- `MonitorModesTests.exe`: **12/12** aprovados.
- `SwapChainLifecycleTests.exe`: **13/13** aprovados.
