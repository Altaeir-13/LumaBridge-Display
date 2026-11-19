# Investigacao da Falha de Inicializacao (`CM_PROB_FAILED_START` / `0xC000009E`) — Issue #34

Data: 2026-11-18
Branch: `fix/windows-idd-device-start`
Escopo: Milestone M3 — Windows Virtual Display / Issue #34

> **Politica de seguranca e controle:** Nenhuma alteracao de contrato no `.inf`, reducao de versoes UMDF/IddCx (`2.31` / `1.4`), desabilitacao de watchdog do IddCx, instalacao automatica ou modificacao permanente de registro/certificados/BCD deve ser feita sem evidencia direta em runtime.

---

## 1. Evidencias da Execucao Real #1

Na primeira tentativa controlada de instalacao do pacote `Release|x64` (com `EnableVirtualMonitor=0`):

- **Instance ID:** `ROOT\DISPLAY\0000`
- **Driver publicado:** `oem68.inf`
- **Service / UpperFilters:** `WUDFRd` / `IndirectKmd`
- **ProblemCode:** `10` (`0x0a`, `CM_PROB_FAILED_START`)
- **ProblemStatus:** `0xC000009E` (`STATUS_DEVICE_POWER_FAILURE`)
- **Evento Kernel-PnP:** ID `411`
- **Mensagem SetupAPI observada na desinstalacao/instalacao:**
  `Using WDF schema version 2.23 when section requires version 2.31. Section = [LumaBridge_Install.NT.Wdf]`
- **Rollback automatico:** removeu `ROOT\DISPLAY\0000` e `oem68.inf` sem deixar residuos.

### Linha do tempo correlacionada nos logs do host

1. `20:52:06.472` — `Microsoft-Windows-Kernel-PnP` Event `400` registrou dispositivo configurado (`ROOT\DISPLAY\0000`).
2. `20:52:06.474` — `setupapi.dev.log` registrou inicio da inicializacao do dispositivo.
3. `20:52:06.562` *(+88 ms, 9 ms antes do Event `411`)* — `Microsoft-Windows-WerKernel/Operational` Event `1001` (PID `4`) registrou:
   `Component WATCHDOG has requested to create a Live Kernel Dump and the request has been completed. RequestedType Mini Dump, GrantedType Mini Dump, Status STATUS_SUCCESS, ThrottleCheckResult 0x0.`
4. `20:52:06.571` *(+97 ms)* — `Microsoft-Windows-Kernel-PnP` Event `411` e `setupapi.dev.log` registraram `CM_PROB_FAILED_START (0x0a)` com `ProblemStatus = 0xC000009E`.

### Por que a causa raiz exata nao ficou isolada na execucao #1

- Os canais `Microsoft-Windows-DriverFrameworks-UserMode/Operational` e `Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic` estavam desabilitados (`IsEnabled = false`).
- Nenhuma sessao ETW (`TraceLogging` / `IddCx WPP`) nem captura `[LB-DRIVER]` (DebugView) estava ativa durante os ~97 ms entre configuracao e falha.
- O rollback automatico removeu imediatamente `ROOT\DISPLAY\0000` (junto com os logs/subchaves PnP) e `oem68.inf` antes que qualquer coleta post-mortem fosse persistida em disco.

---

## 1.5 Evidencias da Execucao Real #2 (`Attempt2`) e Forense dos ETLs

Na segunda tentativa instrumentada (`EnableVirtualMonitor=0`, pacote assinado em `C:\Temp\LumaBridgeStaging_Attempt2`, artefatos preservados em `C:\Users\Altair\AppData\Local\LumaBridgeDisplay\Diagnostics\Attempt2`):

- **Resultado PnP:** `ROOT\DISPLAY\0000`, `ProblemCode = 10` (`CM_PROB_FAILED_START`), `ProblemStatus = 0xC000009E` (`STATUS_DEVICE_POWER_FAILURE`), rollback concluido sem residuos.
- **Carregamento confirmado no host UMDF (`WUDFHost.exe`, PID `23812`, Host `{fdfb7f82-12cf-4e87-a92b-9a1e9447e6f8}`):**
  - `Microsoft-Windows-DriverFrameworks-UserMode/Operational` registrou `54` eventos no intervalo.
  - `00:57:48.012Z`: host solicitado a carregar `LumaBridgeIddDriver` no nivel `0` para `ROOT\DISPLAY\0000`.
  - `00:57:48.017Z`–`00:57:48.028Z`: DLLs carregadas no processo (`WUDFx02000.dll`, `IddCx.dll`, `lumabridgeidddriver.dll` a partir do Driver Store `lumabridgeidddriver.inf_amd64_c9580eb694d9b571`, `dxgi.dll`, `d3d11.dll`, `WppRecorderUM.dll`, `d2d1.dll`, `DWrite.dll`, `dxcore.dll`, `CRYPT32.dll`).
  - `00:57:48.0287643Z` (Event `2006`): `O Host UMDF carregou com exito o driver no nivel 0`.
  - `00:57:48.0291Z`–`00:57:48.0306Z`: operacoes `(27, 9)` (`IRP_MN_QUERY_CAPABILITIES`) e `(27, 0)` (`IRP_MN_START_DEVICE`) encaminhadas ao driver inferior (`0x0` apos forward `0xC00000BB`).
  - `00:57:48.0308806Z` (Event `2103`, **`235 us` apos o envio de `(27, 0)` e ~`2.1 ms` apos Event `2006`**): operacao PnP `(27, 0)` falhou para `ROOT\DISPLAY\0000` com `NTSTATUS 0xC000009E` (`STATUS_DEVICE_POWER_FAILURE`).
  - `00:57:48.0310951Z` (**`215 us` DEPOIS do Event `2103`**): `Microsoft-Windows-WerKernel/Operational` Event `1001` (`WATCHDOG` Live Kernel Mini Dump, `STATUS_SUCCESS`).
  - `00:57:48.0314Z`–`00:57:48.0369Z`: `(27, 2)` (`IRP_MN_REMOVE_DEVICE`, `0x0`), encerramento do `WUDFHost` (`1006`, `2900`, `2901`, `1008`) e `Kernel-PnP` `411` (`0xA`, `0xC000009E`).
- **Implicacao direta sobre o `WATCHDOG`:** o dump `WATCHDOG` ocorreu **215 us depois** que o Event `2103` ja havia registrado `0xC000009E` em `(27, 0)`. Logo, o `WATCHDOG` foi consequencia imediata da falha de start, e **nao** um timeout/hang do driver.

### Auditoria forense dos arquivos `.etl` da Execucao #2

A ausencia de eventos proprios do LumaBridge e de breadcrumbs `Diag*` em `Attempt2\diagnostics-summary.md` foi explicada por tres causas acumuladas na coleta #2 (sem permitir concluir que `DriverEntry` nao tenha rodado):

1. **Wrap circular por alto volume do `DxgKrnl` + `Watchdog-Events`:**
   - `LumaBridgeIddTrace.etl` (`134.217.728` bytes, modo `bincirc` de `128 MB`, `261` buffers de `1 MB` entre `00:57:23.8675098Z` e `00:58:20.1785180Z`) armazenou `1.152.206` eventos no total: **`877.901` eventos de `Microsoft-Windows-DxgKrnl`** e **`274.286` eventos de `Microsoft-Windows-Watchdog-Events`** contra apenas `7` sobreviventes de `DriverFrameworks-UserMode` e `3` de WPP `IddCx`.
   - Embora o header indique `Events Lost = 0`, `FirstReliableEventTimeStamp` ficou em `40.937.109 us` (`00:58:04.804Z`) — **`16.8 s` apos a falha (`24.163.371 us`)**, comprovando que `10` de `12` buffers per-CPU do instante `00:57:48` foram sobrescritos pelo buffer circular antes do `logman stop`.
2. **Limite pre-filtro de 500 eventos no parser PowerShell anterior:**
   - A versao anterior de `Get-LumaBridgeEtlEventSummary` interrompia a leitura nos primeiros `500` registros brutos do ETL (`492` eventos `DxgKrnl` + `8` headers), antes de aplicar filtragem por provider, GUID, janela temporal ou PID.
3. **Decodificacao WPP classica do `IddCx` sem cache TMF e canal `Analytic`:**
   - Eventos WPP classicos do `IddCx` (`{D92BCB52-FA78-406F-A9A5-2037509FADEA}`) chegam em `EventLogReader` sem mensagem formatada e com `ProviderId = 00000000-...`, exigindo extracao de `.tmf` via `symchk.exe` + `tracepdb.exe` sobre os simbolos publicos correspondentes aos binarios instalados (`IddCx.dll` `10.0.26100.9818` e `WUDFx02000.dll` `10.0.26100.9818`) e decodificacao com `tracefmt.exe`.
   - Adicionalmente, `Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic` e um canal `Analytic` (`retention: true`), nao consultavel por query padrao simples sem `/q:true` ou sessao ETW dedicada (`{966CD1C0-3F69-42AD-9877-517DCE8462B4}`).
   - `Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace.etl` tinha `65.536` bytes com apenas `2` eventos de cabecalho (`End Time: Not set`).

### Traces WPP/Kernel sobreviventes decodificados de `Attempt2\Etw\LumaBridgeIddTrace.etl`

Com os `.tmf` oficiais extraidos dos simbolos de `IddCx.dll` (`10.0.26100.9818`) e `WUDFx02000.dll` (`10.0.26100.9818`), sobreviveram os seguintes registros na janela exata `21:57:48` (horario local `UTC-3`, equivalente a `00:57:48Z`):

- **PID `23812` (`5D04`, TID `1F7C`, CPU 9) — inicializacao do `IddCx` em `WUDFHost.exe`:**
  - `21:57:48.021`: `[IddCx]?IddCxLibraryInitialize@@YAJXZ: Enter`
  - `21:57:48.021`: `[IddCx]?IddCxLibraryInitialize@@YAJXZ: Exit`
  - `21:57:48.021`: `[IddCx]DriverEntry: Exit, status=STATUS_SUCCESS`
- **PID `4` (System, TID `4456`) — eventos de watchdog e `DxgKrnl` no kernel durante o start (~`21:57:48.029`–`.030`):**
  - `Watchdog-Events/LogWarning` (`Param1 = 0xFFFFFFFFC0000034` / `STATUS_OBJECT_NAME_NOT_FOUND`)
  - `DxgKrnl/DpiDispatchPnp/Start` (`DeviceObject = 0xFFFFBB84F4FCE030`)
  - `Watchdog-Events/LogEvent` (`Param1 = 0xFFFFFFFFC0000034`)
- **Inspecao de binario e breadcrumbs:** A DLL de staging do Attempt2 (`LumaBridgeIddDriver.dll`) contem o nome `"LumaBridgeIddDriver"`, `"DriverStage"` e o GUID do provider TraceLogging (`{A7E4C910-5B32-4F8E-9D21-7C3A1B8E4F01}`). A ausencia de breadcrumbs `Diag*` pode ocorrer quando `LumaBridgePersistStartupDiagnostics` falha em `WdfDeviceOpenRegistryKey(PLUGPLAY_REGKEY_DEVICE, KEY_SET_VALUE)` (por ACL sob `LOCAL SERVICE`) ou quando `IddCxDeviceInitialize`/D0 falha antes do ponto esperado — lacuna agora instrumentada no C++.

---

## 2. Auditoria Estatica vs. Exemplo Oficial Microsoft e `rdpidd.inf`

Ambiente auditado no host: Windows 11 x64 build `26300.9974`, WDK `10.0.28000.0`, MSVC `14.51.36231`, `WUDFx02000.dll` `2.35.0`, UMDF alvo `2.31` (min `2.25`), IddCx alvo `1.4` (min `1.4`), `Driver_SpectreMitigation=Spectre`, Test Signing `Enabled`, Secure Boot `Disabled`.

| Area auditada | Situacao observada no LumaBridge | Referencia / Verificacao no host | Conclusao |
|---|---|---|---|
| **Exports & dependencias da DLL** | `dumpbin /exports /dependents` mostra export `FxDriverEntryUm`, dependencias `d3d11.dll`, `dxgi.dll`, `ntdll.dll`, `KERNEL32.dll` e Win32 API sets (`api-ms-win-*`), zero dependencia de VCRuntime | Driver UMDF C++ sem CRT dinamica externa | Carregamento de dependencias estaticamente integro |
| **Assinatura & CodeIntegrity** | Pacote validado com `signtool` / `CryptCAT*`; log `CodeIntegrity/Operational` sem rejeicoes no horario da falha | Assinatura de teste + `TestSigning=Enabled` ativos | Nao houve bloqueio por assinatura/HVCI/CI |
| **Versao WDF / IddCx ABI** | `WdfBindInfo` (`2.31`, min `25`) e `_IddCx_BIND_INFO` (`1.4`, min `4`) | `WUDFx02000.dll` `2.35.0` no host satisfaz ambas | Compativel; nenhuma evidencia para downgrade |
| **Divergencia WDF schema `2.23` vs `2.31`** | Aviso `"Using WDF schema version 2.23 when section requires version 2.31"` no `setupapi.dev.log` | INFs inbox ativos no host (`usbncmum.inf`, `hidcfu.inf`, `storfwupdate.inf`) emitem exatamente o mesmo aviso | **Benigno** (limitacao do parser do `Wudfrd`/`SetupAPI`, nao e a causa raiz) |
| **Validacao `InfVerif`** | `LumaBridgeIddDriver.inf` estampado em `Debug\|x64` e `Release\|x64` | `infverif.exe /v /u` e `infverif.exe /v /w` retornam exit code `0` | INF estruturalmente valido |
| **Execucao via Driver Store (`DIRID 13`)** | `[DestinationDirs] UMDriverCopy = 13`, `ServiceBinary = %13%\LumaBridgeIddDriver.dll` | `C:\Windows\INF\rdpidd.inf` usa identico `UMDriverCopy = 13` + `%13%\RdpIdd.dll` | `DIRID 13` suportado e funcional no host |
| **Diretivas INF (`NT.Wdf` / `NT.hw`)** | `UmdfExtensions = IddCx0102`, `UpperFilters = IndirectKmd`, `AllowKernelModeClients`, `ProcessSharingDisabled`; `DeviceGroupId` esta em `[LumaBridge_HardwareDeviceSettings]` (`NT.hw`), sem `Security` SDDL explicito | Em `rdpidd.inf`, `DeviceGroupId` fica em `[RdpIdd_Install.AddReg]` (secao do servico) e ha `HKR,, Security,, "D:P(A;;GA;;;WD)"` | Diferenca estrutural anotada apenas como hipotese (INF **nao alterado** sem prova em runtime) |
| **Fluxo `DriverEntry` -> `IddCxAdapterInitAsync`** | `DriverEntry`, `LumaBridgeEvtDeviceAdd` (`IddCxDeviceInitConfig` -> `WdfDeviceCreate` -> `IddCxDeviceInitialize`), `EvtDeviceD0Entry` (`IddCxGetVersion` -> `IDD_STRUCTURE_SIZE` em caps/versoes -> `IddCxAdapterInitAsync`), `EvtIddCxAdapterInitFinished` (`WdfDeviceSetFailed` em erro) | Alinhado a `Windows-driver-samples/video/IndirectDisplay` e `IddCx.h` (`10.0.28000.0`); mutex/locks nao ficam retidos durante `IddCxAdapterInitAsync` | Sem defeito estatico obvio; requer telemetria de runtime para identificar o estagio exacto aos +88 ms |

---

## 3. Hipoteses Ranqueadas (Atualizadas apos Execucao #2)

1. **H1 (Mais provavel) — Falha sincrona ou interna em `IddCxDeviceInitialize`, `EvtDeviceD0Entry` ou `IddCxAdapterInitAsync` (~2.1 ms apos Event `2006`):**
   Na tentativa #2, `WUDFHost.exe` (PID `23812`) carregou `LumaBridgeIddDriver.dll` (`00:57:48.0287643Z`, Event `2006`), `IddCx!DriverEntry` concluiu `STATUS_SUCCESS`, e somente **`235 us` apos** o envio de `IRP_MN_START_DEVICE (27, 0)` o Event `2103` registrou `0xC000009E` (`00:57:48.0308806Z`), seguido **215 us depois** pelo `WATCHDOG` Event `1001` (`00:57:48.0310951Z`). Isso refuta hipotese de timeout prolongado no `WATCHDOG`. Alem disso, diferentemente de `IddSampleDeviceD0Entry` (que sempre retorna `STATUS_SUCCESS`), `LumaBridgeEvtDeviceD0Entry` propaga o `NTSTATUS` retornado por `LumaBridgeStartAdapter`, fazendo com que qualquer erro em `IddCxAdapterInitAsync` ou pre-check falhe `D0Entry`/`IRP_MN_START_DEVICE`.
2. **H2 — Falha em `DriverEntry` / `EvtDeviceAdd` / `IddCxDeviceInitConfig` / `WdfDeviceCreate`:**
   `DriverEntry` ou `EvtDeviceAdd` falha antes de `D0Entry`; na tentativa #2 essa evidencia nao sobreviveu no ETL por sobrescrita circular causada pelo `DxgKrnl` + `Watchdog-Events` (1.152.206 eventos, `FirstReliableEventTimeStamp = +40.937 s`).
3. **H3 — Comportamento especifico de enumeracao raiz (`Root\LumaBridgeIddDriver`) vs `SwDeviceCreate` ou metadados INF (`DeviceGroupId` / `ProcessSharingDisabled`):**
   Deve ser isolado antes de qualquer alteracao no `.inf` por meio do teste de controle com `IddSampleDriver` (`SwDeviceCreate` vs `Root\IddSampleDriver`) e do runbook de WinDbg em [windows-idd-windbg-and-reference-control.md](./windows-idd-windbg-and-reference-control.md).
4. **H4 — Rejeicao assincrona em `EvtIddCxAdapterInitFinished` (`WdfDeviceSetFailed`):**
   `IddCxAdapterInitAsync` retorna `STATUS_SUCCESS`, mas `dxgkrnl`/`IddCx` conclui a inicializacao com falha devido a capacidades/ambiente (`IDDCX_ADAPTER_CAPS`, GPU de renderizacao ou contexto).
5. **H5 (Refutada) — Timeout do `WATCHDOG`, aviso WDF schema `2.23` vs `2.31` ou `CodeIntegrity`:**
   O `WATCHDOG` Event `1001` ocorreu **apos** a falha `2103` (`+215 us`); o aviso WDF schema ocorre igualmente nos INFs inbox do Windows 11; e os logs `CodeIntegrity` e assinatura estao integros.

---

## 4. Instrumentacao Adicionada para Captura Pre-Rollback

### C++ (`LumaBridgeIddDriver`)

- **TraceLogging ETW nativo (`LUMABRIDGE_ENABLE_TRACELOGGING=1`):** provider `"LumaBridgeIddDriver"` (`{A7E4C910-5B32-4F8E-9D21-7C3A1B8E4F01}`), gravando eventos estruturados em paralelo ao `OutputDebugStringA` (`[LB-DRIVER]`) com `level`, `pid`, `tid`, `stage`, `status`, `state`, `lastOk` (`LastSuccessfulStage`) e `msg`.
  - Em `Driver.cpp` / `Driver.h`: `DriverEntry` agora captura o `HRESULT` retornado por `TraceLoggingRegister(g_LumaBridgeTraceProvider)`, consulta `TraceLoggingProviderEnabled(g_LumaBridgeTraceProvider, 0, 0)`, registra `tlRegHr=... tlEnabled=...` no evento inicial de `DriverEntry`, expoe `LumaBridgeGetTraceLoggingRegisterResult()` e `LumaBridgeIsTraceLoggingEnabled()`, e somente chama `TraceLoggingUnregister` quando o registro teve sucesso.
- **Rastreamento completo da sequencia de startup:**
  - `DllMain` minimalista (loader-lock-safe, apenas contador atomico de `DLL_PROCESS_ATTACH` via `LumaBridgeGetDllProcessAttachCount()`).
  - Entrada/saida e `NTSTATUS` em `DriverEntry`, `EvtDriverUnload`, `EvtDeviceAdd`, `IddCxDeviceInitConfig`, `WdfDeviceCreate`, `IddCxDeviceInitialize`, `EvtDeviceD0Entry`, `IddCxGetVersion`, `IddCxAdapterInitAsync`, `EvtIddCxAdapterInitFinished`, `WdfDeviceSetFailed`, `EvtDeviceD0Exit`.
- **Breadcrumbs best-effort na Hardware Key (`PLUGPLAY_REGKEY_DEVICE`):** antes e depois das chamadas `IddCx*`, `Adapter.cpp` grava `DiagLastStage`, `DiagLastSuccessfulStage`, `DiagLastStatus`, `DiagLastErrorStage`, `DiagLastErrorStatus`, `DiagIddCxVersion`, `DiagHostProcessId`, `DiagDllAttachCount` — sem tocar em `EnableVirtualMonitor`. Se `WdfDeviceOpenRegistryKey(PLUGPLAY_REGKEY_DEVICE, KEY_SET_VALUE)` falhar, emite um `LumaBridgeTraceWarn` unico (`[LB-DRIVER]` + ETW) com o `NTSTATUS` real em vez de ignorar silenciosamente.

### Tooling PowerShell (`windows/driver/scripts/`)

- `LumaBridgeDriverCommon.psm1`:
  - Coleta `DEVPKEY_Device_ProblemStatus` (`ProblemStatusHex`), `UpperFilters`/`LowerFilters` e breadcrumbs `Diag*` em `Get-LumaBridgePnpInstances` e exibe `ProblemStatus` em `Test-LumaBridgeDeviceDriverBinding`.
  - Adiciona `Get-LumaBridgeSetupApiLogExcerpt` (parser estreito contextualizado a LumaBridge/Display, evitando falsos positivos como `VBoxSup.inf`), `Get-LumaBridgeEventChannelStatus`, `Get-LumaBridgeDiagnosticEvents`, `Get-LumaBridgeCrashDumpInventory`, `Get-LumaBridgeDriverTraceStageSummary` e hash/DriverVer em `Test-LumaBridgePackageArtifacts`.
  - **Correcao ETW/ETL streaming e WPP:**
    - Remove o teto de `500` eventos pre-filtragem; `Get-LumaBridgeEtlEventSummary` utiliza `Get-LumaBridgeEtlXPathQuery` e `Invoke-LumaBridgeEtlXPathReader` (`EventLogReader` nativo em streaming) aplicando filtros de provider/GUID, `StartTimeUtc`/`EndTimeUtc` e `ProcessId` diretamente no leitor, excluindo por padrao `DxgKrnl` e `Watchdog-Events`, e exposicao de estatisticas (`Get-LumaBridgeEtlTraceStats` com alerta de wrap circular via `FirstReliableEventTimeStamp`).
    - Adiciona `New-LumaBridgeEtwProviderFileContent`, `Test-LumaBridgeEtwSessionProviders`, `Initialize-LumaBridgeWppTmfCache` (`symchk.exe` + `tracepdb.exe`) e `Invoke-LumaBridgeWppEtlDecode` (`tracefmt.exe` com leitura em streaming linha a linha via `[System.IO.File]::ReadLines`).
- `Invoke-LumaBridgeEtwTrace.ps1`:
  - Cria duas sessoes independentes via arquivos `-pf` explícitos (formato `<GUID> <Flags> <Level>`): sessao **sequencial** `LumaBridgeIddCore` (`-f bin -max 256`, `6` providers Core: `LumaBridgeIddDriver`, `Microsoft-Windows-IndirectDisplays-ClassExtension-Events`, `IddCx WPP` com flags `0xFFFFFFFFFFFFFFFF`, `DriverFrameworks-UserMode`, `WDF Core WPP` e `WerKernel`), seguida de verificacao imediata `logman.exe query LumaBridgeIddCore -ets` (`VerifyProviders`). Somente quando `-IncludeDxgKrnl` e passado, inicia a sessao **circular separada** `LumaBridgeIddDxg` (`-f bincirc -max 128`) para `Microsoft-Windows-DxgKrnl` + `Microsoft-Windows-Watchdog-Events`, impedindo saturacao da sessao Core.
  - Suporta acoes `Start`, `Stop`, `Status`, `VerifyProviders`, `ExportSummary` e `DecodeWpp`.
- `Collect-LumaBridgeDiagnostics.ps1`:
  - Ancora automaticamente a janela temporal do ETL (`±30 s` ao redor dos eventos PnP `400`/`411`/`2006`/`2103`), coleta resumo do `LumaBridgeIddCore.etl` e `LumaBridgeIddDxg.etl`, executa `DecodeWpp` opcional (`-DecodeWpp`) e registra `XPathUsed` e `CircularWrapWarning` em `diagnostics-summary.json` / `.md`.
- `Prepare-IddSampleReference.ps1`:
  - Prepara download isolado e compilacao de controle (`IddSampleDriver` + `IddSampleApp` de `microsoft/Windows-driver-samples/video/IndirectDisplay`) fora do repositorio, sem instalar automaticamente no host.

---

## 5. Procedimento Sequencial — Controle Experimental, Depuracao e Tentativa #3 (`EnableVirtualMonitor=0`)

> **Ordem recomendada:** Antes de executar uma 3a instalacao do LumaBridge, siga [windows-idd-windbg-and-reference-control.md](./windows-idd-windbg-and-reference-control.md) para validar o driver de controle `IddSampleDriver` no host e/ou anexar WinDbg + WDF Verifier. Ao executar uma nova captura ETW para o LumaBridge (`Attempt3`), utilize o procedimento atualizado abaixo (sessao `LumaBridgeIddCore` `-f bin` sem `DxgKrnl` no mesmo ETL).

Execute todos os comandos abaixo em um **PowerShell elevado (Administrador)** na raiz do repositorio. Nenhum comando deve habilitar `EnableVirtualMonitor=1` nesta etapa.

### Etapa A — Recompilar pacote Release|x64 e validar estaticamente

Em um prompt do **VS x64 Developer Command Prompt** (`VsDevCmd.bat -arch=amd64 -host_arch=amd64`):

```bat
msbuild windows\driver\LumaBridgeIddDriver.sln /t:Rebuild /p:Configuration=Release;Platform=x64 /m
```

- **Resultado esperado:** build concluido com `0 warnings` e `0 errors`, contendo `LUMABRIDGE_ENABLE_TRACELOGGING=1` e `/Qspectre`.

### Etapa B — Previa Dry-Run (nao destrutiva) e preparar staging assinado

```powershell
$stagingDir = 'C:\Temp\LumaBridgeStaging_Attempt3'
$diagDir    = "$env:LOCALAPPDATA\LumaBridgeDisplay\Diagnostics\Attempt3"
$etwDir     = "$diagDir\Etw"
$etlPath    = "$etwDir\LumaBridgeIddCore.etl"
$dxgEtlPath = "$etwDir\LumaBridgeIddDxg.etl"

# 1. Previa nao destrutiva
.\windows\driver\scripts\Test-LumaBridgePrerequisites.ps1 -Configuration Release -StagingDir $stagingDir
.\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 -Action Start -OutputDir $etwDir -EtlPath $etlPath -DryRun
.\windows\driver\scripts\Install-LumaBridgeDriver.ps1 -Configuration Release -StagingDir $stagingDir -DiagnosticsOutputDir $diagDir -EtlPath $etlPath -DryRun

# 2. Assinar pacote em staging isolado (reutiliza certificado ou cria e confia explicitamente)
$signResult = .\windows\driver\scripts\Invoke-LumaBridgePackageSigning.ps1 `
    -Configuration Release `
    -StagingDir $stagingDir `
    -CreateTestCertificateIfMissing `
    -TrustCertificate `
    -Force
```

- **Criterio de aprovacao:** `$signResult.Verification.IsCryptographicallyValid -eq $true`, hashes dos binarios originais em `windows\driver\x64\Release\LumaBridgeIddDriver` preservados.

### Etapa C — Habilitar temporariamente os canais ETW/EventLog de UMDF e IddCx

*(Habilite somente durante esta captura e desabilite na Etapa F.)*

```powershell
wevtutil.exe sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /e:true
wevtutil.exe sl "Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic" /e:true

# Conferir estado dos canais antes de iniciar
.\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 -Action Status -OutputDir $etwDir -EtlPath $etlPath
```

- **Resultado esperado:** ambos os canais reportam `IsEnabled = True`.

### Etapa D — Iniciar captura Core sequencial (`-pf`), verificar providers e instalar com `EnableVirtualMonitor=0`

1. *(Opcional recomendado)* Abrir Sysinternals **DebugView** como Administrador com *Capture Win32*, *Capture Global Win32* e *Log to File* salvando em `"$diagDir\debugview.log"`.
2. Iniciar a sessao sequencial `LumaBridgeIddCore` (adicione `-IncludeDxgKrnl` somente se quiser o `DxgKrnl` na sessao circular separada `LumaBridgeIddDxg`), confirmar `AllProvidersVerified -eq $true` e executar `Install-LumaBridgeDriver.ps1`:

```powershell
# 1. Iniciar sessao sequencial Core via -pf (opcionalmente adicione -IncludeDxgKrnl para sessao separada DxgKrnl)
$traceStart = .\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 `
    -Action Start `
    -OutputDir $etwDir `
    -EtlPath $etlPath `
    -DxgEtlPath $dxgEtlPath `
    -Force

$traceStart.ProviderVerification | Format-List AllProvidersVerified, MissingProviderGuids
.\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 -Action VerifyProviders -OutputDir $etwDir

# 2. Executar instalacao controlada mantendo EnableVirtualMonitor=0 e captura pre-rollback
.\windows\driver\scripts\Install-LumaBridgeDriver.ps1 `
    -Configuration Release `
    -StagingDir $stagingDir `
    -DiagnosticsOutputDir $diagDir `
    -EtlPath $etlPath `
    -Force
# Se estiver gravando DebugView em arquivo, passe tambem: -DebugLogPath "$diagDir\debugview.log"
```

### Etapa E — Parar captura ETW, decodificar WPP/ETL em streaming e inspecionar evidencias

```powershell
.\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 `
    -Action Stop `
    -OutputDir $etwDir `
    -EtlPath $etlPath `
    -DxgEtlPath $dxgEtlPath `
    -DecodeWpp `
    -Force

# Inspecionar artefatos preservados:
Get-Content -LiteralPath "$diagDir\diagnostics-summary.md"
Get-Content -LiteralPath "$etwDir\etw-decoded-events.json"
Get-Content -LiteralPath "$etwDir\wpp-decoded-summary.json" -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath "C:\Windows\LiveKernelReports\WATCHDOG" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5
```

*(Para reprocessar manualmente os `.etl` existentes ou com janela temporal / PID especifico sem nova instalacao:)*

```powershell
.\windows\driver\scripts\Collect-LumaBridgeDiagnostics.ps1 `
    -Configuration Release `
    -StagingDir $stagingDir `
    -OutputDir "$diagDir\PostEtwMerge" `
    -EtlPath $etlPath `
    -DxgEtlPath $dxgEtlPath `
    -DecodeWpp `
    -DebugLogPath "$diagDir\debugview.log"
```

### Etapa F — Limpeza completa e restauracao do host (Recuperacao)

```powershell
# 1. Garantir parada das sessoes ETW caso ainda estejam ativas
logman.exe stop LumaBridgeIddCore -ets 2>$null
logman.exe stop LumaBridgeIddDxg -ets 2>$null
logman.exe stop LumaBridgeIddTrace -ets 2>$null

# 2. Desabilitar os canais que estavam desligados antes do teste
wevtutil.exe sl "Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic" /e:false
wevtutil.exe sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /e:false

# 3. Remover dispositivo, pacote OEM e certificado somente se ainda presentes (substituir pelo thumbprint usado)
.\windows\driver\scripts\Uninstall-LumaBridgeDriver.ps1 `
    -RemoveTestCertificate `
    -CertificateThumbprint $signResult.CertificateThumbprint `
    -ConfirmCertificateRemoval `
    -Force
```
