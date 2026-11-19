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

## 3. Hipoteses Ranqueadas (Aguardando Confirmacao em Runtime)

1. **H1 (Mais provavel) — Falha ou timeout em `IddCxDeviceInitialize`, `EvtDeviceD0Entry` ou `IddCxAdapterInitAsync` (~88 ms):**
   O host `WUDFHost.exe` inicia o driver e chega ao `IddCx`/`IndirectKmd`, onde uma falha de comunicacao com o subsistema grafico (`dxgkrnl`/`IndirectKmd`) dispara o `WATCHDOG` Live Kernel Dump (Event `1001` aos +88 ms) e devolve `STATUS_DEVICE_POWER_FAILURE` (`0xC000009E`) ao PnP aos +97 ms.
2. **H2 — Falha em `DriverEntry` / `EvtDeviceAdd` / `IddCxDeviceInitConfig` ou falha previa do refletor UMDF:**
   `WUDFRd` nao consegue carregar/vincular `LumaBridgeIddDriver.dll` ou um dos passos iniciais em `EvtDeviceAdd` falha sem emitir log habilitado na tentativa #1.
3. **H3 — Diferenca de metadados INF (`DeviceGroupId` em `NT.hw` vs secao de servico `AddReg`, ou ausencia de descritor `Security` SDDL):**
   `IndirectKmd.sys` ou `WUDFRd` pode exigir o contexto `WUDF\DeviceGroupId` na chave do servico UMDF ou permissoes especificas no objeto de dispositivo para o canal kernel/user-mode. *Nao modificar o INF antes de confirmar H1/H2 via traces.*
4. **H4 — Rejeicao assincrona em `EvtIddCxAdapterInitFinished`:**
   `IddCxAdapterInitAsync` retorna `STATUS_SUCCESS`, mas `dxgkrnl`/`IddCx` conclui a inicializacao com erro devido aos parametros de `IDDCX_ADAPTER_CAPS` (`TransmissionType`, `MaxDisplayPipelineRate`, versoes).
5. **H5 (Refutada estaticamente como causa primaria) — Aviso WDF schema `2.23` vs `2.31` ou CodeIntegrity:**
   Contradito pelos INFs inbox do proprio Windows 11 que emitem o mesmo aviso e pelo status valido da assinatura/CI.

---

## 4. Instrumentacao Adicionada para Captura Pre-Rollback

### C++ (`LumaBridgeIddDriver`)

- **TraceLogging ETW nativo (`LUMABRIDGE_ENABLE_TRACELOGGING=1`):** provider `"LumaBridgeIddDriver"` (`{A7E4C910-5B32-4F8E-9D21-7C3A1B8E4F01}`), gravando eventos estruturados em paralelo ao `OutputDebugStringA` (`[LB-DRIVER]`) com `level`, `pid`, `tid`, `stage`, `status`, `state`, `lastOk` (`LastSuccessfulStage`) e `msg`.
- **Rastreamento completo da sequencia de startup:**
  - `DllMain` minimalista (loader-lock-safe, apenas contador atomico de `DLL_PROCESS_ATTACH` via `LumaBridgeGetDllProcessAttachCount()`).
  - Entrada/saida e `NTSTATUS` em `DriverEntry`, `EvtDriverUnload`, `EvtDeviceAdd`, `IddCxDeviceInitConfig`, `WdfDeviceCreate`, `IddCxDeviceInitialize`, `EvtDeviceD0Entry`, `IddCxGetVersion`, `IddCxAdapterInitAsync`, `EvtIddCxAdapterInitFinished`, `WdfDeviceSetFailed`, `EvtDeviceD0Exit`.
- **Breadcrumbs best-effort na Hardware Key (`PLUGPLAY_REGKEY_DEVICE`):** antes e depois das chamadas `IddCx*`, `Adapter.cpp` grava `DiagLastStage`, `DiagLastSuccessfulStage`, `DiagLastStatus`, `DiagLastErrorStage`, `DiagLastErrorStatus`, `DiagIddCxVersion`, `DiagHostProcessId`, `DiagDllAttachCount` — sem tocar em `EnableVirtualMonitor`.

### Tooling PowerShell (`windows/driver/scripts/`)

- `LumaBridgeDriverCommon.psm1`:
  - Coleta `DEVPKEY_Device_ProblemStatus` (`ProblemStatusHex`), `UpperFilters`/`LowerFilters` e breadcrumbs `Diag*` em `Get-LumaBridgePnpInstances` e exibe `ProblemStatus` em `Test-LumaBridgeDeviceDriverBinding`.
  - Adiciona `Get-LumaBridgeSetupApiLogExcerpt`, `Get-LumaBridgeEventChannelStatus`, `Get-LumaBridgeDiagnosticEvents` (Kernel-PnP Configuration/Device Management/Driver Watchdog, CodeIntegrity, DriverFrameworks-UserMode, WerKernel, DxgKrnl Admin/Operational, IddCx Diagnostic e System), `Get-LumaBridgeCrashDumpInventory`, `Get-LumaBridgeEtlEventSummary`, `Get-LumaBridgeDriverTraceStageSummary` e hash/DriverVer em `Test-LumaBridgePackageArtifacts`.
- `Invoke-LumaBridgeEtwTrace.ps1`:
  - Gerencia sessao ETW `-ets` (`logman`) habilitando `LumaBridgeIddDriver`, `Microsoft-Windows-IndirectDisplays-ClassExtension-Events`, `IddCx WPP` (`0x4000000004f4`), `DriverFrameworks-UserMode`, `WDF Core WPP`, `Watchdog-Events`, `WerKernel` e opcionalmente `Microsoft-Windows-DxgKrnl` (`-IncludeDxgKrnl`).
- `Collect-LumaBridgeDiagnostics.ps1`:
  - Consolida pacotes/hashes, status dos canais, eventos filtrados, excerto filtrado do `setupapi.dev.log`, inventario de dumps (`WDF`, `LiveKernelReports\WATCHDOG`, `CrashDumps`, `WER`, AutoLogger `RdpIdd`), resumo ETL e `StageExecutionSummary` (`DriverEntryReached`, `LastStage`, `LastSuccessfulStage`, `FirstFailureStage`, `FirstFailureStatusHex`) em `diagnostics-summary.json`, `diagnostics-summary.md` e `setupapi-excerpt.log`.
- `Install-LumaBridgeDriver.ps1`:
  - Em qualquer falha de instalacao/atualizacao, **antes** do rollback remover a instancia PnP e o `oemXX.inf`, executa `Collect-LumaBridgeDiagnostics.ps1` (sem bloquear o rollback em caso de erro de coleta) e grava `post-rollback-status.json` apos o rollback.

---

## 5. Procedimento Sequencial — Segunda Tentativa Instrumentada (`EnableVirtualMonitor=0`)

Execute todos os comandos abaixo em um **PowerShell elevado (Administrador)** na raiz do repositorio. Nenhum comando deve habilitar `EnableVirtualMonitor=1` nesta etapa.

### Etapa A — Recompilar pacote Release|x64 e validar estaticamente

Em um prompt do **VS x64 Developer Command Prompt** (`VsDevCmd.bat -arch=x64 -host_arch=x64`):

```bat
msbuild windows\driver\LumaBridgeIddDriver.sln /t:Build /p:Configuration=Release;Platform=x64 /m
```

- **Resultado esperado:** build concluido com `0 warnings` e `0 errors`, contendo `LUMABRIDGE_ENABLE_TRACELOGGING=1` e `/Qspectre`.

### Etapa B — Previa Dry-Run (nao destrutiva) e preparar staging assinado

```powershell
$stagingDir = 'C:\Temp\LumaBridgeStaging_Attempt2'
$diagDir    = "$env:LOCALAPPDATA\LumaBridgeDisplay\Diagnostics\Attempt2"
$etwDir     = "$diagDir\Etw"
$etlPath    = "$etwDir\LumaBridgeIddTrace.etl"

# 1. Previa nao destrutiva
.\windows\driver\scripts\Test-LumaBridgePrerequisites.ps1 -Configuration Release -StagingDir $stagingDir
.\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 -Action Start -IncludeDxgKrnl -OutputDir $etwDir -EtlPath $etlPath -DryRun
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

*(Esses canais estavam desabilitados na tentativa #1; habilite somente durante esta captura e desabilite na Etapa F.)*

```powershell
wevtutil.exe sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /e:true
wevtutil.exe sl "Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic" /e:true

# Conferir estado dos canais antes de iniciar
.\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 -Action Status -OutputDir $etwDir -EtlPath $etlPath
```

- **Resultado esperado:** ambos os canais reportam `IsEnabled = True`.

### Etapa D — Iniciar captura ETW (e opcionalmente DebugView) e executar instalacao instrumentada

1. *(Opcional recomendado)* Abrir Sysinternals **DebugView** como Administrador com *Capture Win32*, *Capture Global Win32* e *Log to File* salvando em `"$diagDir\debugview.log"`.
2. Iniciar a sessao ETW e executar `Install-LumaBridgeDriver.ps1` com `EnableVirtualMonitor=0`:

```powershell
# Iniciar sessao ETW LumaBridgeIddTrace (-IncludeDxgKrnl opcional, recomendado na tentativa #2)
.\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 `
    -Action Start `
    -IncludeDxgKrnl `
    -OutputDir $etwDir `
    -EtlPath $etlPath `
    -Force

# Executar instalacao controlada mantendo EnableVirtualMonitor=0 e captura pre-rollback
.\windows\driver\scripts\Install-LumaBridgeDriver.ps1 `
    -Configuration Release `
    -StagingDir $stagingDir `
    -DiagnosticsOutputDir $diagDir `
    -EtlPath $etlPath `
    -Force
# Se estiver gravando DebugView em arquivo, passe tambem: -DebugLogPath "$diagDir\debugview.log"
```

### Etapa E — Parar captura ETW, decodificar ETL e coletar/inspecionar evidencias

Mesmo que `Install-LumaBridgeDriver.ps1` falhe e dispare rollback automatico, os arquivos pre-rollback ja estarao salvos em `$diagDir`. Pare o trace ETW logo em seguida:

```powershell
.\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 `
    -Action Stop `
    -OutputDir $etwDir `
    -EtlPath $etlPath `
    -Force

# Inspecionar artefatos preservados:
Get-Content -LiteralPath "$diagDir\diagnostics-summary.md"
Get-Content -LiteralPath "$etwDir\etw-decoded-events.json"
Get-ChildItem -LiteralPath "C:\Windows\LiveKernelReports\WATCHDOG" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5
```

*(Caso o DebugView tenha sido gravado apos a captura ou para reprocessar com o DebugLog completo, execute:)*

```powershell
.\windows\driver\scripts\Collect-LumaBridgeDiagnostics.ps1 `
    -Configuration Release `
    -StagingDir $stagingDir `
    -OutputDir "$diagDir\PostEtwMerge" `
    -EtlPath $etlPath `
    -DebugLogPath "$diagDir\debugview.log"
```

- **O que observar no resultado:**
  1. `StageExecutionSummary.DriverEntryReached`: indica se `WUDFRd` conseguiu carregar `LumaBridgeIddDriver.dll` e entrar em `DriverEntry`.
  2. `StageExecutionSummary.LastSuccessfulStage` e `FirstFailureStage` / `FirstFailureStatusHex`: aponta exatamente em qual chamada (`DeviceInitConfig`, `WdfDeviceCreate`, `IddCxDeviceInitialize`, `DeviceD0Entry`, `IddCxGetVersion`, `IddCxAdapterInitAsync`, `EvtIddCxAdapterInitFinished`) o driver parou antes do `WATCHDOG` (+88 ms).
  3. Eventos em `etw-decoded-events.json` (`Microsoft-Windows-IndirectDisplays-ClassExtension-Events` / `DriverFrameworks-UserMode` / `WerKernel`) e eventuais dumps novos em `C:\Windows\LiveKernelReports\WATCHDOG` ou `C:\ProgramData\Microsoft\WDF`.

### Etapa F — Limpeza completa e restauracao do host (Recuperacao)

Caso a instalacao tenha tido sucesso inesperado (ou se precisar limpar residuos) e para restaurar os canais de diagnostico do Windows:

```powershell
# 1. Garantir parada da sessao ETW caso ainda esteja ativa
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
