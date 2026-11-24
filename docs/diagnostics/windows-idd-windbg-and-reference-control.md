# Controle Experimental (`IddSampleDriver`), Depuracao WinDbg e Isolamento Incremental — Issue #34

Data: 2026-11-19
Branch: `fix/windows-idd-device-start`
Escopo: Milestone M3 — Windows Virtual Display / Issue #34

> **Politica de controle e seguranca:** Nenhum comando abaixo instala drivers automaticamente, altera registro, certificados, Boot Configuration Data (`BCD`), desativa `Secure Boot`, nem desativa protecoes de seguranca/watchdog do `IddCx`. Execute apenas manualmente em ambiente dedicado de testes e realize a limpeza completa ao final.

---

## 1. Matriz Comparativa Semantica e Binaria (15 Pontos): `IddSampleDriver` vs. `LumaBridgeIddDriver`

Comparacao verificada entre a compilacao isolada de `microsoft/Windows-driver-samples` (`video/IndirectDisplay` em `<WorkDir>\IndirectDisplay`, ex.: `%TEMP%\LumaBridgeReference\IndirectDisplay`), os binarios do runtime Windows 11 (`IddCx.dll` e `WUDFx02000.dll` `10.0.26100.9818`) via `cdb.exe`, e `windows/driver/LumaBridgeIddDriver`:

| # | Dimensao comparada | `IddSampleDriver` (Controle Microsoft — PASSOU) | `LumaBridgeIddDriver` (Antes da correcao -> Apos correcao) | Veredito / Prova `cdb.exe` |
|---|---|---|---|---|
| 1 | **`DriverEntry` e vinculo WDF (`WdfBindInfo`)** | `Version = 2.25.0`, `Min = 25`, `FuncCount = 0x10C`, `StructCount = 0x4D`. `DriverEntry` chama apenas `WdfDriverCreate`. | `Version = 2.31.0`, `Min = 25`, `FuncCount = 0x111`, `StructCount = 0x4E`. Registra `TraceLogging` (`Stage >= 3`) + `WdfDriverCreate`. | `WUDFx02000.dll` `10.0.26100.9818` aceita ambas; Event `2006` confirmou carregamento no nivel `0`. |
| 2 | **Vinculo `IddCx` (`_IddCx_BIND_INFO`)** | `Size = 0x78`, `ClassName = "IddCx"`, `Version = 1.4.0`, `Min = 4`, `FunctionTableCount = 0x19`, `StructCount = 0x47`. | **100% identico** (`Size = 0x78`, `Version = 1.4.0`, `Min = 4`, `0x19`, `0x47`). | Binarios vinculados ao exato mesmo ABI IddCx `1.4`. |
| 3 | **`EvtDeviceAdd` &Callbacks PnP/Power** | Registra `EvtDeviceD0Entry` (`EvtDeviceD0Exit` omitido). | Registra `EvtDeviceD0Entry` e `EvtDeviceD0Exit`. | Sem impacto negativo no start; `D0Exit` gerencia suspensao D3. |
| 4 | **`IDD_CX_CLIENT_CONFIG` e `IddCxDeviceInitConfig`** | `IDD_CX_CLIENT_CONFIG_INIT`, preenche 7 callbacks obrigatorios (`0xA8` bytes para 1.4). | Identico (`0xA8` bytes, 7 callbacks nao nulos validados por `IddCx!Validate` `000000018001a5d0`). | Totalmente conforme `IddCx!IddCxImplDeviceInitConfig`. |
| 5 | **`WdfDeviceCreate` -> `IddCxDeviceInitialize`** | `WdfDeviceCreate` -> `IddCxDeviceInitialize` -> `new IndirectDeviceContext`. | `WdfDeviceCreate` -> `LumaBridgeInitializeDeviceContext` -> aloca `DeviceSwapChainHost` (com `StateLock`, `Stage >= 4`) -> `IddCxDeviceInitialize`. | `IddCx!IddCxImplDeviceInitialize` (`0000000180022720`) cria filas e copia config do `WDFDEVICE_INIT` independentemente do contexto do driver. |
| 6 | **Ordem de inicializacao dos contextos** | Contexto unico `IndirectDeviceContextWrapper` em `WDFDEVICE` e `IDDCX_ADAPTER`. | Contextos separados (`LumaBridgeDeviceContext`, `LumaBridgeAdapterContext`, `LumaBridgeMonitorContext`) associados por `g_AdapterInitGate`. | Nao causa rejeicao em `IddCxDeviceInitialize` / `IddCxAdapterInitAsync`. |
| 7 | **`EvtDeviceD0Entry` e propagacao de `NTSTATUS`** | `IddSampleDeviceD0Entry` chama `VOID InitAdapter()` e **sempre retorna `STATUS_SUCCESS`**, mascarando falha de `IddCxAdapterInitAsync`. | `LumaBridgeEvtDeviceD0Entry` propaga o `NTSTATUS` de `LumaBridgeStartAdapter`. | **`WUDFx02000!FxPkgPnp::PnpEventHardwareAvailablePowerPolicyFailed` (`000000018008edf0`)** traduz falha em `D0Entry` para `0xC000009E` (`Event 2103`). **Regra preservada: nunca mascarar falhas.** |
| 8 | **`IDDCX_ADAPTER_CAPS.Size` (`IDD_STRUCTURE_SIZE` vs `sizeof`)** | `sizeof(AdapterCaps) = 0x58`, `sizeof(EndPointDiagnostics) = 0x38`, `sizeof(Version) = 0x18`. | `IDD_STRUCTURE_SIZE(...)` produz os exatos mesmos tamanhos em IddCx `1.4`: `0x58`, `0x38`, `0x18`. | Conforme `IddCx!Validate(IDDCX_ADAPTER_CAPS)` (`00000001800194b0`). |
| 9 | **`IDDCX_ENDPOINT_DIAGNOSTIC_INFO.TransmissionType`** | **`IDDCX_TRANSMISSION_TYPE_WIRED_OTHER` (`3`)**. | **Antes:** `IDDCX_TRANSMISSION_TYPE_NETWORK_OTHER` (`9`). **Apos fix:** `kAdapterTransmissionType = IDDCX_TRANSMISSION_TYPE_WIRED_OTHER` (`3`). | **CAUSA RAIZ #1:** `IddCx!Validate+0x13e` (`00000001800195ee`) testa `lea eax, [rcx-9]; cmp eax, 0FFFFFFF5h; ja VALID`, rejeitando `9` com `0xC000000D` (`"Invalid IDDCX_TRANSMISSION_TYPE, value %d"`). |
| 10 | **`IDDCX_ENDPOINT_VERSION` e `GammaSupport`** | `MajorVer = 1` (`0|Minor|Build|SKU != 0`), `GammaSupport = NONE (1)`, `MaxMonitorsSupported = 3`, `MaxDisplayPipelineRate = 0`. | **Antes:** `MajorVer = 0, MinorVer = 1`. **Apos fix:** `kEndpointMajorVersion = 1, MinorVer = 1`, `GammaSupport = NONE (1)`, `MaxMonitorsSupported = 1`, `MaxDisplayPipelineRate = 2560*1440*60`. | Todos aprovados por `IddCx!Validate(IDDCX_ENDPOINT_VERSION)` (`0000000180019c44`). |
| 11 | **`IddCxAdapterInitAsync`** | Chamada direta sem lock adicional. | Locks liberados antes da chamada (`g_InFlightInitSlot` protege janela nao vinculada). | Na tentativa #2 falhou sincronamente em `Validate` antes mesmo de retornar `AdapterObject`. |
| 12 | **`EvtIddCxAdapterInitFinished`** | Conclui criacao assincrona dos monitores. | Atualiza `AdapterLifecycleTracker`; se `!NT_SUCCESS`, chama `WdfDeviceSetFailed(WdfDeviceFailedNoRestart)`; em `AdapterReady` e `Stage >= 4`, aciona `VirtualMonitorManager`. | Nao chegou a ser invocada no Attempt #2 devido ao erro sincrono em `IddCxAdapterInitAsync`. |
| 13 | **Criacao/enumeracao do dispositivo** | `SwDeviceCreate` (`SWD\...`) e `devcon install` (`ROOT\DISPLAY\0000`) **ambos passaram** no host. | `devcon install ... "Root\LumaBridgeIddDriver"` (`ROOT\DISPLAY\0000`). | Controle comprovou que enumeracao `ROOT` e `IndirectKmd` estao saudaveis. |
| 14 | **Diretivas INF e isolamento `WUDFHost`** | `%12%\UMDF\`, sem `ProcessSharingDisabled`, `DeviceGroupId` em `NT.hw`. | `%13%\` (`DIRID 13`), `UmdfHostProcessSharing = ProcessSharingDisabled`, `DeviceGroupId = LumaBridgeIddGroup` em `NT.hw`, passa `InfVerif /v /u` e `/v /w`. | INF preservado intacto (Spectre, UMDF `2.31`, IddCx `1.4`). |
| 15 | **Breadcrumbs `WdfDeviceOpenRegistryKey`** | Nao grava `Diag*` em registro. | **Antes:** `PLUGPLAY_REGKEY_DEVICE` abria `\` sem escrita sob `LOCAL SERVICE`. **Apos fix:** `PLUGPLAY_REGKEY_DEVICE \| WDF_REGKEY_DEVICE_SUBKEY` (`1 \| 256`) + `DiagBuildStage`. | **`WUDFx02000!FxDevice::_OpenDeviceRegistryKey` (`00000001800341a4`):** bit 8 abre `Device Parameters\LumaBridgeIddDriver` gravavel. |

---

## 2. Resultado Registrado do Controle Experimental (`IddSampleDriver`)

Executado manualmente pelo operador no mesmo host (`Windows 11 x64 26300.9974`, `NVIDIA GeForce RTX 3060 Ti`):

| Modo do controle | InstanceId | Status PnP / ProblemCode | ProblemStatus | Monitores criados | Limpeza pos-teste |
|---|---|---|---|---|---|
| `SwDeviceCreate` (`IddSampleApp.exe`) | `SWD\IDDSAMPLEDRIVER\IDDSAMPLEDRIVER` | `OK` | — | `3` | Encerrado |
| `ROOT` via `DevCon` (`Root\IddSampleDriver`) | `ROOT\DISPLAY\0000` | `OK` / `0` | `Empty` | `3` | `ROOT\DISPLAY\0000` e pacote OEM (`oemXX.inf`) removidos sem erros |

*(O script isolado [Prepare-IddSampleReference.ps1](../../windows/driver/scripts/Prepare-IddSampleReference.ps1) permanece disponivel para eventuais re-validacoes de referencia sem tocar no repositorio.)*

---

## 3. Runbook de Depuracao WinDbg e WDF Verifier

### Caminhos verificados no host (WDK `10.0.28000.0` / Debuggers x64)

- **WinDbg GUI:** `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe`
- **CDB console:** `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe`
- **WDF Verifier:** `C:\Program Files (x86)\Windows Kits\10\Tools\10.0.28000.0\x64\wdfverifier.exe`
- **Symchk:** `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe`
- **TracePDB / TraceFmt:** `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\tracepdb.exe` e `tracefmt.exe`

### 3.1 Preparar simbolos locais e Microsoft Symbol Server

Garanta o mesmo PDB do build instalado em Staging/Release (`_NT_SYMBOL_PATH`):

```powershell
$repoRoot = (Get-Location).Path
$pdbDir   = Join-Path $repoRoot 'windows\driver\x64\Release'
$symCache = Join-Path $env:TEMP 'LumaBridgeSymCache'
New-Item -Path $symCache -ItemType Directory -Force | Out-Null

# Pre-baixar PDBs de sistema (opcional, acelera WinDbg)
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /if 'C:\Windows\System32\drivers\UMDF\IddCx.dll' /s "srv*$symCache*https://msdl.microsoft.com/download/symbols"
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /if 'C:\Windows\System32\WUDFx02000.dll' /s "srv*$symCache*https://msdl.microsoft.com/download/symbols"

$env:_NT_SYMBOL_PATH = "$pdbDir;srv*$symCache*https://msdl.microsoft.com/download/symbols"
```

### 3.2 Configurar `wdfverifier.exe` para capturar startup antes da falha de ~2 ms

Como na tentativa #2 `WUDFHost.exe` iniciou e falhou em ~2.1 ms apos o carregamento do driver, e necessario configurar `HostProcessDbgBreakOnDriverLoad` (ou `HostProcessDbgBreakOnStart`) antes de rodar `Install-LumaBridgeDriver.ps1`:

1. Abra **`C:\Program Files (x86)\Windows Kits\10\Tools\10.0.28000.0\x64\wdfverifier.exe`** como **Administrador**.
2. Se o driver ainda nao estiver instalado permanentemente (rollback ativo), habilite as opcoes globais UMDF para verificacao e espera de debugger no host process:
   - Ative **UMDF Application Verifier / Track Object References / Log verbose IFR** conforme disponivel para `LumaBridgeIddDriver` (ou apos staging via `pnputil /add-driver` na secao de servico `LumaBridgeIddDriver`).
   - Defina **`HostProcessDbgBreakOnDriverLoad = 0xFFFFFFFF`** (ou valor decimal em segundos, ex.: `60`, na chave de configuracao UMDF do servico ou pela UI do `wdfverifier.exe`), ou use `windbg.exe -server tcp:port=5005` / **Attach to WUDFHost.exe** (`-pn WUDFHost.exe` com Image File Execution Options somente em VM dedicada de testes).
   - **Nota sobre `LOCAL SERVICE`:** `WUDFHost.exe` roda sob a conta `NT AUTHORITY\LOCAL SERVICE`. Execute o **WinDbg como Administrador elevado** para poder anexar ao processo ou utilize debuggers UMDF configurados via `wdfverifier`.
3. **Importante:** Restaure as opcoes do `wdfverifier` ao valor original ao concluir a investigacao.

### 3.3 Os 9 Breakpoints Obrigatorios e Inspecoes em Runtime

Todos os nomes de simbolos abaixo foram verificados diretamente com `cdb.exe` contra `LumaBridgeIddDriver.dll`, `IddCx.dll` e `WUDFx02000.dll` instalados no host. Execute os comandos abaixo na janela de comandos do WinDbg logo apos o carregamento de `LumaBridgeIddDriver.dll` (`ld LumaBridgeIddDriver; ld IddCx; ld WUDFx02000`):

```dbg
.sympath <RepoRoot>\windows\driver\x64\Release;srv*%TEMP%\LumaBridgeSymCache*https://msdl.microsoft.com/download/symbols
.reload /f

* --- 1. Entrada do WDF UMDF Stub ---
bu LumaBridgeIddDriver!FxDriverEntryUm ".echo [BP1] FxDriverEntryUm; k 6; gu; r rax; g"

* --- 2. DriverEntry (verifique retorno STATUS e TraceLoggingRegister HRESULT) ---
bu LumaBridgeIddDriver!DriverEntry ".echo [BP2] DriverEntry; k 6; gu; .echo [BP2 RET RAX=NTSTATUS]; r rax; g"

* --- 3. EvtDeviceAdd (verifique rcx=Driver, rdx=DeviceInit) ---
bu LumaBridgeIddDriver!LumaBridgeEvtDeviceAdd ".echo [BP3] LumaBridgeEvtDeviceAdd; r rcx rdx; gu; .echo [BP3 RET RAX=NTSTATUS]; r rax; g"

* --- 4. IddCxDeviceInitConfig (inlined stub no LumaBridge + impl real em IddCx.dll) ---
bu LumaBridgeIddDriver!IddCxDeviceInitConfig ".echo [BP4a] Stub IddCxDeviceInitConfig; dt -b iddConfig; g"
bu IddCx!IddCxImplDeviceInitConfig ".echo [BP4b] IddCxImplDeviceInitConfig; gu; .echo [BP4b RET RAX=NTSTATUS]; r rax; g"

* --- 5. WdfDeviceCreate (versao padrao e Verifier) ---
bu WUDFx02000!imp_WdfDeviceCreate ".echo [BP5] imp_WdfDeviceCreate; gu; .echo [BP5 RET RAX=NTSTATUS]; r rax; g"
bu WUDFx02000!imp_VfWdfDeviceCreate ".echo [BP5v] imp_VfWdfDeviceCreate; gu; .echo [BP5v RET RAX=NTSTATUS]; r rax; g"

* --- 6. IddCxDeviceInitialize (inlined stub + impl real em IddCx.dll) ---
bu LumaBridgeIddDriver!IddCxDeviceInitialize ".echo [BP6a] Stub IddCxDeviceInitialize; g"
bu IddCx!IddCxImplDeviceInitialize ".echo [BP6b] IddCxImplDeviceInitialize; gu; .echo [BP6b RET RAX=NTSTATUS]; r rax; g"

* --- 7. EvtDeviceD0Entry ---
bu LumaBridgeIddDriver!LumaBridgeEvtDeviceD0Entry ".echo [BP7] LumaBridgeEvtDeviceD0Entry; r rcx rdx; gu; .echo [BP7 RET RAX=NTSTATUS]; r rax; g"

* --- 8. IddCxAdapterInitAsync (inlined stub + impl real em IddCx.dll) ---
bu LumaBridgeIddDriver!IddCxAdapterInitAsync ".echo [BP8a] Stub IddCxAdapterInitAsync; dt adapterCaps; g"
bu IddCx!IddCxImplAdapterInitAsync ".echo [BP8b] IddCxImplAdapterInitAsync; gu; .echo [BP8b RET RAX=NTSTATUS]; r rax; g"

* --- 9. EvtIddCxAdapterInitFinished ---
bu LumaBridgeIddDriver!LumaBridgeEvtAdapterInitFinished ".echo [BP9] LumaBridgeEvtAdapterInitFinished; dt -b *((LumaBridgeIddDriver!IDARG_IN_ADAPTER_INIT_FINISHED*)@rdx); g"
```

**Comandos de inspecao quando o erro aparecer (`rax != 0` ou excecao C++ / WDF):**

```dbg
!load wdfkd
!wdfkd.wdfdriverinfo LumaBridgeIddDriver 0x10
!wdfkd.wdflogdump LumaBridgeIddDriver
!teb
dv /t /v
```

### 3.4 Inspecao de Live Kernel Dumps (`WATCHDOG`)

Quando houver arquivos recentes em `C:\Windows\LiveKernelReports\WATCHDOG\*.dmp` gerados no horario da falha:

```powershell
Get-ChildItem 'C:\Windows\LiveKernelReports\WATCHDOG\*.dmp' | Sort-Object LastWriteTime -Descending | Select-Object -First 5 FullName, Length, LastWriteTime
```

Abra o dump mais recente no WinDbg/CDB elevado com o `_NT_SYMBOL_PATH` configurado:

```bat
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe" -z "C:\Windows\LiveKernelReports\WATCHDOG\<ARQUIVO>.dmp" -y "srv*%TEMP%\LumaBridgeSymCache*https://msdl.microsoft.com/download/symbols" -c "!analyze -v; !blackboxbsd; lmvm IndirectKmd; lmvm dxgkrnl; !wdfkd.wdflogdump IndirectKmd; q"
```

---

## 4. Plano de Variante Diagnostica em 7 Estagios (`LUMABRIDGE_DIAGNOSTIC_STAGE` `1..6` + Estagio `0`)

Para permitir isolamento incremental sem descartar nem sobrescrever a implementacao completa (padrao `LUMABRIDGE_DIAGNOSTIC_STAGE = 6`), [DiagnosticStageConfig.h](../../windows/driver/LumaBridgeIddDriver/DiagnosticStageConfig.h) e [Build-LumaBridgeDiagnosticStage.ps1](../../windows/driver/scripts/Build-LumaBridgeDiagnosticStage.ps1) isolam os subsistemas mantendo `.inf`, UMDF `2.31` (min `25`), IddCx `1.4` (min `4`) e `/Qspectre`:

| Estagio | Escopo / Variavel controlada | Macro / Comando de build + manifesto | Criterio de aprovacao & Logs/Hashes esperados | Rollback |
|---|---|---|---|---|
| **0** | Controle oficial `IddSampleDriver` (`SwDeviceCreate` + `Root\IddSampleDriver`) | `.\windows\driver\scripts\Prepare-IddSampleReference.ps1 -Configuration Release` | **JA APROVADO:** `Status=OK`, `ProblemCode=0`, `ProblemStatus=Empty`, `3` monitores | `pnputil /remove-device` + `pnputil /delete-driver oemYY.inf /uninstall` |
| **1** | Esqueleto minimo LumaBridge (`DriverEntry` -> `EvtDeviceAdd` -> `EvtDeviceD0Entry` -> `IddCxAdapterInitAsync` + `EvtIddCxAdapterInitFinished`, sem `AdapterStateMachine`, `TraceLogging`, `VirtualMonitor` ou `SwapChainProcessor`) | `.\windows\driver\scripts\Build-LumaBridgeDiagnosticStage.ps1 -DiagnosticStage 1 -Configuration Release -RestoreDefaultStageAfterBuild` | Dispositivo `ROOT\DISPLAY\0000` inicia com `Status=OK`, `ProblemCode=0`; `stage-build-manifest.json` contem `DiagnosticStage=1` e SHA-256 de `.dll/.inf/.cat/.pdb` | `.\windows\driver\scripts\Uninstall-LumaBridgeDriver.ps1 -Force` *(e remocao de `$env:LOCALAPPDATA\LumaBridgeDisplay\DiagnosticStages\Stage1`)* |
| **2** | Reintroduz `AdapterStateMachine`, `g_InFlightInitSlot` / `SRWLOCK` e `EvtDeviceD0Exit` (`Stage 1` + estados/locks) | `.\windows\driver\scripts\Build-LumaBridgeDiagnosticStage.ps1 -DiagnosticStage 2 -Configuration Release -RestoreDefaultStageAfterBuild` | `ROOT\DISPLAY\0000` permanece `Status=OK`, `ProblemCode=0`; transicoes de energia/cleanup sem deadlock | `.\windows\driver\scripts\Uninstall-LumaBridgeDriver.ps1 -Force` |
| **3** | Reintroduz `TraceLoggingRegister` (`LUMABRIDGE_ENABLE_TRACELOGGING=1`) e breadcrumbs `Diag*` com `WDF_REGKEY_DEVICE_SUBKEY` | `.\windows\driver\scripts\Build-LumaBridgeDiagnosticStage.ps1 -DiagnosticStage 3 -Configuration Release -RestoreDefaultStageAfterBuild` | `Status=OK`, `ProblemCode=0`; ETL `LumaBridgeIddCore` registra `LumaBridgeIddDriver` (`diagStage=3`) e registro grava `DiagBuildStage=3` + `DiagLastStage=AdapterInitFinished` | `.\windows\driver\scripts\Uninstall-LumaBridgeDriver.ps1 -Force` |
| **4** | Reintroduz `VirtualMonitorManager` (`EnableVirtualMonitor=0` primeiro, depois `EnableVirtualMonitor=1` opcional) | `.\windows\driver\scripts\Build-LumaBridgeDiagnosticStage.ps1 -DiagnosticStage 4 -Configuration Release -RestoreDefaultStageAfterBuild` | Com `0`: `AdapterReady` sem monitor; com `1`: monitor virtual chega (`STATUS_SUCCESS`), `DiagBuildStage=4` | `.\windows\driver\scripts\Set-LumaBridgeVirtualMonitor.ps1 -Disable -Force` e `Uninstall-LumaBridgeDriver.ps1 -Force` |
| **5** | Reintroduz `SwapChainProcessor` (D3D11/DXGI loop passivo sem copiar pixels) | `.\windows\driver\scripts\Build-LumaBridgeDiagnosticStage.ps1 -DiagnosticStage 5 -Configuration Release -RestoreDefaultStageAfterBuild` | `Status=OK`; swapchain atribuida sem `STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN` quando monitor ativo | `.\windows\driver\scripts\Uninstall-LumaBridgeDriver.ps1 -Force` |
| **6** | **Implementacao completa padrao** (inclui `EmitHostMetricsSnapshot` e toda a telemetria) | `msbuild windows\driver\LumaBridgeIddDriver.sln /t:Rebuild /p:Configuration=Release;Platform=x64 /m` *(ou `-DiagnosticStage 6`)* | `Status=OK`, `ProblemCode=0`, `DiagBuildStage=6`, `DiagLastStage=AdapterInitFinished`, ETL `LumaBridgeIddDriver` + `[LB-DRIVER]` integros, zero dump `WATCHDOG` | `.\windows\driver\scripts\Uninstall-LumaBridgeDriver.ps1 -Force` |

> **Recomendacao pratica para o proximo teste (#3):** Como a causa raiz do Code 10 foi identificada diretamente no disassembly (`IDDCX_TRANSMISSION_TYPE_NETWORK_OTHER` -> `0xC000000D` -> `0xC000009E`), teste primeiro diretamente o **Estagio 6 padrao corrigido** seguindo [windows-idd-start-failure-investigation.md](./windows-idd-start-failure-investigation.md#5-procedimento-sequencial--validacao-do-build-corrigido-estagio-6-enablevirtualmonitor0); recorra aos Estagios `1..5` apenas se surgir uma segunda falha distinta.
