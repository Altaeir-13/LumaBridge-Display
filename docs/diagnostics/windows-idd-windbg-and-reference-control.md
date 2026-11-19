# Controle Experimental (`IddSampleDriver`), Depuracao WinDbg e Isolamento Incremental — Issue #34

Data: 2026-11-19
Branch: `fix/windows-idd-device-start`
Escopo: Milestone M3 — Windows Virtual Display / Issue #34

> **Politica de controle e seguranca:** Nenhum comando abaixo instala drivers automaticamente, altera registro, certificados, Boot Configuration Data (`BCD`), desativa `Secure Boot`, nem desativa protecoes de seguranca/watchdog do `IddCx`. Execute apenas manualmente em ambiente dedicado de testes e realize a limpeza completa ao final.

---

## 1. Matriz Comparativa (11 Pontos): `IddSampleDriver` vs. `LumaBridgeIddDriver`

Comparacao verificada diretamente entre a compilacao isolada de `microsoft/Windows-driver-samples` (`video/IndirectDisplay` em `C:\Temp\LumaBridgeReference\IndirectDisplay`) e `windows/driver/LumaBridgeIddDriver`:

| # | Dimensao comparada | `IddSampleDriver` (Microsoft oficial) | `LumaBridgeIddDriver` (LumaBridge) | Implicacao diagnostica |
|---|---|---|---|---|
| 1 | **INF e diretivas UMDF** | `[DestinationDirs] UMDriverCopy=12,UMDF`, `ServiceBinary=%12%\UMDF\IddSampleDriver.dll`, `UmdfKernelModeClientPolicy=AllowKernelModeClients`, `UmdfExtensions=IddCx0102`, **sem** `UmdfHostProcessSharing`. `InfVerif /v /u` passa (`INF is VALID`), mas `InfVerif /v /w` **falha** com `ERROR(1322)` (nao usa `DIRID 13`). | `[DestinationDirs] UMDriverCopy=13`, `ServiceBinary=%13%\LumaBridgeIddDriver.dll`, `UmdfKernelModeClientPolicy=AllowKernelModeClients`, `UmdfHostProcessSharing=ProcessSharingDisabled`, `UmdfExtensions=IddCx0102`. Passa `InfVerif /v /u` e `/v /w`. | Contrato `.inf` do LumaBridge atende regras estritas Windows/DIRID 13 (como `rdpidd.inf`). Nao alterar INF antes de comprovar causa em runtime. |
| 2 | **Versoes WDF e IddCx** | `UMDF_VERSION_MAJOR=2`, `UMDF_VERSION_MINOR=25` (sem override explicito de minimo); `.vcxproj` define `IDDCX_VERSION_MAJOR=1`, `IDDCX_VERSION_MINOR=6`, `IDDCX_MINIMUM_VERSION_REQUIRED=4`. | UMDF `2.31` (minimo `2.25`); IddCx `1.4` (minimo `1.4`). Host Windows 11 x64 (`26300.9974`) possui `WUDFx02000.dll` `2.35.0` (`10.0.26100.9818`) e `IddCx.dll` `10.0.26100.9818`. | Ambas as combinacoes sao suportadas pelo runtime do host; nao reduzir versoes sem evidencia de runtime. |
| 3 | **Propriedades de build e vinculacao** | Toolset `WindowsUserModeDriver10.0`, `EnablePREfast=true` (exigiu `_CL_=/analyze-` no wrapper externo sob MSVC `14.51` + WDK `10.0.28000.0` pelos avisos `C28183`/`C6031`/`C28193` no `Driver.cpp` oficial), `WppEnabled=true`, `WppRecorderEnabled=true`, `OneCoreUAP.lib;avrt.lib`, `Spectre` habilitado. `dumpbin /dependents`: `ntdll.dll`, `KERNEL32.dll`, `ole32.dll`, `dxgi.dll`, `d3d11.dll`, `AVRT.dll`, `api-ms-win-crt-*`. | Toolset `WindowsUserModeDriver10.0`, `Driver_SpectreMitigation=Spectre`, linka `d3d11.lib;dxgi.lib`, usa TraceLogging (`LUMABRIDGE_ENABLE_TRACELOGGING=1`) + `OutputDebugStringA`, sem WPP proprio. `dumpbin`: sem CRT dinamica externa. | Carregamento de dependencias de ambos verificado na tentativa #2 (`WUDFHost.exe` carregou todas as DLLs do LumaBridge com sucesso ate Event `2006`). |
| 4 | **Criacao e enumeracao do dispositivo** | `IddSampleApp.exe` cria dispositivo de software efemero via `SwDeviceCreate("IddSampleDriver", "HTREE\\ROOT\\0", ...)`; INF tambem declara `Root\IddSampleDriver`. | Dispositivo raiz persistente via `devcon install ... "Root\LumaBridgeIddDriver"` (ou equivalencia PnP em `ROOT\DISPLAY\XXXX`). | **Ponto critico de controle:** testar `IddSampleApp.exe` (`SwDeviceCreate`) vs `devcon install` (`Root\IddSampleDriver`) distingue problema do host Windows vs mecanismo `ROOT\DISPLAY` vs codigo LumaBridge. |
| 5 | **`DriverEntry` e `EvtDeviceAdd`** | `DllMain` no-op; `DriverEntry` chama apenas `WdfDriverCreate`; `IddSampleDeviceAdd` chama `IddCxDeviceInitConfig`, `WdfDeviceCreate` e `IddCxDeviceInitialize`, alocando `new IndirectDeviceContext(Device)` **depois** de `IddCxDeviceInitialize`. | `DllMain` incrementa contador atomico; `DriverEntry` registra TraceLogging (`tlRegHr` + `TraceLoggingProviderEnabled`) e `WdfDriverCreate`; `LumaBridgeEvtDeviceAdd` registra callbacks, chama `LumaBridgeConfigureDeviceInit` (`IddCxDeviceInitConfig`), `WdfDeviceCreate` e `LumaBridgeInitializeDeviceContext` (`DeviceSwapChainHost` + breadcrumbs de registro + `IddCxDeviceInitialize`). | Testar no WinDbg se `LumaBridgeInitializeDeviceContext` falha antes ou dentro de `IddCxDeviceInitialize`. |
| 6 | **Callbacks de energia (`EvtDeviceD0*`)** | Registra somente `PnpPowerCallbacks.EvtDeviceD0Entry = IddSampleDeviceD0Entry` (`EvtDeviceD0Exit` omitido). | Registra ambos: `EvtDeviceD0Entry = LumaBridgeEvtDeviceD0Entry` e `EvtDeviceD0Exit = LumaBridgeEvtDeviceD0Exit`. | `EvtDeviceD0Exit` entra em cena ao desfazer D0 se `IRP_MN_START_DEVICE` falhar ou ao desligar. |
| 7 | **Inicializacao `IddCx` e propagacao de `NTSTATUS`** | `IddSampleDeviceD0Entry` chama `pContext->pContext->InitAdapter()` (`void`) e **sempre retorna `STATUS_SUCCESS`**, mesmo que `IddCxAdapterInitAsync` retorne erro sincronamente. | `LumaBridgeEvtDeviceD0Entry` retorna diretamente o `NTSTATUS` de `LumaBridgeStartAdapter(Device)`. Qualquer erro sincrono na cadeia propaga falha para o WDF durante `D0Entry`/`IRP_MN_START_DEVICE`, traduzido para `0xC000009E`. | **Principal diferenca de controle de erro:** um retorno nao-sucesso em `LumaBridgeEvtDeviceD0Entry` gera exatamente `Event 2103 (27, 0) -> 0xC000009E`. Breakpoint em `LumaBridgeEvtDeviceD0Entry` e `IddCx!IddCxImplAdapterInitAsync` comprovara ou refutara isso em segundos. |
| 8 | **Estrutura `IDDCX_ADAPTER_CAPS`** | `Size = sizeof(AdapterCaps)`, `MaxMonitorsSupported = 3`, `TransmissionType = IDDCX_TRANSMISSION_TYPE_WIRED_OTHER`, `MaxDisplayPipelineRate` zerado (`0`), `StaticDesktopReencodeFrameCount = 0`, `MajorVer = 1` compartilhado entre hardware e firmware. | `Size = IDD_STRUCTURE_SIZE(IDDCX_ADAPTER_CAPS)`, `MaxMonitorsSupported = 1`, `MaxDisplayPipelineRate = kMaxDisplayPipelineRate` (`2560*1440*60`), `TransmissionType = IDDCX_TRANSMISSION_TYPE_NETWORK_OTHER`, `endpointVersion` / `firmwareVersion`, `StaticDesktopReencodeFrameCount = 0`. | Se `IddCxImplAdapterInitAsync` rejeitar `NETWORK_OTHER` ou `MaxDisplayPipelineRate` especifico no host, sera visivel imediatamente no retorno de `IddCx!IddCxImplAdapterInitAsync`. |
| 9 | **Alocacao de contextos e locks** | Wrapper unico `IndirectDeviceContextWrapper` compartilhado em `WDFDEVICE` e `IDDCX_ADAPTER`; sem locks explicitos (`m_Adapter` atribuido em thread unica de D0). | Contextos dedicados (`LumaBridgeDeviceContext`, `LumaBridgeAdapterContext`, `LumaBridgeMonitorContext`) com `SRWLOCK`/`CRITICAL_SECTION` (`StateLock`), gate global `g_AdapterInitGate` + `InFlightAdapterBindingSlot` e `ConditionVariable`. | Breakpoints em `LumaBridgeStartAdapter` e `LumaBridgeEvtAdapterInitFinished` confirmam se o gate/slot ou context wrapper interfere na associacao. |
| 10 | **`DeviceGroupId` e isolamento do `WUDFHost`** | `HKR, "WUDF", "DeviceGroupId", %REG_SZ%, "IddSampleDriverGroup"` em `NT.hw` sem `ProcessSharingDisabled`. | `HKR, "WUDF", "DeviceGroupId", %REG_SZ%, "LumaBridgeIddGroup"` em `NT.hw` + `UmdfHostProcessSharing = ProcessSharingDisabled` em `NT.Wdf`. | Na tentativa #2 o `WUDFHost.exe` isolado (PID `23812`) iniciou e carregou `LumaBridgeIddDriver.dll` sem conflito de grupo, mas o controle testa com/sem `ProcessSharingDisabled` caso necessario. |
| 11 | **Exports e verificacao estatica de artefatos** | `IddSampleDriver.dll` exporta `FxDriverEntryUm` (`RVA 00002F30`); catalogo `iddsampledriver.cat` gerado sem assinatura (staging isolado). | `LumaBridgeIddDriver.dll` exporta `FxDriverEntryUm`; pacote `Release|x64` passa `InfVerif /v /u` e `/v /w` e verificacao Authenticode/SIP apos staging assinado. | Integridade estatica do binario e pacote comprovada nos dois drivers. |

---

## 2. Teste de Controle Experimental com `IddSampleDriver` (Execucao Manual)

O script [Prepare-IddSampleReference.ps1](file:///c:/Users/Altair/Documents/Working/Development/LumaBridge Display/windows/driver/scripts/Prepare-IddSampleReference.ps1) baixa e compila **exclusivamente em diretorio isolado** (`C:\Temp\LumaBridgeReference\IndirectDisplay`), sem alterar o repositorio nem instalar nada.

### Etapa A — Verificar ou regenerar compilacao isolada do controle

```powershell
# Previa nao destrutiva (DryRun):
.\windows\driver\scripts\Prepare-IddSampleReference.ps1 -DryRun

# Caso precise baixar novamente e compilar Release|x64 fora do repositorio (nao instala nada):
.\windows\driver\scripts\Prepare-IddSampleReference.ps1 -Configuration Release -Force
```

Artefatos esperados em `C:\Temp\LumaBridgeReference\IndirectDisplay\x64\Release\`:
- Driver package: `IddSampleDriver\IddSampleDriver.inf`, `IddSampleDriver\IddSampleDriver.dll`, `IddSampleDriver\iddsampledriver.cat`
- App de enumeracao SW: `IddSampleApp.exe`
- PDBs: `IddSampleDriver.pdb` e `IddSampleApp.pdb`

### Etapa B — Assinar e testar `IddSampleDriver` com `SwDeviceCreate` (PowerShell elevado manual)

Use um certificado de teste existente (ex.: o gerado/confiado manualmente durante a preparacao de testes) ou crie um dedicado somente para a sessao de controle:

```powershell
$refPkgDir = 'C:\Temp\LumaBridgeReference\IndirectDisplay\x64\Release\IddSampleDriver'
$refInf    = Join-Path $refPkgDir 'IddSampleDriver.inf'
$refDll    = Join-Path $refPkgDir 'IddSampleDriver.dll'
$refCat    = Join-Path $refPkgDir 'iddsampledriver.cat'
$signtool  = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe'
$inf2cat   = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x86\Inf2Cat.exe'

# 1. Localizar certificado de teste ja confiado em CurrentUser\My (ou criar separadamente se necessario)
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like '*LumaBridge*' } | Select-Object -First 1
if ($null -eq $cert) { throw 'Crie/confie um certificado de teste manualmente antes de prosseguir.' }

# 2. Assinar DLL, regenerar catalogo para Win11 x64 e assinar catalogo
& $signtool sign /fd SHA256 /sha1 $cert.Thumbprint $refDll
& $inf2cat /os:10_VB_X64,10_CO_X64,10_NI_X64,10_GE_X64 /uselocaltime /driver:$refPkgDir
& $signtool sign /fd SHA256 /sha1 $cert.Thumbprint $refCat
& $signtool verify /pa /v $refCat

# 3. Instalar no Driver Store (sem criar dispositivo ROOT ainda) e disparar SwDeviceCreate:
pnputil.exe /add-driver $refInf /install
C:\Temp\LumaBridgeReference\IndirectDisplay\x64\Release\IddSampleApp.exe
```

- **O que observar:** em outra janela PowerShell, antes de pressionar `x` para encerrar `IddSampleApp.exe`, verifique:
  ```powershell
  Get-PnpDevice -Class Display -PresentOnly | Format-Table Status, InstanceId, FriendlyName, Problem -AutoSize
  ```

### Etapa C — Controle opcional com dispositivo raiz (`Root\IddSampleDriver`)

Para isolar especificamente `SwDeviceCreate` vs `devcon install` (`ROOT\DISPLAY\XXXX`), somente apos encerrar `IddSampleApp.exe`:

```powershell
$devcon = 'C:\Program Files (x86)\Windows Kits\10\Tools\10.0.28000.0\x64\devcon.exe'
& $devcon install $refInf 'Root\IddSampleDriver'
Get-PnpDevice -Class Display | Where-Object { $_.InstanceId -like 'ROOT\DISPLAY*' } | Format-List InstanceId, Status, Problem, Service
```

### Matriz de decisao 2x2 (Resultado do controle vs. Proximo passo)

| `IddSampleApp.exe` (`SwDeviceCreate`) | `Root\IddSampleDriver` (`devcon`) | Diagnostico | Acao seguinte |
|---|---|---|---|
| **Passa** (`OK`) | **Passa** (`OK`) | Ambiente Windows 11 + `IndirectKmd` + `IddCx` + `ROOT\DISPLAY` funcionam no host; causa esta isolada ao binario/contrato especifico do `LumaBridgeIddDriver`. | Executar WinDbg com os 9 breakpoints da Secao 3 e/ou plano de bissecao incremental da Secao 4. |
| **Passa** (`OK`) | **Falha (`Code 10`)** | `IddCx` funciona com `SwDeviceCreate` (`HTREE\ROOT\0`), mas falha sob `Root\*` (`ROOT\DISPLAY`) neste host/GPU. | Investigar enumeracao SW (`SwDeviceCreate` / PnP capabilities / `IndirectKmd` binding) antes de alterar codigo core. |
| **Falha (`Code 10`)** | **Falha (`Code 10`)** | Bloqueio do proprio host/VM/sessao grafica (adaptador de renderizacao basico, GPO/WDAC/HVCI, `IndirectKmd` ou sessao sem DWM GPU). | Analisar `WATCHDOG` dump + `IndirectKmd` + adaptadores DXGI do host (nao e defeito especifico do LumaBridge). |

### Etapa D — Limpeza obrigatoria do controle experimental

```powershell
# 1. Remover qualquer dispositivo Root\IddSampleDriver se testado
pnputil.exe /enum-devices /class Display
# Substituir <INSTANCE_ID> pela instancia do IddSampleDriver se existir:
# pnputil.exe /remove-device "<INSTANCE_ID>"

# 2. Localizar o oemXX.inf publicado do IddSampleDriver e remover do Driver Store
pnputil.exe /enum-drivers /format xml
# Substituir oemYY.inf pelo PublishedName do IddSampleDriver.inf:
# pnputil.exe /delete-driver oemYY.inf /uninstall
```

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
.sympath C:\Users\Altair\Documents\Working\Development\LumaBridge Display\windows\driver\x64\Release;srv*C:\Temp\LumaBridgeSymCache*https://msdl.microsoft.com/download/symbols
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

## 4. Plano Condicional de Bissecao com Variante Diagnostica Minima

**Pre-requisito para executar esta secao:** o teste de controle `IddSampleDriver` (Secao 2) deve **funcionar** neste host e a causa exata ainda nao ter sido isolada por um unico breakpoint do WinDbg. **Nao** altere o `LumaBridgeIddDriver.inf` nem a versao base arbitrariamente; isole apenas em branch/experimento temporario incremental:

1. **Estagio 1 — Esqueleto minimo LumaBridge (`DriverEntry` -> `EvtDeviceAdd` -> `EvtDeviceD0Entry` -> `IddCxAdapterInitAsync`):**
   - Manter apenas callbacks obrigatorios, `IDDCX_ADAPTER_CAPS` equivalente ao minimo valido e `EvtDeviceD0Entry` propagando/logando `IddCxAdapterInitAsync` sem threads extras ou registry I/O. Se passar, comprova que INF, `DIRID 13`, UMDF `2.31`, IddCx `1.4` e Spectre funcionam juntos no host.
2. **Estagio 2 — Reintroduzir `AdapterStateMachine`, locks (`SRWLOCK`) e `EvtDeviceD0Exit`:**
   - Reativa `InFlightAdapterBindingSlot`, gate de inicializacao e transicoes `AdapterLifecycleTracker`. Testa se algum lock/callback `D0Exit` causa erro de estado PnP.
3. **Estagio 3 — Reintroduzir `TraceLogging` e breadcrumbs `WdfDeviceOpenRegistryKey` (`Diag*`):**
   - Valida impacto de `TraceLoggingRegister` e gravacao na Hardware Key sob `LOCAL SERVICE`.
4. **Estagio 4 — Reintroduzir `VirtualMonitor` (`EnableVirtualMonitor=0`) e `SwapChainProcessor`:**
   - Restaura `DeviceSwapChainHost` e criacao tardia de objetos D3D11/DXGI.
