# Procedimento Controlado e Plano de Validacao Funcional (Windows 11 x64)

Data: 2026-11-18
Escopo: Preparacao documental para assinatura de teste, instalacao controlada, ativacao do monitor virtual e validacao funcional do `LumaBridgeIddDriver`.

> **Aviso de seguranca e governanca:** Nenhum comando abaixo deve ser executado automaticamente sem autorizacao explicita. Nao altere configuracoes de seguranca permanentemente nem desative o watchdog do IddCx. A issue #20 (Spectre Mitigation via `<Driver_SpectreMitigation>Spectre</Driver_SpectreMitigation>` e `MSVC\14.51.36231\lib\spectre\x64`) ja foi resolvida; o repositorio permanece com `SignMode=Off` para o build padrao e toda preparacao de assinatura/instalacao utiliza copias em staging fora do Git via `windows/driver/scripts/` com suporte obrigatorio a `-DryRun`.

## 0. Scripts automatizados (`windows/driver/scripts/`)

Os seguintes scripts modulares automatizam o ciclo de preparacao, diagnostico e rollback com verificacao de privilegios administrativos, tratamento estrito de erros e confirmacao explicita (`-DryRun` / `-Force`):

| Script | Responsabilidade | Privilegio Admin |
|---|---|---|
| `LumaBridgeDriverCommon.psm1` | Modulo compartilhado (Hardware ID `Root\LumaBridgeIddDriver`, descoberta WDK, lookup PnP exclusivo por `DEVPKEY_Device_HardwareIds`, Driver Store via XML invariante de idioma, verificacao criptografica INF+DLL+CAT + correspondencia de certificados, correlacao `WUDFHost.exe`) | N/A |
| `Test-LumaBridgePrerequisites.ps1` | Diagnostico somente leitura de Windows 11 x64, Secure Boot e Test Signing (com fallback via registro sem elevacao), UMDF/IddCx e artefatos | Nao |
| `Invoke-LumaBridgePackageSigning.ps1` | Valida isolamento e limpa staging fora do repo antes do `Inf2Cat`, gera/reutiliza certificado de teste, assina `.dll`, regenera/assina `.cat`, verifica integridade INF+DLL+CAT e confirma hashes originais intactos | Somente com `-TrustCertificate` |
| `Install-LumaBridgeDriver.ps1` | Valida pre-requisitos e assinaturas (inclusive com `-AllowUntrustedChain`, sem aceitar arquivos adulterados), desabilita/reinicia monitor antes de atualizar dispositivo existente, confirma driver vinculado, preserva diagnosticos pre-rollback (`DEVPKEY_Device_ProblemStatus`, SetupAPI, eventos, dumps e breadcrumbs `Diag*`) antes de executar rollback em falhas parciais | Sim (exceto `-DryRun`) |
| `Set-LumaBridgeVirtualMonitor.ps1` | Localiza dinamicamente a instancia PnP via `DEVPKEY_Device_HardwareIds`, ajusta `EnableVirtualMonitor` (`1`/`0`), reinicia o dispositivo e executa rollback para `0` em falha parcial de ativacao | Sim (exceto `-DryRun`) |
| `Invoke-LumaBridgeEtwTrace.ps1` | Gerencia sessoes ETW separadas via `-pf` (`LumaBridgeIddCore` sequencial `-f bin -max 256` + verificacao `VerifyProviders`, e opcional `LumaBridgeIddDxg` circular `-f bincirc -max 128` via `-IncludeDxgKrnl`), exporta eventos via XPath streaming e executa decodificacao WPP (`DecodeWpp` com `symchk`/`tracepdb`/`tracefmt`) | Sim para `Start`/`Stop` (exceto `-DryRun`); Nao para `Status`/`VerifyProviders`/`ExportSummary`/`DecodeWpp` |
| `Collect-LumaBridgeDiagnostics.ps1` | Coleta estado PnP (incluindo `DEVPKEY_Device_ProblemStatus` e breadcrumbs `Diag*`), Driver Store, excerto SetupAPI contextualizado, canais/eventos, inventario de crash dumps, resumo ETL em streaming (`LumaBridgeIddCore.etl` e `LumaBridgeIddDxg.etl`), `DecodeWpp` opcional, `StageExecutionSummary`, versoes/hashes de pacote e `WUDFHost.exe` associado ao LumaBridge em JSON/Markdown (sem pixels da tela) | Nao |
| `Prepare-IddSampleReference.ps1` | Baixa somente `video/IndirectDisplay` de `microsoft/Windows-driver-samples` e compila `IddSampleDriver` + `IddSampleApp` em diretorio isolado fora do repositorio (`-DryRun` nao cria diretorios nem executa comandos), sem instalar no host | Nao |
| `Uninstall-LumaBridgeDriver.ps1` | Desativa monitor, remove instancias PnP, limpa `oemXX.inf` do Driver Store sem `/force` por padrao (opt-in via `-ForceDriverStoreDelete`) e remove certificado somente por `-CertificateThumbprint` + `-ConfirmCertificateRemoval` | Sim (exceto `-DryRun`) |

> **Diagnostico das falhas #1 e #2 (`CM_PROB_FAILED_START` / `0xC000009E`), controle `IddSampleDriver` e WinDbg:** Consulte [windows-idd-start-failure-investigation.md](../diagnostics/windows-idd-start-failure-investigation.md) e [windows-idd-windbg-and-reference-control.md](../diagnostics/windows-idd-windbg-and-reference-control.md) antes de executar uma nova instalacao.

Fluxo recomendado de simulacao antes da execucao real:

```powershell
# 1. Diagnostico somente leitura
.\windows\driver\scripts\Test-LumaBridgePrerequisites.ps1 -Configuration Release

# 2. Previa Dry Run completa sem alterar o sistema
.\windows\driver\scripts\Invoke-LumaBridgePackageSigning.ps1 -Configuration Release -CreateTestCertificateIfMissing -DryRun
.\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 -Action Start -IncludeDxgKrnl -DryRun
.\windows\driver\scripts\Install-LumaBridgeDriver.ps1 -Configuration Release -DryRun
.\windows\driver\scripts\Set-LumaBridgeVirtualMonitor.ps1 -Action Enable -DryRun
.\windows\driver\scripts\Collect-LumaBridgeDiagnostics.ps1 -Configuration Release -DryRun
.\windows\driver\scripts\Uninstall-LumaBridgeDriver.ps1 -RemoveTestCertificate -CertificateThumbprint "<THUMBPRINT_SHA1_40_HEX>" -DryRun
```

Fluxo controlado real em Prompt/PowerShell **como Administrador** (apos `bcdedit /set testsigning on` + reboot manuais caso necessario):

```powershell
$signResult = .\windows\driver\scripts\Invoke-LumaBridgePackageSigning.ps1 -Configuration Release -CreateTestCertificateIfMissing -TrustCertificate
.\windows\driver\scripts\Install-LumaBridgeDriver.ps1 -Configuration Release
.\windows\driver\scripts\Set-LumaBridgeVirtualMonitor.ps1 -Action Enable
.\windows\driver\scripts\Collect-LumaBridgeDiagnostics.ps1 -Configuration Release
# Rollback completo ao finalizar (remocao de certificado exige thumbprint explicito e -ConfirmCertificateRemoval):
.\windows\driver\scripts\Uninstall-LumaBridgeDriver.ps1 -RemoveTestCertificate -CertificateThumbprint $signResult.CertificateThumbprint -ConfirmCertificateRemoval
```

## 1. Prerequisitos do ambiente de teste

1. Windows 11 x64 (build `22000` ou superior; validado localmente em build `26300`).
2. Issue #20 resolvida e pacote recompilado em `Release|x64` (`windows/driver/x64/Release/LumaBridgeIddDriver/` contendo `.dll`, `.inf` e `.cat`).
3. Recomendacao forte: executar a primeira validacao em VM Windows 11 dedicada (ou ponto de restauracao criado previamente) antes de testar em maquina de uso pessoal.
4. Conta com privilegios de Administrador local para assinatura de teste e instalacao PnP.

## 2. Assinatura de teste controlada (fora do build padrao)

Em ambiente de teste controlado (sem alterar `SignMode=Off` no `.vcxproj` nem commitar certificados no repositorio):

```powershell
# 1. Gerar certificado temporario de desenvolvimento (executar uma vez em ambiente de teste)
$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject "CN=LumaBridge Test Driver Signing" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -NotAfter (Get-Date).AddMonths(6)

# 2. Exportar o certificado publico (.cer) para pasta temporaria fora do repo
$cerPath = "$env:TEMP\LumaBridgeTest.cer"
Export-Certificate -Cert $cert -FilePath $cerPath

# 3. Confiar no certificado apenas durante os testes (Admin):
# certutil -addstore Root $cerPath
# certutil -addstore TrustedPublisher $cerPath

# 4. Assinar o catalogo e a DLL no pacote Release (nao versionado)
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe"
& $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /t http://timestamp.digicert.com `
  "windows\driver\x64\Release\LumaBridgeIddDriver\LumaBridgeIddDriver.dll"
& $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /t http://timestamp.digicert.com `
  "windows\driver\x64\Release\LumaBridgeIddDriver\lumabridgeidddriver.cat"
```

*Nota:* Em sistemas com Secure Boot ativo, o uso de driver assinado em modo de teste pode exigir **Test Signing** habilitado (`bcdedit /set testsigning on` apenas com autorizacao explicita e em ambiente dedicado, revertendo com `bcdedit /set testsigning off` ao concluir).

## 3. Instalacao controlada e ativacao do monitor virtual

O driver inicia com **ativacao do monitor virtual desabilitada por padrao** (`EnableVirtualMonitor` ausente ou `0`).

1. **Instalar pacote e criar dispositivo raiz (Admin):**
   ```bat
   pnputil /add-driver "windows\driver\x64\Release\LumaBridgeIddDriver\LumaBridgeIddDriver.inf" /install
   devcon install "windows\driver\x64\Release\LumaBridgeIddDriver\LumaBridgeIddDriver.inf" "Root\LumaBridgeIddDriver"
   ```
   Nesta fase inicial (`EnableVirtualMonitor` ausente), o adaptador `LumaBridge Indirect Display Adapter` deve aparecer em *Gerenciador de Dispositivos -> Adaptadores de video* sem erros, e o log `[LB-DRIVER]` deve registrar `"Virtual monitor activation is disabled by default; skipping IddCxMonitorCreate/Arrival"`.

2. **Habilitar monitor virtual de forma controlada:**
   Localizar a chave de hardware do dispositivo (`HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\DISPLAY\<id>\Device Parameters`) e definir `EnableVirtualMonitor` (`REG_DWORD = 1`), reiniciando o dispositivo pelo Gerenciador de Dispositivos (`pnputil /restart-device "<instance-id>"`).

3. **Coleta de diagnostico `[LB-DRIVER]`:**
   - Capturar logs UMDF via Sysinternals **DebugView** (habilitar *Capture Win32* e *Capture Global Win32*) filtrando por `[LB-DRIVER]`.
   - Verificar eventos de driver UMDF no Visualizador de Eventos (`Applications and Services Logs -> Microsoft -> Windows -> DriverFrameworks-UserMode -> Operational`).

## 4. Desinstalacao e rollback seguro

Para remover completamente o dispositivo, o monitor virtual e o pacote do Driver Store (Admin):

```bat
REM 1. Opcionalmente voltar EnableVirtualMonitor para 0 antes de remover
REM 2. Remover instancia do dispositivo raiz
pnputil /remove-device "ROOT\DISPLAY\<instance-id>"

REM 3. Identificar o oemXX.inf correspondente (XML invariante de idioma) e remover do Driver Store sem /force por padrao
pnputil /enum-drivers /format xml
pnputil /delete-driver oemXX.inf /uninstall
```

Remover os certificados temporarios de teste das stores `CurrentUser\My`, `LocalMachine\Root` e `LocalMachine\TrustedPublisher` **somente por thumbprint SHA-1 exato** (`certutil -delstore <Store> <Thumbprint>`) e restaurar `testsigning off` caso tenha sido alterado em VM.

## 5. Plano de testes funcionais (10 cenarios)

| # | Cenario | Procedimento | Criterio de aceitacao esperado |
|---|---|---|---|
| 1 | **Reconhecimento do monitor pelo Windows** | Definir `EnableVirtualMonitor = 1`, reiniciar dispositivo e abrir *Configuracoes -> Sistema -> Tela* e `dxdiag`. | Um unico monitor adicional (`ConnectorIndex = 0`) aparece ativo com nome do adaptador LumaBridge e modo preferencial `1920x1080@60Hz`; logs registram `MonitorCreate` e `MonitorArrival` com `STATUS_SUCCESS`. |
| 2 | **Extensao da area de trabalho** | Selecionar *Estender estes videos* nas Configuracoes de Tela do Windows. | Janelas podem ser movidas para a tela estendida; cursor e composicao DWM respondem sem travamentos ou tela preta no monitor fisico. |
| 3 | **Alternancia entre resolucoes** | Alternar entre `1920x1080 (60 Hz)` e `1280x720 (60 Hz)` e retornar para `1920x1080 (60 Hz)`. | `EvtIddCxAdapterCommitModes` aceita apenas modos anunciados (`vSyncFreqDivider = 1`); novo swapchain substitui o anterior sem leaks (`SwapChainDeletedCount` incrementa de 1 por transicao). |
| 4 | **Processamento de frames** | Movimentar janelas / reproduzir animacao no monitor estendido por 60 segundos. | `SwapChainProcessor` processa frames continuamente sem spin de CPU em `E_PENDING`; `FramesProcessed` cresce proporcionalmente as atualizacoes de desktop sem falhas fatais. |
| 5 | **Desativacao e reativacao do dispositivo** | Executar `pnputil /disable-device` seguido de `pnputil /enable-device` (3 ciclos). | Em cada desativacao ocorrem `MonitorDeparture`, `OnSuspend`/`Shutdown` e desaparecimento do monitor; na reativacao o monitor retorna com o mesmo `ContainerId` sem duplicacao. |
| 6 | **Suspensao e retomada do sistema** | Colocar o sistema em suspensao (`D0Exit`) e retomar (`D0Entry`). | Monitor parte ordenadamente em `D0Exit` e retorna em `D0Entry` (`OnResume` + `EnsureMonitorArrived`) sem timeout PnP ou `AdapterFailed`. |
| 7 | **Recuperacao de falhas graficas** | Simular reset de GPU / TDR controlado (ou troca de adaptador de renderizacao). | `DXGI_ERROR_DEVICE_REMOVED` / `DXGI_ERROR_DEVICE_RESET` encerra a thread trabalhadora limpando `hSwapChain` uma unica vez; circuit breaker (`kMaxConsecutiveSwapChainFailures = 5`) impede loop infinito caso a falha persista. |
| 8 | **Consumo de CPU, GPU e memoria** | Monitorar `WUDFHost.exe` no Gerenciador de Tarefas / Resource Monitor em idle (desktop estatico) e com movimento por 5 minutos. | Consumo proximo a `0%` de CPU com desktop estatico (sem busy-wait); memoria privada de `WUDFHost.exe` estavel sem crescimento continuo. |
| 9 | **Ausencia de monitores fantasmas e leaks** | Desabilitar `EnableVirtualMonitor = 0`, reiniciar e executar `pnputil /remove-device` + `/delete-driver`. | Nenhum monitor fantasma permanece listado em *Gerenciador de Dispositivos -> Monitores* ou Configuracoes de Tela; `WUDFHost.exe` encerra sem handles abertos ou crash dump. |
| 10 | **Extracao M4.1 opt-in e consumo em `lumabridge-host.exe`** | Com `EnableVirtualMonitor = 1`, definir `REG_DWORD EnableFrameExtraction = 1` na chave `Device Parameters` (ou `Device Parameters\LumaBridgeIddDriver`), reiniciar o dispositivo, executar `lumabridge-host.exe --max-frames 30 --json-summary <temp.json>` e testar desconexao/reconexao. | `lumabridge-host.exe` autentica no Named Pipe `\\.\pipe\LumaBridgeFrameIpc_v1`, recebe frames reais (`FramesDelivered` == `FramesReceived`, `ChecksumMismatches = 0`, `ProtocolErrors = 0`), desconexao nao trava o driver (`FramesDroppedByBackpressure` atua normalmente) e `EnableFrameExtraction = 0` restaura o modo sem copia. |

## 6. Validacao controlada da extracao M4.1 e rollback especifico

1. **Habilitacao opt-in (Admin, apos instalacao controlada e `EnableVirtualMonitor = 1`):**
   ```powershell
   $dev = Get-PnpDevice | Where-Object { $_.InstanceId -like 'ROOT\DISPLAY\*' -and $_.FriendlyName -like '*LumaBridge*' } | Select-Object -First 1
   $devParams = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($dev.InstanceId)\Device Parameters"
   New-ItemProperty -LiteralPath $devParams -Name 'EnableFrameExtraction' -PropertyType DWord -Value 1 -Force | Out-Null
   pnputil /restart-device $dev.InstanceId
   ```
2. **Captura ETW + execucao do host consumidor em processo separado:**
   ```powershell
   .\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 -Action Start -Force
   $verify = .\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 -Action VerifyProviders
   $verify.AllProvidersVerified # deve retornar True
   .\windows\driver\x64\Release\lumabridge-host.exe --max-frames 30 --json-summary "$env:TEMP\lb-host-summary.json"
   .\windows\driver\scripts\Invoke-LumaBridgeEtwTrace.ps1 -Action Stop -Force
   .\windows\driver\scripts\Collect-LumaBridgeDiagnostics.ps1 -Configuration Release -EtlPath "$env:LOCALAPPDATA\LumaBridgeDisplay\Diagnostics\Etw\LumaBridgeIddCore.etl"
   ```
3. **Rollback imediato para modo sem extracao (ou desinstalacao completa):**
   ```powershell
   New-ItemProperty -LiteralPath $devParams -Name 'EnableFrameExtraction' -PropertyType DWord -Value 0 -Force | Out-Null
   pnputil /restart-device $dev.InstanceId
   ```
   Para rollback total do pacote e certificado, utilize `Uninstall-LumaBridgeDriver.ps1`.

4. **Riscos ainda nao resolvidos na etapa M4.1:**
   - O caminho atual de M4.1 utiliza staging D3D11 + copia CPU via Named Pipe (em vez de NT shared handles GPU-to-GPU), atingindo ~48.63 FPS em `1920x1080` com verificacao CRC/padrao ativa no hardware RTX 3060 Ti; 1080p60 sustentado para streaming interativo dependera do path GPU compartilhado + NVENC em M4.2.
   - A execucao dentro do `WUDFHost.exe` real em sistema operacional com `EnableFrameExtraction = 1` depende de instalacao controlada autorizada e nao foi executada automaticamente neste ambiente.
