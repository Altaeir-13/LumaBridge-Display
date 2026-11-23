# Procedimento Controlado e Plano de Validacao Funcional (Windows 11 x64)

Data: 2026-11-18
Escopo: Preparacao documental para assinatura de teste, instalacao controlada, ativacao do monitor virtual e validacao funcional do `LumaBridgeIddDriver`.

> **Aviso de seguranca e governanca:** Nenhum comando abaixo deve ser executado automaticamente sem autorizacao explicita. Nao altere configuracoes de seguranca permanentemente nem desative o watchdog do IddCx. A issue #20 (Spectre Mitigation via `<Driver_SpectreMitigation>Spectre</Driver_SpectreMitigation>` e `MSVC\14.51.36231\lib\spectre\x64`) ja foi resolvida; o repositorio permanece com `SignMode=Off` para o build padrao e toda preparacao de assinatura/instalacao utiliza copias em staging fora do Git via `windows/driver/scripts/` com suporte obrigatorio a `-DryRun`.

## 0. Scripts automatizados (`windows/driver/scripts/`)

Os seguintes scripts modulares automatizam o ciclo de preparacao, diagnostico e rollback com verificacao de privilegios administrativos, tratamento estrito de erros e confirmacao explicita (`-DryRun` / `-Force`):

| Script | Responsabilidade | Privilegio Admin |
|---|---|---|
| `LumaBridgeDriverCommon.psm1` | Modulo compartilhado (Hardware ID `Root\LumaBridgeIddDriver`, descoberta WDK, lookup PnP exclusivo por `DEVPKEY_Device_HardwareIds`, Driver Store via XML invariante de idioma, verificacao criptografica INF+DLL+CAT + correspondencia de certificados, correlacao `WUDFHost.exe`) | N/A |
| `Test-LumaBridgePrerequisites.ps1` | Diagnostico somente leitura de Windows 11 x64 (`Architecture`), Secure Boot, Test Signing, VBS e HVCI (`Win32_DeviceGuard` + fallback registro), servicos (`WUDFRd`, `WudfPf`, `PlugPlay`, `EventLog`), APIs/NVENC, diferenciacao entre bloqueios e avisos informativos, UMDF/IddCx e artefatos | Nao |
| `Invoke-LumaBridgePackageSigning.ps1` | Valida isolamento e limpa staging fora do repo antes do `Inf2Cat`, gera/reutiliza certificado de teste, assina `.dll`, regenera/assina `.cat`, verifica integridade INF+DLL+CAT e confirma hashes originais intactos | Somente com `-TrustCertificate` |
| `Install-LumaBridgeDriver.ps1` | Valida pre-requisitos e assinaturas (inclusive com `-AllowUntrustedChain`, sem aceitar arquivos adulterados), desabilita/reinicia monitor antes de atualizar dispositivo existente, confirma driver vinculado, preserva diagnosticos pre-rollback (`DEVPKEY_Device_ProblemStatus`, SetupAPI, eventos, dumps e breadcrumbs `Diag*`) antes de executar rollback em falhas parciais | Sim (exceto `-DryRun`) |
| `Set-LumaBridgeVirtualMonitor.ps1` | Localiza dinamicamente a instancia PnP via `DEVPKEY_Device_HardwareIds`, ajusta `EnableVirtualMonitor` (`1`/`0`), reinicia o dispositivo e executa rollback para `0` em falha parcial de ativacao | Sim (exceto `-DryRun`) |
| `Invoke-LumaBridgeEtwTrace.ps1` | Gerencia sessoes ETW separadas via `-pf` (`LumaBridgeIddCore` sequencial `-f bin -max <CoreMaxFileSizeMb>` + verificacao `VerifyProviders`, e opcional `LumaBridgeIddDxg` circular `-f bincirc -max 128` via `-IncludeDxgKrnl`), exporta eventos via XPath streaming e executa decodificacao WPP (`DecodeWpp` com `symchk`/`tracepdb`/`tracefmt`) | Sim para `Start`/`Stop` (exceto `-DryRun`); Nao para `Status`/`VerifyProviders`/`ExportSummary`/`DecodeWpp` |
| `Invoke-LumaBridgeFunctionalValidation.ps1` | Orquestrador ponta a ponta em 11 etapas com `RunId` exclusivo, snapshot inicial completo, verificacao estrita de binding/SHA-256 do driver, identificacao anti-stale de `WUDFHost.exe`, telemetria continua (5 s) com `NOT_MEASURED`, gates rigorosos por subperfil (`1080p60`, `>=98%` quadros, `>=95%` FPS, NVENC ratio/drops, `TimestampMeasurementErrors==0`), timeouts ate `3600s` e rollback nao-mascarado em `finally` | Sim (exceto `-DryRun`) |
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
.\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 -Configuration Release -DryRun
.\windows\driver\scripts\Collect-LumaBridgeDiagnostics.ps1 -Configuration Release -DryRun
.\windows\driver\scripts\Uninstall-LumaBridgeDriver.ps1 -RemoveTestCertificate -CertificateThumbprint "<THUMBPRINT_SHA1_40_HEX>" -DryRun
```

Fluxo controlado real em Prompt/PowerShell **como Administrador** (apos `bcdedit /set testsigning on` + reboot manuais caso necessario):

> **Nota sobre o objeto retornado por `Invoke-LumaBridgePackageSigning.ps1`:** O campo com o diretorio isolado preparado se chama `$signResult.StagingDir` (e nao `StagingDirectory`).

```powershell
$signResult = .\windows\driver\scripts\Invoke-LumaBridgePackageSigning.ps1 -Configuration Release -CreateTestCertificateIfMissing -TrustCertificate
.\windows\driver\scripts\Install-LumaBridgeDriver.ps1 -Configuration Release -StagingDir $signResult.StagingDir
.\windows\driver\scripts\Set-LumaBridgeVirtualMonitor.ps1 -Action Enable
.\windows\driver\scripts\Collect-LumaBridgeDiagnostics.ps1 -Configuration Release -StagingDir $signResult.StagingDir
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

## 6. Validacao controlada GPU + NVENC H.264 (M4.2 / M4.2.1 / M0.1), Telemetria Continua e Perfis Prolongados

Utilize preferencialmente o script automatizado `Invoke-LumaBridgeFunctionalValidation.ps1`, que usa `$signResult.StagingDir` em diretorio isolado por `RunId`, valida assinatura/binding/hash SHA-256 do driver, identifica dinamicamente o `WUDFHost.exe` associado ao LumaBridge e aplica gates estritos independentes em cada subperfil executado:

- **Perfil A (`-TestProfile Smoke`):** valida integridade ponta a ponta do driver instalado exigindo no minimo `1` frame real valido (`--min-frames 1 --max-frames 60 --duration-ms 5000`) com `--require-valid-timestamps` e `--run-id`, sem exigir 60 quadros em desktop estatico nem confundir termino normal por duracao ou timeouts recuperaveis de ociosidade com falha de transporte.
- **Perfil B (`-TestProfile Performance` ou `Both`):** executa estimulo visual diagnostico controlado (`CREATE_WAITABLE_TIMER_HIGH_RESOLUTION`) exclusivamente no display virtual identificado (`--visual-stimulus --require-virtual-stimulus --require-max-frames`) para medir entrega continua real. Nos perfis compostos (`Both` e `Full`), **cada subperfil executado e avaliado de forma independente** (uma falha no Smoke, Performance ou Benchmark30s derruba o resultado geral mesmo se o ultimo subperfil passar).
- **Benchmark 30 s (`-TestProfile Benchmark30s`, `-BenchmarkDurationSec 30`):** exige `1920x1080` (`-ExpectedBenchmarkWidth 1920 -ExpectedBenchmarkHeight 1080`), estimulo `60 FPS`, duracao efetivamente medida `>= 95%` da solicitada, no minimo `98%` dos quadros validos esperados no intervalo efetivamente medido (`-MinBenchmarkFrameRatio 0.98`, ~`1.764` quadros em 30 s), FPS sustentado `>= 95%` (`-MinSustainedFpsRatio 0.95`, `>= 57.0 FPS` avaliado separadamente da contagem), `GpuSharedNtHandle` sem fallback nem readback CPU, `NvencFramesEncoded >= floor(FramesValid * -MinNvencEncodeRatio)` e quedas `<= -MaxDropRatio` (`0.02`, rejeitando `NvencFramesEncoded = 1`), decodificacao estrutural H.264 validada, `TimestampMeasurementErrors == 0`, cobertura temporal `>= 95%`, binding verificado e `WUDFHost.exe` LumaBridge verificado vivo. *Regra estrita:* `Benchmark30s` **nunca** marca `ProlongedStabilityProven = true`.
- **Estabilidade Prolongada (`-TestProfile ProlongedStability`, `-StabilityDurationSec 180..3600`, ou `-TestProfile Full`):** utiliza exatamente os mesmos criterios rigorosos de `1080p60` (`>= 98%` quadros, ~`10.584` quadros em `180 s`, timeouts seguros ate `3600 s` com margens de prewarm/shutdown, amostragem Algorithm R por reservoir sampling acima de `65.536` amostras e limite ETW ajustavel via `-CoreEtwMaxFileSizeMb`). `ProlongedStabilityProven = true` exige execucao completa com aprovacao de `ProlongedStability` atendendo `>= -MinProlongedStabilitySec` (`180 s` por padrao).
- **Telemetria Continua (5 s) e Contrato `NOT_MEASURED`:** durante toda a execucao ativa do `lumabridge-host.exe`, o runner coleta amostras periodicas (`-ResourceSampleIntervalSec 5`) de CPU, Working Set, memoria privada, handles, threads, VRAM dedicada e GPU Engine **filtradas estritamente por PID** (`pid_<PID>_*`) separando `lumabridge-host.exe` e o `WUDFHost.exe` do LumaBridge (nunca somando GPU de processos alheios e registrando `NOT_MEASURED` com motivo quando indisponivel — nunca `0`).
- **Modo GPU Shared + NVENC (`M4.2` / `M4.2.1`):** utilize `-TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc [-VerifyH264Decode]` para exigir texturas compartilhadas (`D3D11_RESOURCE_MISC_SHARED_NTHANDLE | KEYEDMUTEX`, `CpuStagingReadsPerformed = 0`), codificacao NVENC H.264 e validacao estrutural NAL/MFT (`StructuralDecodeValidated=true`, mantendo `FidelityPsnrValidated=false` sem referencia sintetica). Para comprovar fidelidade PSNR em isolamento sem pixels privados, execute `FrameEndToEndIntegrationTests.exe` (`--verify-h264-psnr`) ou informe `-SyntheticFidelityExecutablePath`.

```powershell
# Previa Dry Run sem efeitos colaterais (M0.1/M4.2.1 Benchmark 30s e Estabilidade Prolongada 180s..3600s):
.\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 -Configuration Release -TestProfile Benchmark30s -BenchmarkDurationSec 30 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -DryRun
.\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 -Configuration Release -TestProfile ProlongedStability -StabilityDurationSec 180 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -DryRun

# Execucao real como Administrador (somente mediante autorizacao explicita):
.\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 -Configuration Release -TestProfile Benchmark30s -BenchmarkDurationSec 30 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -CreateTestCertificateIfMissing -TrustCertificate -AllowUntrustedChain
.\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 -Configuration Release -TestProfile ProlongedStability -StabilityDurationSec 180 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -CreateTestCertificateIfMissing -TrustCertificate -AllowUntrustedChain
```

> **Semantica de Rollback e Codigos de Saida (`S-02`, `S-06`):** O runner registra um snapshot inicial completo (`InitialSystemSnapshot` distinguindo valor de registro ausente vs `0` vs `1`, certificados existentes, sessoes ETW, binding/INF e topologia de telas) e separa explicitamente seis resultados: `FunctionalValidationSucceeded`, `RuntimeCleanupSucceeded`, `SystemStateRestored`, `DriverBindingPersisted`, `RollbackClean` e `OverallSucceeded`. Se o rollback falhar parcialmente, `OverallSucceeded = false` e `ValidationSucceeded = false` com lancamento de excecao (exit code != 0), preservando ambos os erros sem mascaramento e gravando o relatorio JSON/Markdown inclusive em falhas de estagios intermediarios. Certificados pre-existentes (ex.: `1EEFC55BD7EEB2A9115432607B97978736B9DFE0`) e pacotes historicos do Driver Store **nunca** sao removidos automaticamente como efeito colateral; quando uma atualizacao autorizada do driver permanece instalada apos o benchmark, o relatorio registra `DriverBindingPersisted = true` e `SystemStateRestored = false`.

### Procedimento Seguro de Recuperacao Manual (`S-06`)

Se uma execucao interrompida exigir intervencao manual em PowerShell **como Administrador**, preserve obrigatoriamente o estado inicial do host, dispositivos de terceiros e o monitor virtual se ele ja estava ativo (`EnableVirtualMonitor = 1`):

1. **Identificar PID especifico do consumidor e dispositivo LumaBridge sem afetar terceiros:**
   ```powershell
   # Nunca executar Stop-Process -Name lumabridge-host indiscriminadamente entre sessoes.
   Get-CimInstance Win32_Process -Filter "Name = 'lumabridge-host.exe'" |
     Select-Object ProcessId, ParentProcessId, CommandLine
   # Encerre apenas o PID orfao especifico via Stop-Process -Id <PID> caso necessario.

   # Localize dinamicamente apenas instancias com DEVPKEY_Device_HardwareIds = Root\LumaBridgeIddDriver:
   Import-Module .\windows\driver\scripts\LumaBridgeDriverCommon.psm1 -Force
   $dev = @(Get-LumaBridgePnpInstances) | Select-Object -First 1
   ```
2. **Restaurar exatamente os valores do `InitialSystemSnapshot` (sem forcar `EnableVirtualMonitor = 0` se antes era `1`):**
   ```powershell
   $devParams = $dev.DeviceParametersPath
   # Reverter EnableFrameExtraction para 0 (ou remover se ausente no snapshot inicial):
   New-ItemProperty -LiteralPath $devParams -Name 'EnableFrameExtraction' -PropertyType DWord -Value 0 -Force | Out-Null
   # Remover chaves temporarias caso estivessem ausentes no snapshot inicial (ou restaurar valor anterior):
   Remove-ItemProperty -LiteralPath $devParams -Name 'EnableGpuSharedTransport' -ErrorAction SilentlyContinue
   Remove-ItemProperty -LiteralPath $devParams -Name 'AuthorizedHostUserSid' -ErrorAction SilentlyContinue
   # Somente defina EnableVirtualMonitor=0 se InitialSystemSnapshot indicava 0/ausente;
   # se o monitor virtual do usuario ja estava ativo (1), mantenha EnableVirtualMonitor=1!
   pnputil /restart-device $dev.InstanceId
   ```
3. **Encerrar apenas sessoes ETW orfas do LumaBridge e preservar certificados/Driver Store pre-existentes:**
   ```powershell
   logman stop LumaBridgeIddCore -ets 2>$null
   logman stop LumaBridgeIddDxg -ets 2>$null
   # Nao remover o certificado pre-existente 1EEFC55BD7EEB2A9115432607B97978736B9DFE0
   # nem os pacotes historicos do Driver Store sem autorizacao explicita.
   ```
   Para desinstalacao completa autorizada apenas quando o dispositivo foi criado especificamente pelo teste, utilize `Uninstall-LumaBridgeDriver.ps1`.

4. **Status M4.2 / M0.1 e proximos passos:**
   - A arquitetura detalhada, modelo de sincronizacao `IDXGIKeyedMutex`, modelo de seguranca `PROCESS_DUP_HANDLE`, benchmark controlado 3-way (CPU vs GPU Shared vs GPU+NVENC) e caminho para transmissao Linux estao documentados em [windows-gpu-shared-textures-nvenc.md](../architecture/windows-gpu-shared-textures-nvenc.md).
   - Validacao ao vivo dentro de `WUDFHost.exe` com instalacao controlada da versao compilada e benchmarks `Benchmark30s` / `ProlongedStability` depende de autorizacao administrativa explicita do operador no host Windows 11.
