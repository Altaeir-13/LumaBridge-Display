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
- **Benchmark 30 s (`-TestProfile Benchmark30s`, `-BenchmarkDurationSec 30`):** exige `1920x1080` (`-ExpectedBenchmarkWidth 1920 -ExpectedBenchmarkHeight 1080`), estimulo `60 FPS`, duracao efetivamente conectada `TotalConnectedDurationUs >= 100%` da nominal solicitada (`>= 30.000.000 us` sem tolerancia de 95% via `--duration-counts-connected` e `--max-execution-ms`), relogio QPC valido (`QpcClockValid = true`, `QpcFrequency > 0`, sem `SafetyExecutionTimeoutHit`), stream realmente ativo (`ActiveStreamingDurationUs >= 95%` da duracao nominal e `ConnectedFps >= 57.0 FPS` alem de `SustainedLiveFps >= 57.0 FPS`, rejeitando pipe conectado ocioso ou rajada inicial), no minimo `98%` dos quadros validos esperados no intervalo (`-MinBenchmarkFrameRatio 0.98`, `>= 1.764` quadros em 30 s), `GpuSharedNtHandle` sem fallback nem readback CPU, `NvencFramesEncoded >= floor(FramesValid * -MinNvencEncodeRatio)` e quedas `<= -MaxDropRatio` (`0.02`, rejeitando `NvencFramesEncoded = 1`), decodificacao estrutural H.264 validada, `TimestampMeasurementErrors == 0`, cobertura temporal `>= 95%`, binding verificado e `WUDFHost.exe` LumaBridge verificado vivo. *Regra estrita:* `Benchmark30s` **nunca** marca `ProlongedStabilityProven = true`.
- **Estabilidade Prolongada (`-TestProfile ProlongedStability`, `-StabilityDurationSec 180..3600`, ou `-TestProfile Full`):** utiliza exatamente os mesmos criterios rigorosos de `1080p60` (`TotalConnectedDurationUs >= 180.000.000 us` para `180 s` sem desconto de 95%, `>= 98%` quadros / `>= 10.584` em `180 s`, timeouts seguros ate `3600 s` com `--max-execution-ms` e margens de prewarm/shutdown, auditoria completa de metodologia de percentis para 12 metricas do Host e 10 metricas `Nvenc.*` distinguindo `ExactPopulation`, `ReservoirSampledEstimate_AlgorithmR` acima de `65.536` amostras e `NotAvailable` com `null`, alem de limite ETW ajustavel via `-CoreEtwMaxFileSizeMb`). `ProlongedStabilityProven = true` exige execucao completa com aprovacao de `ProlongedStability` atendendo `MeasuredDurationSec >= -MinProlongedStabilitySec` (`180 s` exatos por padrao).
- **Metodologia de Percentis (`LatencyMethodologyAudit` / `Latency & Percentile Methodology`):** todos os resumos JSON e relatorios do runner registram `PercentilesAvailable`, `PercentilesAreEstimated` e `PercentileMethod` (`NotAvailable`, `ExactPopulation` ou `ReservoirSampledEstimate_AlgorithmR`), preservando `MinUs`/`AvgUs`/`MaxUs` exatos sobre todos os `SampleCount` e emitindo `null` (nunca `0`) em `P50Us`/`P95Us`/`P99Us` quando `PercentilesAvailable = false`.
- **Comportamento de `-Force` no orquestrador:** passar `-Force` suprime a unica confirmacao interativa humana de alto nivel na Etapa 2 (`Confirm-LumaBridgeAction` antes de assinatura/ETW/instalacao/registro); as chamadas internas aos sub-scripts so propagam `-Force` depois que a Etapa 2 ja foi confirmada pelo operador. Portanto, execucoes reais assistidas devem **omitir `-Force`** para preservar o prompt `[y/N]`.
- **Resolucao inequivoca de `RuntimeInformation` e preflight (`M0.2.2`):** no Windows PowerShell 5.1 interativo com `PSReadLine 2.0.0`, o assembly `Microsoft.PowerShell.PSReadLine.dll` define um tipo interno homonimo `System.Runtime.InteropServices.RuntimeInformation` sem a propriedade estatica `OSArchitecture`, o que causava `PropertyNotFoundStrict` sob `Set-StrictMode -Version Latest` em resolucoes diretas. `Get-LumaBridgeHostOsArchitecture` e `Resolve-LumaBridgeRuntimeInformationType` consultam exclusivamente os assemblies confiaveis do runtime .NET (`mscorlib`, `System.Private.CoreLib` ou `System.Runtime.InteropServices.RuntimeInformation` com validacao de `PublicKeyToken`), tratando tipo/propriedade/valor ausente como `Unavailable` (bloqueando com diagnostico explicito sem inferir `X64` a partir de `Is64BitOperatingSystem`). Falhas nos Estagios 1 e 2 de preflight emitem aviso estruturado (`PreflightFailure: Stage=..., Function=..., ErrorId=..., DriverInstallationStarted=False`) preservando integralmente a excecao original.
- **Telemetria Continua (5 s) e Contrato `NOT_MEASURED`:** durante toda a execucao ativa do `lumabridge-host.exe`, o runner coleta amostras periodicas (`-ResourceSampleIntervalSec 5`) de CPU, Working Set, memoria privada, handles, threads, VRAM dedicada e GPU Engine **filtradas estritamente por PID** (`pid_<PID>_*`) separando `lumabridge-host.exe` e o `WUDFHost.exe` do LumaBridge (nunca somando GPU de processos alheios e registrando `NOT_MEASURED` com motivo quando indisponivel — nunca `0`).
- **Modo GPU Shared + NVENC (`M4.2` / `M4.2.1`):** utilize `-TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc [-VerifyH264Decode]` para exigir texturas compartilhadas (`D3D11_RESOURCE_MISC_SHARED_NTHANDLE | KEYEDMUTEX`, `CpuStagingReadsPerformed = 0`), codificacao NVENC H.264 e validacao estrutural NAL/MFT (`StructuralDecodeValidated=true`, mantendo `FidelityPsnrValidated=false` sem referencia sintetica). Para comprovar fidelidade PSNR em isolamento sem pixels privados, execute `FrameEndToEndIntegrationTests.exe` (`--verify-h264-psnr`) ou informe `-SyntheticFidelityExecutablePath`.

```powershell
# Previa Dry Run sem efeitos colaterais (M0.2.1+ Benchmark 30s e Estabilidade Prolongada 180s com DXGI explicito):
.\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 -Configuration Release -TestProfile Benchmark30s -BenchmarkDurationSec 30 -StimulusBackend Dxgi -StimulusFps 60 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -ResourceSampleIntervalSec 5 -GpuSampleIntervalSec 15 -CertificateThumbprint "<THUMBPRINT_SHA1_40_HEX>" -DryRun
.\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 -Configuration Release -TestProfile ProlongedStability -StabilityDurationSec 180 -MinProlongedStabilitySec 180 -StimulusBackend Dxgi -StimulusFps 60 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -ResourceSampleIntervalSec 5 -GpuSampleIntervalSec 15 -CertificateThumbprint "<THUMBPRINT_SHA1_40_HEX>" -DryRun

# Execucao real como Administrador (Etapa B — SEM -Force para manter a confirmacao interativa [y/N], somente apos autorizacao explicita):
.\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 -Configuration Release -TestProfile Smoke -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -CertificateThumbprint "<THUMBPRINT_SHA1_40_HEX>"
.\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 -Configuration Release -TestProfile Benchmark30s -BenchmarkDurationSec 30 -StimulusBackend Dxgi -StimulusFps 60 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -ResourceSampleIntervalSec 5 -GpuSampleIntervalSec 15 -CertificateThumbprint "<THUMBPRINT_SHA1_40_HEX>"
.\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 -Configuration Release -TestProfile ProlongedStability -StabilityDurationSec 180 -MinProlongedStabilitySec 180 -StimulusBackend Dxgi -StimulusFps 60 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -ResourceSampleIntervalSec 5 -GpuSampleIntervalSec 15 -CertificateThumbprint "<THUMBPRINT_SHA1_40_HEX>"

# Reutilizacao segura de staging assinado ja instalado (sem reassinar nem reinstalar pacote; manter <OutputDir> exclusivo):
.\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 -Configuration Release -TestProfile ProlongedStability -StabilityDurationSec 180 -MinProlongedStabilitySec 180 -StimulusBackend Dxgi -StimulusFps 60 -TransportMode Gpu -RequireGpuShared -EnableNvenc -RequireNvenc -VerifyH264Decode -ResourceSampleIntervalSec 5 -GpuSampleIntervalSec 15 -CertificateThumbprint "<THUMBPRINT_SHA1_40_HEX>" -StagingDir "<StagingDir>" -OutputDir "<OutputDir>" -SkipDriverInstall -ReuseSignedStaging
```

> **Semantica de Rollback e Codigos de Saida (`S-02`, `S-06`):** O runner registra um snapshot inicial completo (`InitialSystemSnapshot` distinguindo valor de registro ausente vs `0` vs `1`, certificados existentes, sessoes ETW, binding/INF e topologia de telas) e separa explicitamente seis resultados: `FunctionalValidationSucceeded`, `RuntimeCleanupSucceeded`, `SystemStateRestored`, `DriverBindingPersisted`, `RollbackClean` e `OverallSucceeded`. Se o rollback falhar parcialmente, `OverallSucceeded = false` e `ValidationSucceeded = false` com lancamento de excecao (exit code != 0), preservando ambos os erros sem mascaramento e gravando o relatorio JSON/Markdown inclusive em falhas de estagios intermediarios. Certificados pre-existentes (identificados por `<THUMBPRINT_SHA1_40_HEX>`) e pacotes historicos do Driver Store **nunca** sao removidos automaticamente como efeito colateral; quando uma atualizacao autorizada do driver permanece instalada apos o benchmark, o relatorio registra `DriverBindingPersisted = true` e `SystemStateRestored = false`. Em execucoes com `-SkipDriverInstall -ReuseSignedStaging` que nao alteram o vinculo do driver e restauram integralmente os parametros temporarios, o relatorio registra `DriverBindingPersisted = false` e `SystemStateRestored = true`.

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
   # Nao remover o certificado pre-existente <THUMBPRINT_SHA1_40_HEX>
   # nem os pacotes historicos do Driver Store sem autorizacao explicita.
   ```
   Para desinstalacao completa autorizada apenas quando o dispositivo foi criado especificamente pelo teste, utilize `Uninstall-LumaBridgeDriver.ps1`.

4. **Status da validacao ao vivo (`M0.3`) e referencia arquitetural:**
   - A arquitetura detalhada do caminho residente em GPU (`SharedTexturePool`, `IDXGIKeyedMutex`, IPC local `LBIF` v1.1 e `NvencH264Encoder`) esta documentada em [windows-gpu-shared-textures-nvenc.md](../architecture/windows-gpu-shared-textures-nvenc.md).
   - O historico consolidado de encerramento da validacao funcional Windows (`Benchmark30s` e `ProlongedStability` de `180 s` em `WUDFHost.exe`) encontra-se na Secao 7 abaixo.

## 7. Encerramento da Validacao Funcional da M0 (`M0.2.4` - `M0.3`)

Esta secao consolida o fechamento da validacao funcional do emissor Windows (`M0`) de forma reproduzivel e sanitizada, sem dados especificos da estacao do operador (SIDs, caminhos absolutos, identidades de hardware local ou certificados pessoais).

### 7.1 Evolucao do driver e pipeline Windows (`M3` -> `M0.3`)

| Marco | Escopo entregue e validado |
|---|---|
| **`M3`** | Driver UMDF/IddCx base (`LumaBridgeIddDriver`), enumeracao opt-in de 1 monitor virtual (`EnableVirtualMonitor`), modos CTA-861 (`1280x720@60`, `1920x1080@60`), pipeline `SwapChainProcessor` D3D11 e validacao de pacote `InfVerif`/`Inf2Cat`. |
| **`M4.1` / `M4.1.1`** | Extracao D3D11 com liberacao imediata da superficie IddCx, IPC local Named Pipe `LBIF v1.0` autenticado por token/SID/sessao/integridade (`AllowSameUserAccess = false`) e consumidor separado `lumabridge-host.exe`. |
| **`M4.2` / `M4.2.1`** | Pool limitado de texturas compartilhadas (`D3D11_RESOURCE_MISC_SHARED_NTHANDLE \| SHARED_KEYEDMUTEX`), IPC `LBIF v1.1` (`136 B` por frame, `DuplicateHandle` por PID autenticado, validacao `AdapterLuid`), codificador GPU `NVENC H.264` (preset P1 Ultra-Low-Latency, 0 B-frames), normalizacao causal QPC e pre-aquecimento. |
| **`M0.1` - `M0.2.2`** | Orquestrador em 11 etapas (`Invoke-LumaBridgeFunctionalValidation.ps1`), contrato explicito de rollback em `finally`, correlacao por modulo carregado de `WUDFHost.exe`, telemetria continua com contrato `NOT_MEASURED`, metodologia explicita de percentis (`ExactPopulation` vs `ReservoirSampledEstimate_AlgorithmR` vs `NotAvailable`) e resolucao estrita de `RuntimeInformation` no PowerShell 5.1. |
| **`M0.2.4` - `M0.3`** | Dominio unico de sequencia e transicoes de sessao em `FrameIpcServer`, telemetria ETW `SessionSummary`, contrato estrito GPU-only (`--require-gpu-shared`), estimulo `D3d11DxgiVSync` racional sem drift e sem fallback silencioso para GDI (`--stimulus-backend dxgi`), worker assincrono limitado de decode MFT (`AsyncH264ValidationWorker`, capacidade `256`) sem recalculo redundante de percentis por pacote, reutilizacao criptografica de staging assinado (`-SkipDriverInstall -ReuseSignedStaging`) e aprovacoes reais ao vivo de `30 s` e `180 s` em `WUDFHost.exe`. |

### 7.2 Defeitos encontrados, causas comprovadas e correcoes

1. **Erros causais de timestamp e `LiveEndToEndLatency` vazia (`M4.2.1`):** `IDDCX_METADATA::PresentDisplayQPCTime` representa o alvo futuro de VSync do DWM (`PresentDisplayQPCTime > acquireQpc`). A normalizacao causal passou a usar `SwapChainAcquireQpcTime` preservando o valor bruto para diagnostico (`PresentDisplayQpcWasFutureTarget`).
2. **Latencia fria no Quadro 1 e complexidade quadratica (`M4.2.1` / `M0.2.5.1`):** Inicializacao tardia de D3D11/NVENC/MFT e chamadas redundantes a `Summarize()` em caminho critico (`O(N^2 log N)`). O pre-aquecimento antes da conexao e a consolidacao exclusiva no encerramento (`H264BitstreamValidator::Finish()`) eliminaram o custo por pacote mantendo os mesmos percentis.
3. **Colisao de `RuntimeInformation` no PowerShell 5.1 (`M0.2.2`):** `PSReadLine 2.0.0` expoe um tipo interno homonimo sem `OSArchitecture`. Corrigido consultando exclusivamente assemblies confiaveis do .NET runtime validados por `PublicKeyToken`.
4. **Reprovacao do 1o `Benchmark30s` real (`DriverVer 11.48.30.582`):** O estimulo GDI atingiu apenas `1.744/1.764` quadros validos (`58,13 FPS`) e uma janela de corrida entre atribuicao de sequencia e transicao `CPU -> GPU` produziu `OutOfOrderSequenceCount = 1`, `SequenceGapsDetected = 1` e `3` quadros CPU em sessao GPU (`HostLiveEndToEnd p99 = 15.432 us`, `IpcTransit p99 = 11.265 us`, `ExtractToBitstream p99 = 30.144 us`). Corrigido em `M0.2.4` com serializacao de publicacao/sequencia por geracao de sessao (`FrameIpcServer`), contrato estrito GPU-only, backend `D3d11DxgiVSync` e desacoplamento do MFT para thread trabalhadora dedicada.
5. **Selecao explicita DXGI e protecao do worker MFT (`M0.2.5.1`):** Adicionado encaminhamento de `-StimulusBackend Dxgi` com propagacao obrigatoria de `LastHResult` e `TerminalFailure` pos-inicializacao (proibindo fallback silencioso para GDI) e endurecido o ciclo COM/MF + drenagem com timeout limitado (`wait_until` sem `detach()`) no `AsyncH264ValidationWorker`.

### 7.3 Testes automatizados e benchmarks sinteticos (commit funcional validado)

- **Commit funcional validado:** `6b297856af535a1737658da97d381c19231913e4` (branch `fix/m0-validation-gates-hardening`), distinto do commit documental posterior de encerramento da `M0`.
- **Cobertura automatizada aprovada no commit funcional (`6b297856`):**
  - **157/157** testes C++ unitarios e de componentes (`AdapterLifecycleTests` = 21, `DriverPackageValidationTests` = 6, `MonitorModesTests` = 12, `SwapChainLifecycleTests` = 15, `VirtualMonitorLifecycleTests` = 15, `FrameExtractionTests` = 12, `GpuSharedTextureTests` = 9, `FrameIpcTests` = 31, `NvencEncoderTests` = 8, `HostValidationWorkerAndStimulusTests` = 28);
  - **9/9** testes E2E multiprocesso (`FrameEndToEndIntegrationTests`);
  - **71/71** testes PowerShell (`LumaBridgeFunctionalToolingTests.ps1`);
  - **`InfVerif`** aprovado em `Debug|x64` e `Release|x64`.
- **Benchmark sintetico `M0.2.5.1` (3 execucoes de 30 s @ 1080p60 — sem `WUDFHost.exe`/DWM reais):** `1800/1800` quadros validos, codificados e decodificados nas 3 execucoes, `0` erros de timestamps/contrato GPU; medianas de `p99`: `HostLiveEndToEnd = 301 us`, `NVENC Encode = 12.946 us`, `ExtractToBitstream = 13.178 us`, `MftDecode = 3.407 us`. Benchmarks sinteticos medem exclusivamente o subsistema IPC+NVENC+MFT em isolamento e nao equivalem a execucoes reais em `WUDFHost.exe`.

### 7.4 Proveniencia reproduzivel dos artefatos e fronteira de assinatura

- **Versao do pacote (`DriverVer` `Release|x64`):** `11/23/2026,23.3.21.222`
- **Hashes SHA-256 reproduziveis do build (`6b297856af535a1737658da97d381c19231913e4`, `Release|x64`):**
  - `LumaBridgeIddDriver.dll` (build nao assinado): `3142694CD2EEDA89D4ECD3CB517DBFC1FBCA6C9BB01231ABED0CE5B89AA6247C`
  - `LumaBridgeIddDriver.inf`: `CC939B59B203C91D5FF3E08FB0192C9C96A7AB17831665BBD564EE7163E12189`
  - `lumabridgeidddriver.cat` (build nao assinado): `9B3EA0ABD9B3D1AEAC594CF44638E6067E7A0E7ADF4A5DED4E9329D10D1A153E`
  - `lumabridge-host.exe` (`Release|x64`): `319614683D6BEF5A8B5A9777DA0B72E0581C31A311BA612D694E80D374E54047`
- **Assinatura de teste vs qualificacao de producao:** A assinatura utilizada nesta validacao ocorreu exclusivamente em `<StagingDir>` isolado fora do repositorio com certificado de teste no ambiente de desenvolvimento (`TestSigning` habilitado e `Secure Boot` desabilitado — limitacoes conhecidas do ambiente de teste que devem permanecer segregadas e nao equivalem a certificacao EV/attestation/WHQL exigida para distribuicao em producao). Na validacao prolongada de `180 s`, o modo `-SkipDriverInstall -ReuseSignedStaging` verificou assinatura Authenticode no ambiente de teste, associacao ao catalogo e correspondencia SHA-256 bit a bit entre a DLL do staging reutilizado e a DLL carregada pelo `WUDFHost.exe`, sem reassinar arquivos nem modificar o Driver Store.

### 7.5 Resultados quantitativos das validacoes reais em `WUDFHost.exe`

| Metrica / Criterio | 1o `Benchmark30s` Real (Reprovado — `11.48.30.582`) | 2o `Benchmark30s` Real (Aprovado — `23.3.21.222`) | `ProlongedStability` 180s Real (Aprovado — `23.3.21.222`, `ReusedSignedStaging`) |
|---|---:|---:|---:|
| Duracao conectada (`TotalConnectedDurationUs`) | `30,005 s` (`30.005.274 us`) | `30,011 s` (`30.011.404 us`) | `180,005 s` (`180.004.956 us`) |
| Duracao de streaming ativo (`ActiveStreamingDurationUs`) | `29,990 s` (`29.990.267 us`) | `29,990 s` (`29.989.514 us`) | `179,985 s` (`179.984.534 us`) |
| Quadros validos / Minimo do gate / Meta nominal | `1.744 / 1.764 / 1.800` | `1.800 / 1.764 / 1.800` | `10.670 / 10.584 / 10.800` (`98,80%`) |
| Codificados NVENC / Decodificados MFT | `1.741 / 1.741` | `1.800 / 1.800` (`100%`) | `10.670 / 10.670` (`100%`) |
| `SustainedLiveFps` / `EncoderOutputFps` | `58,13 / 58,12 FPS` | `59,99 / 59,98 FPS` | `59,28 / 59,28 FPS` |
| Backend estimulo efetivo / Fallback GDI | Legado GDI (`Ticks=1.823`, `60,02 FPS`) | `D3d11DxgiVSync` / `false` (`1.810` presents, `60,03 FPS`) | `D3d11DxgiVSync` / `false` (`10.808` presents, `60,00 FPS`) |
| Oclusoes / Falhas DXGI / Recriacoes swapchain | — | `0 / 0 / 0` (`DeadlineMiss = 0`) | `0 / 0 / 0` (`DeadlineMiss = 0`) |
| Transporte recebido (`GPU / CPU`) / Violacoes / Readbacks CPU | `1.741 GPU / 3 CPU` / `0` readbacks | `1.800 GPU / 0 CPU / 0 / 0` | `10.670 GPU / 0 CPU / 0 / 0` |
| `OutOfOrder` / `SequenceGaps` / `TimestampErrors` / Cobertura | `1 / 1 / 0 / 100%` | `0 / 0 / 0 / 100%` | `0 / 0 / 0 / 100%` |
| `HostLiveEndToEnd` (`p50 / p95 / p99`, us) | `188 / 315 / 15.432` | `144 / 201 / 257` | `130 / 196 / 239` |
| `IpcTransit p99` / `QueueWait p99` (us) | `11.265 / 3.076` | `234 / 43` | `209 / 41` |
| `Nvenc.EncodeLatency` (`p50 / p95 / p99`, us) | `8.770 / 14.051 / 16.517` | `11.533 / 12.385 / 13.673` | `11.706 / 12.717 / 13.726` |
| `ExtractToBitstream p99` / `PresentToBitstream p99` (us) | `30.144 / 30.193` | `13.837 / 13.889` | `13.878 / 13.923` |
| `InterFrameInterval` (`p50 / p95 / p99`, us) | `16.690 / 18.898 / 33.502` | `16.656 / 17.144 / 17.307` | `16.654 / 17.181 / 33.056` |
| `InterFrameJitter` (`p50 / p95 / p99`, us) | `492 / 10.257 / 17.350` | `284 / 920 / 1.205` | `300 / 1.036 / 16.757` |
| `MftDecodeLatency` (`p50 / p95 / p99`, us) / `QueuePeakDepth` | `NOT_MEASURED` | `1.316 / 1.650 / 2.621` / `1` | `1.204 / 1.554 / 2.457` / `1` |
| `SessionSummary` (ETW do driver) | `NOT_MEASURED` | `1.801 pub = 1.800 ent + 1 flush` (`0` drops) | `10.671 pub = 10.670 ent + 1 flush` (`0` drops) |
| Desfecho / Rollback / Estado | **`FAIL`** (`ExitCode = 1`) | **`PASS`** (`RollbackClean=True`, `DriverBindingPersisted=True`) | **`PASS`** (`ProlongedStabilityProven=True`, `RollbackClean=True`, `SystemStateRestored=True`, `DriverBindingPersisted=False`) |

**Contratos, conservacao de quadros, metodologia e escopo das medicoes:**
- **Duracao conectada vs streaming ativo:** Em `180 s`, `TotalConnectedDurationUs` atingiu `180,005 s` (`>= 180 s`), enquanto `ActiveStreamingDurationUs` foi `179,985 s` devido ao intervalo inicial entre conexao do pipe e chegada do 1o quadro. O minimo nominal do gate (`10.584` quadros = `0,98 * 180 * 60`) foi superado com `10.670` quadros (`98,80%` da meta nominal de `10.800`).
- **Pacing e jitter (`180 s`):** O backend `D3d11DxgiVSync` apresentou `10.808` quadros sem oclusoes, falhas ou gaps `> 25 ms` (`MaxInterPresentGapUs = 22.192 us`). Na recepcao IPC, foram registrados `134` intervalos de chegada superiores a `25 ms`, dos quais `115` ultrapassaram `33 ms` (`InterArrivalGapMaxUs = 34.163 us`), acompanhados por `33` eventos com `PresentationDelta = 2` e zero regressões ou saltos de sequência. Esse comportamento e compativel com a cadencia DWM/IddCx observada sem descartes no pipeline, embora nao constitua atribuicao causal exclusiva comprovada (nem todos os `134` intervalos correspondem necessariamente a exatamente dois vblanks). Como os percentis de latencia do JSON sao agregados sobre toda a sessao e `RecentAnomalies` retem apenas as ultimas `64` ocorrencias, esta evidencia nao permite declarar ausencia absoluta de degradacao temporal ao longo da janela completa.
- **Conservacao contábil fechada dos quadros:** Os `10.808` presents DXGI (`180,131 s`) e as `10.671` publicacoes do driver pertencem a dominios e janelas temporais distintos (sem subtracao direta entre eles para inferir perdas). A conservacao contábil fechada inicia-se nas publicacoes IPC registradas em `SessionSummary`: em `180 s`, `10.671` publicacoes = `10.670` entregas ao host + `1` flush limpo na transicao de encerramento (`DisconnectReason = 0`, `GpuFramesDropped = 0`, `FramesDroppedByBackpressure = 0`); na etapa do host e encode/decode, `10.670` recebidos GPU (`0` CPU) = `10.670` codificados NVENC (`0` drops) = `10.670` enfileirados/processados/decodificados estruturalmente no worker MFT (`QueuePeakDepth = 1/256`, `PacketsRejected = 0`, `QueuePendingAtShutdown = 0`, `ComBalanced = true`, `CompletionState = NormalShutdown`). Analogamente em `30 s`: `1.801 = 1.800 + 1` e `1.800 = 1.800 = 1.800`.
- **Metodologia de percentis:** Todas as `22` metricas auditadas em `30 s` e `180 s` usaram `PercentileMethod = ExactPopulation` (`PercentilesAreEstimated = false`, `SamplesTruncated = false`, `ReservoirSampled = false`), pois todos os contadores permaneceram abaixo do limite de `65.536` amostras.
- **Estabilidade de recursos (`180 s`):** O processo `WUDFHost.exe` manteve-se plano/decrescente em `25` amostras ativas (`WS -0,274 MB`, `Private -0,180 MB`, `VRAM 42,562 MB` constante em `9/9`, `GPU ~4,60%`, `Handles -2`). O consumidor `lumabridge-host.exe` manteve `VRAM 102,066 MB` constante em `9/9`, `Handles` com delta liquido `0` em regime ativo, taxa de CPU plana por tercos e variacao privada limitada (`+4,313 MB` em regime ativo, classificada como `BOUNDED`), compativel com o acumulo limitado de estruturas de telemetria em memoria ate `65.536` amostras, sem atribuir causalidade exclusiva sem medicao de alocacao especifica e sem extrapolar ausencia de vazamentos para sessoes de varias horas.
- **Escopo estrito de qualidade e latencia:** Permanece `H264FidelityPsnr = NOT_TESTED` em desktop real (`ValidationMode = StructuralDecodeOnly`, `StructuralDecodeValidated = true`, `FidelityPsnrValidated = false`), permanecendo a fidelidade PSNR restrita aos testes sinteticos. Todas as latencias medidas nesta etapa refletem exclusivamente a **latencia interna do emissor Windows**, nao incluindo transporte em rede nem latencia glass-to-glass em receptor remoto (`FramesPresented = NOT_MEASURED_NO_REMOTE_RECEIVER`).

### 7.6 Estado de governanca e limitacoes remanescentes (nao bloqueantes para `M0`)

- **Diferenciacao de marcos e integracao:**
  - `M0` funcionalmente aprovada no commit `6b297856af535a1737658da97d381c19231913e4` (seguido do commit documental `f1d2565e82b9878f8655aeb8ddb3d4a4ace3ecac`).
  - `M0` consolidada localmente na branch `integration/m0-windows-closure`.
  - **`M0` ainda nao integrada em `dev` remoto (`origin/dev`).**
  - **`M1` ainda nao iniciada.**
- **Observabilidade PDH/GPU:** cada consulta de contadores PDH GPU consumiu `~5,6 - 6,4 s` no runner, elevando o intervalo efetivo medio para `~20,7 s` em `180 s` e mantendo `DedicatedVram` do servidor visto internamente pelo host como `NOT_MEASURED`.
- **Duracao de 180 s e regime `> 65.536` amostras:** comprova estabilidade para encerramento funcional da `M0`, mas nao substitui ensaios de longa duracao de varias horas (inclusive alem de `65.536` amostras, onde entra `ReservoirSampledEstimate_AlgorithmR`).
- **Distincao de politica de fallback no servidor:** o driver ainda registra o default estrutural `AllowCpuFallback = 1` em `SessionSummary` mesmo quando o host negocia `--require-gpu-shared` (`0` frames CPU); a explicitao por handshake fica para refinamento incremental sem alterar contratos `M0`.
- **Ambiente de desenvolvimento vs producao, fidelidade visual real, otimizacao de NVENC sincrono, wraparound teorico `UINT64_MAX`, assinatura EV/WHQL de producao, protocolo de rede `LBWP v1`, receptor Linux e latencia glass-to-glass** ficam transferidos para `M1` e marcos posteriores conforme [UNIVERSAL_ROADMAP.md](../planning/UNIVERSAL_ROADMAP.md).

