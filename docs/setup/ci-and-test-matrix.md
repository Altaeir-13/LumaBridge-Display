# Matriz de Dependências de Testes e Escopo do CI Inicial (`M0.6`)

Este documento inventaria todas as suítes de testes e verificações existentes no repositório (`10` suítes C++ unitárias/componentes totalizando `157` casos, `9` testes E2E multiprocesso em `FrameEndToEndIntegrationTests.cpp` e `71` testes PowerShell em `LumaBridgeFunctionalToolingTests.ps1`), classifica cada item conforme suas dependências reais de infraestrutura e define exatamente o escopo do **CI convencional não administrativo** em `.github/workflows/`.

---

## 1. Categorias Oficiais de Dependência

Um mesmo teste ou suíte pode pertencer a múltiplas categorias simultaneamente:

| Categoria | Significado Técnico |
|---|---|
| `DETERMINISTIC_CPU_ONLY` | Lógica determinística em CPU com mocks ou parsers puros; sem dependência de GPU física, WDK, sessão interativa ou privilégio administrativo. |
| `WINDOWS_TOOLCHAIN_REQUIRED` | Requer toolchain MSVC (`cl.exe` / SDK Windows x64) e/ou APIs/runtime Win32 do Windows (ex.: Named Pipes, D3D11 WARP, COM, Media Foundation). |
| `WDK_REQUIRED` | Requer Windows Driver Kit (`wdf.h`, `IddCx.h`, `InfVerif.exe`, `Inf2Cat.exe`, `signtool.exe`, `devcon.exe`, `tracepdb.exe`) e/ou pacote `.dll/.inf/.cat` compilado pelo projeto WDK. |
| `GPU_REQUIRED` | Requer adaptador GPU físico com suporte a recursos gráficos/compartilhamento D3D11/DXGI em hardware real (não apenas emulação WARP em CI). |
| `NVENC_REQUIRED` | Requer GPU NVIDIA compatível e driver NVIDIA com `nvEncodeAPI64.dll` instalado em `System32`. |
| `INTERACTIVE_DESKTOP_REQUIRED` | Requer sessão gráfica interativa ativa com compositor DWM desocluído para estímulo visual `D3d11DxgiVSync` ou medição de cadência real de desktop. |
| `ADMINISTRATIVE_RUNTIME_REQUIRED` | Requer privilégios de Administrador local (`bcdedit`, trust de certificado em `LocalMachine`, `pnputil`/`devcon` PnP, carregamento real em `WUDFHost.exe` ou sessões ETW do sistema). |

---

## 2. Inventário das 10 Suítes C++ Unitárias e de Componentes (`157` casos)

| Suíte | Casos | Categorias de Dependência | Dependências Transitivas / Runtime | CI Windows Hospedado | Motivo da Seleção ou Exclusão |
|---|---:|---|---|---|---|
| [`AdapterLifecycleTests.cpp`](../../windows/driver/tests/AdapterLifecycleTests.cpp) | 21 | `DETERMINISTIC_CPU_ONLY`, `WINDOWS_TOOLCHAIN_REQUIRED` | Headers `AdapterStateMachine.h`, `DiagnosticStageConfig.h`, `Windows.h`, `ntstatus.h` | **Selecionada (`21/21`)** | Máquina de estados determinística sem WDK runtime, GPU ou admin. |
| [`MonitorModesTests.cpp`](../../windows/driver/tests/MonitorModesTests.cpp) | 12 | `DETERMINISTIC_CPU_ONLY`, `WINDOWS_TOOLCHAIN_REQUIRED` | `MonitorModes.cpp/.h`, `Windows.h`, `ntstatus.h` | **Selecionada (`12/12`)** | Cálculo e validação determinística CTA-861 sem GPU ou WDK. |
| [`SwapChainLifecycleTests.cpp`](../../windows/driver/tests/SwapChainLifecycleTests.cpp) | 15 | `DETERMINISTIC_CPU_ONLY`, `WINDOWS_TOOLCHAIN_REQUIRED` | `SwapChainProcessor.cpp/.h` com mock `ISwapChainBackend` | **Selecionada (`15/15`)** | Lógica de thread/circuit-breaker mockada sem GPU ou WDK. |
| [`VirtualMonitorLifecycleTests.cpp`](../../windows/driver/tests/VirtualMonitorLifecycleTests.cpp) | 15 | `DETERMINISTIC_CPU_ONLY`, `WINDOWS_TOOLCHAIN_REQUIRED` | `VirtualMonitor.cpp/.h` com mock `IVirtualMonitorBackend` | **Selecionada (`15/15`)** | Ciclo de vida do monitor virtual mockado sem `IddCx.dll`. |
| [`FrameExtractionTests.cpp`](../../windows/driver/tests/FrameExtractionTests.cpp) | 12 | `WINDOWS_TOOLCHAIN_REQUIRED` | `FrameExtractor.*`, `FrameTransport.*`, `SharedTexturePool.*`, `SwapChainProcessor.*`, `d3d11.lib`, `dxgi.lib`, `advapi32.lib` (fallback automático `D3D_DRIVER_TYPE_WARP`) | **Selecionada (`12/12`)** | Executa com dispositivo D3D11 real ou fallback WARP em CPU sem exigir GPU física nem admin. |
| [`GpuSharedTextureTests.cpp`](../../windows/driver/tests/GpuSharedTextureTests.cpp) | 9 | `WINDOWS_TOOLCHAIN_REQUIRED` | `SharedTexturePool.*`, `FrameTransport.*`, `SwapChainProcessor.*`, `FrameConsumer.*`, `d3d11.lib`, `dxgi.lib`, `advapi32.lib`, `user32.lib`, `gdi32.lib` (fallback automático `D3D_DRIVER_TYPE_WARP`) | **Selecionada (`9/9`)** | Valida contratos `SHARED_NTHANDLE` / `KEYEDMUTEX` / `AdapterLuid` sobre D3D11/WARP; não comprova zero-copy em silício físico. |
| [`FrameIpcTests.cpp`](../../windows/driver/tests/FrameIpcTests.cpp) | 31 | `WINDOWS_TOOLCHAIN_REQUIRED` | `SharedTexturePool.*`, `FrameTransport.*`, `FrameConsumer.*`, Named Pipes, tokens/SIDs/Low-IL Win32, D3D11 WARP fallback, teste #31 com `StimulusBackend::Auto` (`GdiLegacy` em oclusão) | **Selecionada (`31/31`)** | Cobre segurança IPC, backpressure e metodologia; o caso #31 usa fallback `GdiLegacy` quando o desktop está ocluído (`INTERACTIVE_DESKTOP_REQUIRED` aplica-se apenas à prova real de VSync DXGI). |
| [`HostValidationWorkerAndStimulusTests.cpp`](../../windows/driver/tests/HostValidationWorkerAndStimulusTests.cpp) | 28 | `WINDOWS_TOOLCHAIN_REQUIRED` | `FrameConsumer.*`, `NvencH264Encoder.*`, `H264BitstreamValidator.*`, `mfplat.lib`, `mfuuid.lib`, `wmcodecdspuuid.lib`, `ole32.lib` (27 mocks determinísticos + caso #27 `P0D_RealMftDecoderComAndMfThreadBalance` com `CLSID_CMSH264DecoderMFT`) | **Selecionada (`28/28`)** *(sujeita à disponibilidade de Media Foundation MFT no runner)* | Não exige GPU/NVENC física (usa mocks e testa balanceamento COM/MF no worker). Se o runner Server não possuir `CLSID_CMSH264DecoderMFT`, o fato deve ser registrado explicitamente sem alterar o teste. |
| [`DriverPackageValidationTests.cpp`](../../windows/driver/tests/DriverPackageValidationTests.cpp) | 6 | `WINDOWS_TOOLCHAIN_REQUIRED`, `WDK_REQUIRED` | `crypt32.lib`, `wintrust.lib`, artefatos compilados `windows/driver/x64/{Debug,Release}/LumaBridgeIddDriver/{.dll,.inf,.cat}` gerados por MSBuild/WDK + StampInf + Inf2Cat | **Excluída (`0/6`)** | Os casos 3–5 exigem builds `Debug\|x64` e `Release\|x64` do projeto WDK (`IddCx.h`, `wdf.h`, `Inf2Cat.exe`) indisponíveis sem WDK. |
| [`NvencEncoderTests.cpp`](../../windows/driver/tests/NvencEncoderTests.cpp) | 8 | `WINDOWS_TOOLCHAIN_REQUIRED`, `GPU_REQUIRED`, `NVENC_REQUIRED` | `NvencH264Encoder.*`, `H264BitstreamValidator.*`, `FrameConsumer.*`, `nvEncodeAPI.h`, `nvEncodeAPI64.dll` em runtime, GPU NVIDIA + decoder MFT | **Excluída (`0/8`)** | Requer GPU física NVIDIA e driver `nvEncodeAPI64.dll` ausentes em runners hospedados padrão. |

**Resumo C++ unitário/componentes:** **8 de 10 suítes selecionadas (`143` de `157` casos esperados)**; **2 suítes excluídas (`14` casos: `6` `WDK_REQUIRED` + `8` `GPU_REQUIRED`/`NVENC_REQUIRED`)**.  
Adicionalmente, `lumabridge-host.exe` (`windows/host/main.cpp` e módulos auxiliares) passa apenas por **compilação no CI (`compile-only`, `WINDOWS_TOOLCHAIN_REQUIRED`)** sem execução operacional, o que **não** equivale à validação real do driver `LumaBridgeIddDriver`.

---

## 3. Inventário dos 9 Testes E2E Multiprocesso (`FrameEndToEndIntegrationTests.cpp`)

Todos os 9 testes residem no binário monolítico [`FrameEndToEndIntegrationTests.cpp`](../../windows/driver/tests/FrameEndToEndIntegrationTests.cpp), que lança `lumabridge-host.exe` via `CreateProcessW` sem flags de seleção individual no código existente. Para não alterar o código do teste nem introduzir flags genéricas de skip, **toda a suíte (`0/9`) permanece excluída do CI hospedado convencional** e reservada à trilha especializada local/dedicada:

| # | Caso E2E | Categorias de Dependência | Motivo da Exclusão no CI Hospedado |
|---:|---|---|---|
| 1 | `EndToEndRealD3d11ExtractionToSeparateHostProcess720pAnd1080p` | `WINDOWS_TOOLCHAIN_REQUIRED` | Executável E2E único acoplado a casos `GPU_REQUIRED`/`NVENC_REQUIRED` abaixo. |
| 2 | `EndToEndHostDisconnectAndReconnectDuringActiveSwapChainLoop` | `WINDOWS_TOOLCHAIN_REQUIRED` | Executável E2E único acoplado a casos `GPU_REQUIRED`/`NVENC_REQUIRED` abaixo. |
| 3 | `EndToEndSmokeDurationExitAndMinFramesVsTargetCli` | `WINDOWS_TOOLCHAIN_REQUIRED` | Executável E2E único acoplado a casos `GPU_REQUIRED`/`NVENC_REQUIRED` abaixo. |
| 4 | `EndToEndThroughputAndLatencyBenchmark720pAnd1080p` | `WINDOWS_TOOLCHAIN_REQUIRED` | Benchmark de throughput/latência entre processos sensível a ruído de VM compartilhada e acoplado ao mesmo binário. |
| 5 | `VirtualDisplayStimulusHighResTimer60FpsVerification` | `WINDOWS_TOOLCHAIN_REQUIRED`, `INTERACTIVE_DESKTOP_REQUIRED` | Requer desktop interativo desocluído para validar `D3d11DxgiVSync` sem fallback `GdiLegacy`. |
| 6 | `EndToEndPhaseAGpuSharedTextureSeparateHostProcess720pAnd1080p` | `WINDOWS_TOOLCHAIN_REQUIRED`, `GPU_REQUIRED` | Exige transporte real GPU entre processos via `OpenSharedResource1` / `IDXGIKeyedMutex`. |
| 7 | `EndToEndPhaseBGpuSharedTexturePlusNvencAndIndependentDecode720pAnd1080p` | `WINDOWS_TOOLCHAIN_REQUIRED`, `GPU_REQUIRED`, `NVENC_REQUIRED` | Exige GPU NVIDIA com `nvEncodeAPI64.dll` e decoder MFT para PSNR H.264. |
| 8 | `EndToEndControlledThreeWayBenchmark720pAnd1080p` | `WINDOWS_TOOLCHAIN_REQUIRED`, `GPU_REQUIRED`, `NVENC_REQUIRED` | Benchmark comparativo de 3 vias com NVENC H.264. |
| 9 | `EndToEndProlonged1080p60GpuNvenc30SecondBenchmark` | `WINDOWS_TOOLCHAIN_REQUIRED`, `GPU_REQUIRED`, `NVENC_REQUIRED`, `INTERACTIVE_DESKTOP_REQUIRED` | Ensaio de 30 s @ 1080p60 em GPU/NVENC com metas estritas de `p99`. |

---

## 4. Inventário dos 71 Testes PowerShell (`LumaBridgeFunctionalToolingTests.ps1`)

Uma auditoria AST e de dependências de [`LumaBridgeFunctionalToolingTests.ps1`](../../windows/driver/tests/LumaBridgeFunctionalToolingTests.ps1) comprova que **a suíte PowerShell completa (`71/71`) NÃO pode ser executada em runner hospedado sem WDK nem artefatos compilados `Release|x64`**, porque 50 testes dependem diretamente de `windows/driver/x64/Release/LumaBridgeIddDriver/{.dll,.inf,.cat}` ou de ferramentas WDK (`signtool.exe`, `Inf2Cat.exe`, `devcon.exe`, `tracepdb.exe`).

Para não alterar [`LumaBridgeFunctionalToolingTests.ps1`](../../windows/driver/tests/LumaBridgeFunctionalToolingTests.ps1), o runner [`scripts/ci/Invoke-LumaBridgeCiWindowsTests.ps1`](../../scripts/ci/Invoke-LumaBridgeCiWindowsTests.ps1) valida por AST a bijeção exata dos `71` casos e executa um subconjunto explícito de **`21` testes independentes de WDK** usando um script efêmero montado fora do repositório com o preâmbulo, asserções e rodapé originais sem modificações.

### 4.1 Casos PowerShell Selecionados no CI Windows (`21` casos)

| # | Nome do Teste | Categorias | O que Valida |
|---:|---|---|---|
| 7 | `PnpIdentificationUsesEffectiveDevpkeyHardwareIdsOnly` | `DETERMINISTIC_CPU_ONLY` | Lookup exclusivo por `DEVPKEY_Device_HardwareIds` com mocks. |
| 8 | `DriverStoreXmlParsingIsLocaleIndependent` | `DETERMINISTIC_CPU_ONLY` | Parser XML estruturado de `pnputil /enum-drivers /format xml`. |
| 14 | `VirtualMonitorEnablePartialFailureTriggersRollback` | `DETERMINISTIC_CPU_ONLY` | Rollback para `EnableVirtualMonitor=0` com mocks. |
| 15 | `UninstallOmitsForceByDefaultAndSupportsOptInForce` | `DETERMINISTIC_CPU_ONLY` | Política padrão sem `/force` e opt-in `-ForceDriverStoreDelete` com mocks. |
| 16 | `UninstallCertificateRemovalRequiresThumbprintAndConfirmation` | `DETERMINISTIC_CPU_ONLY` | Exigência de thumbprint SHA-1 e confirmação explícita com mocks. |
| 17 | `DiagnosticsIdentifiesLumaBridgeWudfHostProcess` | `DETERMINISTIC_CPU_ONLY` | Correlação de processo `WUDFHost.exe` com mocks. |
| 19 | `PnpProblemStatusAndStartupBreadcrumbsCollected` | `DETERMINISTIC_CPU_ONLY` | Formatação `NTSTATUS` e coleta de breadcrumbs `Diag*` com mocks. |
| 21 | `SetupApiExcerptAndEventChannelCollection` | `DETERMINISTIC_CPU_ONLY` | Excerto `setupapi.dev.log` e leitura multi-canal mockada. |
| 22 | `DriverStageSummaryIdentifiesLastSuccessfulAndFailingStage` | `DETERMINISTIC_CPU_ONLY` | Correlação de estágios `DriverStage` e breadcrumbs. |
| 23 | `CrashDumpInventoryAndEtwTraceDryRun` | `DETERMINISTIC_CPU_ONLY` | Inventário de dumps e `-DryRun` de `Invoke-LumaBridgeEtwTrace.ps1`. |
| 24 | `EtwTraceUsesProviderFileAndSeparatesDxgKrnlSession` | `DETERMINISTIC_CPU_ONLY` | Conteúdo `-pf` (`6` providers Core vs `2` Dxg) e verificação de GUIDs. |
| 25 | `StreamingEtlQueryAppliesNativeXPathWithoutPreFilterCap` | `DETERMINISTIC_CPU_ONLY` | Geração de XPath nativo, streaming ETL e filtro estreito de SetupAPI. |
| 27 | `PrepareIddSampleReferenceDryRunEnforcesIsolation` | `DETERMINISTIC_CPU_ONLY` | Bloqueio de diretório no repositório e `-DryRun` de `Prepare-IddSampleReference.ps1`. |
| 28 | `DiagnosticStageBuildManifestAndSubkeyBreadcrumbs` | `DETERMINISTIC_CPU_ONLY` | Leitura da subchave `DiagBuildStage` e manifesto com `-SkipBuild`. |
| 29 | `ObservabilityVerifyProvidersAndUnclampedEtlTraceLoggingRecovery` | `DETERMINISTIC_CPU_ONLY` | `AllProvidersVerified` e recuperação de eventos TraceLogging GUID-only. |
| 42 | `M01_S04_TimeoutCalculation30To3600SecAndOverflowValidation` | `DETERMINISTIC_CPU_ONLY` | Cálculo de timeouts `30..3600s` e guarda contra overflow. |
| 43 | `M01_S05_ContinuousTelemetrySamplingAndNotMeasuredContract` | `DETERMINISTIC_CPU_ONLY` | Isolamento por PID em telemetria e contrato `NOT_MEASURED`. |
| 49 | `M01_S08_HostSecurityVbsHvciAndServicesReadOnlyDiagnostics` | `DETERMINISTIC_CPU_ONLY`, `WINDOWS_TOOLCHAIN_REQUIRED` | Mocks de segurança VBS/HVCI + consulta somente leitura em `Test-LumaBridgePrerequisites.ps1`. |
| 55 | `M022_RuntimeInformationResolvesFrameworkUnambiguouslyAndHandlesCollisions` | `DETERMINISTIC_CPU_ONLY`, `WINDOWS_TOOLCHAIN_REQUIRED` | Resolução de `RuntimeInformation` contra colisão com `PSReadLine 2.0.0`. |
| 56 | `M022_IsolatedProcessWithPsReadLineLoadedPassesPrerequisitesUnderStrictMode` | `DETERMINISTIC_CPU_ONLY`, `WINDOWS_TOOLCHAIN_REQUIRED` | Execução isolada de `Test-LumaBridgePrerequisites.ps1` com `PSReadLine` e `StrictMode Latest`. |
| 64 | `M024_DecoupledLightweightAndGpuTelemetrySkipsEndGpuCounterAndReportsIntervalsAndLeakAssessment` | `DETERMINISTIC_CPU_ONLY`, `WINDOWS_TOOLCHAIN_REQUIRED` | Telemetria desacoplada por processo filho com mocks de GPU counters. |

### 4.2 Casos PowerShell Excluídos no CI Windows (`50` casos — `WDK_REQUIRED`)

| Faixa / Índices | Quantidade | Nomes dos Casos Excluídos | Categoria | Motivo Objetivo da Exclusão |
|---|---:|---|---|---|
| `#1–#6` | 6 | `PackageSigningAndCryptographicVerificationPositive`, `InfTamperingRejectedEvenWithAllowUntrustedChain`, `DllTamperingRejectedEvenWithAllowUntrustedChain`, `UnsignedTamperedCatAndExpiredCertRejected`, `SignerCertificateMismatchRejected`, `IsolatedCleanStagingRejectsRepoPathsAndCleansResiduals` | `WDK_REQUIRED` | Exigem `windows/driver/x64/Release/LumaBridgeIddDriver/{.dll,.inf,.cat}`, `signtool.exe` e `Inf2Cat.exe`. |
| `#9` | 1 | `DuplicateDevicesBlockedByInstallAndMonitorScripts` | `WDK_REQUIRED` | Chama `Install-LumaBridgeDriver.ps1 -DryRun`, que exige `devcon.exe` sob `Windows Kits\10`. |
| `#10–#13`, `#20` | 5 | `FreshInstallSucceedsAndConfirmsDriverBinding`, `RepeatedInstallDisablesMonitorBeforeUpdate`, `PartialFreshInstallFailureTriggersRollback`, `PartialUpdateFailureTriggersRollback`, `InstallFailurePreservesPreRollbackDiagnosticsBeforeCleanup` | `WDK_REQUIRED` | Executam `New-SignedTestPackage` (`Release` package + `signtool.exe` + `Inf2Cat.exe`) e `Install-LumaBridgeDriver.ps1` (`devcon.exe`). |
| `#18` | 1 | `AllScriptsDryRunDoNotMutateSystemState` | `WDK_REQUIRED` | Exige `BuildPackage.AllFilesPresent -eq $true`, `signtool.exe`, `Inf2Cat.exe` e `devcon.exe`. |
| `#26` | 1 | `WppTmfCacheAndDecodeDryRunAndStreamFilter` | `WDK_REQUIRED` | Exige `tracepdb.exe` no Windows Kits para gerar comando planejado em `Initialize-LumaBridgeWppTmfCache -DryRun`. |
| `#30–#41`, `#44–#48`, `#50–#54`, `#57–#63`, `#65–#71` | 36 | `FunctionalValidationScriptDryRunAndFinallyRollbackOnFailure`, `HostProcessOutputCaptureGlobalTimeoutAndTwoProfileRunner`, `M42GpuTransportNvencGatesAndRollback`, `M421TimestampErrorsMaskingRejectedAndProlongedProfilesDryRun`, `M01_S01_WudfHostMultiCandidateAndAntiStaleCorrelation`, `M01_S01_WudfHostMissingReusedPidAndMidRunExitRejected`, `M01_S02_PartialRollbackAlwaysFailsOverallWithNonZeroThrow`, `M01_S03_BenchmarkRejectsWrongResolution`, `M01_S03_BenchmarkRejectsLowFramesOrLowSustainedFps`, `M01_S03_NvencSingleFrameEncodedRejected`, `M01_S03_ExcessiveFrameDropsRejected`, `M01_S03_Benchmark30sNeverProves180sProlongedStability`, `M01_S06_InitialSnapshotPreservesPreExistingCertsAndRegistrySemantics`, `M01_S07_StaleWrongRunIdAndIncompleteJsonRejected`, `M01_S07_WrongDriverVersionMissingBindingAndBinaryHashMismatchRejected`, `M01_S07_CompositeProfilesBothAndFullEvaluateEachSubprofileIndependently`, `M01_S06_S07_IntermediateStage6_7_8_9FailuresWithRecoveryAndDiagnostics`, `M021_Benchmark30sRejects28500MsAnd29999MsAndAccepts30000Ms`, `M021_ProlongedStability180sRejects171sAnd179999MsAndAccepts180000Ms`, `M021_InvalidQpcClockIdleConnectedPipeAndSafetyTimeoutRejected`, `M021_PercentileMethodologyAuditsHostAndNvencExactEstimatedAndNullUnavailable`, `M021_ProlongedDryRunForwardsConnectedDurationAndSafetyExecutionFlags`, `M022_PreflightFailureEmitsStructuredDiagnosticAndPreservesOriginalException`, `M024_Benchmark30sWithoutSmokePassesAndReportsFunctionalSmokeNotTested`, `M024_SmokeFailurePropagatesToAcceptanceCriteriaAndReport`, `M024_CpuFramesInGpuOnlySessionFailsSubprofileAndExitCode1ClassifiedAsControlledExitGateFailure`, `M024_ReuseSignedStagingPreservesArtifactsByteForByteAndRejectsTamperingAndInvalidSig`, `M024_ReuseSignedStagingRejectsMismatchedBindingOverlappingPathsAndHistoricalReportDir`, `M024_ReuseSignedStagingDryRunMutatesZeroFiles`, `M024_RuntimeInformationWithPsReadLineAndStrictModePassesForValidationScripts`, `M025_1_StimulusBackendDryRunForwardingAndRetrocompat`, `M025_1_ExplicitDxgiGatePositivePass`, `M025_1_ExplicitDxgiGateRejectsFallbackZeroPresentIncompleteTerminalAndMissingFields`, `M025_1_H264WorkerFailureAndMissingFieldsFailGate`, `M025_1_AutoModeBackwardCompatAndGdiSelection`, `M025_1_PsReadLineStrictModeDxgiDryRun` | `WDK_REQUIRED` | Invocam `New-M01ValidationMockHarness`, `New-SignedTestPackage` ou `Invoke-LumaBridgeFunctionalValidation.ps1` (que exigem `signtool.exe`, `Inf2Cat.exe`, `devcon.exe` e pacote `Release\|x64` compilado mesmo em `-DryRun`). |

**Resumo PowerShell:** **21 de 71 casos selecionados**; **50 de 71 casos excluídos (`WDK_REQUIRED`)**; **soma exata = `71/71`**.

### 4.3 Contabilização Consolidada (`CI` vs Inventário Histórico vs Infraestrutura Python)

- **Cobertura de inventário do CI Windows hospedado:** o runner Windows executa **`143` casos C++ + `21` casos PowerShell = `164` casos** de um inventário histórico Windows de **`237` casos** (`157` C++ unitários/componentes + `9` E2E + `71` PowerShell), o que corresponde a **aproximadamente `69,2%` do inventário de casos históricos** *(e **não** a `69,2%` de cobertura de código/linhas/branches)*.
- **Casos históricos não executados (`73` casos):** os **`73` casos restantes** (`14` C++ + `9` E2E + `50` PowerShell) são excluídos no CI hospedado por dependências ambientais (`WDK_REQUIRED`, `GPU_REQUIRED`, `NVENC_REQUIRED`, `INTERACTIVE_DESKTOP_REQUIRED`) e **não são classificados como reprovados**.
- **Autotestes da infraestrutura Linux/Python (contagem separada):** os **`6` autotestes originais** de [`scripts/ci/test_repo_hygiene.py`](../../scripts/ci/test_repo_hygiene.py) e os **`3` casos de regressão incrementais da `M0.6.1`** (`9` autotestes unitários Python ao todo) verificam exclusivamente a infraestrutura de higiene, segurança de workflows e DCO prospectivo no workflow Linux, sendo contabilizados **separadamente** do inventário histórico de `237` casos Windows.
- **Execução condicional do check DCO prospectivo:** em eventos `pull_request`, [`check_repo_hygiene.py`](../../scripts/ci/check_repo_hygiene.py) valida trailers Git efetivos `Signed-off-by`, correspondência com autoria e cutoff histórico `23a28046`; em eventos `push` e `workflow_dispatch` sem faixa DCO fornecida, o check de DCO registra **`SKIPPED` por contrato** (não constituindo aprovação nem falha da verificação prospectiva).

### 4.4 Dependências Fixadas vs Dependências Providas pelo Runner Hospedado

- **Artefatos e ações fixados por versão/revisão:** `actions/checkout` e `actions/upload-artifact` fixados por SHA completo de 40 caracteres com `persist-credentials: false`, somados aos scripts versionados em [`scripts/ci/`](../../scripts/ci/Invoke-LumaBridgeCiWindowsTests.ps1).
- **Dependências fornecidas pelo ambiente do runner hospedado (variáveis com a imagem GitHub Actions):** SO e SDKs das imagens `windows-2025` e `ubuntu-24.04`, toolchain MSVC / Windows SDK instalada via `vswhere.exe`, PowerShell 5.1 / `PSReadLine`, codec `CLSID_CMSH264DecoderMFT` (Media Foundation) no runner Windows, além de Python 3 e PyYAML na imagem Linux.

---

## 5. Separação Estrita da Qualificação Especializada (`M0` Histórica vs CI Convencional)

O CI convencional implementado em `.github/workflows/` **NÃO comprova** e **NÃO substitui**:

1. Inicialização real do driver `LumaBridgeIddDriver` via `IddCx` (`IddCxDeviceInitialize` / `IddCxAdapterInitAsync`).
2. Execução em runtime dentro do processo isolado `WUDFHost.exe` (`LOCAL SERVICE`).
3. Instalação PnP (`Root\LumaBridgeIddDriver`) e vinculação no Driver Store (`WUDFRd` + `IndirectKmd`).
4. Transporte real de texturas compartilhadas em GPU física (`IDXGIKeyedMutex` sem WARP).
5. Qualificação NVENC H.264 em hardware NVIDIA físico (`nvEncodeAPI64.dll`).
6. Fidelidade de captura e composição real de desktop via `D3d11DxgiVSync` sem oclusão.
7. Execução real de `Benchmark30s` (`30 s` @ `1080p60`).
8. Execução real de `ProlongedStability` (`180 s` @ `1080p60`).
9. Latência de transporte de rede / glass-to-glass (`M1`+) e assinatura EV / Attestation / WHQL para distribuição do driver em produção (`M6`).
10. Validação real do driver por meio da compilação (`compile-only`) isolada de `lumabridge-host.exe`.

A qualificação funcional completa da `M0` referente ao commit funcional `6b297856af535a1737658da97d381c19231913e4` e às revalidações locais `M0.4`/`M0.4.1` (preservando as duas reprovações `p99` iniciais da `M0.4`) permanece documentada de forma independente em [`windows-idd-functional-validation.md`](windows-idd-functional-validation.md) e na trilha especializada Windows 11 x64.

### 5.1 Pendências Conhecidas e Critério Objetivo de Encerramento da `M0`

- **Issue #33 (mantida ABERTA — dívida técnica aceita):** ausência de persistência de `MonitorContainerId` em `PLUGPLAY_REGKEY_DEVICE` em [`Adapter.cpp`](../../windows/driver/LumaBridgeIddDriver/Adapter.cpp) / [`VirtualMonitor.cpp`](../../windows/driver/LumaBridgeIddDriver/VirtualMonitor.cpp), a ser tratada antes da expansão para múltiplos monitores virtuais ou múltiplas instâncias dependentes de identidade persistente.
- **Issue #34 (mantida ABERTA com escopo residual não bloqueante):** escopo funcional núcleo de `M0` validado em `6b297856`; itens operacionais residuais (monitor inicialmente desabilitado dedicado em §7.5, alternância real 720p60/1080p60, bateria dedicada de desativação/reativação, desinstalação pós-sucesso, remoção de certificado e restauração de segurança) permanecem documentados para VM descartável ou ambiente dedicado sem bloquear o encerramento da `M0` nem o início futuro da `M1`.
- **Critério verificável de encerramento da `M0`:** a `M0` é considerada formalmente encerrada somente após integração por Merge commit do PR de governança `#38` em `dev`, aprovação dos checks pós-merge em `dev` (`Linux Repository Hygiene & Governance` e `Windows Non-Admin CI`), reconciliação registrada do `PR #36` / `Issue #33` / `Issue #34` e verificação da proteção configurada para `refs/heads/dev`.
- **Rust / Cargo / FFI / `LBWP v1`:** pertencem à **`M1`** e são validados em workflow dedicado sem alterar a matriz `M0` acima.

---

## 6. Matriz Adicional de Verificação `M1.1` / `M1.2` (`core/` Rust + `LBWP v1`)

Sem alterar as contagens históricas de `237` casos Windows (`M0`) ou `9` autotestes Python, os dois checks Rust obrigatórios definidos em [`.github/workflows/ci-ffi-poc.yml`](../../.github/workflows/ci-ffi-poc.yml) executam continuamente:

- **`Windows Rust + MSVC Debug/Release FFI PoC`** (`scripts/ci/Invoke-LumaBridgeFfiPocCi.ps1`) e **`Linux Rust Tests + Android ARM64 & UniFFI PoC`:**
  - `cargo fmt --all --check` e deriva de `cbindgen` (`lumabridge_ffi.h`);
  - `cargo clippy --locked --workspace --all-targets -- -D warnings` em `default`, `--features poc-fault-injection` e `--features uniffi`;
  - `cargo test --locked --workspace`: **`37/37`** (`default`), **`39/39`** (`poc-fault-injection`) e **`38/38`** (`uniffi`), incluindo **`25`** testes de `lumabridge-protocol` (`14` unitários, `6` de golden vectors + corpus malformado + `40` amostras de regressão de fuzzing em [`fuzz_regression_corpus.hex`](../../core/crates/lumabridge-protocol/tests/corpus/fuzz_regression_corpus.hex), `5` *property tests*);
  - `cargo deny --locked check advisories licenses bans sources` contra [`core/deny.toml`](../../core/deny.toml);
  - Cross-build Android ARM64 (`aarch64-linux-android`, API `29`) de `lumabridge-protocol` (`liblumabridge_protocol.rlib`) e `lumabridge-ffi` (`liblumabridge_ffi.so`) + verificação ELF / geração Kotlin UniFFI;
  - Nota de escopo: o harness `fuzz/` isolado (`5` alvos `libFuzzer` + AddressSanitizer) é verificado sob demanda em campanhas explícitas (não como execução ilimitada por push em CI).
