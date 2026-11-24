# Testes do modulo `windows/driver`

## Escopo atual

`AdapterLifecycleTests.cpp` executa **21 testes unitarios deterministicos** sobre a maquina de estados (`AdapterLifecycleTracker`), o slot de associacao em voo (`InFlightAdapterBindingSlot`) e a configuracao de validacao/estagios (`DiagnosticStageConfig.h`) definidos em `windows/driver/LumaBridgeIddDriver/`:

1. `NormalInitializationLifecycle` — fluxo normal `DeviceConfigured -> DeviceInitialized -> AdapterInitPending -> AdapterReady`;
2. `EarlyAsyncCompletionBeforeInitAsyncReturns` — conclusao assincrona (`EvtIddCxAdapterInitFinished`) chegando antes do retorno pos-processado de `IddCxAdapterInitAsync`;
3. `EarlyAsyncFailureBeforeInitAsyncReturns` — falha assincrona antes do retorno de `IddCxAdapterInitAsync` preservando `AdapterFailed`;
4. `SyncInitAsyncFailureNeverRecoversSilentlyOnRetry` — falha sincrona de `IddCxAdapterInitAsync` nunca mascarada em reentrada D0 subsequente;
5. `AsyncFailureThenD0ExitThenD0EntryMustFail` — falha assincrona com `HasAdapterHandle=true` preservando `AdapterFailed` apos `D0Exit` e novo `D0Entry`;
6. `D0ExitDuringPendingInitPreservesDeviceStoppedOnAsyncSuccess` — `D0Exit` durante inicializacao pendente preservando `DeviceStopped` quando `EvtIddCxAdapterInitFinished` conclui fora de D0;
7. `D0ReentryWhilePendingDoesNotTreatStatusPendingAsSuccess` — rejeicao do falso positivo `NT_SUCCESS(STATUS_PENDING)` em reentrada D0;
8. `D0ExitDuringPendingInitFollowedByAsyncFailure` — `D0Exit` durante inicializacao pendente seguido de falha assincrona;
9. `PendingStatusRejectedAsInitFinishedResult` — rejeicao de `STATUS_PENDING` como resultado de `EvtIddCxAdapterInitFinished`;
10. `SuspendResumeAndCommitModes` — transicoes de suspensao/retomada (`D0Exit` -> `D0Entry`) e contagem de paths em `CommitModes`;
11. `CleanupResetsHandlesAndState` — limpeza deterministica de handles e contexto do adaptador/dispositivo;
12. `ConcurrentMultiDeviceAssociationIsolation` — isolamento da associacao entre dispositivos concorrentes A e B via `InFlightAdapterBindingSlot` sem vinculacao cruzada;
13. `CleanupDuringInFlightInitPreventsCrossDeviceLateCallbackBinding` — regressao garantindo que cleanup do dispositivo A em voo (`MarkDeviceCleanedUp` + `HasBoundDevice`) impede liberacao prematura do slot e vinculacao cruzada de callbacks tardios de A no dispositivo B;
14. `CleanupDuringPendingInitialization` — cleanup de adaptador e dispositivo durante inicializacao pendente (`AdapterInitPending`), com rejeicao de `D0Entry` posterior;
15. `LateAsyncInitFinishedAfterCleanupIsRejected` — rejeicao de conclusao assincrona/sincrona tardia ou duplicada apos cleanup/falha sem ressuscitar handles ou estado;
16. `LateCommitModesAfterFailureOrCleanupIsRejected` — rejeicao de `TransitionOnCommitModes` em `AdapterFailed` ou apos cleanup sem alterar `CommittedPathCount`;
17. `DiagnosticStageSuccessProgressionTracksLastSuccessfulStage` — progressao de `LastSuccessfulStage` e `LastStageStatus` ao longo das etapas de inicializacao (`DeviceInitConfig` -> `WdfDeviceCreate` -> `IddCxDeviceInitialize` -> `DeviceD0Entry` -> `AdapterInitAsync` -> `AdapterInitFinished`);
18. `DeviceInitializeFailurePreservesPreviousSuccessfulStage` — preservacao de `LastSuccessfulStage = WdfDeviceCreate` quando `IddCxDeviceInitialize` falha com `STATUS_DEVICE_POWER_FAILURE`;
19. `AdapterInitFailuresPreserveLastSuccessfulStage` — preservacao de `LastSuccessfulStage` (`DeviceD0Entry` na falha sincrona e `AdapterInitAsync` na falha assincrona) em falhas `STATUS_DEVICE_POWER_FAILURE`;
20. `IddCxRuntimeTransmissionTypeValidatorRejectsNetworkOtherAndAcceptsWiredOther` — valida a regra binaria de runtime do `IddCx.dll` (`10.0.26100.9818`) que rejeita `0` e `9` (`IDDCX_TRANSMISSION_TYPE_NETWORK_OTHER`) e aceita `[1..8]` (incluindo `3 = IDDCX_TRANSMISSION_TYPE_WIRED_OTHER`) e `0xFFFFFFFF`;
21. `DiagnosticStageCapabilitiesProgressMonotonicallyFromStage1ToStage6` — valida `kActiveDiagnosticStage == 6` por padrao e o escalonamento incremental de capacidades dos Estagios `1..6`.

`DriverPackageValidationTests.cpp` executa **6 verificacoes automatizadas** sobre o INF fonte e os pacotes gerados em `windows/driver/x64/Debug/` e `windows/driver/x64/Release/`:

1. `ParserAndHelperRejectInvalidInputs` — valida parsing de secao/arquivos referenciados e rejeicao de placeholders/PEs invalidos;
2. `SourceInfContainsStampInfPlaceholders` — confirma tokens `NT$ARCH$.10.0...22000`, `$UMDFVERSION$` e `CatalogFile` no INF fonte;
3. `DebugPackageArtifactsValidAndConsistent` — valida DLL x64 sem assinatura embutida (`IMAGE_DIRECTORY_ENTRY_SECURITY` + `WinVerifyTrust`), INF carimbado sem tokens nao expandidos e com todas as diretivas obrigatorias UMDF/IddCx (`wudfrd.inf`, `IddCx0102`, `IndirectKmd`, `DeviceGroupId`, `AllowKernelModeClients`, `ProcessSharingDisabled`, `NTamd64.10.0...22000`), integridade do catalogo via APIs oficiais do Windows (`CryptCATOpen`, `CryptCATEnumerateCatAttr` para Windows 11 `_v100_X64_21H2`/`22H2`/`24H2`, `CryptCATEnumerateMember`, hashes Authenticode/SIP via `CryptCATAdminCalcHashFromFileHandle2`, ausencia de assinatura via `CryptQueryObject`/`WinVerifyTrust`) e paridade entre `$(PackageDir)` e `$(OutDir)` em `Debug|x64`;
4. `ReleasePackageArtifactsValidAndConsistent` — repete a verificacao integral para o pacote `Release|x64`;
5. `NegativeTamperedAndInconsistentPackagesRejected` — testes negativos cobrindo adulteracao de `.dll` e `.inf`, catalogo corrompido, catalogo inconsistente entre configuracoes e artefato ausente;
6. `AdapterSourceEnforcesSupportedIddCxTransmissionTypeAndStageConfig` — garante uso de `kAdapterTransmissionType = IDDCX_TRANSMISSION_TYPE_WIRED_OTHER`, `kEndpointMajorVersion = 1`, `WDF_REGKEY_DEVICE_SUBKEY`, `DiagBuildStage`, ausencia de `IDDCX_TRANSMISSION_TYPE_NETWORK_OTHER` em `Adapter.cpp` e propagacao nao mascarada de falha em `LumaBridgeEvtDeviceD0Entry`.

`MonitorModesTests.cpp` executa **12 testes unitarios deterministicos** sobre `MonitorModes.h` / `MonitorModes.cpp`:

1. `Validate720p60Mode` — valida timings CTA-861 VIC 4 (`1280x720@60Hz`, `1650x750` total, `74.25 MHz`);
2. `Validate1080p60Mode` — valida timings CTA-861 VIC 16 (`1920x1080@60Hz`, `2200x1125` total, `148.50 MHz`);
3. `PreferredModeIs1080p60` — confirma `1920x1080@60Hz` como modo preferencial;
4. `FrequencyAndPixelRateCalculations` — verifica consistencia de `pixelRate`, `hSyncFreq`, `vSyncFreq` e divisores em `IDDCX_MONITOR_MODE` (`0`) e `IDDCX_TARGET_MODE` (`1`);
5. `RejectsInvalidAndUnsupportedResolutions` — rejeita dimensoes nulas, `active > total` e resolucoes nao habilitadas no MVP;
6. `RejectsInvalidRefreshRatesAndScanlineOrdering` — rejeita taxas != 60 Hz, denominadores nulos, modo entrelacado e divisores invalidos;
7. `EnforcesAdapterPipelineBandwidthLimit` — valida filtragem por `maxPipelineRate`;
8. `NegotiateModeBufferCountQueryAndInsufficientBuffer` — valida consulta preliminar (`OutputCount = 2`), `STATUS_BUFFER_TOO_SMALL`, `STATUS_INVALID_PARAMETER` e copia completa;
9. `RejectsArithmeticOverflowInTimingAndBandwidth` — valida protecao contra overflow em `SafeMultiplyU64`/`SafeMultiply3U64` e `ValidateTargetModeVideoSignalInfo`;
10. `SupportedModesContainNoDuplicates` — confirma ausencia de modos equivalentes duplicados;
11. `MonitorAndTargetModesEnforceDistinctVSyncDividers` — regressao confirmando `vSyncFreqDivider == 0` exclusivo de monitor modes e `vSyncFreqDivider == 1` exclusivo de target modes/commit;
12. `CommitValidationRejectsUnadvertisedTimingsWithMatchingActiveResolution` — regressao rejeitando timings nao anunciados mesmo para resolucoes 1080p60 validas.

`SwapChainLifecycleTests.cpp` executa **15 testes unitarios deterministicos** sobre `SwapChainProcessor.h` / `SwapChainProcessor.cpp` (independentes de GPU fisica via mock de `ISwapChainBackend`):

1. `AssignProcessFramesAndUnassignLifecycle` — atribuicao, processamento de frames, invariantes de metricas, desatribuicao e preservacao do handle `hNextSurfaceAvailable`;
2. `PendingAcquireWaitsOnSurfaceEventWithoutBusyWaiting` — retorno `E_PENDING` aguardando evento do SO sem busy-wait;
3. `InitializationFailureAbandonsSwapChainWithoutDeletingCallerHandle` — falha pre-ownership retornando `STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN` sem chamar `DeleteSwapChainObject` (SO retem ownership);
4. `DeviceRemovedStopsWorkerAndDeletesOwnedSwapChainOnce` — encerramento espontaneo em `DXGI_ERROR_DEVICE_REMOVED` com delecao unica no epilogo e ausencia de dupla liberacao em `UnassignSwapChain`;
5. `FinishFrameFailureStopsWorkerAndCountsDroppedFrame` — contabilizacao de frame descartado e erro fatal quando `FinishProcessingFrame` falha;
6. `InvalidSurfaceCountsAsDroppedFrame` — frame sem superficie valida incrementando `FramesDropped`;
7. `RepeatedAssignReplacesPreviousSwapChainCleanly` — substituicao limpa de swapchain em `AssignSwapChain` repetido;
8. `ConcurrentUnassignIsIdempotentAndFreeOfRaces` — chamadas concorrentes a `UnassignSwapChain` sem race nem dupla delecao;
9. `RejectsNullHandlesWithoutDeletingUnownedSwapChain` — rejeicao de handles nulos com abandono seguro sem deletar handle nao transferido;
10. `TransientErrorsRetryAndRecoverBeforeEscalating` — recuperacao de erros transitorios abaixo de `kMaxConsecutiveTransientErrors` e escalonamento ao atingir o limite;
11. `CircuitBreakerStopsUnboundedSwapChainRecreationLoops` — estado `Faulted` apos `kMaxConsecutiveSwapChainFailures` falhas consecutivas bloqueando recriacoes ilimitadas ate `OnResume()`;
12. `SuspendAndShutdownPreventLateOrPostTeardownAssignments` — bloqueio de atribuicoes durante `Suspended` (ate `OnResume()`) e bloqueio permanente apos `Shutdown()` (`Stopped`);
13. `ReentrantUnassignDuringDeleteDoesNotDeadlockOrDoubleDelete` — prevencao de deadlock e dupla delecao quando `DeleteSwapChainObject` aciona `UnassignSwapChain` reentrantemente na thread do caller ou da worker thread;
14. `StaleMonitorUnassignDoesNotStopNewMonitorSwapChain` — regressao garantindo que `UnassignSwapChainForMonitor` de monitor antigo ignora e preserva a swapchain ativa de monitor recem-criado;
15. `FrameTimingAndFpsMetricsRecordedWithoutStoringPixels` — registra `AcquireFps`, `ProcessFps` e latencias QPC em microssegundos (`LastFrameProcessingTimeUs`, `TotalFrameProcessingTimeUs`, `AvgFrameProcessingTimeUs`, `MaxFrameProcessingTimeUs`) sem copiar pixels.

`VirtualMonitorLifecycleTests.cpp` executa **15 testes unitarios deterministicos** sobre `VirtualMonitor.h` / `VirtualMonitor.cpp` (independentes de WUDFHost/GPU via mock de `IVirtualMonitorBackend`):

1. `DisabledByDefaultSkipsMonitorCreationAndArrival` — confirma que o monitor permanece desabilitado por padrao sem chamar `IddCxMonitorCreate` ou `IddCxMonitorArrival`;
2. `ControlledActivationCreatesAndArrivesSingleMonitorWithPersistentIdentity` — valida criacao e chegada com `ConnectorIndex = 0` e `ContainerId` persistente;
3. `DuplicateArrivalRequestIsPreventedWhileMonitorIsActive` — impede criacao/chegada duplicada enquanto monitor esta ativo;
4. `CreateMonitorFailureTransitionsToFaultedWithoutOrphanHandle` — trata falha em `IddCxMonitorCreate` sem handle orfao;
5. `PartialInitFailureOnArrivalDeletesUnarrivedMonitorObject` — exclui objeto `IDDCX_MONITOR` via `DeleteUnarrivedMonitorObject` se `IddCxMonitorArrival` falhar;
6. `SafeDepartureStopsSwapChainAndAllowsCleanRecreation` — garante parada da swapchain antes de `IddCxMonitorDeparture` e recriacao limpa subsequente;
7. `DepartureIsIdempotentWhenMonitorNotActive` — garante idempotencia de `DepartMonitor()`;
8. `DisablingActivationAfterDeparturePreventsSubsequentArrival` — impede nova chegada apos desativacao;
9. `NotifyMonitorObjectCleanedUpResetsActiveHandleSafely` — limpa handle ativo no cleanup WDF do monitor;
10. `RejectsNullAdapterHandleWhenEnabled` — rejeita adaptador nulo com `STATUS_INVALID_PARAMETER`;
11. `FailedDeparturePreservesHandleBlocksRecreationAndRecovers` — preserva `m_monitorHandle` quando `IddCxMonitorDeparture` falha, bloqueia recriacao (`STATUS_DEVICE_BUSY`) e recupera apos retry bem-sucedido ou cleanup WDF;
12. `SuspendResumeAndLateCreateCancellation` — valida estados `Suspended`/`OnResume()` e delecao imediata caso `OnSuspend()` ocorra durante `CreateMonitor`;
13. `IrreversibleShutdownAndInFlightTeardownCancellation` — garante `Shutdown()` irreversivel, rejeicao permanente de `OnResume()`/`EnsureMonitorArrived()` e desconexao imediata caso ocorra durante `ArriveMonitor`;
14. `ReentrantBackendCallbacksDoNotDeadlockOrLeakReferences` — garante ausencia de deadlock e balanco exato de referencias em callbacks reentrantes;
15. `DerivedContainerIdsAreUniqueAndRfc4122ValidPerInstance` — confirma `ContainerId` deterministico, unico por instancia/conector e valido segundo RFC 4122.

`LumaBridgeFunctionalToolingTests.ps1` executa **71 verificacoes automatizadas PowerShell** com mocks isolados e assinaturas efemeras em diretorio temporario sobre `windows/driver/scripts/`:

1. `PackageSigningAndCryptographicVerificationPositive` — valida assinatura em staging isolado, hashes SIP de `.dll` e `.inf` no `.cat`, assinatura PKCS#7 e correspondencia de certificados preservando hashes originais de build;
2. `InfTamperingRejectedEvenWithAllowUntrustedChain` — comprova bloqueio de `.inf` adulterado inclusive com `-AllowUntrustedChain`;
3. `DllTamperingRejectedEvenWithAllowUntrustedChain` — comprova bloqueio de `.dll` adulterada (`HashMismatch`) inclusive com `-AllowUntrustedChain`;
4. `UnsignedTamperedCatAndExpiredCertRejected` — rejeita pacote sem assinatura, `.cat` adulterado e certificado expirado mesmo com `-AllowUntrustedChain`;
5. `SignerCertificateMismatchRejected` — rejeita divergencia de thumbprint entre `.dll`, `.cat` e `LumaBridgeTest.cer`;
6. `IsolatedCleanStagingRejectsRepoPathsAndCleansResiduals` — rejeita staging dentro do repositorio/build e limpa residuos antes do `Inf2Cat`;
7. `PnpIdentificationUsesEffectiveDevpkeyHardwareIdsOnly` — garante lookup exclusivo via `DEVPKEY_Device_HardwareIds` rejeitando falsos positivos por `FriendlyName`;
8. `DriverStoreXmlParsingIsLocaleIndependent` — valida parsing estruturado de `pnputil /enum-drivers /format xml` independente de idioma;
9. `DuplicateDevicesBlockedByInstallAndMonitorScripts` — garante bloqueio na presenca de dispositivos duplicados;
10. `FreshInstallSucceedsAndConfirmsDriverBinding` — valida instalacao nova, `EnableVirtualMonitor = 0` e confirmacao de vinculo do driver;
11. `RepeatedInstallDisablesMonitorBeforeUpdate` — confirma desabilitacao (`EnableVirtualMonitor = 0`) e restart do dispositivo antes da atualizacao;
12. `PartialFreshInstallFailureTriggersRollback` — valida rollback automatico removendo dispositivo parcial e `oemXX.inf` recem-adicionado;
13. `PartialUpdateFailureTriggersRollback` — valida rollback automatico em falha de atualizacao mantendo estado anterior seguro;
14. `VirtualMonitorEnablePartialFailureTriggersRollback` — valida reversao para `EnableVirtualMonitor = 0` e restart em falha de ativacao;
15. `UninstallOmitsForceByDefaultAndSupportsOptInForce` — garante ausencia de `/force` por padrao e suporte opt-in a `-ForceDriverStoreDelete`;
16. `UninstallCertificateRemovalRequiresThumbprintAndConfirmation` — exige thumbprint SHA-1 valido e confirmacao dedicada (`-ConfirmCertificateRemoval`);
17. `DiagnosticsIdentifiesLumaBridgeWudfHostProcess` — valida correlacao exata do processo `WUDFHost.exe` associado ao LumaBridge;
18. `AllScriptsDryRunDoNotMutateSystemState` — confirma execucao limpa de `-DryRun` em todos os scripts (incluindo `Invoke-LumaBridgeEtwTrace.ps1`) sem efeitos colaterais;
19. `PnpProblemStatusAndStartupBreadcrumbsCollected` — valida formatacao de `DEVPKEY_Device_ProblemStatus` (`0xC000009E`), leitura de `UpperFilters` (`IndirectKmd`), leitura de breadcrumbs `Diag*` e exposicao em `Test-LumaBridgeDeviceDriverBinding`;
20. `InstallFailurePreservesPreRollbackDiagnosticsBeforeCleanup` — simula falha real de start (`ROOT\DISPLAY\0000`, `oem68.inf`, `ProblemCode=10`, `0xC000009E`) e garante preservacao de `diagnostics-summary.json`, `diagnostics-summary.md`, `setupapi-excerpt.log` e `post-rollback-status.json` apos rollback completo;
21. `SetupApiExcerptAndEventChannelCollection` — valida parser filtrado de `setupapi.dev.log` (WDF `2.23` vs `2.31` e `CM_PROB_FAILED_START`) e coleta multi-canal (`Kernel-PnP`, `CodeIntegrity`, `WerKernel`) pulando canais desabilitados;
22. `DriverStageSummaryIdentifiesLastSuccessfulAndFailingStage` — valida correlacao combinada de traces `[LB-DRIVER]`, eventos TraceLogging ETL e breadcrumbs `Diag*` para identificar `LastSuccessfulStage` e `FirstFailureStage`;
23. `CrashDumpInventoryAndEtwTraceDryRun` — valida inventario de dumps (`CrashDumps`, `AutoLogger`), `-DryRun` do `Invoke-LumaBridgeEtwTrace.ps1` (sessoes `Core` + `Dxg`) e `-Action ExportSummary`;
24. `EtwTraceUsesProviderFileAndSeparatesDxgKrnlSession` — valida arquivos `-pf` (`6` providers Core sem comentarios `#` e `2` providers `DxgKrnl`/`Watchdog-Events`), verificacao imediata de GUIDs via `Test-LumaBridgeEtwSessionProviders` e ausencia de `DxgKrnl` sem `-IncludeDxgKrnl`;
25. `StreamingEtlQueryAppliesNativeXPathWithoutPreFilterCap` — valida geracao de XPath nativo (`Provider`, `TimeCreated`, `Execution[@ProcessID]`, exclusao padrao `DxgKrnl`/`Watchdog-Events`), streaming sem teto de 500 eventos pre-filtro, exposicao de `CircularWrapWarning` e filtro estreito do `setupapi.dev.log` excluindo `VBoxSup.inf`;
26. `WppTmfCacheAndDecodeDryRunAndStreamFilter` — valida `-DryRun` de `Initialize-LumaBridgeWppTmfCache` e decodificacao WPP em streaming (`Invoke-LumaBridgeWppEtlDecode`) filtrando PID `23812` e excluindo ruido `DxgKrnl`/`Watchdog-Events`;
27. `PrepareIddSampleReferenceDryRunEnforcesIsolation` — valida bloqueio de diretorios dentro do repositorio e execucao limpa de `Prepare-IddSampleReference.ps1 -DryRun` sem criar arquivos nem instalar drivers;
28. `DiagnosticStageBuildManifestAndSubkeyBreadcrumbs` — valida leitura automatica de `Diag*` (incluindo `DiagBuildStage`) na subchave `Device Parameters\LumaBridgeIddDriver` e geracao isolada de manifesto/SHA-256 em `Build-LumaBridgeDiagnosticStage.ps1`;
29. `ObservabilityVerifyProvidersAndUnclampedEtlTraceLoggingRecovery` — valida exposicao de `AllProvidersVerified` no nivel raiz de `VerifyProviders`, nao truncamento de `Collect-LumaBridgeDiagnostics.ps1` por eventos PnP antigos e recuperacao direcionada de eventos TraceLogging sem manifesto (`ProviderId` sem `ProviderName`) apos teto `MaxMatchedEvents`;
30. `FunctionalValidationScriptDryRunAndFinallyRollbackOnFailure` — valida `Invoke-LumaBridgeFunctionalValidation.ps1 -DryRun`, uso estrito de `$signResult.StagingDir` na documentacao/script e rollback garantido no bloco `finally` (reversao de `EnableFrameExtraction=0`, limpeza de `AuthorizedHostUserSid`, restauracao de `EnableVirtualMonitor`, parada da sessao ETW e restart do dispositivo) mesmo apos falha no host ou erro no meio do fluxo;
31–57. Cobertura `M4.2.1` / `M0.1` / `M0.2.1` / `M0.2.2` — gates estritos por subperfil (`Benchmark30s` sem desconto de duracao, `ProlongedStability >= 180s`), identidade `WUDFHost`, metodologia de percentis (`ExactPopulation`, `ReservoirSampledEstimate_AlgorithmR`, `NotAvailable`), `RuntimeInformation` isolado contra `PSReadLine` e diagnosticos `M0.2.2`;
58–65. Cobertura `M0.2.4` — independencia de `FunctionalSmokePassed` no `Benchmark30s`, classificacao `ControlledExitGateFailure` / `TimeoutKilled` / `CrashOrAbnormalExit`, rejeicao de frames CPU em sessao GPU-only, reuso criptograficamente verificado de staging assinado (`-ReuseSignedStaging`) com protecao contra sobrescrita de relatorios historicos e telemetria desacoplada (`-GpuSampleIntervalSec` sem `Get-Counter` na fase `End`);
66–71. Cobertura `M0.2.5.1` — encaminhamento `-StimulusBackend Dxgi|Gdi|Auto` no `DryRun` (`Benchmark30s` e `ProlongedStability`), gate estrito zero-default para `Dxgi` (rejeicao de fallback GDI, `PresentSucceeded=0`, `CompletedCleanly=false`, `TerminalFailure=true`, campos ausentes/invalidos e cadencia insuficiente com `PresentSucceeded>0`), reprovacao por falha/timeout no `H264DecodeValidation.Worker`, compatibilidade retroativa/erro terminal em `Auto`, selecao `Gdi` e `Benchmark30s -StimulusBackend Dxgi -DryRun` isolado com `PSReadLine` + `StrictMode Latest`.

`FrameExtractionTests.cpp` executa **12 testes deterministicos e D3D11 reais** sobre `FrameExtractor.h` / `FrameExtractor.cpp` (dispositivo D3D11 real hardware/WARP e injecao de falhas via `ID3d11ExtractionHooks`):

1. `ValidRealD3d11Texture720pAnd1080pExtraction` — extrai texturas D3D11 reais `1280x720` e `1920x1080` (`BGRA8` e `RGBA8`), reutilizacao de staging e integridade byte-a-byte de padrao sintetico + CRC-32;
2. `InvalidDimensionsAndBoundsRejected` — rejeita dimensoes nulas e acima de `kMaxFrameWidth`/`kMaxFrameHeight`;
3. `UnsupportedDxgiFormatRejected` — rejeita formatos nao suportados (`DXGI_FORMAT_R16G16B16A16_FLOAT`) com `DXGI_ERROR_UNSUPPORTED`;
4. `InvalidMipLevelsArraySizeAndMsaaRejected` — rejeita `MipLevels > 1`, `ArraySize > 1` e MSAA (`SampleDesc.Count > 1`);
5. `NullSurfaceAndMissingDeviceRejected` — rejeita dispositivo ausente, superficie nula e `IDXGIResource` sem `ID3D11Texture2D`;
6. `ProtectedContentRejectedWithoutExposingPixels` — rejeita `HwProtectedSurface` e `D3D11_RESOURCE_MISC_HW_PROTECTED` com `DXGI_ERROR_ACCESS_DENIED` sem expor pixels;
7. `StagingAllocationFailureHandledCleanly` — trata `E_OUTOFMEMORY` na alocacao da textura staging e recupera no frame seguinte;
8. `MapAndCopyFailureHandledCleanly` — trata erros de `CopyResource` / `Map`, garante `Unmap` RAII e reempacotamento de linhas quando `RowPitch > Width * 4`;
9. `DeviceRemovedAndResetPropagated` — propaga `DXGI_ERROR_DEVICE_REMOVED` / `DXGI_ERROR_DEVICE_RESET` limpando a staging texture;
10. `AcquiredSurfaceComReferenceLifetimeReleasedBeforeReturn` — comprova via stub COM rastreado (incluindo `AdoptSourceTexture` via `ComPtr::Detach()`) que a referencia `ID3D11Texture2D`/`IDXGIResource` adquirida e liberada antes do `Map` e antes do retorno de `ExtractFrame`;
11. `PoolBufferMemoryBoundsAndFlushStorageRelease` — valida retencao de capacidade ate `kMaxRetainedPoolBufferBytes` (`~14.06 MiB` para 720p/1080p/1440p), liberacao automatica de picos de `64 MiB` na reciclagem, rejeicao acima de `kMaxFramePayloadBytes` e zeragem integral da memoria em `FlushQueue()`;
12. `SwapChainProcessorIntegrationWithExtractionAndIddCxFinish` — integra `SwapChainProcessor`, extrator D3D11 real, fila limitada e `FinishProcessingFrame`.

`FrameIpcTests.cpp` executa **31 testes deterministicos** sobre `FrameIpcProtocol.h`, `FrameTransport.h/.cpp` e `FrameConsumer.h/.cpp`:

1. `ValidHandshakeFrameTransferAndAck` — handshake versionado, sessao, transferencia de frames BGRA8 e confirmacao `FrameIpcFrameAck`;
2. `IncompatibleProtocolVersionRejected` — rejeicao de `VersionMajor` incompativel com `VersionMismatch` e aceitacao subsequente de cliente valido;
3. `InvalidMessageLengthAndBadMagicRejected` — validacao de envelope, magic invalido, tamanho divergente e cliente truncado no pipe;
4. `IncorrectSessionIdRejected` — rejeicao de `SessionId` nulo ou divergente no header e no `FrameAck` em execucao no pipe;
5. `FrameSequenceMonotonicityAndGapDetection` — sequencia monotonica e contabilizacao exata de `SequenceGapsDetected`;
6. `PayloadLimitsAndOverflowValidation` — protecao contra overflow de 64 bits, pitch invalido, teto de 64 MiB e formatos invalidos;
7. `UnauthorizedClientRejected` — rejeicao de `ClientProcessId` nulo ou falsificado via `GetNamedPipeClientProcessId` antes de qualquer transmissao de pixels, alem de verificacao real de DACL e SACL do Named Pipe (`WinNetworkSid`/`WinAnonymousSid` negados, `IU` ausente por padrao, `SYSTEM`/`BA`/`LS`/SID do proprietario permitidos, `WinMediumLabelSid` presente);
8. `HostDisconnectReconnectAndMidFrameDisconnect` — desconexao abrupta no meio do frame, preservacao do servidor e reconexao com nova sessao;
9. `BoundedQueueBackpressureSlowConsumerAndNoBusyWait` — politica `drop-oldest` (`MaxQueueDepth = 3`), ausencia de bloqueio no produtor sem host e ausencia de busy-wait;
10. `ConcurrentShutdownSuspendAndResourceCleanup` — encerramento limpo (`Stop()`) sob producao e conexoes concorrentes sem deadlocks;
11. `CrossUserSidAuthorizationAndRestrictedDaclRejection` — testes negativos de acesso entre usuarios via `AuthorizedUserSid` (rejeicao no handshake e na DACL restrita do kernel quando `RestrictDaclToAuthorizedSid` esta ativo, sem vazamento de pixels) e aceitacao com SID exato autorizado;
12. `CrossSessionAndSpoofedSessionRejection` — rejeicao de cliente fora da sessao permitida (`AllowedClientSessionId`) e de `ClientSessionId` adulterado no handshake em desacordo com `TokenSessionId` do kernel;
13. `ProcessIntegrityAndAnonymousSqosRejectionBeforePixels` — rejeicao por `MinimumIntegrityRid` insuficiente, bloqueio de `SECURITY_ANONYMOUS` SQOS e bloqueio real no kernel de thread com token duplicado em `SECURITY_MANDATORY_LOW_RID` (`ERROR_ACCESS_DENIED`), mantendo frame enfileirado intacto para consumidor autorizado;
14–25. Cobertura `M4.1.1` / `M4.2` / `M0.2.1` — limites de pool, razoes de saida smoke/idle, sessoes repetidas, negociacao v1.1 GPU Shared Texture, bloqueio de clientes nao autorizados/LUID divergente, reservoir sampling e duracao conectada QPC;
26–31. Cobertura `M0.2.4` — transicoes `CPU->GPU` e `GPU->CPU` com descarte de frames stale/mismatch, estresse concorrente de publicacao e desconexao mid-stream, wraparound `UINT64_MAX -> 1` + descarte nao bloqueante sem consumidor, rejeicao de `FrameHeader` CPU em sessao GPU-only, pacing racional QPC sem drift (`108k` ticks) + recusa de fallback em monitor fisico + `PacingCorrelation`, e ciclo DXGI stimulus em superficie explicita de teste.

`HostValidationWorkerAndStimulusTests.cpp` executa **28 testes unitarios e de componentes deterministicos** (M0.2.5.1) cobrindo:
- P0-A (5 testes): ausencia de consolidacao de percentis por pacote, equivalencia estatistica M0.2.1, escalas sinteticas (`1800`, `10800`, `65536`, `65537` e `216000` amostras), semantica nula em zero pacotes e falhas de decode/drain;
- P0-C (8 regressoes de `VirtualDisplayStimulus`): erro terminal pos-start preservando `HRESULT`, falha de init, parada normal limpa, oclusao temporaria recuperada, oclusao persistente em `Dxgi` sem fallback, recriaçao de swapchain com recuperacao e falha definitiva, proibicao de fallback GDI em `Dxgi`, e fallback autorizado em `Auto`;
- P0-D (15 testes de `AsyncH264ValidationWorker` e `EvaluateHostGates`): startup/shutdown, ordem FIFO + move sem copia, saturacao de fila, timeout de enqueue e propagacao aos gates, falha de prewarm, excecao `std::bad_alloc` via seam sem perda silenciosa, falha de decodificacao, rejeicao pos-stop, drain de fila pendente, falha/deadline de drain sem `detach()`, `WatchdogForcedTermination`, consolidacao final antes de gates/JSON, balanco COM/MF real na thread do worker MFT e lifecycle explicito do fallback sincrono.

`FrameEndToEndIntegrationTests.cpp` executa **9 testes de integracao multiprocesso reais** com D3D11 real + `D3d11SharedTexturePool` + `FrameIpcServer` + processo filho `lumabridge-host.exe` lancado via `CreateProcessW` (incluindo `EndToEndProlonged1080p60GpuNvenc30SecondBenchmark`, parametro opcional `--only-bench30s` e variavel `LUMABRIDGE_BENCH30S_EVIDENCE_PATH` para preservacao de evidencia JSON, alem de classificacao explicita `BLOCKED_BY_ENVIRONMENT` quando DXGI sofre `DXGI_STATUS_OCCLUDED` em desktop isolado — nesses casos, o modo `Auto` valida apenas pacing em fallback `GdiLegacy`, e nao pacing efetivo `D3d11DxgiVSync`):

1. `EndToEndRealD3d11ExtractionToSeparateHostProcess720pAnd1080p` — extrai texturas D3D11 reais `1280x720` e `1920x1080` com padrao sintetico, envia pelo pipe local e valida recebimento de 6/6 frames e CRC-32/pixels no processo separado `lumabridge-host.exe`;
2. `EndToEndHostDisconnectAndReconnectDuringActiveSwapChainLoop` — executa `SwapChainProcessor` ativo enquanto dois processos `lumabridge-host.exe` conectam, desconectam e reconectam com janela intermediaria de backpressure;
3. `EndToEndSmokeDurationExitAndMinFramesVsTargetCli` — valida perfis CLI de smoke (`--min-frames`) vs target (`--require-max-frames`);
4. `EndToEndThroughputAndLatencyBenchmark720pAnd1080p` — mede throughput e latencia reais M4.1.1 para 30 frames `1280x720` e `1920x1080`;
5. `VirtualDisplayStimulusHighResTimer60FpsVerification` — valida `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` atingindo ~60 FPS reais no `VirtualDisplayStimulus`;
6. `EndToEndPhaseAGpuSharedTextureSeparateHostProcess720pAnd1080p` — comprova todos os 7 criterios da Fase A em processos separados (`CpuStagingReadsPerformed == 0` no modo normal, integridade visual no modo sintetico, `GpuFramesOpened`, `IDXGIKeyedMutex` e liberacao limpa pos-ACK);
7. `EndToEndPhaseBGpuSharedTexturePlusNvencAndIndependentDecode720pAnd1080p` — valida pipeline completo GPU Shared -> NVENC H.264 -> decodificador Media Foundation independente em 720p e 1080p;
8. `EndToEndControlledThreeWayBenchmark720pAnd1080p` — benchmark controlado comparando M4.1.1 (CPU Staging), M4.2 Fase A (GPU Shared) e M4.2 Fase B (GPU Shared + NVENC H.264) para 120 frames em `1280x720` e `1920x1080`.

`GpuSharedTextureTests.cpp` executa **9 testes deterministas da Fase A** (criacao NT handle/KeyedMutex, sincronizacao GPU sem leitura CPU, backpressure/pool esgotado, LUID incompativel, DACL restrita/SDDL, desconexao durante mutex ativo, timeout, `DXGI_ERROR_DEVICE_REMOVED` / `ReconstructSession`, recriacao de swapchain + separacao de metricas GPU/CPU e liberacao pos-flush).

`NvencEncoderTests.cpp` executa **8 testes reais de hardware NVIDIA NVENC H.264** (`ProbeAvailability`, sessao 720p/1080p, `DirectArgb` vs `ID3D11VideoProcessor` GPU `NV12`, rejeicao de formato DXGI incompativel, IDR periodico/forcado, injecao de `NV_ENC_ERR_ENCODER_BUSY` / `DEVICE_REMOVED` + `ReconstructSession`, validacao independente de PSNR com `Microsoft H.264 Video Decoder MFT`, e `TestNvencTimestampCoverageValidationAndStageBreakdown` cobrindo timestamps causais e breakdown por estagio NVENC — somando **157** casos C++ unitarios e de componentes efetivamente inventariados nos fontes, frente ao valor historico `156` citado antes da conferencia nominal).

## Fronteira com validacao em runtime WDF/IddCx

Estes testes validam exclusivamente a logica deterministica de transicoes de estado/associacao e a integridade estatica dos artefatos empacotados (`.dll`, `.inf`, `.cat`), sem substituir `InfVerif`, `Inf2Cat` nem execucao real em runtime dentro de `WUDFHost.exe` ou instalacao PnP. A execucao real do driver depende de assinatura de teste controlada, enumeracao de dispositivo, monitor virtual e processamento de modos/swapchain.

## Como compilar e executar

Em ambiente x64 do Visual Studio (`VsDevCmd.bat -arch=amd64 -host_arch=amd64`), apos o rebuild de `Debug|x64` e `Release|x64` da solucao, os artefatos de teste sao direcionados para `windows/driver/x64/Debug/` (ignorado por `windows/driver/.gitignore`):

```bat
cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\AdapterLifecycleTests.cpp /Fowindows\driver\x64\Debug\AdapterLifecycleTests.obj /Fe:windows\driver\x64\Debug\AdapterLifecycleTests.exe
windows\driver\x64\Debug\AdapterLifecycleTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\DriverPackageValidationTests.cpp /Fowindows\driver\x64\Debug\DriverPackageValidationTests.obj /Fe:windows\driver\x64\Debug\DriverPackageValidationTests.exe
windows\driver\x64\Debug\DriverPackageValidationTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\MonitorModesTests.cpp windows\driver\LumaBridgeIddDriver\MonitorModes.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\MonitorModesTests.exe
windows\driver\x64\Debug\MonitorModesTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\SwapChainLifecycleTests.cpp windows\driver\LumaBridgeIddDriver\SwapChainProcessor.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\SwapChainLifecycleTests.exe
windows\driver\x64\Debug\SwapChainLifecycleTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\VirtualMonitorLifecycleTests.cpp windows\driver\LumaBridgeIddDriver\VirtualMonitor.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\VirtualMonitorLifecycleTests.exe
windows\driver\x64\Debug\VirtualMonitorLifecycleTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\FrameExtractionTests.cpp windows\driver\LumaBridgeIddDriver\FrameExtractor.cpp windows\driver\LumaBridgeIddDriver\FrameTransport.cpp windows\driver\LumaBridgeIddDriver\SharedTexturePool.cpp windows\driver\LumaBridgeIddDriver\SwapChainProcessor.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\FrameExtractionTests.exe /link d3d11.lib dxgi.lib advapi32.lib
windows\driver\x64\Debug\FrameExtractionTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc /DUNICODE /D_UNICODE /Iwindows\driver\LumaBridgeIddDriver windows\driver\tests\GpuSharedTextureTests.cpp windows\driver\LumaBridgeIddDriver\SharedTexturePool.cpp windows\driver\LumaBridgeIddDriver\FrameTransport.cpp windows\driver\LumaBridgeIddDriver\SwapChainProcessor.cpp windows\host\FrameConsumer.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\GpuSharedTextureTests.exe /link d3d11.lib dxgi.lib advapi32.lib user32.lib gdi32.lib
windows\driver\x64\Debug\GpuSharedTextureTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc /DUNICODE /D_UNICODE windows\driver\tests\FrameIpcTests.cpp windows\driver\LumaBridgeIddDriver\SharedTexturePool.cpp windows\driver\LumaBridgeIddDriver\FrameTransport.cpp windows\host\FrameConsumer.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\FrameIpcTests.exe /link d3d11.lib dxgi.lib advapi32.lib user32.lib gdi32.lib
windows\driver\x64\Debug\FrameIpcTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc /DUNICODE /D_UNICODE /Iwindows\host /Iwindows\driver\LumaBridgeIddDriver windows\driver\tests\NvencEncoderTests.cpp windows\host\NvencH264Encoder.cpp windows\host\H264BitstreamValidator.cpp windows\host\FrameConsumer.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\NvencEncoderTests.exe /link d3d11.lib dxgi.lib advapi32.lib user32.lib gdi32.lib mfplat.lib mfuuid.lib wmcodecdspuuid.lib ole32.lib
windows\driver\x64\Debug\NvencEncoderTests.exe

cl /nologo /std:c++20 /W4 /WX /EHsc /O2 /MD /DNDEBUG /DUNICODE /D_UNICODE /Iwindows\driver\LumaBridgeIddDriver /Iwindows\host windows\host\main.cpp windows\host\FrameConsumer.cpp windows\host\NvencH264Encoder.cpp windows\host\H264BitstreamValidator.cpp /Fowindows\driver\x64\Release\ /Fe:windows\driver\x64\Release\lumabridge-host.exe /link d3d11.lib dxgi.lib advapi32.lib user32.lib gdi32.lib mfplat.lib mfuuid.lib wmcodecdspuuid.lib ole32.lib psapi.lib
cl /nologo /std:c++20 /W4 /WX /EHsc /O2 /MD /DNDEBUG /DUNICODE /D_UNICODE /Iwindows\driver\LumaBridgeIddDriver /Iwindows\host windows\driver\tests\FrameEndToEndIntegrationTests.cpp windows\driver\LumaBridgeIddDriver\SharedTexturePool.cpp windows\driver\LumaBridgeIddDriver\FrameExtractor.cpp windows\driver\LumaBridgeIddDriver\FrameTransport.cpp windows\driver\LumaBridgeIddDriver\SwapChainProcessor.cpp /Fowindows\driver\x64\Release\ /Fe:windows\driver\x64\Release\FrameEndToEndIntegrationTests.exe /link d3d11.lib dxgi.lib advapi32.lib user32.lib gdi32.lib
windows\driver\x64\Release\FrameEndToEndIntegrationTests.exe

cl /nologo /std:c++20 /W4 /WX /EHsc /Od /Zi /MDd /DUNICODE /D_UNICODE /Iwindows\host /Iwindows\driver\LumaBridgeIddDriver windows\driver\tests\HostValidationWorkerAndStimulusTests.cpp windows\host\FrameConsumer.cpp windows\host\NvencH264Encoder.cpp windows\host\H264BitstreamValidator.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\HostValidationWorkerAndStimulusTests.exe /link d3d11.lib dxgi.lib advapi32.lib user32.lib gdi32.lib mfplat.lib mfuuid.lib wmcodecdspuuid.lib ole32.lib
windows\driver\x64\Debug\HostValidationWorkerAndStimulusTests.exe
```

Suíte PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File windows\driver\tests\LumaBridgeFunctionalToolingTests.ps1
```

## Separacao entre CI Convencional e Qualificacao Especializada (`M0.6`)

- A matriz completa de dependencias de todas as `10` suites C++ (`157` casos), `9` testes E2E e `71` testes PowerShell encontra-se documentada em [ci-and-test-matrix.md](../../../docs/setup/ci-and-test-matrix.md).
- O workflow inicial nao administrativo em `.github/workflows/ci-windows.yml` (via `scripts/ci/Invoke-LumaBridgeCiWindowsTests.ps1`) compila `lumabridge-host.exe` (compile-only), executa as suites C++ independentes de WDK/GPU/NVENC fisica e o subconjunto explicitamente listado (`21/71`) de testes PowerShell sem dependencia do WDK/pacote `Release|x64`.
- As suites `DriverPackageValidationTests` (`WDK_REQUIRED`), `NvencEncoderTests` (`GPU_REQUIRED` / `NVENC_REQUIRED`), `FrameEndToEndIntegrationTests` (`9/9` E2E), os `50/71` casos PowerShell dependentes do WDK e a validacao real em `WUDFHost.exe` (`Benchmark30s` / `ProlongedStability`) permanecem exclusivamente na trilha especializada Windows 11 x64 local/dedicada e preservam a qualificacao historica do commit `6b297856`.
