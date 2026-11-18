# Testes do modulo `windows/driver`

## Escopo atual

`AdapterLifecycleTests.cpp` executa **16 testes unitarios deterministicos** sobre a maquina de estados (`AdapterLifecycleTracker`) e o slot de associacao em voo (`InFlightAdapterBindingSlot`) definidos em `windows/driver/LumaBridgeIddDriver/AdapterStateMachine.h`:

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
16. `LateCommitModesAfterFailureOrCleanupIsRejected` — rejeicao de `TransitionOnCommitModes` em `AdapterFailed` ou apos cleanup sem alterar `CommittedPathCount`.

`DriverPackageValidationTests.cpp` executa **5 verificacoes automatizadas** sobre o INF fonte e os pacotes gerados em `windows/driver/x64/Debug/` e `windows/driver/x64/Release/`:

1. `ParserAndHelperRejectInvalidInputs` — valida parsing de secao/arquivos referenciados e rejeicao de placeholders/PEs invalidos;
2. `SourceInfContainsStampInfPlaceholders` — confirma tokens `NT$ARCH$.10.0...22000`, `$UMDFVERSION$` e `CatalogFile` no INF fonte;
3. `DebugPackageArtifactsValidAndConsistent` — valida DLL x64 sem assinatura embutida (`IMAGE_DIRECTORY_ENTRY_SECURITY` + `WinVerifyTrust`), INF carimbado sem tokens nao expandidos e com todas as diretivas obrigatorias UMDF/IddCx (`wudfrd.inf`, `IddCx0102`, `IndirectKmd`, `DeviceGroupId`, `AllowKernelModeClients`, `ProcessSharingDisabled`, `NTamd64.10.0...22000`), integridade do catalogo via APIs oficiais do Windows (`CryptCATOpen`, `CryptCATEnumerateCatAttr` para Windows 11 `_v100_X64_21H2`/`22H2`/`24H2`, `CryptCATEnumerateMember`, hashes Authenticode/SIP via `CryptCATAdminCalcHashFromFileHandle2`, ausencia de assinatura via `CryptQueryObject`/`WinVerifyTrust`) e paridade entre `$(PackageDir)` e `$(OutDir)` em `Debug|x64`;
4. `ReleasePackageArtifactsValidAndConsistent` — repete a verificacao integral para o pacote `Release|x64`;
5. `NegativeTamperedAndInconsistentPackagesRejected` — testes negativos cobrindo adulteracao de `.dll` e `.inf`, catalogo corrompido, catalogo inconsistente entre configuracoes e artefato ausente.

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

`SwapChainLifecycleTests.cpp` executa **13 testes unitarios deterministicos** sobre `SwapChainProcessor.h` / `SwapChainProcessor.cpp` (independentes de GPU fisica via mock de `ISwapChainBackend`):

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
13. `ReentrantUnassignDuringDeleteDoesNotDeadlockOrDoubleDelete` — prevencao de deadlock e dupla delecao quando `DeleteSwapChainObject` aciona `UnassignSwapChain` reentrantemente na thread do caller ou da worker thread.

`VirtualMonitorLifecycleTests.cpp` executa **10 testes unitarios deterministicos** sobre `VirtualMonitor.h` / `VirtualMonitor.cpp` (independentes de WUDFHost/GPU via mock de `IVirtualMonitorBackend`):

1. `DisabledByDefaultSkipsMonitorCreationAndArrival` — confirma que o monitor permanece desabilitado por padrao sem chamar `IddCxMonitorCreate` ou `IddCxMonitorArrival`;
2. `ControlledActivationCreatesAndArrivesSingleMonitorWithPersistentIdentity` — valida criacao e chegada com `ConnectorIndex = 0` e `ContainerId` persistente;
3. `DuplicateArrivalRequestIsPreventedWhileMonitorIsActive` — impede criacao/chegada duplicada enquanto monitor esta ativo;
4. `CreateMonitorFailureTransitionsToFaultedWithoutOrphanHandle` — trata falha em `IddCxMonitorCreate` sem handle orfao;
5. `PartialInitFailureOnArrivalDeletesUnarrivedMonitorObject` — exclui objeto `IDDCX_MONITOR` via `DeleteUnarrivedMonitorObject` se `IddCxMonitorArrival` falhar;
6. `SafeDepartureStopsSwapChainAndAllowsCleanRecreation` — garante parada da swapchain antes de `IddCxMonitorDeparture` e recriacao limpa subsequente;
7. `DepartureIsIdempotentWhenMonitorNotActive` — garante idempotencia de `DepartMonitor()`;
8. `DisablingActivationAfterDeparturePreventsSubsequentArrival` — impede nova chegada apos desativacao;
9. `NotifyMonitorObjectCleanedUpResetsActiveHandleSafely` — limpa handle ativo no cleanup WDF do monitor;
10. `RejectsNullAdapterHandleWhenEnabled` — rejeita adaptador nulo com `STATUS_INVALID_PARAMETER`.

## Fronteira com validacao em runtime WDF/IddCx

Estes testes validam exclusivamente a logica deterministica de transicoes de estado/associacao e a integridade estatica dos artefatos empacotados (`.dll`, `.inf`, `.cat`), sem substituir `InfVerif`, `Inf2Cat` nem execucao real em runtime dentro de `WUDFHost.exe` ou instalacao PnP. A execucao real do driver depende de assinatura de teste controlada, enumeracao de dispositivo, monitor virtual e processamento de modos/swapchain.

## Como compilar e executar

Em ambiente x64 do Visual Studio (`VsDevCmd.bat -arch=x64 -host_arch=x64`), apos o rebuild de `Debug|x64` e `Release|x64` da solucao, os artefatos de teste sao direcionados para `windows/driver/x64/Debug/` (ignorado por `windows/driver/.gitignore`):

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
```
