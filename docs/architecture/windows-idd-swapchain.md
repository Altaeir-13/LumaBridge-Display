# Pipeline Minimo de Swapchain Direct3D 11 / DXGI no LumaBridgeIddDriver

Data: 2026-11-18
Branch: `feature/windows-idd-swapchain`
Issue relacionada: #27 (Milestone M3 - Windows Virtual Display)

## 1. Objetivo e escopo

Implementar o pipeline minimo de aquisicao, processamento leve e liberacao de frames do swapchain indireto no driver `LumaBridgeIddDriver` (UMDF 2.31 / IddCx 1.4+), garantindo gerenciamento deterministico de ciclo de vida, thread dedicada com cancelamento cooperativo, selecao do adaptador de renderizacao por LUID e ausencia de vazamentos de COM/WDF/handles.

Nesta entrega:

- `EvtIddCxMonitorAssignSwapChain` e `EvtIddCxMonitorUnassignSwapChain` sao implementados via `SwapChainProcessor` e `D3d11IddCxSwapChainBackend`.
- Os frames sao adquiridos (`IddCxSwapChainReleaseAndAcquireBuffer`), validados minimamente via `IDXGIResource` / `ID3D11Texture2D` e concluidos (`IddCxSwapChainFinishedProcessingFrame`), **sem** copiar pixels do desktop, sem encoder (NVENC) e sem streaming.
- **Restricao mantida:** `IddCxMonitorCreate` e `IddCxMonitorArrival` ainda nao sao executados; nenhum monitor virtual e anunciado ao Windows nesta etapa.

## 2. Arquitetura e separacao de responsabilidades

1. **`SwapChainProcessor` (`SwapChainProcessor.h` / `SwapChainProcessor.cpp`):**
   - Orquestra ciclo de vida (`AssignSwapChain`, `UnassignSwapChain`, `~SwapChainProcessor`), thread dedicada, cancelamento cooperativo via evento manual-reset (`m_stopEvent`), espera bloqueante sem busy-wait (`WaitForMultipleObjects`), tratamento de `E_PENDING` e `DXGI_ERROR_DEVICE_REMOVED`/`DXGI_ERROR_DEVICE_RESET` e registro de metricas (`SwapChainMetricsSnapshot`).
   - Desacoplado das DDIs reais por `ISwapChainBackend`, permitindo testes unitarios deterministicos independentes de GPU fisica.
2. **`D3d11IddCxSwapChainBackend` e `DeviceSwapChainHost` (`Adapter.cpp`):**
   - Seleciona o adaptador grafico via `CreateDXGIFactory1` -> `IDXGIFactory4::EnumAdapterByLuid(RenderAdapterLuid)`.
   - Cria o dispositivo Direct3D 11 com `D3D11_CREATE_DEVICE_BGRA_SUPPORT` (feature levels `11_1` -> `10_0`) e o associa ao swapchain via `IddCxSwapChainSetDevice`.
   - Em `ReleaseAndAcquireBuffer`, adota `MetaData.pSurface` usando `ComPtr<IDXGIResource>::Attach` (transferencia direta da referencia COM criada pelo SO, evitando leak de contagem de referencia), verifica a presenca de `ID3D11Texture2D` com dimensoes validas e libera o recurso automaticamente ao sair de escopo antes da proxima iteracao.
   - Em `FinishProcessingFrame`, invoca `IddCxSwapChainFinishedProcessingFrame`.
   - Em `DeleteSwapChainObject`, libera as interfaces `ComPtr` do dispositivo/contexto D3D11 e chama `WdfObjectDelete(hSwapChain)`.

## 3. Regras de ownership, RAII e concorrencia

- **`hNextSurfaceAvailable` (auto-reset event):** pertence exclusivamente ao SO/IddCx; o driver **nunca** chama `CloseHandle` sobre esse handle.
- **`m_stopEvent` e `m_workerThread`:** encapsulados em `ScopedWin32Handle` (RAII), fechados deterministicamente no encerramento.
- **`hSwapChain` (`IDDCX_SWAPCHAIN`):**
  - **Falhas anteriores a transferencia de ownership:** quando `AssignSwapChain` recusa a atribuicao antes da criacao bem-sucedida da worker thread (argumentos invalidos, estado `Suspended`/`Stopping`/`Stopped`, circuit breaker em `Faulted`, falha em `InitializeDeviceAndBindSwapChain`, `CreateEventW` ou `CreateThread`), o driver **nao** chama `WdfObjectDelete(hSwapChain)`, pois ao retornar `STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN` o proprio SO/IddCx retem o ownership e libera o objeto recusado.
  - **Pos-transferencia de ownership:** apos `AssignSwapChain` retornar `STATUS_SUCCESS`, `hSwapChain` passa a pertencer exclusivamente ao `SwapChainProcessor`. Se a worker thread encerrar espontaneamente (ex.: `DXGI_ERROR_DEVICE_REMOVED`, `DXGI_ERROR_DEVICE_RESET` ou limite de falhas transitorias), o epilogo de `WorkerLoop` limpa `m_activeSwapChain` sob `m_metricsLock` e executa `DeleteSwapChainObject` fora do lock exatamente uma vez.
  - Em `UnassignSwapChain` / `OnSuspend` / `Shutdown`, o driver verifica o retorno de `SetEvent(m_stopEvent)` e `WaitForSingleObject(m_workerThread, INFINITE)` fora de `m_metricsLock`; os recursos compartilhados e `hSwapChain` so sao liberados se o retorno `WAIT_OBJECT_0` confirmar a conclusao da worker thread.
- **Estados explicitos, reentrancia e protecao de contexto:** `SwapChainProcessorState` (`Ready`, `Active`, `Suspended`, `Stopping`, `Stopped`, `Faulted`) impede novas atribuicoes em `Suspended` (`D0Exit`) e apos inicio do teardown (`Shutdown` em `AdapterContextCleanup`/`DeviceContextCleanup`). Rastreamento de `m_lifecycleLockOwnerThreadId` e `m_workerThreadId` evita deadlock por reentrancia em callbacks WDF/IddCx. Todos os acessos a `MonitorContext` em `Adapter.cpp` sao protegidos por `g_AdapterInitGate`.
- **Circuit breaker e falhas transitorias vs permanentes:** erros transitorios (`DXGI_ERROR_WAS_STILL_DRAWING`, `ERROR_BUSY`) realizam ate `kMaxConsecutiveTransientErrors = 3` tentativas com backoff de `kTransientRetryBackoffMs = 2 ms` via `WaitForSingleObject(stopEvent, ...)` antes de escalar. `kMaxConsecutiveSwapChainFailures = 5` falhas consecutivas acionam `SwapChainProcessorState::Faulted`, evitando loops ilimitados de recriacao ate `OnResume()`.
- **Hierarquia fixa de locks:** `g_AdapterInitGate` -> `DeviceContext::StateLock` -> `SwapChainProcessor::m_lifecycleLock` -> `SwapChainProcessor::m_metricsLock`. A worker thread adquire **apenas** `m_metricsLock` (lock folha) por microssegundos ao atualizar contadores escalares, tornando impossivel ocorrer deadlock durante `WaitForSingleObject(m_workerThread, INFINITE)`.
- **Protecao contra use-after-free:** `DeviceSwapChainHost` utiliza contagem de referencias atomica (`AddRef`/`Release` via `InterlockedIncrement`/`InterlockedDecrement`) para permanecer valido caso um callback concorra com `LumaBridgeEvtDeviceContextCleanup`.

## 4. Tratamento de erros e metricas

`SwapChainMetricsSnapshot` contabiliza sem armazenar nenhum dado visual do desktop:

- `AssignAttempts`, `AssignCount`, `AbandonedAssignCount`, `UnassignCount`, `SwapChainDeletedCount`
- `FramesAcquired`, `FramesProcessed`, `FramesDropped`
- `EmptyAcquireWaits` (`E_PENDING` aguardando `hNextSurfaceAvailable`)
- `TransientErrors`, `DeviceRemovedErrors` (`DXGI_ERROR_DEVICE_REMOVED` / `DXGI_ERROR_DEVICE_RESET`), `FatalErrors`
- `CircuitBreakerRejections`, `ConsecutiveFailures`, `LastErrorHResult`
- `LastPresentationFrameNumber`, `ActiveRenderAdapterLuid`, `State`, `IsActive`

## 5. Resultados dos testes e pendencias

- `SwapChainLifecycleTests.exe`: **13 testes unitarios deterministicos** aprovados (`0` falhas), sem depender de GPU fisica.
- `MonitorModesTests.exe`: **12/12** aprovados; `AdapterLifecycleTests.exe`: **16/16** aprovados; `DriverPackageValidationTests.exe`: **5/5** aprovados.
- `MSBuild` `Debug|x64` e `Release|x64`: **0 erros, 0 warnings**.
- **Pendencia Spectre (issue #20):** `Driver_SpectreMitigation=false` permanece registrado porque as bibliotecas MSVC Spectre (`lib\spectre`) continuam ausentes no Build Tools local; deve ser resolvido antes da assinatura/instalacao em maquina pessoal.
- **Proximo passo elegivel:** implementacao controlada de `IddCxMonitorCreate` / `IddCxMonitorArrival` / `IddCxMonitorDeparture` associando `LumaBridgeMonitorContext` ao `WDFDEVICE` e validacao de ciclo completo em ambiente controlado.
