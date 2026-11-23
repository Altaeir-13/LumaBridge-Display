# Pipeline de Swapchain D3D11, Extracao de Frames e IPC Local (`M3` + `M4.1`)

Data de atualizacao: 2026-11-22
Branch de referencia M4.1: `feature/windows-frame-extraction-ipc` (baseada em `fix/windows-idd-device-start` / `c4be4c5`)

## 1. Objetivo e escopo

Implementar o ciclo completo de aquisicao IddCx, extracao de pixels Direct3D 11, enfileiramento limitado com backpressure e transporte local autenticado para o processo Windows separado `lumabridge-host.exe`, preservando integralmente o comportamento padrao do driver quando a extracao esta desabilitada (`EnableFrameExtraction = 0` ou ausente).

Fora de escopo nesta entrega (M4.1):
- Codificacao H.264 / NVENC (reservada para M4.2).
- Transporte em rede local (UDP/RTP/QUIC) ou cliente Linux.
- Captura automatica de pixels da area de trabalho para disco.

## 2. Diagrama do fluxo de frames

```text
Windows DWM
    |
    v
IddCx Swapchain (IddCxSwapChainReleaseAndAcquireBuffer)
    |
    v  (ComPtr<IDXGIResource>::Attach -> QueryInterface ID3D11Texture2D)
D3d11IddCxSwapChainBackend::ReleaseAndAcquireBuffer
    |
    +-- [EnableFrameExtraction == 0 (padrao)] --> valida descritor -> Release COM -> FinishProcessingFrame
    |
    +-- [EnableFrameExtraction == 1 (opt-in)]
          |
          v
    D3d11FrameExtractor::ExtractFrame
      1. GetDesc() + rejeicao imediata de conteudo protegido (HwProtected / MISC_HW_PROTECTED)
      2. Valida dimensoes [1..4096], MipLevels=1, ArraySize=1, SampleDesc.Count=1, formato suportado
      3. Aloca/reutiliza staging (D3D11_USAGE_STAGING, CPU_ACCESS_READ)
      4. CopyResource(staging, source) -> Release imediato da COM surface adquirida
      5. Map(D3D11_MAP_READ) -> copia tightly-packed para slot do pool -> Unmap -> CRC-32 + QPC
          |
          v  (FinishProcessingFrame chamado antes da proxima iteracao; sem bloqueio IPC no worker)
    FrameIpcServer::EnqueueFrame (Bounded Ring: MaxQueueDepth = 3, Pool = 5, drop-oldest)
          |
          v  (Thread dedicada de transporte IPC com I/O overlapped + CancelIoEx)
    Named Pipe Local (\\.\pipe\LumaBridgeFrameIpc_v1, ACL restritiva + PIPE_REJECT_REMOTE_CLIENTS)
          |
          v
    lumabridge-host.exe (FrameConsumer)
      -> Autenticacao (ClientHello/ServerHello) -> Validacao de sessao, bounds e CRC-32 -> FrameAck
          |
          v
    Futuro Pipeline NVENC H.264 (M4.2)
```

## 3. Avaliacao da estrategia GPU/CPU e trade-offs

Foram avaliadas duas abordagens para disponibilizacao de pixels entre `WUDFHost.exe` (Session 0, `LOCAL SERVICE`) e `lumabridge-host.exe` (sessao interativa do usuario):

1. **Interoperabilidade GPU entre processos via NT Shared Handle (`IDXGIResource1::CreateSharedHandle` / `ID3D11Device1::OpenSharedResource1`):**
   - Vantagens: evita transferencia GPU -> CPU -> IPC -> GPU antes do NVENC; essencial para 1080p60/1440p60 com latencia minima.
   - Restricoes para M4.1: exige gerenciamento rigoroso de ACLs em handles NT entre `LOCAL SERVICE` e processo de usuario, sincronizacao explicita por `IDXGIKeyedMutex` ou fences D3D11 entre dispositivos distintos, tratamento de recriacao de swapchain/dispositivo (TDR) entre processos e um consumidor com contexto D3D11/NVENC ativo (ainda fora do escopo de M4.1).
2. **`D3D11_USAGE_STAGING` + copia GPU->CPU + Named Pipe local (`Estrategia M4.1 implementada`):**
   - **Nao e zero-copy:** realiza `CopyResource` (GPU default -> GPU staging), `Map(D3D11_MAP_READ)` (staging -> buffer tightly-packed em RAM) e escrita/leitura em Named Pipe local com verificacao CRC-32.
   - **Vantagens para M4.1:** isolamento completo de falhas entre `WUDFHost.exe` e `lumabridge-host.exe`, compatibilidade deterministica com `LOCAL SERVICE` -> usuario interativo via SDDL + `Medium Mandatory Label`, validacao real byte-a-byte de pixels sem depender de NVENC e interface limpa (`FrameIpcProtocol.h` / `D3d11FrameExtractor` / `FrameIpcServer`) pronta para evoluir o payload para descritor compartilhado GPU na etapa M4.2.
   - **Custo medido localmente (RTX 3060 Ti, build `Release|x64`, incluindo CRC-32 e verificacao sintetica):**
     - `1280x720` (`3.68 MB/frame`): `~603 us` copia D3D11, `~20.7 ms` latencia E2E no host, **108.22 FPS** recebidos.
     - `1920x1080` (`8.29 MB/frame`): `~1,193 us` copia D3D11, `~48.2 ms` latencia E2E no host, **48.63 FPS** recebidos (limitado pelo throughput de copia em CPU + pipe NPFS de ~8.3 MB/frame).

## 4. Contrato do IPC Local (`FrameIpcProtocol.h` v1.0)

Arquivo compartilhado: `windows/driver/LumaBridgeIddDriver/FrameIpcProtocol.h` (`#pragma pack(push, 1)` com `static_assert` de tamanho exato):

- **Endpoint padrao:** `\\.\pipe\LumaBridgeFrameIpc_v1` (`PIPE_TYPE_BYTE`, `PIPE_REJECT_REMOTE_CLIENTS`, `FILE_FLAG_OVERLAPPED`).
- **Seguranca / ACL:** SDDL `D:P(D;;GA;;;NU)(D;;GA;;;AN)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;LS)(A;;GRGW;;;IU)` + SID do usuario proprietario (para testes no mesmo usuario) + `S:(ML;;NW;;;ME)` (Medium Mandatory Level, permitindo `lumabridge-host.exe` nao elevado conectar-se ao pipe criado por `WUDFHost.exe` enquanto bloqueia processos Low/AppContainer e acessos de rede/anonimos). Alem da ACL, `FrameIpcServer` valida `ClientAuthToken` (`0x4148424C`) e compara `ClientHello.ClientProcessId` com `GetNamedPipeClientProcessId()`.
- **Mensagens versionadas (`Magic = 0x4649424C`, `Version = 1.0`):**
  1. `FrameIpcEnvelope` (`16 B`): `Magic`, `VersionMajor`, `VersionMinor`, `MessageType`, `Reserved0`, `HeaderSizeBytes`.
  2. `FrameIpcClientHello` (`32 B`): `Envelope`, `ClientProcessId`, `ClientAuthToken`, `ClientCapabilities`, `Reserved1`.
  3. `FrameIpcServerHello` (`48 B`): `Envelope`, `Status`, `ServerProcessId`, `SessionId` (monotonico != 0), `AdapterLuidLow`, `AdapterLuidHigh`, `MaxQueueDepth`, `Reserved1`.
  4. `FrameIpcFrameHeader` (`104 B`): `Envelope`, `SessionId`, `FrameSequence`, `PresentationFrameNumber`, `Width`, `Height`, `RowPitchBytes`, `PixelFormat`, `Flags`, `DirtyRectCount`, `MoveRegionCount`, `PresentDisplayQpcTime`, `ExtractCompleteQpcTime`, `ServerSendQpcTime`, `QpcFrequency`, `PayloadSizeBytes`, `PayloadCrc32` (seguido exatamente por `PayloadSizeBytes` bytes de pixels).
  5. `FrameIpcFrameAck` (`56 B`): `Envelope`, `SessionId`, `FrameSequence`, `PresentationFrameNumber`, `Status`, `HostReceiveQpcTime`, `Reserved1`.
  6. `FrameIpcDisconnectNotice` (`32 B`): `Envelope`, `SessionId`, `ReasonCode`, `Reserved1`.
- **Limites explicitos:** `Width/Height` em `[1..4096]`, `RowPitchBytes == Width * 4`, `PayloadSizeBytes <= 64 MiB` (`4096 * 4096 * 4`), validacao contra overflow de 64 bits.

## 5. Formatos suportados e protecao de conteudo

Formatos aceitos para extracao (`IsSupportedExtractionDxgiFormat`):
- `DXGI_FORMAT_B8G8R8A8_UNORM` (`87`)
- `DXGI_FORMAT_B8G8R8A8_UNORM_SRGB` (`91`)
- `DXGI_FORMAT_R8G8B8A8_UNORM` (`28`)
- `DXGI_FORMAT_R8G8B8A8_UNORM_SRGB` (`29`)

Restricoes adicionais:
- Rejeita `MipLevels != 1`, `ArraySize != 1`, `SampleDesc.Count != 1`, dimensoes nulas ou acima de `4096x4096`.
- Rejeita imediatamente (`DXGI_ERROR_ACCESS_DENIED`) qualquer superficie marcada com `IDDCX_METADATA::HwProtectedSurface` ou `D3D11_RESOURCE_MISC_HW_PROTECTED` sem copiar ou mapear pixels (`ProtectedFramesRejected++`), concluindo normalmente o frame no IddCx via `FinishProcessingFrame`.

## 6. Modelo de ownership, concorrencia e backpressure

- **Superficie IddCx:** `ComPtr<IDXGIResource>::Attach(bufferOut.MetaData.pSurface)` adota a referencia do SO. Durante `ExtractFrame`, a copia GPU->staging (`CopyResource`) e disparada e `sourceTexture.Reset()` + `surface.Reset()` liberam **todas** as referencias COM a superficie original antes mesmo de `Map(D3D11_MAP_READ)` e muito antes de `IddCxSwapChainFinishedProcessingFrame`.
- **Swapchain (`IDDCX_SWAPCHAIN`) e evento (`hNextSurfaceAvailable`):** preservados integralmente conforme M3 (`AssignSwapChain`, `UnassignSwapChain`, `UnassignSwapChainForMonitor`, `OnSuspend`, `OnResume`, `Shutdown`, `DeleteSwapChainObject` exatamente uma vez).
- **Hierarquia de locks (sem inversao e sem I/O sob lock):**
  - Pipeline driver: `g_AdapterInitGate` -> `DeviceContext::StateLock` -> `SwapChainProcessor::m_lifecycleLock` -> `SwapChainProcessor::m_metricsLock`.
  - Transporte IPC: `FrameIpcServer::m_lifecycleLock` -> `m_queueLock` ou `m_metricsLock` (folhas separadas; nenhuma trava e mantida durante `ReadFile`/`WriteFile`/`WaitForMultipleObjects`).
- **Politica de backpressure (`drop-oldest`):**
  - Fila limitada a `MaxQueueDepth = 3` (teto maximo configuravel `16`), abastecida por um pool pre-alocado de `5` `ExtractedFrameBuffer` (`PixelByteBuffer` sem excecoes C++, `new (std::nothrow)` compativel com UMDF sem `/EHsc`).
  - Se a fila atingir `MaxQueueDepth` (host ausente ou lento), o frame mais antigo e removido da frente da fila, tem sua capacidade de memoria reutilizada e incrementa `FramesDroppedByBackpressure`.
  - A thread de aquisicao IddCx **nunca** aguarda IPC; sem host conectado, `FrameIpcServer` permanece bloqueado em `ConnectNamedPipe` overlapped (`INFINITE` com wakeup imediato via `m_stopEvent`), sem busy-wait.
  - Em `OnSuspend` (`D0Exit`), `DeviceContextCleanup` e `AdapterContextCleanup`, `Processor.Shutdown()`/`OnSuspend()` conclui a worker thread antes de `Backend.ShutdownTransport()` cancelar I/O (`CancelIoEx` + `GetOverlappedResult(..., TRUE)`) e encerrar o servidor IPC.

## 7. Telemetria e observabilidade

`SwapChainMetricsSnapshot`, `[LB-DRIVER] [METRICS]` (`Trace.h`) e o novo evento TraceLogging `DriverMetrics` diferenciam explicitamente cada estagio (sem armazenar pixels):
1. `FramesAcquired`: buffers adquiridos com `S_OK` do IddCx.
2. `FramesProcessed`: buffers concluidos com `FinishProcessingFrame`.
3. `FramesExtractionAccepted`: superficies validas, suportadas e nao protegidas aceitas pelo extrator.
4. `FramesCopied`: frames efetivamente copiados para RAM (`FrameCopyLatencyUs`, `LastFrameSequence`).
5. `FramesDelivered`: frames entregues e confirmados via `FrameIpcFrameAck` por `lumabridge-host.exe` (`FrameDeliveryLatencyUs`, `ActiveHostConnections`).
6. Descarte/rejeicao por causa: `FramesDropped` (superficie invalida/falha de conclusao), `FramesDroppedByBackpressure` (fila cheia), `ProtectedFramesRejected`, `FrameCopyFailures`, `FrameTransportFailures`.

Correcoes de observabilidade aplicadas na infraestrutura de diagnostico (`windows/driver/scripts/`):
- `Invoke-LumaBridgeEtwTrace.ps1` agora expoe `AllProvidersVerified`, `FoundProviderGuids` e `MissingProviderGuids` diretamente no topo do retorno de `VerifyProviders`, `Start` e `Status` (mantendo `ProviderVerification`).
- `Collect-LumaBridgeDiagnostics.ps1` nao restringe mais a leitura de ETLs a timestamps antigos do Event Log PnP quando `-EtlStartTimeUtc`/`-EtlEndTimeUtc` nao sao especificados (mantendo `InferredPnpAnchorStartUtc`/`EndUtc` apenas informativos).
- `LumaBridgeDriverCommon.psm1` identifica eventos TraceLogging sem manifesto por `ProviderId` (`{A7E4C910-5B32-4F8E-9D21-7C3A1B8E4F01}`) mesmo quando `ProviderName` vem vazio, executa uma segunda passagem XPath direcionada pelo GUID do LumaBridge quando a leitura geral atinge o teto `MaxMatchedEvents`, e preserva registros de `DriverStage` (8 propriedades) separados de `DriverMetrics` (29 propriedades).

## 8. Criterios para integrar NVENC na proxima etapa (M4.2)

1. Adicionar capacidade de negociacao na `FrameIpcServerHello` / `FrameIpcFrameHeader` (versao `1.1` ou flag de transporte GPU) para transportar **handles NT compartilhados (`HANDLE` duplicado para o PID autenticado do `lumabridge-host`) + `IDXGIKeyedMutex`** quando produtor (`WUDFHost.exe`) e `lumabridge-host` compartilharem o mesmo `AdapterLuid`.
2. Manter o caminho atual de staging/Named Pipe como fallback de diagnostico e compatibilidade.
3. No `lumabridge-host`, abrir o recurso D3D11 compartilhado (`OpenSharedResource1`), alimentar diretamente o encoder **NVENC H.264** (`NV_ENC_INPUT_RESOURCE_TYPE_DIRECTX`, sem B-frames, lookahead desligado, low-latency preset) e validar 1080p60 sustentado sem copia GPU -> CPU -> GPU.
4. Estender `FrameEndToEndIntegrationTests` para validar encode H.264 real com frames sinteticos antes da integracao de rede LAN.
