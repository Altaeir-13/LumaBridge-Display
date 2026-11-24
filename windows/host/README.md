# `lumabridge-host` — Processo Consumidor GPU/IPC e Codificador NVENC H.264 (`M4.1` / `M4.2`)

Processo Windows separado de `WUDFHost.exe` que se conecta ao endpoint IPC local de `LumaBridgeIddDriver` (`SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, validado no servidor por token de acesso Windows, SID/broker `AuthorizedHostUserSid`, `TokenSessionId` e integridade `>= Medium`, sem segredo estatico). Suporta tanto o protocolo `1.1` residente em GPU (`D3D11_RESOURCE_MISC_SHARED_NTHANDLE` + `IDXGIKeyedMutex` + validacao de `AdapterLuid` + codificacao `NVENC H.264` em GPU com `NvEncodeAPI64.dll` em runtime e fila limitada `EncodedFrameQueue`) quanto fallback diagnostico `1.0` (`CpuStagingPipe`), emitindo `FrameIpcFrameAck` e telemetria JSON granular sem gravar frames em disco.

## Compilacao

Em ambiente `x64` do Visual Studio (`VsDevCmd.bat -arch=amd64 -host_arch=amd64`):

```bat
cl /nologo /std:c++17 /W4 /WX /EHsc /Od /Zi /MDd /DUNICODE /D_UNICODE /Iwindows\host /Iwindows\driver\LumaBridgeIddDriver windows\host\main.cpp windows\host\FrameConsumer.cpp windows\host\NvencH264Encoder.cpp windows\host\H264BitstreamValidator.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\lumabridge-host.exe /link d3d11.lib dxgi.lib advapi32.lib user32.lib gdi32.lib mfplat.lib mfuuid.lib wmcodecdspuuid.lib ole32.lib psapi.lib
cl /nologo /std:c++17 /W4 /WX /EHsc /O2 /Zi /MD /DNDEBUG /DUNICODE /D_UNICODE /Iwindows\host /Iwindows\driver\LumaBridgeIddDriver windows\host\main.cpp windows\host\FrameConsumer.cpp windows\host\NvencH264Encoder.cpp windows\host\H264BitstreamValidator.cpp /Fowindows\driver\x64\Release\ /Fe:windows\driver\x64\Release\lumabridge-host.exe /link d3d11.lib dxgi.lib advapi32.lib user32.lib gdi32.lib mfplat.lib mfuuid.lib wmcodecdspuuid.lib ole32.lib psapi.lib
```

## Opcoes de linha de comando

- `--pipe <nome>`: caminho do Named Pipe local (padrao: `\\.\pipe\LumaBridgeFrameIpc_v1`)
- `--max-frames <N>`: encerra antecipadamente apos receber `N` frames validos (`0` = continuo ate `--duration-ms`, Ctrl+C ou desconexao)
- `--min-frames <N>`: exige no minimo `N` frames validos para retorno `ExitCode=0` mesmo que a meta `--max-frames` nao seja atingida antes de `--duration-ms` (Perfil A — smoke test)
- `--require-max-frames`: exige atingir a meta integral `--max-frames` para `ExitCode=0` (Perfil B — benchmark continuo)
- `--duration-ms <ms>`: duracao alvo em milissegundos (`0` = ilimitado)
- `--duration-counts-connected`: contabiliza `--duration-ms` exclusivamente enquanto conectado ao servidor IPC via ticks QPC monotonicos sem overflow (pausa em espera inicial e reconexao)
- `--max-execution-ms <ms>`: teto de seguranca total de execucao (*wall-clock*) em milissegundos; ao expirar encerra com `SafetyExecutionTimeout` e codigo nao-zero
- `--connect-timeout-ms <ms>`: timeout de conexao ao pipe (padrao: `3000`)
- `--io-timeout-ms <ms>`: timeout por operacao I/O overlapped em ms (padrao: `500`)
- `--verify-synthetic-pattern`: valida padrao sintetico BGRA8 deterministico por pixel (em modo GPU realiza readback diagnostico explicito; em modo normal `CpuStagingReadsPerformed` permanece `0`)
- `--reconnect`: reconecta automaticamente em caso de desconexao ou troca de modo/swapchain
- `--transport <gpu|cpu|auto>`: selecao de transporte IPC (`auto` negocia `1.1 GpuSharedNtHandle` com fallback `1.0`, `gpu` exige GPU, `cpu` forca `CpuStagingPipe`)
- `--require-gpu-shared`: falha se o pipe nao negociar `GpuSharedNtHandle`, se ocorrer fallback CPU, ou se houver leitura CPU de pixels em operacao normal
- `--nvenc`: habilita codificacao NVENC H.264 na GPU sobre as texturas recebidas
- `--require-nvenc`: exige `NvencFramesEncoded > 0` e bitstream valido para `ExitCode=0`
- `--nvenc-bitrate-bps <bps>`: bitrate CBR do codificador NVENC (padrao: `15000000`)
- `--nvenc-gop <frames>`: intervalo de GOP / IDR em frames (padrao: `120`)
- `--nvenc-force-idr-every <N>`: solicita keyframe IDR explicitamente a cada `N` frames codificados
- `--nvenc-color-format <auto|argb|nv12>`: seleciona entrada direta `ARGB/ABGR` ou conversao GPU `ID3D11VideoProcessor` (`BGRA8 -> NV12`)
- `--verify-h264-decode`: inspeciona NALs Annex-B (`SPS`/`PPS`/`IDR`) e decodifica via `Microsoft H.264 Video Decoder MFT` (Media Foundation), mantendo `FidelityPsnrValidated=false` quando executado sobre desktop real sem referencia sintetica
- `--verify-h264-psnr`: ativa `--verify-h264-decode` e valida PSNR (`MinYPsnrDb`/`MinUvPsnrDb`/`MinCombinedPsnrDb`) contra padrao sintetico BGRA8 conhecido (`FidelityPsnrValidated=true`), mantendo `CpuStagingReadsPerformed=0` no caminho GPU
- `--prewarm-width <px>` / `--prewarm-height <px>`: pre-aquece dispositivo D3D11, sessao NVENC e decoder Media Foundation antes de conectar (padrao `1920x1080`; `0` desativa pre-aquecimento de sessao), eliminando o pico frio do Quadro 1
- `--visual-stimulus`: renderiza janela de movimento sintetico com timer de alta resolucao (`CREATE_WAITABLE_TIMER_HIGH_RESOLUTION`) diretamente no monitor virtual LumaBridge ativo
- `--require-virtual-stimulus`: falha com codigo de saida nao-zero se o estimulo visual nao conseguir identificar o display virtual
- `--stimulus-fps <fps>`: taxa alvo de atualizacao do estimulo visual (`1..120`, padrao `60`)
- `--stimulus-backend <auto|dxgi|gdi>`: seleciona explicitamente o backend do estimulo visual (`auto` usa DXGI D3D11/Flip-Discard com fallback autorizado para GDI diante de oclusao/falha; `dxgi` exige `D3d11DxgiVSync` sem fallback GDI e propaga `LastHResult` e `TerminalFailure` mesmo em falhas pos-inicializacao; `gdi` forca `GdiLegacy`)
- `--stimulus-display <gdiName>`: override explicito opcional do display GDI (ex.: `\\.\DISPLAY2`)
- `--run-id <id>`: associa identificador exclusivo da execucao (`RunId`, `HostProcessId`, `GeneratedAtUtc` e `SummaryComplete`) no JSON de resumo
- `--require-valid-timestamps`: exige `TimestampMeasurementErrors == 0`, monotonicidade QPC e cobertura temporal `>= 95%` para `ExitCode=0`
- `--require-width <px>` / `--require-height <px>`: exige resolucao exata dos quadros validos recebidos (e largura/altura da sessao NVENC ativa)
- `--min-nvenc-encoded-frames <n>`: quantidade minima absoluta de quadros codificados pelo NVENC quando `--require-nvenc`
- `--min-nvenc-encode-ratio <0..1>`: razao minima `NvencFramesEncoded / FramesValid` exigida quando `--require-nvenc`
- `--max-nvenc-drop-ratio <0..1>`: teto maximo para `(NvencDroppedFrames + EncodedQueueDrops) / NvencFramesSubmitted` quando `--require-nvenc`
- `--json-summary <caminho>`: grava resumo JSON nao visual com metricas de GPU pool, breakdown de sub-etapas NVENC (`FormatPrepare`, `EncodePicture`, `BitstreamLockCopy`, `EncodedQueueWait`), cobertura temporal (`TemporalTelemetry`), validacao de relogio e duracao (`QpcClockValid`, `DurationCountsConnected`, `RequestedDurationUs`, `TotalConnectedDurationUs`, `ActiveStreamingDurationUs`, `LiveStreamingDurationUs`, `DurationTargetReached`, `SafetyExecutionTimeoutHit`, `DurationOk`), metodologia explicita de percentis (`PercentilesAvailable`, `PercentilesAreEstimated`, `PercentileMethod` = `NotAvailable` | `ExactPopulation` | `ReservoirSampledEstimate_AlgorithmR`, amostragem uniforme Algorithm R com `StoredSampleCount = 65536` e `SamplesTruncated = true` acima de `65.536` mantendo `MinUs`/`AvgUs`/`MaxUs` exatos sobre todos os `SampleCount`, e `P50Us`/`P95Us`/`P99Us = null` quando `PercentilesAvailable = false`), `ResourceUsage` (CPU, RAM, `HandleCount`, VRAM dedicada com `NOT_MEASURED` quando indisponivel), decoder H.264 (com `MftDecodeLatencyUs` consolidado exclusivamente no encerramento via `Finish()`, sem ordenacao redundante por pacote, e subobjeto `H264DecodeValidation.Worker` cobrindo fila limitada de 256 pacotes, espera monotônica limitada, zero descarte silencioso, ciclo COM/MF na thread dona e os 9 contadores `PacketsEnqueued`, `PacketsDequeued`, `PacketsProcessed`, `PacketsRejected`, `QueuePeakDepth`, `QueuePendingAtShutdown`, `QueueFullWaitCount`, `QueueWaitTimeoutCount` e `WorkerFailureCount`), `GateEvaluation` e `VisualStimulus` (incluindo `LastHResult`, `TerminalFailure` e `StopRequested`)
- `--quiet`: omite log por frame no stdout

## Worker assincrono MFT e contencao de bloqueio externo

- O `AsyncH264ValidationWorker` executa COM MTA (`CoInitializeEx(COINIT_MULTITHREADED)`), inicializacao Media Foundation (`MFStartup`), criacao/uso/liberacao de `IMFTransform`, `Finish()`, `Shutdown()`, `MFShutdown()` e o `CoUninitialize()` pareado integralmente na mesma thread do worker.
- Fila FIFO limitada a `256` pacotes com ownership por valor (`std::move`), backpressure com `wait_until` monotônico (`EnqueueTimeoutMs`) e encerramento sem `detach()` nem `TerminateThread()`. Caso uma chamada sincrona externa do MFT bloqueie indefinidamente alem de `DrainWaitTimeoutMs`, o worker marca `DrainDeadlineExceeded` / `DrainFailed` e conclui `join()` de forma segura; o `HardTimeoutMs` externo do runner permanece como ultima fronteira de contencao.

## Limites e privacidade

- Nenhum frame, screenshot ou buffer de pixels e salvo em disco nem lido da area de trabalho pelo estimulo diagnostico.
- Payload CPU fallback limitado a `4096 x 4096 x 4` bytes (`64 MiB`). Em transporte GPU (`M4.2`), trafegam pelo Named Pipe apenas `136` bytes por frame (`FrameIpcGpuFrameHeader`) contendo o `HANDLE` NT duplicado para o PID autenticado do host, mantendo `CpuStagingReadsPerformed = 0` durante operacao normal.
- Consulte [windows-gpu-shared-textures-nvenc.md](../../docs/architecture/windows-gpu-shared-textures-nvenc.md) para detalhes do modelo de sincronizacao, seguranca e licenca MIT do cabeçalho `nvEncodeAPI.h`.
