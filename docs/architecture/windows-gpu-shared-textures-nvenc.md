# LumaBridge Display — Arquitetura GPU Shared Textures e NVENC H.264 (M4.2)

## 1. Visão Geral da Arquitetura

A entrega **M4.2** substitui o transporte integral de pixels BGRA8 em RAM/CPU da M4.1.1 por um pipeline residente em GPU (`zero-CPU-pixel-read` no caminho normal), preservando o protocolo `1.0` (`CpuStagingPipe`) como fallback diagnóstico explícito:

```text
Windows DWM
    │
    ▼
IddCx Swapchain (LumaBridgeIddDriver.dll em WUDFHost.exe / LOCAL SERVICE)
    │  [se EnableGpuSharedTransport != 0 && sessão negociou v1.1 GpuSharedNtHandle]
    ▼
D3d11SharedTexturePool (GPU CopyResource -> Textura Compartilhada D3D11)
    │  Flags: D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX
    │  Sincronização: IDXGIKeyedMutex (Produtor libera chave 0 -> 1)
    │  Liberação imediata da superfície IddCx (COM Reset)
    ▼
FrameIpcServer (Named Pipe IPC Seguro v1.1)
    │  DuplicateHandle(PROCESS_DUP_HANDLE -> PID autenticado do host)
    │  Envia apenas FrameIpcGpuFrameHeader (136 bytes: HANDLE + Slot + AdapterLuid + Timestamps)
    ▼
lumabridge-host.exe (Sessão de Usuário Interativo)
    │  Valida AdapterLuid -> OpenSharedResource1 -> IDXGIKeyedMutex::AcquireSync(1)
    ▼
NvencH264Encoder (Carregamento dinâmico nvEncodeAPI64.dll)
    │  Entrada direta ARGB/ABGR ou conversão GPU BGRA8 -> NV12 (ID3D11VideoProcessor)
    │  Preset P1 + Ultra-Low-Latency (0 B-frames, repeatSPSPPS=1, CBR)
    ▼
EncodedFrameQueue (Buffer limitado drop-oldest de NALs Annex-B)
    │
    ▼
[Próxima Etapa] Transporte LAN + Cliente Linux
```

O driver UMDF (`LumaBridgeIddDriver`) permanece **100% independente do NVIDIA Video Codec SDK** (`nvEncodeAPI.h`). Toda lógica de codificação reside exclusivamente em `lumabridge-host.exe`.

---

## 2. Componentes Implementados

### 2.1 Pool de Texturas Compartilhadas (`SharedTexturePool.h` / `.cpp`)
- Capacidade fixa limitada (`kDefaultSharedTexturePoolSize = 4`, intervalo permitido `2..8` slots).
- A superfície recebida de `IddCxSwapChainReleaseAndAcquireBuffer` **nunca** é presumida compartilhável: `D3d11SharedTexturePool::ExtractToSharedTexture` cria ou reutiliza um slot com `D3D11_USAGE_DEFAULT` e sinalizadores `D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX`, executando `CopyResource` diretamente na GPU.
- A referência COM à textura original do IddCx (`AdoptSourceTexture`) é liberada imediatamente após enfileirar a cópia GPU.
- Política **não bloqueante** na thread da swapchain: se todos os slots estiverem ocupados pelo consumidor (`PoolExhausted`), o quadro é descartado sem bloquear o loop DWM/IddCx (`GpuFramesDropped++`).
- Verificação contínua de `GetDeviceRemovedReason()` com recriação segura de recursos (`ResetResources`) em caso de reset/perda de dispositivo.

### 2.2 Modelo de Sincronização GPU e Lifetime
- Cada slot do pool possui uma máquina de estados determinística (`Free` -> `Queued` -> `InUseByHost` -> `Free`) identificada por `(SlotIndex, SlotGeneration)`.
- **Fluxo de chaves `IDXGIKeyedMutex`:**
  1. Criação da textura inicializa o mutex no estado `0`.
  2. Produtor (`WUDFHost.exe`) adquire chave `0` (timeout configurável, padrão `10 ms` no produtor), copia o frame na GPU e libera para chave `1`.
  3. Consumidor (`lumabridge-host.exe`) valida `SlotGeneration` e `AdapterLuid`, abre/reutiliza a textura via cache por slot (`ID3D11Device1::OpenSharedResource1`), adquire chave `1` (timeout padrão `50 ms`), copia/consome na GPU e libera imediatamente para chave `0`.
  4. O host envia `FrameIpcFrameAck` carregando `SlotIndex`, `SlotGeneration`, status (`Ok` / `GpuSyncTimeout` / `ResourceOpenFailed` / `AdapterLuidMismatch`) e `GpuSyncWaitUs`. Somente após o ACK válido (ou falha/evicção), `CompleteHostUseForSlot` devolve o slot ao estado `Free`.
- **Evicção por backpressure:** Quando um frame ainda enfileirado (`Queued`) é descartado pela política drop-oldest antes de ir ao host, `ReleaseQueuedSlot` executa uma rotação limpa de chave (`AcquireSync(1) -> ReleaseSync(0)`) ou marca o slot para recriação caso falhe, evitando que a chave permaneça presa em `1`.
- **Timeouts e desconexão abrupta:** Caso o consumidor desconecte ou estoure timeout com mutex preso, o slot afetado tem `NeedsRecreate = true` forçado ou rotação segura, sem vazar handles nem travar o próximo host conectado.

---

## 3. Modelo de Segurança IPC e Compartilhamento Entre Processos

`WUDFHost.exe` executa sob conta `LOCAL SERVICE`, enquanto `lumabridge-host.exe` roda na sessão interativa do usuário autenticado:

1. **Named Pipe Endurecido (`FrameTransport.cpp`):**
   - Mantém DACL restritiva ao `AuthorizedHostUserSid` configurado em registro (`REG_SZ AuthorizedHostUserSid`), administradores internos e validação pós-conexão com `GetNamedPipeClientProcessId`, `OpenProcessToken`, verificação de SID, sessão interativa ativa e nível de integridade `>= Medium`.
   - `AllowSameUserAccess = false` no driver garante que outros processos `LOCAL SERVICE` não possam se conectar ao pipe.
2. **Handles NT Anônimos + `DuplicateHandle` Autenticado:**
   - As texturas compartilhadas são criadas via `IDXGIResource1::CreateSharedHandle(..., lpName = nullptr)` — **zero nomes globais expostos em `\BaseNamedObjects\`** para processos locais arbitrários.
   - O descritor de segurança da textura contém DACL restrita ao usuário autorizado (`AuthorizedHostUserSid`) e SACL `S:(ML;;NW;;;ME)` (nível de integridade Medium).
   - O servidor abre o processo cliente já autenticado (`OpenProcess(PROCESS_DUP_HANDLE, FALSE, clientPid)`) e executa `DuplicateHandle` exclusivamente para aquele processo alvo antes de enviar o valor resultante em `FrameIpcGpuFrameHeader::DuplicatedNtHandleValue`.
   - Se `OpenProcess`/`DuplicateHandle` falhar ou a permissão for insuficiente, o cliente não recebe acesso indevido; falhas de cliente ou `DeviceRemoved` limpam o cache de handles duplicados por sessão.
3. **Validação de Compatibilidade de Adaptador GPU (`AdapterLuid`):**
   - `ServerHello` e cada `FrameIpcGpuFrameHeader` informam `AdapterLuidLow`/`AdapterLuidHigh`.
   - O host enumera adaptadores DXGI procurando exatamente o `AdapterLuid` informado e cria seu dispositivo D3D11 na GPU correspondente (ou recusa com `AdapterLuidMismatch` se incompatível ou não encontrado, sem presumir compartilhamento entre GPUs distintas).

---

## 4. Contrato IPC (`1.0` e `1.1`)

- O protocolo mantém total compatibilidade retroativa com `1.0` (`CpuStagingPipe`, envio completo de pixels BGRA8 em `FrameIpcFrameHeader` de 104 bytes).
- A evolução **`1.1`** preserva o `VersionMajor = 1`, eleva `VersionMinor = 1` e adiciona negociação explícita no handshake (`ClientHello.Capabilities` <-> `ServerHello.Reserved1`):
  - `FrameIpcCapabilityFlags`: `GpuSharedNtHandle`, `KeyedMutexSync`, `FallbackToCpuStaging`, `PreferLatestFrameDropOldest`.
  - `FrameIpcGpuFrameHeader` (**136 bytes**): inclui `SessionId`, `FrameSequence`, `PresentationFrameNumber`, `TransportMode`, `SlotIndex`, `SlotGeneration`, `DuplicatedNtHandleValue`, `Width`, `Height`, `PixelFormat`, `AdapterLuidLow`/`AdapterLuidHigh`, chaves/timeout do `IDXGIKeyedMutex`, `PresentDisplayQpcTime`, `ExtractCompleteQpcTime`, `ServerSendQpcTime` e `QpcFrequency`.
  - `FrameIpcFrameAck` (**56 bytes**): codifica em `Reserved1` o `SlotIndex`, `SlotGeneration`, indicador GPU e `GpuSyncWaitUs`.
  - Novos status em `FrameIpcStatus`: `AdapterLuidMismatch` (`11`), `HandleDuplicationFailed` (`12`), `GpuSyncTimeout` (`13`), `ResourceOpenFailed` (`14`), `SlotEvicted` (`15`), `DeviceRemoved` (`16`).

---

## 5. Integração NVIDIA NVENC H.264 (`NvencH264Encoder.h` / `.cpp`)

- **Descoberta em Runtime:** Carrega `nvEncodeAPI64.dll` via `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_SYSTEM32)`. Caso o runtime NVIDIA não exista ou a GPU não suporte H.264, `ProbeAvailability` retorna `false` de forma limpa sem impactar o build ou a inicialização do driver.
- **Consulta de Capacidades Reais:** Abre sessão temporária (`nvEncOpenEncodeSessionEx` DirectX11) e consulta suporte H.264, largura/altura máximas (`4096x4096` na RTX 3060 Ti), B-frames, reconfiguração dinâmica de resolução/bitrate e formatos de entrada (`NV_ENC_BUFFER_FORMAT_ARGB`, `ABGR`, `NV12`).
- **Entrada GPU e Conversão de Cores:**
  - `--nvenc-color-format auto` / `argb`: registra e mapeia entrada `BGRA8` (`NV_ENC_BUFFER_FORMAT_ARGB`) ou `RGBA8` (`ABGR`) na GPU.
  - `--nvenc-color-format nv12`: usa `ID3D11VideoDevice` + `ID3D11VideoProcessor` (`D3D11_VIDEO_USAGE_OPTIMAL_SPEED`) na GPU para converter `BGRA8 -> NV12` antes do `nvEncRegisterResource` / `nvEncMapInputResource`, **sem leitura/conversão por CPU**.
  - Formatos incompatíveis (ex.: `DXGI_FORMAT_R16G16B16A16_FLOAT`) são rejeitados explicitamente com `DXGI_ERROR_UNSUPPORTED` antes do mapeamento.
- **Baixa Latência e Keyframes:**
  - Preset `NV_ENC_PRESET_P1_GUID` com `NV_ENC_TUNING_INFO_ULTRA_LOW_LATENCY`, `frameIntervalP = 1` (`0` B-frames), `enableLookahead = 0`, `zeroReorderDelay = 1`, controle CBR com VBV de 1 quadro e `repeatSPSPPS = 1`.
  - Suporta `gopLength`/`idrPeriod` configurável (`--nvenc-gop`) e solicitação explícita instantânea via `RequestForceIdrOnNextFrame()` (`--nvenc-force-idr-every`).
  - Trata `NV_ENC_ERR_ENCODER_BUSY` contabilizando `NvencDroppedFrames` sem encerrar a sessão, e `DXGI_ERROR_DEVICE_REMOVED` / `NV_ENC_ERR_DEVICE_NOT_EXIST` com reconstrução via `ReconstructSession`.

### Dependências e Licenças
- **`windows/host/third_party/nvenc/nvEncodeAPI.h`:** Cabeçalho da API NVIDIA Video Codec SDK `12.1` (compatível com drivers NVENC `12.x` e `13.x`, verificado em runtime com API `13.1` na RTX 3060 Ti), proveniente de `FFmpeg/nv-codec-headers` (`sdk/12.1`) sob licença permissiva **MIT**.
- **Nenhuma biblioteca estática ou DLL proprietária da NVIDIA** é redistribuída no repositório; o host vincula apenas bibliotecas padrão do Windows SDK (`d3d11.lib`, `dxgi.lib`, `mfplat.lib`, `mfuuid.lib`, `wmcodecdspuuid.lib`, `ole32.lib`).

---

## 6. Estratégias de Fallback e Segurança Operacional

- **Driver:** `REG_DWORD EnableFrameExtraction` continua **`0` por padrão**. Quando ativado (`1`), `REG_DWORD EnableGpuSharedTransport` controla o transporte preferido (`1` por padrão quando ausente; `0` força M4.1.1 CPU Staging).
- **Negociação no Host (`lumabridge-host.exe`):**
  - `--transport auto` (padrão): solicita `1.1 GpuSharedNtHandle`, aceita fallback `1.0 CpuStagingPipe` caso driver ou adaptador não suporte.
  - `--transport gpu --require-gpu-shared`: exige `GpuSharedNtHandle`, falha com código de saída `1` se houver fallback CPU ou se `CpuStagingReadsPerformed > 0` (em modo normal sem `--verify-synthetic-pattern`).
  - `--transport cpu`: força caminho diagnóstico M4.1.1 (`CpuStagingPipe`).

---

## 7. Investigação do Gargalo de 37,33 FPS no Estímulo Visual

Na M4.1.1, o estímulo visual configurado para `60 Hz` atingiu apenas `37,33 FPS`. A inspeção de `windows/host/VirtualDisplayStimulus.h` identificou a causa raiz: o loop de apresentação usava espera relativa fixa `MsgWaitForMultipleObjects(..., 16, QS_ALLINPUT)` sem timer de alta resolução nem compensação de deadline. Como o tick padrão de agendamento do Windows é `15,625 ms`, qualquer atraso marginal acima de `16 ms` ou tempo de `InvalidateRect`/`UpdateWindow` quantizava cada iteração para `~26,8 ms` (`~37,3 FPS`).

A correção introduziu `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` (`0x00000002`) com deadlines absolutos em QPC e ajuste de `spinThresholdQpc` final (~0,8 ms). Verificação isolada em desktop real Windows 11 (`VirtualDisplayStimulusHighResTimer60FpsVerification`, janela de 1,5 s):
- `HighResolutionTimerUsed = true`
- `TicksPresented = 91`, `PaintCount = 92`
- **`AchievedFps = 60,13 FPS`**
- `TickIntervalAvgUs = 16.667 µs`, `TickIntervalP95Us = 16.949 µs`, `TickIntervalMaxUs = 17.160 µs`

Isto separa de forma limpa o ritmo do estímulo (`60,13 FPS`) de gargalos de composição DWM, cópia, IPC e codificação.

---

## 8. Benchmark Controlado (RTX 3060 Ti, 120 quadros por modo)

Resultados medidos em processo real separado (`FrameEndToEndIntegrationTests.exe` + `lumabridge-host.exe`, configuração `Release|x64`, adaptador `Hardware` RTX 3060 Ti, leitura de pixel CPU no caminho normal `cpuReads = 0` nos modos GPU):

| Resolução | Modo | FPS Conectado | FPS Ativo | FPS Saída NVENC | Cópia Produtor (Avg / p95) | Trânsito IPC (Avg) | Sync Mutex GPU (Avg) | Codificação NVENC (Avg / p95) | Latência Host E2E (Avg / p95) | Bytes no Pipe / Bitstream |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **1280×720** | **[A] M4.1.1 CPU Staging** | 118,31 | 119,49 | — | 784 / 1.828 µs | 698 µs | — | — | 1.782 / 2.988 µs | 442.380.480 B (pipe) |
| **1280×720** | **[B] M4.2 Fase A GPU Shared** | 6.666,67 | *(18 ms total)* | — | 0 / 1 µs | 1.892 µs | 34 µs | — | 5.601 / 509 µs | 16.320 B (pipe) |
| **1280×720** | **[C] M4.2 Fase B GPU + NVENC** | 437,99 | 442,15 | **518,61** | 0 µs | 4.053 µs | 23 µs | 1.847 / 1.978 µs | — *(presentToBs 14.317 µs em burst)* | 4.697.269 B (H.264) |
| **1920×1080** | **[A] M4.1.1 CPU Staging** | 51,94 | 52,41 | — | 1.234 / 1.456 µs | 1.807 µs | — | — | 18.405 / 22.927 µs | 995.340.480 B (pipe) |
| **1920×1080** | **[B] M4.2 Fase A GPU Shared** | 6.079,03 | *(19 ms total)* | — | 0 / 1 µs | 1.847 µs | 32 µs | — | 5.488 / 478 µs | **16.320 B** (**60.989× menor**) |
| **1920×1080** | **[C] M4.2 Fase B GPU + NVENC** | 294,45 | **296,29** | **324,78** | 0 µs | 5.123 µs | 25 µs | **2.999 / 3.152 µs** | — *(presentToBs 18.619 µs em burst)* | **4.779.806 B** (**208× menor**) |

*Observações de medição:*
- Nos testes em rajada (`burst` sem cadência de 60 Hz), o produtor enfileira até o limite da fila à frente do codificador (~10–15 ms de fila observável em `presentToBs` durante saturação de 120 quadros contínuos); sob cadência constante de 60 Hz (`16,67 ms`/quadro), o codificador conclui cada frame 1080p em **~3,00 ms** sem acúmulo de fila.
- Validação independente com decodificador CPU Media Foundation (`Microsoft H.264 Video Decoder MFT`, `NvencEncoderTests`): 8/8 quadros decodificados, 0 erros NAL/decodificação, **PSNR mínimo Y = 46,54 dB (média 49,05 dB) e UV = 41,24 dB (média 44,06 dB)**.

---

## 9. Procedimento de Validação Windows e Caminho para Linux

### Validação em Host Windows 11 Real
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\driver\scripts\Invoke-LumaBridgeFunctionalValidation.ps1 `
    -Configuration Release `
    -TestProfile Both `
    -TransportMode Gpu `
    -RequireGpuShared `
    -EnableNvenc `
    -RequireNvenc `
    -VerifyH264Decode `
    -CreateTestCertificateIfMissing -TrustCertificate -AllowUntrustedChain
```
O script habilita temporariamente `EnableFrameExtraction=1` (e `EnableGpuSharedTransport` se explicitado) e garante o rollback completo no bloco `finally` (`EnableFrameExtraction=0`, remoção/restauração de `AuthorizedHostUserSid` e `EnableGpuSharedTransport`, encerramento de ETW e reinício do adaptador).

### Caminho Posterior para Transmissão Linux (M5+)
1. **Empacotamento de Rede em `lumabridge-host.exe`:** Consumir pacotes `EncodedFramePacket` de `EncodedFrameQueue` (já entregues em `Annex-B` com SPS/PPS pré-anexados a cada IDR e `PresentDisplayQpcTime` / `FrameSequence`), fragmentando em datagramas UDP/QUIC/RTP com cabeçalho mínimo de sequência, timestamp monotônico e indicador de keyframe.
2. **Canal de Controle Reverso:** Ao detectar perda de pacote ou mudança de resolução no cliente Linux, enviar pedido explícito de IDR para chamar `NvencH264Encoder::RequestForceIdrOnNextFrame()`.
3. **Cliente Receptor Linux:** Decodificação por hardware via **VA-API / Vulkan Video / NVDEC** sem bufferização de B-frames (`0 B-frames` já garantido pelo encoder NVENC), apresentando via Wayland/DRM-KMS ou Vulkan Swapchain sincronizado ao `PresentationFrameNumber`.
