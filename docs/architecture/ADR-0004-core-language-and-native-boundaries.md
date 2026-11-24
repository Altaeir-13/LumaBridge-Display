# ADR-0004 - Linguagem do núcleo multiplataforma e fronteiras nativas (FFI)

## Metadados

- **ID:** ADR-0004
- **Status:** Proposed *(sujeita à aprovação da Prova de Conceito de interoperabilidade Rust ↔ host Windows C++ em M1)*
- **Data:** 2026-11-23
- **Relações:**
  - Implementa a visão aprovada em [ADR-0003 - Visão oficial da plataforma universal](./ADR-0003-universal-platform-vision.md).
  - Complementada por [ADR-0005 - Arquitetura de transporte e segurança](./ADR-0005-transport-and-security-architecture.md) (`Proposed`) e [universal-platform-architecture.md](./universal-platform-architecture.md).

## Contexto

Com a redefinição do LumaBridge Display para uma plataforma bidirecional entre Windows, Linux (Wayland/X11) e Android (com expansão futura para macOS e iOS/iPadOS), o núcleo de protocolo, segurança, descoberta, transporte de rede e máquina de estados de sessão precisa rodar de forma idêntica e segura em todas as plataformas, sem duplicar lógica crítica em C++, Kotlin e Swift.

Ao mesmo tempo, o projeto já possui aproximadamente 20 mil linhas de código e testes C++17/WDK/PowerShell para Windows (`LumaBridgeIddDriver` e o host D3D11/NVENC em branch de desenvolvimento), altamente acopladas a contratos nativos da Microsoft (`WDF`, `IddCx`, `COM`, `D3D11`, `DXGI`, `Media Foundation`, `nvEncodeAPI.h`).

## Decisão proposta

Adotar uma **arquitetura híbrida de núcleo compartilhado em Rust com backends gráficos e de sistema nativos**, mantendo o código C++ existente intacto:

1. **Rust (núcleo multiplataforma compartilhado):**
   - Responsável por `lumabridge-protocol`, `lumabridge-security`, `lumabridge-transport` e `lumabridge-core` (máquina de estados de nó/sessão, orquestração multi-display, controle de congestionamento/pacing, coleta de telemetria agregada e política de permissões).
2. **C++17 / C++20 (driver Windows e integração nativa de alto desempenho):**
   - `LumaBridgeIddDriver` permanece permanentemente em C++17 + WDK/UMDF/IddCx (sem qualquer dependência de Rust no driver).
   - Backend Windows (`windows/host` e extensões futuras para WGC/DXGI, AMF, oneVPL/QSV, Media Foundation MFT, render D3D11 e `SendInput`) permanece em C++ nativo.
3. **Kotlin (+ NDK/UniFFI) no Android:**
   - Aplicação Android, UI Jetpack Compose, ciclos de `MediaProjection`/`Service`, `MediaCodec`, `SurfaceView` e manipulação de entrada em Kotlin + JNI/NDK conectando-se ao núcleo Rust via UniFFI.
4. **Backends nativos para Linux e plataformas futuras:**
   - Linux utiliza bindings nativos adequados para Wayland/X11, PipeWire, `xdg-desktop-portal`, VA-API/Vulkan/EGL/DRM e `libei`/`XTest` (em C/C++20 ou Rust nativo com bibliotecas do sistema carregadas dinamicamente quando aplicável).
   - Futuras plataformas Apple (`macOS`, `iOS/iPadOS`) utilizarão Swift/Objective-C++ (`ScreenCaptureKit`, `VideoToolbox`, `Metal`) sobre o mesmo núcleo Rust.

> **Importante:** Esta decisão permanece no estado **Proposed** até a conclusão bem-sucedida da Prova de Conceito (PoC) descrita na Seção "Critérios de saída da PoC". Não há reescrita do código C++ existente.

## Alternativas consideradas

### Opção A (Candidata): Núcleo em Rust + Backends Nativos em C++/Kotlin/Swift

- **Prós:**
  - Segurança de memória garantida em tempo de compilação para parsers de pacotes de rede, desfragmentação, estado criptográfico, handshake e controle de entrada remota — reduzindo drasticamente riscos de buffer overflow e *use-after-free* na superfície exposta à rede.
  - Ecossistema maduro e autocontido para QUIC/TLS 1.3 (`quinn` + `rustls` + `tokio`), criptografia moderna (`ed25519-dalek`, `spake2`), serialização e geração de bindings (`cbindgen`, `uniffi`) compilando uniformemente em Windows, Linux e Android (`cargo-ndk`).
  - Preserva 100% do código C++17/WDK/D3D11/NVENC já implementado e validado.
- **Contras:**
  - Exige segunda toolchain (`rustup`/`cargo`, atualmente não instalada no ambiente de desenvolvimento Windows auditado).
  - Introduz uma fronteira FFI (`extern "C"` / `UniFFI`) que demanda disciplina estrita de ownership, ciclo de vida e tratamento de erros.

### Opção B (Alternativa / Fallback): Núcleo integralmente em C++20

- **Prós:**
  - Toolchain única (MSVC no Windows, Clang/GCC no Linux, NDK CMake no Android); ausência de fronteira FFI entre o backend Windows e o núcleo.
- **Contras:**
  - Gerenciamento manual de bibliotecas nativas pesadas de QUIC + TLS 1.3 (`msquic` ou `quiche` + OpenSSL/BoringSSL) via `vcpkg`/Conan/CMake em 3 sistemas operacionais e 4+ arquiteturas.
  - Superfície crítica de rede e parsing exposta em linguagem sem *memory safety* estática, exigindo fuzzing contínuo e sanitizers rigorosos para atingir equivalência de segurança.
  - Mais boilerplate JNI/NDK manual para exposição ao app Android em Kotlin.

### Opção C (Descartada): Linguagens gerenciadas / runtime pesado no núcleo (C#, Go, Electron)

- **Motivo da rejeição:** sobrecarga de runtime/GC em hot path de 60–120+ FPS, complexidade de embarcar em NDK Android e bibliotecas Linux sem conflitos de runtime, e menor previsibilidade de latência p99.

## Análise técnica da fronteira FFI

A viabilidade da Opção A depende de manter a fronteira FFI **estreita, rasa e orientada a dados codificados**:

### 1. Regra de ouro: o que cruza (e o que NÃO cruza) a fronteira FFI

- **Cruza a fronteira FFI:** comandos de controle de sessão, eventos de configuração de display, eventos normalizados de entrada remota, métricas/telemetria e **slices/buffers de bitstream já codificado** (ex.: quadros Annex-B H.264/HEVC/AV1).
- **NUNCA cruza a fronteira FFI:** texturas de GPU cruas (`ID3D11Texture2D*`), handles compartilhados NT DXGI, descritores `DMA-BUF`, `AHardwareBuffer`, contextos D3D11/EGL/Vulkan ou buffers de pixels RGB não comprimidos no caminho normal. Toda troca entre captura/processamento e encoder/decoder permanece 100% em memória nativa/GPU no respectivo backend de plataforma.

### 2. Ownership e gerenciamento de buffers codificados

Alocadores de heap nunca são compartilhados entre Rust, MSVC CRT (`/MD` vs `/MDd`), libc Linux e Android NDK. Dois padrões formais cobrem toda a troca de dados:

- **Caminho síncrono emprestado (TX — Nativo → Rust):** o backend nativo chama `lb_core_submit_encoded_frame(handle, &meta, bytes_ptr, bytes_len)`. O núcleo Rust copia imediatamente para o buffer/datagrama de saída QUIC/TLS ou retorna `LB_ERR_BACKPRESSURE` de forma não bloqueante; após o retorno da função C, o backend nativo mantém ownership total da memória de origem (ex.: reutilizando seu slot em `EncodedFrameQueue`).
- **Transferência assíncrona explícita (`LbOwnedBuffer`):** quando houver enfileiramento assíncrono em qualquer direção (especialmente RX Rust → Decoder Nativo), utiliza-se uma struct explícita com destruidor próprio:

```c
typedef struct LbOwnedBuffer {
    const uint8_t* data;
    size_t         len;
    size_t         capacity;
    void         (*release)(void* user_ctx, const uint8_t* data, size_t len, size_t capacity);
    void*          user_ctx;
} LbOwnedBuffer;
```

Quem aloca o buffer fornece o ponteiro `release`; o receptor chama `release` exatamente uma vez quando concluir a cópia para o bitstream buffer do hardware decoder, garantindo independência total de alocadores e compatibilidade entre builds Debug (`/MDd`) e Release (`/MD`) no Windows.

### 3. Ciclo de vida (`Lifecycle`) e barreira de teardown

- Toda instância do núcleo é representada por um handle opaco `LbCoreHandle*`.
- Ciclo obrigatório: `lb_core_create(...)` → `lb_core_start(...)` → `lb_core_stop(...)` (cooperativo e idempotente) → `lb_core_destroy(...)`.
- `lb_core_destroy` só retorna após drenar e executar `join` em todas as threads internas do runtime Rust (Tokio/QUIC), assegurando a invariante: **nenhum callback nativo registrado pode ser disparado após `lb_core_destroy` retornar**.

### 4. Modelo de erros

- **Zero exceções C++ e zero panics Rust** podem atravessar fronteiras `extern "C"`.
- Toda função exportada em Rust envolve o corpo em `std::panic::catch_unwind`; em caso de panic capturado, o núcleo transiciona para estado `Faulted`, registra diagnóstico sanitizado e retorna `LB_STATUS_INTERNAL_PANIC`.
- Callbacks fornecidos pelo lado C++ devem ser marcados `noexcept`.
- Mensagens de erro detalhadas são entregues por enum numérico `LbStatus` (`uint32_t`) + string UTF-8 alocada/limitada sem dados sensíveis (nunca chaves, PINs ou pixels).

### 5. Threads, reentrância e hierarquia de locks

- O runtime assíncrono do núcleo Rust executa em seu próprio pool de threads e **nunca** deve executar callbacks síncronos enquanto segura mutexes internos de estado de sessão ou fila de rede.
- O backend nativo **nunca** deve bloquear callbacks oriundos da thread da swapchain (`SwapChainProcessor`) ou da thread de UI com I/O síncrono na rede; a submissão de pacotes codificados respeita orçamento não bloqueante com descarte controlado por backpressure.

### 6. Estabilidade de ABI

- Para C/C++ (Windows e Linux), o contrato C99/C11 é gerado a partir do crate `lumabridge-ffi` com `cbindgen`, validado em build por `static_assert` de tamanho e alinhamento em ambos os lados.
- Estruturas públicas carregam cabeçalho de compatibilidade `LbAbiHeader { uint32_t abi_major; uint32_t abi_minor; uint32_t struct_size; }`, enums com largura fixa `uint32_t` e reserva de campos de extensão.
- No Windows, `lumabridge-core` pode ser empacotado como `cdylib` (`lumabridge_core.dll`) para isolar completamente o CRT MSVC (`/MDd` em Debug nos testes C++ vs `/MD` em Rust) ou como `staticlib` com verificação estrita de flags de linker na PoC.
- Para Android, utiliza-se **UniFFI** gerando bindings Kotlin idiomáticos sobre a mesma camada de serviço do núcleo.

### 7. Overhead esperado de FFI

- Uma chamada C ABI direta para submeter um quadro codificado 1080p60 (60 chamadas/s por display) envolve apenas passagem de ponteiro/metadados e cópia/enfileiramento de ~30–150 KiB de bitstream H.264/HEVC (ou 1 passagem de slice no canal de datagrama), com custo típico na ordem de poucos microssegundos — ordens de grandeza abaixo do orçamento de 16.667 µs/quadro de 60 Hz ou do custo de codificação/rede. Esse pressuposto será medido objetivamente na PoC antes de tornar esta ADR `Accepted`.

## Critérios objetivos de saída da PoC (para promover ADR-0004 a `Accepted`)

Antes de iniciar a implementação em larga escala de `M1`, uma PoC isolada deverá comprovar todos os itens abaixo:

1. **Build e linkagem Windows/MSVC:** compilação limpa de `lumabridge_core` integrada ao build de `lumabridge-host` no toolset MSVC `14.51` sem conflitos de CRT (`Debug` e `Release`).
2. **Benchmark de overhead FFI:** envio/recebimento de 1.800 pacotes sintéticos simulando 1080p60 por 30 segundos através da fronteira Rust ↔ C++ com overhead adicionado pela fronteira FFI `p99 < 100 µs`.
3. **Resiliência de ciclo de vida e memória:** 100 ciclos consecutivos de `create/start/submit/stop/destroy` e desconexões abruptas com contagem zero de vazamentos de memória ou handles pendentes.
4. **Contenção de falhas:** teste dedicado comprovando que um panic injetado no lado Rust retorna `LB_STATUS_INTERNAL_PANIC` sem encerrar abruptamente o processo host por *unwinding* através da ABI C.
5. **Cross-build Android:** compilação bem-sucedida de artefato `.so` mínimo de `lumabridge-core` + binding UniFFI para `aarch64-linux-android`.

**Estratégia de reversão (fallback):** se a PoC falhar em qualquer critério crítico de compatibilidade MSVC, NDK ou manutenção de toolchain, a decisão será revertida para **Opção B (núcleo C++20 via CMake)** antes da conclusão de `M1`, preservando integralmente os contratos de protocolo e segurança definidos no repositório.
