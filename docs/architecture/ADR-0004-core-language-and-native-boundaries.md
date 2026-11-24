# ADR-0004 - Linguagem do núcleo multiplataforma e fronteiras nativas (FFI)

## Metadados

- **ID:** ADR-0004
- **Status:** Accepted *(promovida após aprovação dos 5 critérios da PoC `M1.1` e auditoria/endurecimento `M1.1.1` em `2026-11-24`)*
- **Data:** 2026-11-24 *(proposta inicial: 2026-11-23; revisão e aceitação `M1.1.1`: 2026-11-24)*
- **Relações:**
  - Implementa a visão aprovada em [ADR-0003 - Visão oficial da plataforma universal](./ADR-0003-universal-platform-vision.md).
  - Relatório empírico de qualificação: [m1-ffi-poc-report.md](./m1-ffi-poc-report.md).
  - Complementada por [ADR-0005 - Arquitetura de transporte e segurança](./ADR-0005-transport-and-security-architecture.md) (`Proposed`) e [universal-platform-architecture.md](./universal-platform-architecture.md).

## Contexto

Com a redefinição do LumaBridge Display para uma plataforma bidirecional entre Windows, Linux (Wayland/X11) e Android (com expansão futura para macOS e iOS/iPadOS), o núcleo de protocolo, segurança, descoberta, transporte de rede e máquina de estados de sessão precisa rodar de forma idêntica e segura em todas as plataformas, sem duplicar lógica crítica em C++, Kotlin e Swift.

Ao mesmo tempo, o projeto já possui aproximadamente 20 mil linhas de código e testes C++17/WDK/PowerShell para Windows (`LumaBridgeIddDriver` e o host D3D11/NVENC, integrados em `dev` via PR #37 / `23a28046`), altamente acopladas a contratos nativos da Microsoft (`WDF`, `IddCx`, `COM`, `D3D11`, `DXGI`, `Media Foundation`, `nvEncodeAPI.h`).

## Decisão aprovada (`Accepted`)

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

> **Escopo aprovado:** esta decisão promove especificamente a linguagem do núcleo compartilhado e os contratos de fronteira FFI validados em `M1.1`/`M1.1.1`. [`ADR-0005`](./ADR-0005-transport-and-security-architecture.md) permanece `Proposed` e [`wire-protocol-v1.md`](../protocol/wire-protocol-v1.md) permanece `Draft` até as etapas dedicadas de protocolo, segurança e benchmark comparativo QUIC vs TCP/TLS 1.3 (`M1.2+`). Não há reescrita do código C++ validado na `M0`.

## Alternativas consideradas

### Opção A (Aprovada): Núcleo em Rust + Backends Nativos em C++/Kotlin/Swift

- **Prós:**
  - Segurança de memória garantida em tempo de compilação para parsers de pacotes de rede, desfragmentação, estado criptográfico, handshake e controle de entrada remota — reduzindo drasticamente riscos de buffer overflow e *use-after-free* na superfície exposta à rede.
  - Ecossistema maduro e autocontido para QUIC/TLS 1.3 (`quinn` + `rustls` + `tokio`), criptografia moderna (`ed25519-dalek`, `spake2`), serialização e geração de bindings (`cbindgen`, `uniffi`) compilando uniformemente em Windows, Linux e Android (`cargo-ndk`).
  - Preserva 100% do código C++17/WDK/D3D11/NVENC já implementado e validado.
- **Contras:**
  - Exige segunda toolchain (`rustup`/`cargo` pinada em `core/rust-toolchain.toml` como `1.100.0` em escopo do usuário `--no-modify-path`).
  - Introduz uma fronteira FFI (`extern "C"` / `UniFFI`) que demanda disciplina estrita de ownership transacional, alinhamento/pré-leitura de cabeçalhos ABI, ciclo de vida e tratamento de erros.

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

Alocadores de heap nunca são compartilhados entre Rust (`cdylib`), MSVC CRT (`/MD` vs `/MDd`), libc Linux e Android NDK. Dois padrões formais cobrem toda a troca de dados:

- **Caminho síncrono emprestado (TX — Nativo → Rust):** o backend nativo chama `lb_core_submit_encoded_frame(handle, &meta, bytes_ptr, bytes_len)`. O núcleo Rust adquire brevemente um mutex interno de fila, copia os bytes para um buffer interno reciclável (com pré-alocação ansiosa limitada em `4 MiB` totais / `8` slots e limite de `8 MiB` por quadro) e retorna, ou retorna `LB_STATUS_BACKPRESSURE` sem esperar I/O/worker nem reter `bytes_ptr`; após o retorno da função C, o backend nativo mantém ownership total da memória de origem.
- **Transferência assíncrona transacional (`LbOwnedBuffer*`):** quando houver enfileiramento assíncrono em qualquer direção (TX sem cópia no chamador via `lb_core_submit_owned_encoded_frame` e RX Rust → Consumidor Nativo), utiliza-se uma struct explícita com destruidor próprio:

```c
typedef struct LbOwnedBuffer {
    const uint8_t* data;
    size_t         len;
    size_t         capacity;
    void         (*release)(void* user_ctx, const uint8_t* data, size_t len, size_t capacity);
    void*          user_ctx;
} LbOwnedBuffer;
```

- **Semântica transacional de commit (`Nativo → Rust`):** `lb_core_submit_owned_encoded_frame` recebe `LbOwnedBuffer*` mutável. Em `LB_STATUS_OK`, Rust assume ownership único e **zera** `*buffer` (`data == NULL`, `release == NULL`) no ponto de commit após reservar o slot da fila, garantindo invocação `noexcept` única de `release` fora de mutexes. Em erros determinísticos ou pânico **pré-commit**, `*buffer` permanece intacto e `release` nunca é chamado por Rust. Em pânico **pós-commit**, `*buffer` já está zerado e Rust drena/libera o item uma única vez; chamar `lb_core_release_buffer(buffer)` no código de limpeza nativo é seguro em ambos os cenários sem *double-free*.
- **Tempo de vida da biblioteca compartilhada (`Rust → Nativo`):** um `LbOwnedBuffer` alocado por Rust e entregue em `LbOutputPacketCallback` pode ser retido além do retorno do callback, liberado em outra thread e inclusive liberado **após `lb_core_destroy`** via `lb_core_release_buffer`, desde que a DLL/DSO `lumabridge_ffi` permaneça carregada no espaço de endereçamento do processo até a liberação de todos os buffers pendentes.

### 3. Ciclo de vida (`Lifecycle`) e barreira de teardown

- Toda instância do núcleo é representada por um handle opaco `LbCoreHandle*`.
- Ciclo obrigatório: `lb_core_create(...)` → `lb_core_start(...)` → `lb_core_stop(...)` (cooperativo e idempotente) → `lb_core_destroy(...)`.
- Ordem monotônica de notificações de estado (`Created -> Running -> Stopping -> Stopped | Faulted`), sem downgrade de `Faulted` para `Stopped` e sem entrega dupla de estado terminal.
- Chamadores externos concorrentes de `lb_core_stop` aguardam até que callbacks em andamento terminem, a *worker thread* saia completamente e o estado terminal tenha sido entregue antes do retorno; `lb_core_stop` reentrante de dentro do callback da própria *worker thread* nunca realiza auto-*join*. `lb_core_destroy` garante retorno apenas após conclusão do *join* final.

### 4. Modelo de erros

- **Zero exceções C++ e zero panics Rust** podem atravessar fronteiras `extern "C"`.
- Toda função exportada em Rust envolve o corpo em `std::panic::catch_unwind`; em caso de panic capturado, o núcleo transiciona para estado `Faulted`, registra diagnóstico sanitizado e retorna `LB_STATUS_INTERNAL_PANIC`. Callbacks nativos também executam com isolamento adicional em caminhos de recuperação de falha para evitar propagação secundária.
- Callbacks fornecidos pelo lado C++ devem ser marcados `noexcept`. `catch_unwind` **não** intercepta exceções fatais de SO (SEH/violação de acesso), abortos de processo ou UB decorrente de ponteiros inválidos.
- Mensagens de erro detalhadas são entregues por enum numérico `LbStatus` (`uint32_t`) + string UTF-8 limitada sem dados sensíveis (nunca chaves, PINs ou pixels).

### 5. Threads, reentrância, locks e orçamento de memória

- O runtime assíncrono do núcleo Rust executa em seu próprio pool de threads e **nunca** deve executar callbacks nativos (`on_output_packet`, `on_state_changed`, `release`) enquanto segura mutexes internos de estado de sessão ou fila.
- O caminho `submit_*` não realiza I/O de rede nem bloqueia esperando o worker, mas adquire brevemente um mutex interno de fila (além de copiar bytes no caminho `borrowed`).
- Pré-alocação ansiosa de buffers recicláveis é limitada em `MAX_EAGER_PREALLOC_TOTAL_BYTES = 4 MiB` (`<= 8` slots), enquanto cada quadro codificado respeita o teto de `8 MiB` e a fila respeita `queue_capacity <= 256`; um orçamento agregado explícito de bytes em fila permanece planejado para a implementação completa da `M1/M2`.

### 6. Estabilidade de ABI

- Para C/C++ (Windows e Linux), o contrato C99/C11 é gerado a partir do crate `lumabridge-ffi` com `cbindgen`, validado em build por `_Static_assert`/`static_assert` de tamanho e alinhamento em ambos os lados e assinatura em tempo de execução (`lb_core_layout_signature`).
- Estruturas públicas carregam cabeçalho de compatibilidade `LbAbiHeader { uint32_t abi_major; uint32_t abi_minor; uint32_t struct_size; uint32_t reserved; }`, enums com largura fixa `uint32_t` e reserva de campos de extensão.
- Pontos de entrada versionados realizam **pré-leitura segura apenas dos 16 bytes iniciais de `LbAbiHeader` e checagem explícita de alinhamento** antes de criar referências ou ler/escrever a struct completa, protegendo contra acesso fora dos limites em buffers legados menores ou ponteiros desalinhados.
- No Windows, `lumabridge_ffi` é compilada como **`cdylib`** (`lumabridge_ffi.dll`) para isolar completamente alocadores e CRT MSVC (`/MDd` em Debug C++ vs `/MD` em Rust).
- Para Android, utiliza-se **UniFFI** gerando bindings Kotlin sobre a mesma camada de serviço do núcleo.

### 7. Overhead medido de FFI

- Medições em Release x64 (`MSVC 14.51.36231 /O2 /MD`, Rust `--release`, `1.800` pacotes @ `60 pps` de `30–150 KiB`, veja [m1-ffi-poc-report.md](./m1-ffi-poc-report.md)) comprovaram overhead `p99` consistentemente abaixo da meta de `100 µs` mesmo após endurecimento transacional e pré-leitura de cabeçalho ABI (`M1.1.1`: `ffi_borrowed_submit p99 = 56,9 µs`, `ffi_owned_submit p99 = 25,8 µs`, `paired_owned_overhead p99 = 24,0 µs`), ordens de grandeza abaixo do orçamento de quadro `16.667 µs` a `60 Hz`.

## Critérios objetivos de saída da PoC (Todos Aprovados em `M1.1` / `M1.1.1`)

Todos os cinco critérios estabelecidos para promover esta ADR foram verificados com evidências reproduzíveis em [m1-ffi-poc-report.md](./m1-ffi-poc-report.md):

1. **Build e linkagem Windows/MSVC:** compilação limpa de `lumabridge_ffi.dll` integrada ao build de `lumabridge-host.exe` (`--ffi-poc-selftest`) no toolset MSVC `14.51` sem conflitos de CRT (`Debug /MDd` e `Release /MD`), mantendo `lumabridge-host.exe` padrão isolado — **PASS**.
2. **Benchmark de overhead FFI:** envio/recebimento de 1.800 pacotes sintéticos simulando 1080p60 por 30 segundos através da fronteira Rust ↔ C++ com overhead `p99 < 100 µs` (`M1.1`: `51,0 µs`; revalidado em `M1.1.1`: `56,9 µs` borrowed / `25,8 µs` owned) — **PASS**.
3. **Resiliência de ciclo de vida e memória:** 120 ciclos consecutivos (`>= 100`) de `create/start/submit/stop/destroy`, desconexões abruptas concorrentes, stops paralelos, liberação pós-destroy e zero vazamentos de memória ou handles (`55 -> 55`) — **PASS**.
4. **Contenção de falhas:** suíte dedicada (`poc-fault-injection`, Modos `1..4`: pânico FFI, pânico worker e pânicos pré/pós-commit transacional) retorna `LB_STATUS_INTERNAL_PANIC` sem unwinding nem double-free, mantendo símbolo ausente na DLL padrão — **PASS**.
5. **Cross-build Android:** compilação bem-sucedida de `.so` ARM64 (`aarch64-linux-android`, `ELF64 AArch64 DYN`) + geração de bindings Kotlin via UniFFI (escopo transparente: compilação bytecode Gradle/JNA e execução em aparelho permanecem para etapas posteriores) — **PASS**.

**Registro histórico de contingência (não acionado):** durante a proposta inicial previu-se que, caso a PoC falhasse em qualquer critério crítico de compatibilidade MSVC, NDK ou manutenção de toolchain, a decisão seria revertida para **Opção B (núcleo C++20 via CMake)** antes de construir `M1`. Como todos os cinco critérios foram aprovados, o plano de contingência permanece apenas como registro histórico e esta **ADR-0004 torna-se `Accepted` em `2026-11-24`**.
