# Roadmap Universal Incremental (`M0–M6`) — LumaBridge Display

> **Nota de governança (`M0.4`):** A validação funcional real da `M0` com o driver carregado em `WUDFHost.exe` (`Benchmark30s` 30 s e `ProlongedStability` 180 s no commit funcional `6b297856`) foi **aprovada** e a pilha Windows + documentação universal encontra-se consolidada localmente na branch `integration/m0-windows-closure`. Contudo, **`M0` ainda não foi integrada em `dev` remoto (`origin/dev`)** e **`M1` ainda não foi iniciada**. Este documento não adota estimativas arbitrárias de tempo ou percentuais.

---

## 1. Visão de Trilhas Paralelas (`M0–M6`)

Embora a ordem de integração siga a dependência lógica `M0 → M1 → M2 → M3 → M4 → M5 → M6`, várias frentes podem avançar em **trilhas paralelas** sem bloquear umas às outras:

- **Trilha A (Encerramento `M0`):** gate real em `WUDFHost.exe` concluído e consolidado em `integration/m0-windows-closure`; pendente apenas revisão/publicação em `dev` remoto e emissão de `LICENSE`/CI inicial.
- **Trilha B (Núcleo Multiplataforma & CI):** PoC Rust ↔ C++ Windows (`ADR-0004`), implementação de `lumabridge-protocol`, `lumabridge-security`, `lumabridge-transport` (benchmark QUIC vs TCP/TLS 1.3), `lumabridge-core` e pipelines CI (Windows + Linux). *(Pode iniciar em paralelo à Trilha A sobre frames sintéticos.)*
- **Trilha C (Receptor Linux Wayland/X11):** protótipo e construção do receptor Linux consumindo stream sintético do núcleo (`M1`) antes mesmo de receber quadros reais do driver Windows (`M2`).
- **Trilha D (Expansão Multi-GPU, Android e Emissores):** abstrações `IVideoEncoder`/Multi-GPU Windows e app receptor Android podem ser prototipados assim que `M1` congelar o protocolo v1.

---

## 2. Taxonomia Oficial das 7 Categorias de Teste

Nenhuma categoria abaixo pode substituir indevidamente outra:

| Cat. | Categoria de Teste | O que Comprova | O que NÃO Comprova |
|---:|---|---|---|
| **1** | **Testes unitários** | Máquinas de estado, serialização/desserialização, limites e bounds, políticas de permissão, erros FFI, mocks de backend. | Comportamento real de GPU, driver no kernel/UMDF, compositor Wayland/X11 ou rede real. |
| **2** | **Testes sintéticos entre processos** | IPC real entre processos (`Named Pipe` / FFI), backpressure, PSNR sobre padrão sintético conhecido, throughput sustentado (ex.: 30 s / 1.800 quadros). | Composição real do DWM/compositor nem estabilidade do driver em `WUDFHost.exe`. |
| **3** | **Testes de integração com GPU real** | Alocação/cópia GPU, `SharedTexturePool`, `NVENC`/`AMF`/`QSV`/`VA-API`/`MediaCodec` em silício real, zero readback CPU, recuperação `DEVICE_REMOVED`. | Enumeração PnP, criação de saída no desktop ou transmissão em rede entre dispositivos. |
| **4** | **Testes com driver instalado e monitor virtual ativo** | Carregamento real em `WUDFHost.exe` (Windows) ou saída virtual ativa no compositor (Linux), `EnableVirtualMonitor`, extensão real, `D0Entry`/`D0Exit` e rollback sem telas fantasmas. | Desempenho/perdas em rede entre dois dispositivos ou apresentação no receptor remoto. |
| **5** | **Testes com transmissão real entre dois dispositivos** | Descoberta mDNS/manual, pareamento SPAKE2/QR, mTLS, tráfego LAN/Wi-Fi/USB real, negociação MTU, recuperação `AwaitingIdr`/Request-IDR, medição `ClockSync`. | Qualidade visual de apresentação/vsync/input no receptor se testado apenas em headless. |
| **6** | **Testes de apresentação e interação no receptor** | Renderização fullscreen Wayland/X11/Windows/Android, proporção/escala, decodificação HW ativa, legibilidade de texto, injeção autorizada de mouse/teclado/toque e bloqueio sem permissão. | Estabilidade térmica ou ausência de leaks em sessões longas. |
| **7** | **Testes prolongados de estabilidade** | Estabilidade contínua (ex.: 5 a 30+ min), ausência de leaks de RAM/VRAM/handles, estabilidade de FPS e latência p99 sem drift, reconexão repetida e teardown limpo. | Substituição de regressões unitárias negativas ou validações de segurança. |

---

## 3. Critérios Mensuráveis do Primeiro Fluxo Completo (`M2`: Windows → Linux)

O marco `M2` será avaliado por métricas reproduzíveis coletadas sem registro de pixels privados:

- **Resolução e fluidez alvo inicial:** `1920×1080 @ 60 FPS` sustentado com cobertura temporal de medição `>= 95%` e zero erros causais de timestamp (`TimestampMeasurementErrors == 0`).
- **Latência ponta-a-ponta (origem → apresentação no receptor):** mensurada via timestamps monotônicos + `ClockSyncPing`/`ClockSyncPong` (ou validação ótica externa complementar), reportando obrigatoriamente **p50, p95 e p99** por estágio (`captura`, `encode`, `rede`, `decode`, `apresentação`).
  - *Hipótese de produto a validar:* **`p95 <= 100 ms` em rede Ethernet local** (tratada estritamente como meta empírica a validar, não como garantia antecipada).
- **Consumo de recursos:** CPU (`%`), GPU engine/video (`%`), RAM privada e VRAM em ambos os nós (`lumabridge-host`, `WUDFHost.exe` e processo receptor Linux).
- **Qualidade e estabilidade de mídia:** taxa de quadros descartados no emissor/receptor, jitter entre quadros, confirmação de decodificação hardware (`VA-API` ativo; fallback SW apenas diagnóstico) e legibilidade de texto em área de trabalho estendida sem corrupção persistente de referências P-frame.
- **Recuperação e limpeza:** desconexão abrupta de rede ou processo receptor não trava nem o host nem o `WUDFHost.exe`; reconexão retoma vídeo via IDR; encerramento desativa/remove corretamente o monitor virtual e libera todos os handles.

---

## 4. Marcos Incrementais (`M0` a `M6`)

### `M0` — Preservação, Validação Real Windows e Consolidação de Governança

- **Estado atual (`M0.4`):** **Funcionalmente aprovada** (`6b297856`) e **consolidada localmente** (`integration/m0-windows-closure`); **ainda não integrada em `dev` remoto** (e `LICENSE`/`.github/workflows/` pendentes antes do fechamento formal em `dev`).
- **Objetivo:** Formalizar a documentação da visão universal, fechar a validação funcional ao vivo no Windows 11, consolidar para `dev` preservando a ancestralidade dos commits validados e preparar a base open source (`M1` ainda não iniciada).
- **Dependências:** Branches empilhadas `fix/windows-idd-device-start`, `feature/windows-frame-extraction-ipc`, `feature/windows-gpu-shared-textures-nvenc`, `fix/m0-validation-gates-hardening` e `docs/universal-architecture-redefinition`; autorização explícita para publicar em `dev`.
- **Artefatos produzidos:**
  - Documentação da arquitetura universal, ADRs `0003–0005`, protocolo rascunho `LBWP v1`, roadmap, plano de migração, registro de riscos e revisão de licenças;
  - Relatórios reais ao vivo aprovados (`Benchmark30s` 30 s e `ProlongedStability` 180 s com `D3d11DxgiVSync`, transporte GPU puro e rollback verificado no commit `6b297856`);
  - Branch local de integração `integration/m0-windows-closure` com `windows/driver/README.md`, `windows/driver/tests/README.md` e documentação `M0` reconciliados;
  - *(Pendentes de publicação/execução antes de encerrar `M0` formalmente em `dev`)*: merge em `dev`, decisão final e criação de `LICENSE` (`Apache-2.0` candidata), `NOTICE`/`THIRD_PARTY_NOTICES.md` e `.github/workflows/` inicial.
- **Critérios objetivos de aceitação:**
  - `157/157` testes C++ unitários/componentes, `9/9` E2E, `71/71` testes PowerShell e `InfVerif` aprovados na árvore integrada;
  - Execução real ao vivo em `WUDFHost.exe` com `TimestampMeasurementErrors == 0`, `CpuStagingReadsPerformed == 0`, `ProlongedStabilityProven == true` e `RollbackClean == true` *(atendido em `6b297856`)*;
  - Histórico em `dev` livre de conflitos preservando ancestralidade de `6b297856` *(aguardando merge autorizado em `dev`)*;
  - Nenhuma regressão no driver `LumaBridgeIddDriver` (`EnableVirtualMonitor=0` por padrão).
- **Testes necessários:** Categorias **1, 2, 3, 4 (obrigatório)** e **7 (local 30 s + estabilidade prolongada 180 s)**.
- **Condições para avançar ao próximo marco (`M1` / `M2`):**
  - Gate real aprovado e documentado *(cumprido)*; integração definitiva em `dev` autorizada para abertura formal da **`M1` (ainda não iniciada)**.

---

### `M1` — Contratos Multiplataforma, Núcleo Compartilhado e Transporte Validado

- **Objetivo:** Provar a fronteira FFI (`ADR-0004`), validar por benchmark comparativo o transporte (`ADR-0005`), implementar os módulos `lumabridge-protocol`, `lumabridge-security`, `lumabridge-transport` e `lumabridge-core` com contratos `display`/`media`/`input`, e estabelecer testes automatizados multiplataforma.
- **Dependências:** Documentação arquitetural `M0` aprovada; definição da licença oficial do projeto. *(Independe de execução administrativa de driver Windows.)*
- **Artefatos produzidos:**
  - PoC documentada Rust ↔ C++ MSVC (`lumabridge-ffi` + carga em binário Windows) promovendo ou ajustando `ADR-0004`;
  - Benchmark comparativo **QUIC vs TCP/TLS 1.3** promovendo ou ajustando `ADR-0005`;
  - Workspace `core/` (`lumabridge-protocol` `LBWP v1`, `lumabridge-security` Fase 1 SPAKE2/QR + Fase 2 mTLS, `lumabridge-transport` QUIC + fallback TCP/TLS + mDNS, `lumabridge-core` máquina de estados + política `gop_id`/`RequestForceIdr`);
  - Interfaces C/C++ nativas para `lumabridge-display`, `lumabridge-media` e `lumabridge-input`;
  - CI rodando testes de protocolo, segurança e transporte sintético em runners Linux e Windows.
- **Critérios objetivos de aceitação:**
  - Todos os 5 critérios da PoC FFI (`ADR-0004`) atendidos (incluindo overhead FFI `p99 < 100 µs` em 1.800 pacotes sintéticos e cross-build Android mínimo);
  - *Round-trip* e *fuzzing* básico de mensagens `LBWP v1`, rejeição de versões inválidas, mensagens fora de canal e pacotes malformados;
  - Fluxo completo de pareamento Fase 1 (PIN SPAKE2 e QR) resistindo a teste simulado de MITM + conexão operacional Fase 2 mTLS rejeitando peers não pareados/revogados;
  - Política de dependência P-frame comprovada em rede simulada com perda (supressão de cauda quebrada + emissão de `RequestForceIdr` sem alimentar frames órfãos);
  - Tráfego sintético 1080p60 validado entre dois hosts/processos via QUIC e fallback TCP/TLS.
- **Testes necessários:** Categorias **1, 2** e **5 (com stream sintético entre processos/máquinas)**.
- **Riscos e estratégias de recuperação:**
  - *Incompatibilidade CRT/NDK ou overhead FFI na PoC:* executar plano de contingência da `ADR-0004` e migrar núcleo para C++20/CMake antes de construir `M2`.
  - *Degradação severa de QUIC ou TCP em redes reais:* ajustar estratégia de streams efêmeros vs datagrams ou NACK seletivo com base nos dados do benchmark.
- **Condições para avançar ao próximo marco (`M2`):**
  - `ADR-0004` e `ADR-0005` promovidas a `Accepted` (ou substituídas por alternativa validada), `wire-protocol-v1.md` promovida de `Draft` para `v1.0` com suíte de testes verde no CI.

---

### `M2` — Primeiro Fluxo Completo: `Windows → Linux` (Extensão Real em LAN)

- **Objetivo:** Entregar a primeira solução utilizável ponta-a-ponta: monitor virtual real no Windows 11 estendido para um receptor nativo Linux (suportando Wayland e X11) em rede local, usando zero-copy GPU + NVENC no emissor e decodificação por hardware (VA-API quando disponível) no receptor.
- **Dependências:** `M0` (gate real `M4.2.1` aprovado e integrado) e `M1` concluído.
- **Artefatos produzidos:**
  - Adaptação mínima de `windows/host/` para consumir o núcleo (`lumabridge-core` via FFI) por trás de `IVideoFrameSource` e `IVideoEncoder` (`NvencH264Encoder`), respondendo a `RequestForceIdr` e ajuste dinâmico de bitrate;
  - **Receptor Linux** com detecção automática Wayland vs X11, decodificação hardware via **VA-API** (+ fallback SW estritamente diagnóstico), apresentação fullscreen baixa latência (`DMA-BUF`/Vulkan/EGL em Wayland e nativo em X11) e overlay opcional `BRIDGE_TERMINAL`;
  - CLI/configuração persistente básica + guias reproduzíveis de execução Windows e Linux.
- **Critérios objetivos de aceitação:**
  - Janela arrastada para o monitor virtual Windows 11 aparece em tempo real no receptor Linux (validado em pelo menos **1 sessão Wayland** e **1 sessão X11**) a `1920×1080 @ 60 FPS`;
  - Telemetria completa ponta-a-ponta (`p50`, `p95`, `p99`, CPU, GPU, RAM, VRAM, drops, jitter) registrada sem pixels privados; hipótese `p95 <= 100 ms` em Ethernet LAN medida e documentada com dados reais;
  - `VA-API` comprovado ativo no hardware Intel/AMD de teste; queda simulada de pacotes recupera limpo via IDR sem artefatos permanentes; desconexão abrupta desmonta/limpa o monitor virtual sem leaks.
- **Testes necessários:** Categorias **1, 2, 3, 4, 5, 6 (apresentação)** e **7 (sessão real prolongada)**.
- **Riscos e estratégias de recuperação:**
  - *Falha de importação `DMA-BUF` entre decodificador e compositor Wayland/X11:* acionar fallback controlado para upload Vulkan/EGL/SHM mantendo medição explícita de custo extra.
  - *Tearing ou frame pacing irregular no compositor alvo:* ajustar apresentação mailbox/VSync por backend Wayland vs X11.
- **Condições para avançar ao próximo marco (`M3`):**
  - Todos os critérios mensuráveis da Seção 3 aprovados em hardware real em `LAN` Ethernet e Wi-Fi.

---

### `M3` — Independência de GPU Windows, Espelhamento Windows e Expansão de Receptores (`Windows` e `Android`)

- **Objetivo:** Eliminar o acoplamento à GPU NVIDIA no emissor Windows, habilitar o modo Espelhamento no Windows e entregar receptores nativos para **Windows** e **Android**, viabilizando `Windows → Windows`, `Windows → Android` (Wi-Fi/LAN e USB compatível) e preparando receptores universais para os próximos emissores.
- **Dependências:** `M2` estável e validado.
- **Artefatos produzidos:**
  - Backends adicionais `IVideoEncoder` no Windows (`Media Foundation HW MFT` genérico, `AMD AMF` e/ou `Intel oneVPL/QSV`) + suporte opcional a `HEVC` negociado;
  - `WindowsMirrorSource` (WGC / DXGI Desktop Duplication) para modo `MIRROR` sem exigir instalação do driver IddCx;
  - **Receptor Windows** (D3D11 + D3D11VA/MFT HW + swapchain fullscreen/janela);
  - **Receptor Android** (Kotlin + Jetpack Compose + `UniFFI` + `MediaCodec` HW + `SurfaceView`, toque/gestos preparados, reconexão configurável, suporte LAN/Wi-Fi + USB Tethering IP + `adb` dev tunnel + relatório de spike sobre AOA);
  - Spike dedicado avaliando viabilidade de suporte do driver IddCx no **Windows 10 (`19041+`)**.
- **Critérios objetivos de aceitação:**
  - `Windows → Windows` (espelhamento e extensão) e `Windows → Android` (Wi-Fi e USB IP) operando em `1080p60` com decodificação HW;
  - Emissor Windows validado com sucesso em pelo menos uma GPU não-NVIDIA (AMD ou Intel iGPU) mantendo o fluxo completo;
  - USB Android testado sem root; instruções claras quando o modo USB exigir habilitação manual (tethering) ou modo dev (ADB).
- **Testes necessários:** Categorias **1, 2, 3, 4, 5, 6** e **7** nas combinações Windows e Android.
- **Riscos e estratégias de recuperação:**
  - *Instabilidade/latência em `AOA` USB sem tethering:* documentar AOA como não pronto para produção e priorizar Wi-Fi direto / USB Tethering IP + guia explícito ao usuário até resolver gargalos USB.
  - *Incompatibilidades de Windows 10 no driver IddCx:* manter Windows 10 como "não suportado para extensão" até passar integralmente por testes em máquina Windows 10 real.
- **Condições para avançar ao próximo marco (`M4`):**
  - Receptores Linux, Windows e Android operacionais, autenticados e estáveis contra o emissor Windows multi-GPU.

---

### `M4` — Linux Emissor (Wayland + X11) e Interação Remota Autorizada

- **Objetivo:** Tornar o Linux um emissor completo respeitando as fronteiras reais de Wayland e X11, e implementar a interação remota bidirecional (mouse, teclado HID, toque, rolagem) estritamente protegida por permissões separadas (`deny-by-default`).
- **Dependências:** `M2` + `M3` (para testar `Linux → Windows`, `Linux → Linux` e `Linux → Android`).
- **Artefatos produzidos:**
  - Adaptadores Linux de Espelhamento (`xdg-desktop-portal` ScreenCast + PipeWire em Wayland; `XShm`+`XDamage`+`XRandR` em X11);
  - Adaptadores específicos por compositor Wayland para Extensão Real na sessão ativa (GNOME/Mutter, KDE/KWin, Sway, Hyprland) com degradação explícita para somente Espelhamento quando não disponível;
  - Encoders Linux (`VA-API`, `NVENC`/`Vulkan Video`, fallback SW diagnóstico);
  - Subsistema `lumabridge-input` completo: injeção no Windows (`SendInput`, documentando UIPI/UAC), no Linux Wayland (`RemoteDesktop` portal + `libei`/EIS / protocolos wlroots) e no Linux X11 (`XTest`), com fluxo de consentimento `PermissionUpgradeRequest`/`PermissionUpdate`.
- **Critérios objetivos de aceitação:**
  - Matriz mínima Linux Emissor validada em execução real: **GNOME/Mutter**, **KDE Plasma/KWin** e **pelo menos 1 ambiente X11** (além de **Hyprland/Sway** conforme adaptador);
  - `Linux → Windows`, `Linux → Linux` e `Linux → Android` funcionais em espelhamento, e em extensão real onde o compositor suportar;
  - Testes negativos comprovando bloqueio total de `InputEvent` enquanto a permissão de entrada não for concedida explicitamente pelo usuário no dispositivo controlado.
- **Testes necessários:** Categorias **1, 2, 3, 4 (saídas virtuais em compositores Linux), 5, 6 (apresentação + interação)** e **7**.
- **Riscos e estratégias de recuperação:**
  - *Quebra de criação de saída virtual entre versões de Hyprland/Mutter/KWin:* isolar falha ao adaptador específico do compositor e manter `MIRROR` funcional como degradação segura sem derrubar a sessão.
- **Condições para avançar ao próximo marco (`M5`):**
  - Fluxo bidirecional completo validado entre Windows ↔ Linux e Linux → Android com separação estrita de permissões verificada.

---

### `M5` — Android Emissor e Investigação de Extensão Android

- **Objetivo:** Permitir que dispositivos Android atuem como emissores de espelhamento para Windows, Linux e outros Androids, e concluir pesquisa controlada sobre extensão real de desktop e entrada remota no Android sem root.
- **Dependências:** `M3` (app Android base e transporte USB/LAN) e `M4` (maturidade de interação remota nos receptores desktop).
- **Artefatos produzidos:**
  - Pipeline emissor Android (`MediaProjection` + `VirtualDisplay` → `MediaCodec` HW, serviço em primeiro plano compatível com Android 14+ e gestão limpa de revogação pelo sistema);
  - Spike técnico fechado avaliando extensão real (Desktop Mode / External Display em APIs públicas Android) e injeção de entrada opt-in (`AccessibilityService`), atualizando a [Matriz de Compatibilidade](../architecture/compatibility-matrix.md).
- **Critérios objetivos de aceitação:**
  - `Android → Windows`, `Android → Linux` e `Android → Android` estáveis em espelhamento 60 FPS (ou taxa nativa do aparelho) respeitando todas as regras de permissão do Android 14+;
  - Relatório técnico conclusivo (go/no-go por versão/API) documentando os limites reais de extensão Android sem prometer capacidades inexistentes.
- **Testes necessários:** Categorias **1, 2, 5, 6** e **7** em aparelhos Android reais (idealmente >= 2 fabricantes/versões).
- **Riscos e estratégias de recuperação:**
  - *OEMs encerrando `ForegroundService` agressivamente ou bloqueando `MediaProjection`:* seguir recomendações oficiais de ciclo de vida Android e notificar o receptor com erro estruturado em revogação pelo SO.
- **Condições para avançar ao próximo marco (`M6`):**
  - Todas as 9 combinações prioritárias entre Windows, Linux (Wayland/X11) e Android validadas dentro dos modos realmente viáveis de cada plataforma.

---

### `M6` — Recursos Avançados, WAN/NAT, UI Completa, Áudio e Novas Plataformas

- **Objetivo:** Expandir escala, conforto operacional e cobertura de plataformas mantendo estabilidade e segurança.
- **Dependências:** `M4` + `M5`.
- **Artefatos produzidos (incrementais e desacoplados):**
  - Suporte a múltiplos monitores virtuais simultâneos (`kMaxMonitorsSupported > 1` no Windows e múltiplas streams no Linux) e múltiplos receptores na mesma sessão;
  - Áudio sincronizado (WASAPI loopback Windows, PipeWire/PulseAudio Linux, `AudioPlaybackCapture` Android, codec Opus);
  - Suporte a caneta digital (`Stylus` com pressão/inclinação) e `AV1` / `HDR` (`P010`) negociados;
  - Reconexão avançada com migração de rede QUIC e suporte WAN opcional (ICE/STUN + relay auto-hospedável sem acesso ao texto em claro);
  - UI Desktop completa (`BRIDGE_TERMINAL` conforme [DESIGN.md](../design/DESIGN.md)), instaladores, assinatura EV/WHQL do driver Windows para distribuição pública e spikes para **macOS** e **iOS/iPadOS**.
- **Critérios objetivos de aceitação:**
  - Cada recurso adicional passa por gate próprio de regressão garantindo zero aumento mensurável de latência p95 no caminho básico 1080p60;
  - Nenhuma dependência obrigatória de serviço em nuvem introduzida para uso LAN/USB.
- **Testes necessários:** Todas as Categorias **1 a 7**, incluindo testes de carga multi-monitor e auditoria de segurança do modo WAN/relay.
- **Riscos e estratégias de recuperação:**
  - *Custo elevado e processo de assinatura EV/WHQL ou complexidade DriverKit macOS:* manter recursos avançados independentes para não bloquear releases de correção e melhorias do núcleo multiplataforma.
- **Condições para avançar para release estável (`main`):**
  - Checklist completo de release candidate auditado com evidências reproduzíveis e revisão humana conforme [ADR-0001](../architecture/ADR-0001-branching-strategy.md).
