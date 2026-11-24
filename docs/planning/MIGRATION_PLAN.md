# Plano de Migração Conservador — LumaBridge Display

## 1. Inventário Real do Repositório Integrado em `origin/dev` (`23a28046`)

Este plano separa rigorosamente a base Windows integrada em `origin/dev` (via PR #37 / Merge commit `23a28046`, árvore qualificada `7f1685f7`, preservando a ancestralidade de `6b297856` e `a9ad7e43`) da futura implementação multiplataforma (`M1+`, ainda não iniciada). **Nenhum código existente será descartado, reescrito ou alterado nesta etapa.**

### 1.1 Base original `M3` (ancestral em `0c3ddab`)

- **Driver virtual Windows (`windows/driver/LumaBridgeIddDriver/`):**
  - `Driver.h/.cpp`, `Adapter.h/.cpp`, `AdapterStateMachine.h`, `VirtualMonitor.h/.cpp`, `MonitorModes.h/.cpp`, `SwapChainProcessor.h/.cpp`, `Trace.h`, `LumaBridgeIddDriver.inf`, `LumaBridgeIddDriver.vcxproj`, `LumaBridgeIddDriver.sln`.
  - Implementa inicialização WDF/UMDF 2.31 + IddCx 1.4, monitor virtual único controlado (`EnableVirtualMonitor=0` por padrão), modos 720p60/1080p60, processamento de swapchain D3D11 e pacote INF/CAT Windows 11 x64.
- **Tooling operacional (`windows/driver/scripts/`):**
  - `LumaBridgeDriverCommon.psm1`, `Test-LumaBridgePrerequisites.ps1`, `Invoke-LumaBridgePackageSigning.ps1`, `Install-LumaBridgeDriver.ps1`, `Set-LumaBridgeVirtualMonitor.ps1`, `Collect-LumaBridgeDiagnostics.ps1`, `Uninstall-LumaBridgeDriver.ps1`.
- **Suítes de teste registradas até `0c3ddab` (preservadas sem alteração histórica):**
  - 5 suítes C++ unitárias/pacote (`AdapterLifecycleTests.cpp`, `DriverPackageValidationTests.cpp`, `MonitorModesTests.cpp`, `SwapChainLifecycleTests.cpp`, `VirtualMonitorLifecycleTests.cpp`) + 18 testes PowerShell em `LumaBridgeFunctionalToolingTests.ps1`.
- **Governança e Design:** templates `.github/` e [DESIGN.md](../design/DESIGN.md).

### 1.2 Pilha Windows `M4.1–M0.5.3` integrada em `origin/dev` (`23a28046`)

*(Todos os avanços abaixo **já residem em `origin/dev` (`23a28046`)** via Merge commit do PR #37; a `M0` permanece formalmente aberta até o cumprimento integral dos critérios objetivos de encerramento vinculados ao PR de governança `#38`, precedendo a abertura da `M1`.)*

| Branch | Commit Head | Conteúdo Técnico Integrado em `origin/dev` (`23a28046`) | Estado de Validação |
|---|---|---|---|
| `fix/windows-idd-device-start` | `c4be4c5` (PR `#35` / issue `#34`) | Correção `IDDCX_TRANSMISSION_TYPE_WIRED_OTHER`, escrita em `WDF_REGKEY_DEVICE_SUBKEY`, breadcrumbs `Diag*`, TraceLogging ETW/WPP, `DiagnosticStageConfig.h` (7 estágios), `Invoke-LumaBridgeEtwTrace.ps1`, `Prepare-IddSampleReference.ps1`, `Build-LumaBridgeDiagnosticStage.ps1`, `docs/diagnostics/windows-idd-start-failure-investigation.md`. | PR `#35` integrado (`MERGED`); incorporado à pilha funcional. |
| `feature/windows-frame-extraction-ipc` | `04937de` (`M4.1` / `M4.1.1`, PR `#36`) | `FrameExtractor.*`, `FrameTransport.*`, `FrameIpcProtocol.h` v1.0, `windows/host/` inicial (`FrameConsumer.*`, `main.cpp`, `VirtualDisplayStimulus.h`), `Invoke-LumaBridgeFunctionalValidation.ps1` (perfis Smoke vs Performance), novas suítes `FrameExtractionTests.cpp`, `FrameIpcTests.cpp`, `FrameEndToEndIntegrationTests.cpp`. | Todos os 9 commits alcançáveis em `origin/dev` via PR `#37` (`23a28046`). |
| `feature/windows-gpu-shared-textures-nvenc` | `a11f758` (`M4.2` / `M4.2.1`) | `SharedTexturePool.*`, IPC v1.1 (`GpuSharedNtHandle` + `DuplicateHandle` + `IDXGIKeyedMutex` + validação `AdapterLuid`), `NvencH264Encoder.*` + `third_party/nvenc/nvEncodeAPI.h` (MIT), `H264BitstreamValidator.*`, normalização causal QPC (`c4099cf`), pré-aquecimento D3D11/NVENC/MFT, benchmark sintético 30 s 1080p60 (`5c8d7c9`), `GpuSharedTextureTests.cpp`, `NvencEncoderTests.cpp`. | Ancestral direto de `fix/m0-validation-gates-hardening`, integrado em `origin/dev`. |
| `fix/m0-validation-gates-hardening` | `6b297856` *(funcional)* / `f1d2565e` *(documental `M0.3`)* | `AsyncH264ValidationWorker.h`, `HostGateEvaluator.h`, estímulo `D3d11DxgiVSync` explícito sem fallback silencioso, domínio único de sequência em `FrameIpcServer`, telemetria ETW `SessionSummary`, `PacingCorrelation`, metodologia `ExactPopulation`/`AlgorithmR`, reutilização segura de staging (`-SkipDriverInstall -ReuseSignedStaging`), `HostValidationWorkerAndStimulusTests.cpp` (`157` casos C++ unit/component efetivamente inventariados contra `156` histórico anterior, `9` E2E, `71` PowerShell, `InfVerif`). | **Gate funcional real `M0` aprovado em `WUDFHost.exe`:** `Benchmark30s` (`1.800/1.800`, `30,011 s`, `HostLiveE2E p99 = 257 us`) e `ProlongedStability` (`10.670/10.584`, `180,005 s` conectados, `HostLiveE2E p99 = 239 us`, `SystemStateRestored = True`). |
| `integration/m0-windows-closure` | `a9ad7e43` (PR `#37` → `23a28046`) | Merge `--no-ff` preservando ancestralidade de `fix/m0-validation-gates-hardening` (`6b297856` + `f1d2565e`) e `docs/universal-architecture-redefinition` (`69306e77`), reconciliação documental `M0.4`/`M0.4.1` e sanitização de privacidade `M0.5.3`. | **Integrada em `origin/dev` via PR `#37` (`23a28046`)**; `M0.4.1`: `2/2` E2E `9/9` (preservando 2 reprovações `p99` históricas em `M0.4`). |

### 1.3 Rastreabilidade documental e governança `M0.6`

- `windows/driver/README.md` e `windows/driver/tests/README.md`: contagens reais (**157** casos C++ unitários/componentes efetivamente inventariados — frente ao total histórico `156` por `NvencEncoderTests.cpp` conter `8` casos —, **9** E2E e **71** PowerShell) integradas em `origin/dev` (`23a28046`), complementadas pela matriz de dependências CI em [`ci-and-test-matrix.md`](../setup/ci-and-test-matrix.md).
- Documentos legados de planejamento (`docs/planning/IMPLEMENTATION_PLAN.md`, `IMPLEMENTATION_SEQUENCE.md`, `MILESTONES.md`, `MODULE_BREAKDOWN.md`, `BACKLOG.md`, `GITHUB_ISSUES.md`, `NEXT_ACTIONS.md`): preservados como histórico da fase `M0–M3` original; o planejamento vigente passa a ser [UNIVERSAL_ROADMAP.md](./UNIVERSAL_ROADMAP.md) e este documento.

---

## 2. Destino dos Componentes Existentes na Arquitetura Universal

| Componente / Arquivo | Ação Conservadora | Justificativa e Como Evoluir Sem Ruptura |
|---|---|---|
| **Driver `LumaBridgeIddDriver`** (`Driver.*`, `Adapter.*`, `VirtualMonitor.*`, `MonitorModes.*`, `SwapChainProcessor.*`, `FrameExtractor.*`, `SharedTexturePool.*`, `FrameTransport.*`, `Trace.h`) | **Reutilizar integralmente** | Já implementa o modelo oficial IddCx com ciclo de vida determinístico, transporte GPU compartilhado sem readback CPU (cópia GPU-para-GPU para o pool compartilhado `IDXGIKeyedMutex` + NT handle) e segurança de pipe/handle. Deve permanecer 100% isolado de rede e SDKs de encoder. Evolução futura apenas para múltiplos monitores (`kMaxMonitorsSupported > 1`) e modos adicionais (1440p60/dinâmicos) em `M6`. |
| **Contrato IPC local `FrameIpcProtocol.h` (`LBIF` v1.0/v1.1)** *(validado em `M0`)* | **Reutilizar como fronteira interna Windows** | Permanece privado ao enlace local `WUDFHost.exe ↔ backend host Windows`. Nunca é exposto na rede nem substituído pelo `LBWP v1`. |
| **Scripts e testes Windows** (`windows/driver/scripts/`, `windows/driver/tests/`) | **Reutilizar integralmente** | Mantém regressão permanente do driver, empacotamento INF/CAT, segurança Named Pipe, GPU shared textures e NVENC. |
| **`FrameConsumer.*`** *(validado em `M0`)* | **Adaptar (Encapsular)** | Envolver em `WindowsIddVideoSource` implementando o contrato abstrato `VideoSource` (`lumabridge-display`), mantendo intacta a coleta de métricas causais QPC e fallback v1.0. |
| **`NvencH264Encoder.*`** *(validado em `M0`)* | **Adaptar (Extrair Interface)** | Extrair interface abstrata `IVideoEncoder` (`Initialize`, `EncodeD3d11Texture`, `RequestForceIdr`, `ReconfigureBitrate`, `GetCapabilities`) para que `NvencH264Encoder` conviva com futuros `AmfEncoder`, `OneVplQsvEncoder` e `MediaFoundationHwEncoder` (`M3`). |
| **`H264BitstreamValidator.*` e `VirtualDisplayStimulus.h`** *(validados em `M0`)* | **Reutilizar como ferramentas/testes** | Permanecem na suíte de verificação Windows para validação sintética de PSNR e estímulo controlado de alta resolução. |
| **`windows/host/main.cpp`** *(validado em `M0`)* | **Adaptar / Modularizar** | Manter flags atuais de validação local (`--transport`, `--nvenc`, `--json-summary`) intactas para regressão; conectar `EncodedFrameQueue` à fronteira FFI `lumabridge-core` (`M2`) e permitir modo servidor/receptor unificado. |
| **Documentação e governança (`docs/`, `.github/`, raiz)** | **Manter + Expandir (`M0.6`)** | Preservar histórico original com avisos explícitos; adicionar [`LICENSE`](../../LICENSE) (`Apache-2.0`), [`NOTICE`](../../NOTICE), [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md), [`CONTRIBUTING.md`](../../CONTRIBUTING.md) (`DCO 1.1`) e CI inicial em `.github/workflows/` (`M0.6`), expandindo para `cargo-deny` e multiplataforma na `M1`. |
| **`core/` (`protocol`, `security`, `transport`, `core`, `ffi`)** | **Desenvolver do zero (`M1`)** | Novo workspace compartilhado (Rust candidato conforme `ADR-0004`, **`M1` ainda não iniciada**) validado por PoC antes de acoplar ao host Windows. |
| **`platforms/linux/` e `platforms/android/`** | **Desenvolver do zero (`M2–M5`)** | Construção incremental sobre contratos `display`/`media`/`input` + `core/`. |

---

## 3. Estratégia de Consolidação em `dev` e Encerramento Formal da `M0`

Os passos de validação funcional e integração da pilha Windows em `dev` já foram cumpridos; resta a revisão e merge do PR de governança `M0.6` para o encerramento formal da `M0`:

1. **Concluído (`M0.2.4`–`M0.3`) — Gate funcional real aprovado em `6b297856`:**
   - Execuções reais `Benchmark30s` (`30,011 s`, `1.800/1.800` quadros) e `ProlongedStability` (`180,005 s` conectados, `10.670/10.584` quadros mínimos) aprovadas em `WUDFHost.exe` com `D3d11DxgiVSync`, transporte GPU puro (`0` readbacks CPU) e `TimestampMeasurementErrors == 0`.
2. **Concluído e integrado em `origin/dev` (`M0.4`–`M0.5.3`) — PR `#37` (`23a28046`):**
   - Consolidou via merge commits (`--no-ff`, sem squash nem rebase) `fix/m0-validation-gates-hardening` (contendo integralmente `fix/windows-idd-device-start`, `feature/windows-frame-extraction-ipc`, `feature/windows-gpu-shared-textures-nvenc`, `6b297856` e `f1d2565e`) e `docs/universal-architecture-redefinition`, com `157/157` C++, `71/71` PowerShell, `InfVerif` e `2/2` execuções controladas `9/9` E2E aprovadas na `M0.4.1` (preservando no histórico duas reprovações `p99` iniciais da `M0.4`: `30.424 us` e `33.354 us`), e foi integrado em `origin/dev` via **Merge commit `23a28046`** (árvore `7f1685f7`, `M0_INTEGRATED_IN_DEV = True`).
3. **Governança, licenciamento e critério de encerramento formal da `M0` (`M0.6` — PR `#38` → `dev`):**
   - Publica [`LICENSE`](../../LICENSE) (`Apache-2.0` para código próprio, preservadas licenças de terceiros), [`NOTICE`](../../NOTICE), [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md) (`nvEncodeAPI.h` MIT), [`CONTRIBUTING.md`](../../CONTRIBUTING.md) (`DCO 1.1` prospectivo declarativo), [`ci-and-test-matrix.md`](../setup/ci-and-test-matrix.md) e os workflows iniciais `.github/workflows/ci-windows.yml` e `.github/workflows/ci-linux-hygiene.yml`. A `M0` permanece formalmente aberta até o merge do PR `#38` em `dev`, aprovação dos checks pós-merge em `dev`, reconciliação registrada de `PR #36` / `Issue #33` / `Issue #34` e verificação da proteção de `refs/heads/dev`.

---

## 4. Evolução Não-Destrutiva da Estrutura de Diretórios

Para evitar quebra imediata de `.sln`, `.vcxproj`, scripts PowerShell e comandos de build existentes durante `M0–M2`:

- **Manter nos locais atuais durante `M0–M2`:**
  - `windows/driver/` *(Solução WDK e scripts intactos)*
  - `windows/host/` *(Adicionar apenas `CMakeLists.txt` opcional coexistindo com `cl.exe`)*
- **Adicionar novos diretórios raiz limpos em `M1–M5`:**
  - `core/` *(Workspace Rust candidato: `lumabridge-protocol`, `lumabridge-security`, `lumabridge-transport`, `lumabridge-core`, `lumabridge-ffi`)*
  - `platforms/linux/` *(Receptor Wayland/X11 e futuro emissor adaptativo)*
  - `platforms/android/` *(Projeto Gradle/Kotlin + JNI/UniFFI)*
  - `apps/` *(CLI/daemon unificado e futura GUI desktop `BRIDGE_TERMINAL`)*
- **Reorganização cosmética opcional (somente pós-`M2` com CI completo verde):** avaliar mover `windows/` para `platforms/windows/` apenas quando todas as automações, `.vcxproj` e scripts PowerShell puderem ser validados em CI sem risco de regressão.
