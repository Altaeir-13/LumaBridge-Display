# Plano de Migração Conservador — LumaBridge Display

## 1. Inventário Real do Repositório por Estado de Branch

Este plano separa rigorosamente o que já existe na branch base de integração (`origin/dev`) do que existe apenas nas branches de desenvolvimento Windows ainda não integradas. **Nenhum código existente será descartado, reescrito ou alterado nesta etapa.**

### 1.1 Estado integrado em `origin/dev` (`0c3ddab`)

- **Driver virtual Windows (`windows/driver/LumaBridgeIddDriver/`):**
  - `Driver.h/.cpp`, `Adapter.h/.cpp`, `AdapterStateMachine.h`, `VirtualMonitor.h/.cpp`, `MonitorModes.h/.cpp`, `SwapChainProcessor.h/.cpp`, `Trace.h`, `LumaBridgeIddDriver.inf`, `LumaBridgeIddDriver.vcxproj`, `LumaBridgeIddDriver.sln`.
  - Implementa inicialização WDF/UMDF 2.31 + IddCx 1.4, monitor virtual único controlado (`EnableVirtualMonitor=0` por padrão), modos 720p60/1080p60, processamento de swapchain D3D11 e pacote INF/CAT Windows 11 x64.
- **Tooling operacional (`windows/driver/scripts/`):**
  - `LumaBridgeDriverCommon.psm1`, `Test-LumaBridgePrerequisites.ps1`, `Invoke-LumaBridgePackageSigning.ps1`, `Install-LumaBridgeDriver.ps1`, `Set-LumaBridgeVirtualMonitor.ps1`, `Collect-LumaBridgeDiagnostics.ps1`, `Uninstall-LumaBridgeDriver.ps1`.
- **Suítes de teste registradas em `origin/dev` (preservadas sem alteração histórica):**
  - 5 suítes C++ unitárias/pacote (`AdapterLifecycleTests.cpp`, `DriverPackageValidationTests.cpp`, `MonitorModesTests.cpp`, `SwapChainLifecycleTests.cpp`, `VirtualMonitorLifecycleTests.cpp`) + 18 testes PowerShell em `LumaBridgeFunctionalToolingTests.ps1`.
- **Governança e Design:** templates `.github/` e [DESIGN.md](../design/DESIGN.md).

### 1.2 Estado nas branches de desenvolvimento Windows ainda não integradas à `dev`

*(Estes arquivos não residem em `origin/dev`; pertencem exclusivamente à cadeia empilhada abaixo e devem passar por revisão e gate antes do merge.)*

| Branch | Commit Head | Conteúdo Técnico Adicional (Não Integrado em `dev`) | Estado de Validação |
|---|---|---|---|
| `fix/windows-idd-device-start` | `c4be4c5` (PR `#34`) | Correção `IDDCX_TRANSMISSION_TYPE_WIRED_OTHER`, escrita em `WDF_REGKEY_DEVICE_SUBKEY`, breadcrumbs `Diag*`, TraceLogging ETW/WPP, `DiagnosticStageConfig.h` (7 estágios), `Invoke-LumaBridgeEtwTrace.ps1`, `Prepare-IddSampleReference.ps1`, `Build-LumaBridgeDiagnosticStage.ps1`, `docs/diagnostics/windows-idd-start-failure-investigation.md`. | Diagnóstico validado contra controle `IddSampleDriver` e binário `IddCx.dll`; aguardando consolidação em `dev`. |
| `feature/windows-frame-extraction-ipc` | `04937de` (`M4.1` / `M4.1.1`) | `FrameExtractor.*`, `FrameTransport.*`, `FrameIpcProtocol.h` v1.0, `windows/host/` inicial (`FrameConsumer.*`, `main.cpp`, `VirtualDisplayStimulus.h`), `Invoke-LumaBridgeFunctionalValidation.ps1` (perfis Smoke vs Performance), novas suítes `FrameExtractionTests.cpp`, `FrameIpcTests.cpp`, `FrameEndToEndIntegrationTests.cpp`. | Testado na branch em suítes unitárias/E2E e validação local pré-M4.2; aguardando integração em `dev`. |
| `feature/windows-gpu-shared-textures-nvenc` | `a11f758` (`M4.2` / `M4.2.1`, local) | `SharedTexturePool.*`, IPC v1.1 (`GpuSharedNtHandle` + `DuplicateHandle` + `IDXGIKeyedMutex` + validação `AdapterLuid`), `NvencH264Encoder.*` + `third_party/nvenc/nvEncodeAPI.h` (MIT), `H264BitstreamValidator.*`, normalização causal QPC (`c4099cf`), pré-aquecimento D3D11/NVENC/MFT, benchmark sintético 30 s 1080p60 (`5c8d7c9`), `GpuSharedTextureTests.cpp`, `NvencEncoderTests.cpp` (`128` testes C++ e `33` PS na branch). | Evidência real em `WUDFHost.exe` existente apenas da pré-M4.2.1 (`120` quadros com `TimestampMeasurementErrors=120`); **gate real pós-M4.2.1 (`a11f758`) em `WUDFHost.exe` pendente**. |

### 1.3 Dívida documental conhecida e vínculo com merges futuros

Para não falsificar o estado de `origin/dev`, contagens históricas de testes e descrições funcionais em arquivos já presentes em `origin/dev` **não** foram alteradas nesta branch documental. As atualizações listadas abaixo ficam vinculadas aos merges futuros correspondentes:

- `windows/driver/README.md`: descreve estado `M3` em `origin/dev`; deve ser atualizado quando as branches `fix/windows-idd-device-start` → `feature/windows-frame-extraction-ipc` → `feature/windows-gpu-shared-textures-nvenc` forem integradas em `dev`.
- `windows/driver/tests/README.md`: deve manter contagens de testes estritamente sincronizadas com os arquivos de teste presentes em `dev` a cada PR integrado (hoje os totais `128` C++ e `33` PS pertencem exclusivamente à `feature/windows-gpu-shared-textures-nvenc`).
- Documentos legados de planejamento (`docs/planning/IMPLEMENTATION_PLAN.md`, `IMPLEMENTATION_SEQUENCE.md`, `MILESTONES.md`, `MODULE_BREAKDOWN.md`, `BACKLOG.md`, `GITHUB_ISSUES.md`, `NEXT_ACTIONS.md`): preservados como histórico da fase `M0–M3` original; o planejamento vigente passa a ser [UNIVERSAL_ROADMAP.md](./UNIVERSAL_ROADMAP.md) e este documento.

---

## 2. Destino dos Componentes Existentes na Arquitetura Universal

| Componente / Arquivo | Ação Conservadora | Justificativa e Como Evoluir Sem Ruptura |
|---|---|---|
| **Driver `LumaBridgeIddDriver`** (`Driver.*`, `Adapter.*`, `VirtualMonitor.*`, `MonitorModes.*`, `SwapChainProcessor.*`, `FrameExtractor.*`, `SharedTexturePool.*`, `FrameTransport.*`, `Trace.h`) | **Reutilizar integralmente** | Já implementa o modelo oficial IddCx com ciclo de vida determinístico, zero-copy GPU e segurança de pipe/handle. Deve permanecer 100% isolado de rede e SDKs de encoder. Evolução futura apenas para múltiplos monitores (`kMaxMonitorsSupported > 1`) e modos adicionais (1440p60/dinâmicos) em `M6`. |
| **Contrato IPC local `FrameIpcProtocol.h` (`LBIF` v1.0/v1.1)** *(branch M4.2.1)* | **Reutilizar como fronteira interna Windows** | Permanece privado ao enlace local `WUDFHost.exe ↔ backend host Windows`. Nunca é exposto na rede nem substituído pelo `LBWP v1`. |
| **Scripts e testes Windows** (`windows/driver/scripts/`, `windows/driver/tests/`) | **Reutilizar integralmente** | Mantém regressão permanente do driver, empacotamento INF/CAT, segurança Named Pipe, GPU shared textures e NVENC. |
| **`FrameConsumer.*`** *(branch M4.1–M4.2.1)* | **Adaptar (Encapsular)** | Envolver em `WindowsIddVideoSource` implementando o contrato abstrato `VideoSource` (`lumabridge-display`), mantendo intacta a coleta de métricas causais QPC e fallback v1.0. |
| **`NvencH264Encoder.*`** *(branch M4.2–M4.2.1)* | **Adaptar (Extrair Interface)** | Extrair interface abstrata `IVideoEncoder` (`Initialize`, `EncodeD3d11Texture`, `RequestForceIdr`, `ReconfigureBitrate`, `GetCapabilities`) para que `NvencH264Encoder` conviva com futuros `AmfEncoder`, `OneVplQsvEncoder` e `MediaFoundationHwEncoder` (`M3`). |
| **`H264BitstreamValidator.*` e `VirtualDisplayStimulus.h`** *(branch M4.2–M4.2.1)* | **Reutilizar como ferramentas/testes** | Permanecem na suíte de verificação Windows para validação sintética de PSNR e estímulo controlado de alta resolução. |
| **`windows/host/main.cpp`** *(branch M4.1–M4.2.1)* | **Adaptar / Modularizar** | Manter flags atuais de validação local (`--transport`, `--nvenc`, `--json-summary`) intactas para regressão; conectar `EncodedFrameQueue` à fronteira FFI `lumabridge-core` (`M2`) e permitir modo servidor/receptor unificado. |
| **Documentação e governança (`docs/`, `.github/`)** | **Manter + Expandir** | Preservar histórico original com avisos explícitos; adicionar CI em `.github/workflows/` (`M0`/`M1`) e arquivo `LICENSE` após conclusão da revisão de licenças. |
| **`core/` (`protocol`, `security`, `transport`, `core`, `ffi`)** | **Desenvolver do zero (`M1`)** | Novo workspace compartilhado (Rust candidato conforme `ADR-0004`) validado por PoC antes de acoplar ao host Windows. |
| **`platforms/linux/` e `platforms/android/`** | **Desenvolver do zero (`M2–M5`)** | Construção incremental sobre contratos `display`/`media`/`input` + `core/`. |

---

## 3. Estratégia de Consolidação das Branches Empilhadas em `dev`

Os merges das branches acumuladas **não** devem ser feitos automaticamente nem de uma só vez sem revisão. Ordem recomendada após aprovação do gate funcional ao vivo:

1. **Passo A — Fechar gate real da `M4.2.1` na branch `feature/windows-gpu-shared-textures-nvenc`:**
   - Executar com autorização explícita o perfil `Benchmark30s` (30 s 1080p60 GPU+NVENC) e `ProlongedStability` contra o driver real em `WUDFHost.exe`, confirmando rollback limpo e `TimestampMeasurementErrors == 0`.
2. **Passo B — Integrar `fix/windows-idd-device-start` (`c4be4c5`) → `dev`:**
   - Revisar conflitos com `dev` (não esperados, pois é ancestral direto), rodar testes de driver/PS e integrar via PR referenciando `#34`.
3. **Passo C — Integrar `feature/windows-frame-extraction-ipc` (`04937de`) → `dev`:**
   - Rebase/merge limpo sobre o novo `dev`, verificar compilação Debug/Release e suítes M4.1/M4.1.1 antes de aprovar PR.
4. **Passo D — Integrar `feature/windows-gpu-shared-textures-nvenc` (`a11f758`) → `dev`:**
   - Incluir atualização sincronizada de `windows/driver/README.md` e `windows/driver/tests/README.md` (sanando a dívida documental), verificar `128/128` C++ + `33/33` PS + relatório do gate real em `WUDFHost.exe` e integrar via PR.
5. **Passo E — Reconciliar `docs/universal-architecture-redefinition` → `dev`:**
   - Atualizar este documento removendo avisos de "não integrado em `dev`" para os itens já integrados e abrir PR documental.

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
