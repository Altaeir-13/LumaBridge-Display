# Matriz de Compatibilidade Oficial — LumaBridge Display

## 1. Critérios de Classificação e Rastreabilidade

Esta matriz adota rigorosamente **quatro estados mutuamente exclusivos**. A simples existência de uma API no sistema operacional **nunca** é classificada como recurso suportado:

| Estado Oficial | Significado Técnico |
|---|---|
| **Implementado e validado** | Código presente e comportamento comprovado por execução real no ambiente/hardware-alvo (não apenas testes sintéticos). |
| **Implementado, dependente de validação funcional** | Código presente e aprovado em testes unitários/sintéticos, porém ainda pendente de validação real no runtime completo do SO/driver/dispositivo ou presente apenas em branch de desenvolvimento especificada. |
| **Tecnicamente viável, não implementado** | Existem APIs públicas documentadas e estáveis que permitem implementar o recurso sem root nem modificações não oficiais, mas ainda não há código no repositório. |
| **Condicional, investigativo ou indisponível pelas APIs públicas** | Depende de versão específica do SO/compositor/driver/OEM, exige spike para comprovar viabilidade na sessão ativa, ou é bloqueado pelo modelo de permissões/sandbox sem root. |

> **Rastreabilidade de branches (`M0.4`):** Na branch remota `origin/dev` (`0c3ddab`), permanece integrada apenas a base do driver Windows até `M3` (`EnableVirtualMonitor=0` por padrão) — ou seja, **`M0` ainda não foi integrada em `dev` remoto** e **`M1` ainda não foi iniciada**. A pilha funcional `M4.1–M0.3` (`fix/windows-idd-device-start` → `feature/windows-frame-extraction-ipc` → `feature/windows-gpu-shared-textures-nvenc` → `fix/m0-validation-gates-hardening`, commit funcional validado `6b297856`) concluiu as validações reais ao vivo em `WUDFHost.exe` (`Benchmark30s` 30 s e `ProlongedStability` 180 s aprovados em ambiente de desenvolvimento com `TestSigning` habilitado e `Secure Boot` desabilitado) e encontra-se **consolidada localmente** na branch `integration/m0-windows-closure`.

---

## 2. Matriz Geral por Plataforma e Modo Funcional

| Plataforma / Ambiente | Receptor (Exibir Vídeo) | Emissor — Espelhamento | Emissor — Extensão Real na Sessão Ativa | Interação Remota (Injeção de Input) | Múltiplas Telas / Sessões |
|---|---|---|---|---|---|
| **Windows 11 x64 (`22000+`)** | **Tecnicamente viável, não implementado** *(D3D11/DXGI + MFT/D3D11VA/NVDEC)* | **Tecnicamente viável, não implementado** *(WGC / DXGI Desktop Duplication)* | **Implementado e validado** *(emissor local `WUDFHost.exe` aprovado em `30 s` e `180 s` no commit `6b297856` e consolidado em `integration/m0-windows-closure`, sob `TestSigning` habilitado / `Secure Boot` desabilitado em ambiente de desenvolvimento; ainda não integrado em `origin/dev`, e transmissão de rede `M1`/`M2` e assinatura EV/WHQL de produção pendentes)* | **Tecnicamente viável, não implementado** *(`SendInput`; sujeito a UIPI/UAC)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(hoje fixo em `kMaxMonitorsSupported = 1`; protocolo prevê múltiplos `display_id`)* |
| **Windows 10 x64 (`19041+`)** | **Tecnicamente viável, não implementado** *(D3D11/DXGI + MFT/D3D11VA)* | **Tecnicamente viável, não implementado** *(WGC Win10 1903+ / DXGI Desktop Duplication)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *([LumaBridgeIddDriver.inf](../../windows/driver/LumaBridgeIddDriver/LumaBridgeIddDriver.inf) hoje restringe a `NT$ARCH$.10.0...22000`; exige adaptação de INF/catálogo e validação em Win10 real)* | **Tecnicamente viável, não implementado** *(`SendInput`; sujeito a UIPI/UAC)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(mesma restrição de Win10 + limite atual de 1 monitor)* |
| **Linux Wayland — GNOME / Mutter** | **Tecnicamente viável, não implementado** *(Wayland nativo + DMA-BUF/EGL/Vulkan + VA-API/NVDEC)* | **Tecnicamente viável, não implementado** *(`xdg-desktop-portal` ScreenCast + PipeWire)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(viável em versões recentes via `ScreenCast` `VIRTUAL` / `org.gnome.Mutter.ScreenCast` `RecordVirtual`, depende de versão do Mutter/portal e validação de sessão)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(`RemoteDesktop` portal + `libei`/EIS em GNOME 45+; versões antigas restritas)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(depende de múltiplas streams PipeWire/saídas virtuais no Mutter)* |
| **Linux Wayland — KDE Plasma / KWin** | **Tecnicamente viável, não implementado** *(mesmo receptor Wayland nativo)* | **Tecnicamente viável, não implementado** *(`xdg-desktop-portal-kde` + PipeWire)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(saída virtual via portal KDE / KWin em Plasma 5.27+/6.x, sujeito a validação em runtime)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(`RemoteDesktop` portal + `libei`/EIS em Plasma 6.1+)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(depende de suporte do KWin/portal)* |
| **Linux Wayland — Sway (wlroots)** | **Tecnicamente viável, não implementado** *(mesmo receptor Wayland nativo)* | **Tecnicamente viável, não implementado** *(`xdg-desktop-portal-wlr` + PipeWire)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(via adaptador IPC `swaymsg create_output` na sessão ativa + captura; não garantido via portal genérico)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(`wlr-virtual-pointer`/`virtual-keyboard` ou `RemoteDesktop`/EIS dependendo da versão)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(depende de múltiplas saídas headless no compositor)* |
| **Linux Wayland — Hyprland** | **Tecnicamente viável, não implementado** *(mesmo receptor Wayland nativo)* | **Tecnicamente viável, não implementado** *(`xdg-desktop-portal-hyprland` + PipeWire)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(via adaptador IPC `hyprctl output create headless` / portal Hyprland; instabilidade entre versões exige validação contínua)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(protocolos virtuais wlroots/Hyprland ou `RemoteDesktop` portal conforme versão)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(depende de saídas headless no Hyprland)* |
| **Linux Wayland — Outros wlroots / Genérico** | **Tecnicamente viável, não implementado** *(Wayland core + xdg-shell + dmabuf/shm)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(depende de `xdg-desktop-portal-wlr` ou equivalente configurado)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(não há protocolo Wayland universal para criar saídas virtuais; degrada para Espelhamento se ausente)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(depende de compositor expor portal RemoteDesktop/EIS ou protocolos virtuais)* | **Condicional, investigativo ou indisponível pelas APIs públicas** |
| **Linux — X11 / X.Org** | **Tecnicamente viável, não implementado** *(X11 nativo Vulkan/EGL/GLX)* | **Tecnicamente viável, não implementado** *(`XShm` + `XDamage` + `XFixes` + `XRandR`)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(exige saída virtual no driver de vídeo ou módulo kernel `VKMS`; **`Xvfb`/`Xdummy` isolado NÃO estende a sessão ativa**)* | **Tecnicamente viável, não implementado** *(`XTest` na sessão X11 ativa)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(múltiplos displays dependem de saídas XRandR disponíveis)* |
| **Android (10+ / API 29+)** | **Tecnicamente viável, não implementado** *(Kotlin/NDK + `MediaCodec` HW + `SurfaceView`)* | **Tecnicamente viável, não implementado** *(`MediaProjection` + `VirtualDisplay` → `MediaCodec` HW; regras extras no Android 14+)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(sem root não há garantia universal de área estendida independente; `MediaProjection.createVirtualDisplay()` não prova extensão real)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(`AccessibilityService` `dispatchGesture` com ativação manual para toque/gestos; teclado completo limitado)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(receptor pode exibir múltiplas janelas/fluxos; emissor restrito)* |
| **macOS *(Expansão Futura)*** | **Tecnicamente viável, não implementado** *(VideoToolbox + Metal)* | **Tecnicamente viável, não implementado** *(`ScreenCaptureKit`, macOS 12.3+)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(`CGVirtualDisplay` semi-privada vs DriverKit complexo)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(`CGEventPost` requer permissão de Acessibilidade)* | **Condicional, investigativo ou indisponível pelas APIs públicas** |
| **iOS / iPadOS *(Expansão Futura)*** | **Tecnicamente viável, não implementado** *(VideoToolbox + Metal + Touch/Pencil)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(`ReplayKit` Broadcast Extension limitado a ~50 MB de RAM)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(indisponível via APIs públicas pelo sandbox do iOS)* | **Condicional, investigativo ou indisponível pelas APIs públicas** *(injeção de entrada global indisponível pelo sandbox iOS)* | **Condicional, investigativo ou indisponível pelas APIs públicas** |

---

## 3. Detalhamento Crítico por Plataforma

### 3.1 Windows 10 e Windows 11

- **Extensão Real (`LumaBridgeIddDriver`):**
  - Arquitetura UMDF 2.31 (`UMDF_MINIMUM_VERSION_REQUIRED=25`) / IddCx 1.4 (`IDDCX_MINIMUM_VERSION_REQUIRED=4`) atualmente configurada exclusivamente para **Windows 11 x64 (`NT$ARCH$.10.0...22000`, `10_CO_X64;10_NI_X64;10_GE_X64`)** em [LumaBridgeIddDriver.inf](../../windows/driver/LumaBridgeIddDriver/LumaBridgeIddDriver.inf).
  - Não declarar Windows 10 compatível para extensão virtual até realizar spike dedicado ajustando o INF/catálogo (`19041+`), verificando versões de `WUDFx02000.dll` / `IddCx.dll` no Windows 10 e executando bateria funcional completa em máquina Windows 10 real.
  - Em produção pública, Secure Boot + HVCI exigirão assinatura EV/WHQL (em desenvolvimento utiliza-se *Test Signing* controlado em staging isolado).
- **Espelhamento:** Windows Graphics Capture (`Windows.Graphics.Capture`) como API primária (respeita indicador visual de captura do Windows e funciona bem com múltiplos adaptadores) + fallback DXGI Desktop Duplication (`IDXGIOutputDuplication`).
- **Interação Remota:** `SendInput` injeta entrada na sessão interativa atual, mas não interage com janelas elevadas (UAC/Admin) devido ao UIPI (*User Interface Privilege Isolation*) a menos que o processo possua privilégio `uiAccess=true` assinado e instalado em diretório protegido — restrição a documentar claramente ao usuário.

### 3.2 Linux Wayland (Camada de Adaptadores por Compositor)

Em Wayland, **a presença de `xdg-desktop-portal` e PipeWire NÃO garante criação de monitor virtual estendido**; garante apenas transporte de buffers de vídeo após consentimento do usuário quando o backend do portal/compositor suporta o tipo de fonte solicitado. A seleção de extensão real requer adaptadores explícitos:

1. **GNOME / Mutter:**
   - *Espelhamento:* `org.freedesktop.portal.ScreenCast` com `types = MONITOR` ou `WINDOW` + `restore_token` (reduz prompts repetidos).
   - *Extensão Real:* `ScreenCast` `types = VIRTUAL` (quando exposto pelo `xdg-desktop-portal-gnome` / Mutter modernos, GNOME 42+/45+) ou `org.gnome.Mutter.ScreenCast.CreateSession` + `RecordVirtual` (API D-Bus específica do GNOME, sujeita a permissões de sessão). Exige validação explícita de versão e comportamento de layout/escala na sessão ativa.
   - *Input:* `org.freedesktop.portal.RemoteDesktop` acoplado a `libei` / EIS (GNOME 45+).
2. **KDE Plasma / KWin:**
   - *Espelhamento:* `xdg-desktop-portal-kde` `ScreenCast` + PipeWire.
   - *Extensão Real:* criação de saída virtual integrada ao portal KDE (`VIRTUAL` no Plasma 5.27+/6.x) ou interfaces KWin adequadas. Requer verificação prática de persistência de geometria e gerenciamento de cursores.
   - *Input:* `RemoteDesktop` portal + suporte EIS em versões recentes do Plasma (6.1+).
3. **Sway (`wlroots`):**
   - *Espelhamento:* `xdg-desktop-portal-wlr` + PipeWire (ou `wlr-screencopy` em contextos permitidos).
   - *Extensão Real:* `xdg-desktop-portal-wlr` foca captura de saídas existentes; a criação de monitor virtual na sessão ativa requer adaptador específico usando `swaymsg create_output` (adicionando uma saída headless `HEADLESS-N` configurável via `swaymsg output`) combinada com captura PipeWire/`wlr-screencopy` daquela saída específica.
4. **Hyprland:**
   - *Espelhamento:* `xdg-desktop-portal-hyprland` + PipeWire.
   - *Extensão Real:* adaptador específico utilizando `hyprctl output create headless` (associando resolução/taxa/posição via `hyprctl keyword monitor`) e capturando especificamente o monitor criado via portal/PipeWire. Requer validação contínua contra regressões de IPC/portal entre releases do Hyprland.
5. **Outros compositores Wayland / wlroots:**
   - Compositores que não expuserem nem `ScreenCast VIRTUAL` nem API segura de criação de saída headless anunciam `can_extend_session = false` e oferecem exclusivamente **Espelhamento** (ou apenas **Receptor** se não houver portal de captura).

### 3.3 Linux X11 / X.Org

- **Receptor Nativo X11:** usa cliente X11 (`xcb`/`Xlib`) com Vulkan ou EGL/GLX e `_NET_WM_STATE_FULLSCREEN` + `VA-API`/`NVDEC` (sem depender de servidor Wayland).
- **Espelhamento na Sessão Ativa:** `XRandR` para enumerar monitores/geometrias + `XShmGetImage` + `XDamage` (captura incremental de regiões modificadas) + `XFixes` (cursor). Funciona na maioria das sessões X.Org sem privilégio root.
- **Extensão Real na Sessão Ativa (Condicional / Limitada):**
  - Diferentemente do IddCx no Windows, o X.Org **não** oferece uma API padrão de usuário para criar um novo monitor físico/virtual plug-and-play em qualquer driver GPU.
  - Drivers livres (Intel/AMD Mesa `modesetting`) às vezes expõem conectores extras ou dependem de configuração estática prévia (`VirtualHeads`), enquanto drivers proprietários **NVIDIA** frequentemente não permitem ativar saídas virtuais dinâmicas em runtime sem alterar `xorg.conf` e reiniciar o servidor X.
  - **VKMS (Virtual KMS do kernel Linux):** permite criar conectores virtuais DRM/KMS via `configfs`, porém exige privilégio administrativo/módulo de kernel carregado, configuração de compartilhamento DRM/prime com a GPU principal e disponibilidade variável entre distribuições — permanecendo estritamente **Condicional / Investigativo**.
  - **Proibição de falso positivo:** iniciar `Xvfb` ou `Xdummy` cria uma **sessão X isolada** (outro `DISPLAY`), incapaz de receber janelas arrastadas da sessão gráfica atual do usuário. A arquitetura e a UI nunca devem apresentar `Xvfb`/`Xdummy` como extensão real da sessão ativa.

### 3.4 Android

- **Receptor (`Tecnicamente viável, não implementado`):** via `MediaCodec` (Surface output direto em `SurfaceView`) e entrada autorizada. Funcional em Android 10+ (API 29+) sem root e sem permissões especiais intrusivas.
- **Emissor — Espelhamento (`Tecnicamente viável, não implementado`):**
  - Utiliza `MediaProjectionManager` + `MediaProjection.createVirtualDisplay(...)` direcionado ao `Surface` de um `MediaCodec` encoder.
  - **Restrições Android 14+ (API 34+):** exige declaração de `foregroundServiceType="mediaProjection"`, consentimento explícito por sessão (sem reaproveitamento indefinido de `Intent` de projeção) e notificação persistente visível.
- **Emissor — Extensão Real (`Condicional, investigativo ou indisponível pelas APIs públicas`):**
  - **`MediaProjection.createVirtualDisplay()` NÃO cria um monitor estendido independente da área de trabalho do sistema**; seu uso padrão em APIs públicas espelha o display principal (ou uma única tarefa/app em contextos limitados).
  - Recursos de *Desktop Mode* / *External Display* em Android 14–16 e em interfaces proprietárias de fabricantes (ex.: modos desktop OEM) variam drasticamente por fabricante e frequentemente restringem criação de displays secundários estendidos virtuais com janelas livres a permissões `SIGNATURE`/`PRIVILEGED` indisponíveis para apps open source comuns. Portanto, extensão real de Android permanece **investigativa** em `M5`, nunca prometida como capacidade garantida.
- **Interação Remota no Android (quando Android é Emissor):**
  - Android não permite injeção global livre de toque/teclado por apps comuns sem privilégio `INJECT_EVENTS` (assinado pelo sistema/root). A única via pública sem root é implementar um `AccessibilityService` opt-in com consentimento explícito do usuário (`dispatchGesture`), com limitações para atalhos globais de sistema e campos protegidos.

---

## 4. Conectividade e Transportes USB (Computador ↔ Android)

A arquitetura **não** presume que portas USB-C forneçam entrada de vídeo física (DisplayPort Alt-Mode). O USB opera como canal de dados sujeito às restrições do Android sem root:

| Modo USB | Estado na Matriz | Requisitos e Limitações de Usuário Final | Protocolo LumaBridge Aplicado |
|---|---|---|---|
| **USB Tethering (`RNDIS` / `CDC-NCM`)** | **Tecnicamente viável, não implementado** | **Sem root e sem Depuração USB.** Cria enlace IP real ponto-a-ponto entre PC e Android, mas **exige que o usuário ative manualmente "Ancoragem USB / USB Tethering"** nas configurações do Android após conectar o cabo (algumas operadoras/OEMs ocultam ou bloqueiam tethering). | **QUIC / TLS 1.3** (ou TCP/TLS) + mTLS completo. |
| **Android Open Accessory (`AOA v1/v2`)** | **Condicional, investigativo ou indisponível pelas APIs públicas** | **Sem root e sem Depuração USB.** Usa `UsbManager` público no Android e `WinUSB`/`libusb` no desktop. Exige prompt de permissão USB no Android, instalação/associação de driver WinUSB no Windows (via Microsoft OS 2.0 Descriptors) e encapsulamento de pacotes sobre *USB bulk transfers*; precisa de spike para confirmar throughput e latência estáveis em 1080p60 e comportamento durante carregamento/desconexão. | Framing TLS 1.3 sobre canal stream construído sobre endpoints bulk AOA. |
| **ADB Tunnel (`adb reverse` / `adb forward`)** | **Tecnicamente viável, não implementado *(Uso Restrito a Dev/Diagnóstico)*** | Exige habilitar **Opções de Desenvolvedor** e **Depuração USB** no aparelho + aceitar chave RSA. **Inaceitável como experiência principal para usuários finais**; mantido como canal oficial de desenvolvimento, laboratório e diagnóstico automatizado. | **TCP / TLS 1.3** (mTLS obrigatório preservado dentro do túnel ADB). |
| **Adaptador USB-C Ethernet / IP Direto** | **Tecnicamente viável, não implementado** | Enlace Ethernet padrão via adaptador USB-C ↔ RJ45 no tablet/celular ou PC. Sem configuração especial além de rede local. | **QUIC / TLS 1.3**. |
| **USB-C Video Input (DP Alt-Mode / UVC)** | **Condicional, investigativo ou indisponível pelas APIs públicas** | Dispositivos Android em geral não possuem hardware receptor HDMI/DP Alt-Mode nativo (a menos que conectados a placa de captura UVC externa, fora da premissa de software puro). | Não aplicável ao transporte de software LumaBridge. |

---

## 5. Matriz de Hardware, Codecs e Aceleração (Independência de Fabricante)

Nenhum fabricante ou API proprietária é obrigatório; cada sessão negocia o melhor pipeline disponível para `(Emissor, Receptor)`:

| Plataforma / Vendor | Encode H.264 | Encode HEVC | Encode AV1 | Decode H.264 / HEVC / AV1 | Estado e Observações |
|---|---|---|---|---|---|
| **Windows — NVIDIA (`NVENC`/`NVDEC`)** | Sim (`nvEncodeAPI64.dll`) | Sim (Maxwell GM20x+ / Turing+) | Condicional (Ada RTX 40+) | Sim (NVDEC / D3D11VA MFT) | **H.264 implementado em branch dev M4.2/M4.2.1** (validado em RTX 3060 Ti em testes `NvencEncoderTests`, pendente gate ao vivo M4.2.1); HEVC/AV1/NVDEC planejados. |
| **Windows — AMD (`AMF` / `D3D11VA`)** | Tecnicamente viável | Tecnicamente viável | Condicional (RDNA 3+) | Tecnicamente viável | **Não implementado** (`M3`); headers AMF MIT + carregamento dinâmico `amfrt64.dll`. |
| **Windows — Intel (`oneVPL`/`QSV` / `D3D11VA`)** | Tecnicamente viável | Tecnicamente viável | Condicional (Arc / Core Ultra+) | Tecnicamente viável | **Não implementado** (`M3`); Intel oneVPL + fallback D3D11VA. |
| **Windows — Genérico (`Media Foundation HW MFT`)** | Tecnicamente viável | Condicional | Condicional | **Implementado para teste H.264 / viável em HW** | Cobre GPUs heterogêneas (Intel/AMD/ARM Qualcomm) sem SDK específico de fabricante (`M3`). *(Nota: MFT H.264 já usado como validador independente em branch dev M4.2.)* |
| **Linux — Intel / AMD (`VA-API` / Mesa)** | Tecnicamente viável | Tecnicamente viável | Condicional (geração GPU) | Tecnicamente viável (`intel-media-driver`, `radeonsi`) | **Não implementado** (`M2` receptor, `M4` emissor); zero-copy via `DMA-BUF`. |
| **Linux — NVIDIA (`NVENC`/`NVDEC`/`Vulkan Video`)** | Tecnicamente viável | Tecnicamente viável | Condicional (Ada+) | Tecnicamente viável (`NVDEC`/`Vulkan Video`) | **Não implementado**; nota: driver proprietário NVIDIA não provê VA-API nativo sem wrapper externo, exigindo backend `NVDEC`/`Vulkan Video`. |
| **Linux — ARM / SBCs (`V4L2` stateless/stateful)** | Condicional (driver SoC) | Condicional | Condicional | Condicional | **Não implementado**; dependente de drivers V4L2 M2M do kernel. |
| **Android (`MediaCodec` HW)** | Tecnicamente viável | Tecnicamente viável | Condicional (Android 14+ / SoC) | Tecnicamente viável | **Não implementado** (`M3` receptor, `M5` emissor); consulta `MediaCodecInfo.isHardwareAccelerated()`. |
| **Fallback Software (Diagnóstico / Emergência)** | OpenH264 (BSD) / MFT SW | Condicional (licença/CPU) | `SVT-AV1` / `dav1d` (BSD) | `OpenH264` / `dav1d` / FFmpeg LGPL dinâmico | Uso explícito de diagnóstico ou quando nenhuma aceleração HW estiver disponível; menor teto de FPS/resolução conforme CPU. |
