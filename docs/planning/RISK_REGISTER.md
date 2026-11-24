# Registro de Riscos Arquiteturais — LumaBridge Display

Este registro consolida os riscos técnicos, jurídicos, operacionais e de segurança identificados na transição do escopo inicial `Windows → Linux` para a arquitetura universal multiplataforma.

---

## Matriz Resumo

| ID | Domínio | Risco Resumido | Probabilidade | Impacto | Marco Crítico |
|---|---|---|---|---|---|
| `R01` | Windows / Distribuição | Assinatura EV/WHQL e bloqueio Secure Boot/HVCI no driver IddCx | Alta | Alto | `M6` (dev mitigado em `M0`) |
| `R02` | Windows / Compatibilidade | INF exclusivo Windows 11 (`22000+`) e variações/bugs de runtime `IddCx.dll` | Média | Alto | `M0`, `M3` |
| `R03` | Linux Wayland | Fragmentação de criação de saída virtual entre compositores e mudanças de portal | Alta | Alto | `M4` |
| `R04` | Linux X11 | Impossibilidade universal de hot-plug virtual na sessão X11 ativa e falso positivo `Xvfb` | Alta | Médio | `M4` |
| `R05` | Android | Restrições de `MediaProjection` 14+, extensão real incerta sem root e limites de input | Alta | Alto | `M3`, `M5` |
| `R06` | USB Android | `ADB` inadequado para usuário final; tethering exige ação manual; `AOA` incerto | Alta | Médio | `M3` |
| `R07` | GPU / Fabricantes | Acoplamento a NVENC/VA-API e falhas de `DMA-BUF` em notebooks híbridos multi-GPU | Alta | Alto | `M2`, `M3`, `M4` |
| `R08` | Vídeo / Rede | Descarte ingênuo de P-frames causando corrupção persistente do decodificador | Alta | Alto | `M1`, `M2` |
| `R09` | Segurança / Privacidade | MITM no pareamento, elevação indevida para input, UIPI Windows e vazamento em logs | Média | Crítico | `M1`, `M4` |
| `R10` | Licenças & Patentes | Contaminação copyleft incompatível (GPLv2) e exposição a patentes H.264/HEVC | Média | Crítico | `M0`, `M1` |
| `R11` | Toolchain / FFI | Atrito Rust ↔ MSVC CRT / Android NDK ou sobrecarga de fronteira FFI | Média | Alto | `M1` |
| `R12` | Governança / CI | Branches empilhadas sem CI automatizado e divergência documental | Média | Médio | `M0`, `M1` |

---

## Detalhamento, Sinais e Mitigações

### `R01` — Assinatura de Produção e Restrições de Segurança do Driver Windows
- **Descrição:** Distribuição pública de `LumaBridgeIddDriver.dll` sob Windows 10/11 com *Secure Boot* e HVCI ativos exige certificado de assinatura de código EV e submissão ao *Windows Hardware Dev Center* (attestation/WHQL). Assinatura de teste exige `testsigning on`, inviável para usuários finais.
- **Gatilhos/Sinais:** Usuários finais impossibilitados de instalar o driver sem desabilitar proteções do Windows.
- **Mitigação Preventiva:** Manter *Test Signing* estritamente isolado em staging de desenvolvimento (`Invoke-LumaBridgePackageSigning.ps1` com rollback em `finally`); planejar certificação pública em `M6`.
- **Contingência:** Disponibilizar modo **Espelhamento Windows (`WGC` / `DXGI`)** em `M3` e **Receptor Windows** sem necessidade de instalação do driver IddCx.

### `R02` — Compatibilidade Windows 10 vs Windows 11 e Regressões `IddCx`
- **Descrição:** [LumaBridgeIddDriver.inf](../../windows/driver/LumaBridgeIddDriver/LumaBridgeIddDriver.inf) fixa suporte apenas ao Windows 11 x64 (`NT$ARCH$.10.0...22000`, `10_CO_X64;10_NI_X64;10_GE_X64`). Além disso, `IddCx.dll` pode impor validações binárias não triviais (como a descoberta na branch `#34` da rejeição de `IDDCX_TRANSMISSION_TYPE_NETWORK_OTHER` = `9` com `0xC000000D`).
- **Mitigação Preventiva:** Nunca declarar suporte a Windows 10 ou builds novas do Windows 11 sem spike específico, ajuste validado de `.inf`/`Inf2Cat` (`19041+`) e execução completa em ambiente real. Preservar todos os testes de validação estática e contrato em `DriverPackageValidationTests.cpp`.

### `R03` — Fragmentação de Saídas Virtuais no Linux Wayland
- **Descrição:** `xdg-desktop-portal` e PipeWire padronizam a entrega de vídeo consentida, mas não garantem que todos os compositores implementem `source_type = VIRTUAL` ou APIs equivalentes para criar monitores estendidos na sessão ativa.
- **Mitigação Preventiva:** Construir camada explícita de adaptadores por compositor (`GNOME/Mutter`, `KDE/KWin`, `Sway`, `Hyprland`) consultando capacidades reais no handshake; degradar de forma transparente para **Espelhamento** (`can_extend_session = false`) nos demais compositores.
- **Contingência:** Informar claramente na UI/CLI quando o compositor ativo não suportar extensão real.

### `R04` — Limitações de Extensão Real no X11 e Falso Positivo `Xvfb`/`Xdummy`
- **Descrição:** Servidores X.Org com certos drivers proprietários (notadamente NVIDIA) frequentemente não permitem criar conectores virtuais dinâmicos sem editar `xorg.conf` e reiniciar o Xorg; já o módulo kernel `VKMS` exige privilégio administrativo e configuração extra.
- **Mitigação Preventiva:** Suportar nativamente receptor e captura por espelhamento X11 (`XShm`/`XDamage`/`XRandR`/`XTest`); classificar extensão X11 como condicional; proibir contratualmente tratar `Xvfb`/`Xdummy` isolado como extensão da sessão gráfica atual.

### `R05` — Restrições Progressivas do Android sem Root
- **Descrição:** Android 14+ endureceu regras de `MediaProjection` (re-consentimento por sessão e `ForegroundService` dedicado). Além disso, `MediaProjection.createVirtualDisplay()` não cria monitor estendido livre do sistema, e injeção global de eventos é bloqueada sem `AccessibilityService` manual ou privilégio de sistema.
- **Mitigação Preventiva:** Priorizar Android como **Receptor** (`M3`) e **Emissor por Espelhamento** (`M5`) via APIs públicas sem root; manter extensão Android estritamente em pesquisa em `M5`, nunca prometendo suporte universal antecipado.

### `R06` — Fricção de Experiência em Conexões USB com Android
- **Descrição:** Túneis `adb reverse`/`adb forward` exigem Depuração USB (inaceitável como fluxo principal de usuário final); *USB Tethering* sem root exige habilitação manual nas configurações do aparelho; `AOA` requer driver WinUSB no Windows e prova prática de estabilidade de banda.
- **Mitigação Preventiva:** Tratar `ADB` apenas como transporte de desenvolvimento/diagnóstico; priorizar Wi-Fi 5/6 GHz direto + *USB Tethering IP* com guia claro ao usuário; executar spike específico de `AOA` antes de prometer USB plug-and-play universal.

### `R07` — Acoplamento a Fabricantes de GPU e Multi-GPU Híbrido
- **Descrição:** O pipeline atual depende exclusivamente de NVIDIA NVENC no Windows; no Linux, driver proprietário NVIDIA não expõe VA-API nativamente; notebooks com iGPU + dGPU podem falhar ao importar `DMA-BUF` devido a *DRM modifiers* incompatíveis entre drivers.
- **Mitigação Preventiva:** Introduzir interfaces `IVideoEncoder`/`IVideoDecoder` com negociação multi-vendor (`NVENC`, `AMF`, `oneVPL/QSV`, `MF HW MFT`, `VA-API`, `Vulkan Video`, `MediaCodec`) e manter caminho de fallback linear/SHM instrumentado quando zero-copy entre GPUs distintas não for possível.

### `R08` — Corrupção Visual por Quebra de Cadeia de Referência (P-Frames)
- **Descrição:** Em streaming interativo sem B-frames, perder ou descartar um quadro `P_k` enquanto se continua decodificando `P_{k+1}` corrompe o estado do decodificador até o próximo IDR.
- **Mitigação Preventiva:** Implementar desde `M1` a máquina de estado `gop_id` / `chain_broken` / `AwaitingIdr` definida na [ADR-0005](../architecture/ADR-0005-transport-and-security-architecture.md) e no [LBWP v1](../protocol/wire-protocol-v1.md), acoplada a `RequestForceIdr` com cooldown e fallback pós-MVP para NACK/FEC/LTR.

### `R09` — Segurança, Pareamento e Privacidade
- **Descrição:** Redes locais compartilhadas/públicas são hostis (risco de MITM no primeiro pareamento e controle remoto não autorizado); no Windows, `SendInput` não controla janelas elevadas por UIPI; logs diagnósticos poderiam vazar informações da tela ou segredos se mal projetados.
- **Mitigação Preventiva:** Pareamento em duas fases com isolamento de ALPN, SPAKE2/QR vinculado a `tls-exporter` (`RFC 9266`), mTLS estrito pós-pareamento, permissões ortogonais *deny-by-default*, rate-limiting contra brute-force e auditoria rigorosa garantindo zero pixels/teclas/segredos em logs.

### `R10` — Incompatibilidade de Licenças e Patentes Multimídia
- **Descrição:** Vincular estaticamente bibliotecas `GPLv2-only` ou distribuir encoders H.264/HEVC próprios sem observar patentes pode inviabilizar o licenciamento `Apache-2.0` pretendido.
- **Mitigação Preventiva:** Seguir integralmente a política em 3 faixas detalhada em [LICENSE_COMPLIANCE_REVIEW.md](./LICENSE_COMPLIANCE_REVIEW.md), delegando codecs às APIs do sistema/hardware e reservando fallbacks software apenas a componentes compatíveis (ex.: modelo OpenH264 BSD/Cisco ou `SVT-AV1`/`dav1d` BSD).

### `R11` — Fronteira FFI e Complexidade Multi-Toolchain
- **Descrição:** Introduzir Rust ao lado de MSVC C++17/WDK e Android NDK cria risco de conflito de CRT (`/MD` vs `/MDd`), vazamento de *panics* através da ABI C ou overhead inesperado de memória.
- **Mitigação Preventiva:** Manter texturas GPU 100% fora da fronteira FFI; executar PoC com critérios numéricos objetivos (`ADR-0004`) no início de `M1`, mantendo C++20/CMake como fallback arquitetural imediato caso a PoC reprove.

### `R12` — Acúmulo de Branches Empilhadas sem CI
- **Descrição:** A existência de 3 branches Windows encadeadas à frente de `dev` sem pipelines automatizados de build/teste aumenta o risco de conflitos silenciosos e divergência documental.
- **Mitigação Preventiva:** Consolidar `M0` com revisão sequencial de PRs após o gate real `M4.2.1` e configurar `.github/workflows/` (build e testes unitários Windows + Linux) logo na entrada de `M1`.
