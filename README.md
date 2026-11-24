# LumaBridge-Display

Plataforma open source em desenvolvimento para espelhamento, extensao real de area de trabalho na sessao grafica ativa e interacao remota entre dispositivos, com emissor virtual Windows 11 x64 (`LumaBridgeIddDriver` + `lumabridge-host`) e arquitetura multiplataforma planejada para Windows, Linux (Wayland/X11) e Android.

## Estado Atual do Projeto (`M0.4`)

- **M0 (Emissor Windows & Validacao Funcional):** **Funcionalmente aprovada** no commit funcional `6b297856` (`Benchmark30s` 30 s e `ProlongedStability` 180 s com `D3d11DxgiVSync`, transporte GPU puro e `NVENC H.264`) e **consolidada localmente** na branch de integracao `integration/m0-windows-closure`.
- **Integracao em `dev` remoto (`origin/dev`):** **Ainda nao integrada em `dev` remoto** (aguarda revisao e publicacao por merge commit preservando o historico dos commits validados).
- **M1 (Nucleo multiplataforma, `LBWP v1`, FFI e transporte):** **Ainda nao iniciada** (arquitetura e roadmap formalizados para a proxima etapa apos o fechamento formal da `M0`).

## Documentacao Principal

- **Arquitetura Universal & ADRs:** [universal-platform-architecture.md](docs/architecture/universal-platform-architecture.md), [ADR-0003](docs/architecture/ADR-0003-universal-platform-vision.md), [ADR-0004](docs/architecture/ADR-0004-core-language-and-native-boundaries.md), [ADR-0005](docs/architecture/ADR-0005-transport-and-security-architecture.md) e [compatibility-matrix.md](docs/architecture/compatibility-matrix.md).
- **Protocolo de Rede (`LBWP v1`, Draft):** [wire-protocol-v1.md](docs/protocol/wire-protocol-v1.md) *(independente do IPC local Windows `LBIF`)*.
- **Planejamento e Migracao:** [UNIVERSAL_ROADMAP.md](docs/planning/UNIVERSAL_ROADMAP.md), [MIGRATION_PLAN.md](docs/planning/MIGRATION_PLAN.md), [RISK_REGISTER.md](docs/planning/RISK_REGISTER.md) e [LICENSE_COMPLIANCE_REVIEW.md](docs/planning/LICENSE_COMPLIANCE_REVIEW.md).
- **Emissor Windows (`IddCx` + `NVENC` + Validacao):** [windows/driver/README.md](windows/driver/README.md), [windows/host/README.md](windows/host/README.md), [windows/driver/tests/README.md](windows/driver/tests/README.md), [windows-gpu-shared-textures-nvenc.md](docs/architecture/windows-gpu-shared-textures-nvenc.md) e [windows-idd-functional-validation.md](docs/setup/windows-idd-functional-validation.md).
