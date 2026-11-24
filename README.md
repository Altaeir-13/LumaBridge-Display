# LumaBridge-Display

Plataforma open source em desenvolvimento para espelhamento, extensao real de area de trabalho na sessao grafica ativa e interacao remota entre dispositivos, com emissor virtual Windows 11 x64 (`LumaBridgeIddDriver` + `lumabridge-host`) e arquitetura multiplataforma planejada para Windows, Linux (Wayland/X11) e Android.

## Estado Atual do Projeto (`M0.4.1`)

- **M0 (Emissor Windows & Validacao Funcional):** **Funcionalmente aprovada** no commit funcional `6b297856` (`Benchmark30s` 30 s e `ProlongedStability` 180 s com `D3d11DxgiVSync`, transporte GPU compartilhado sem readback CPU e `NVENC H.264`), **consolidada localmente** na branch de integracao `integration/m0-windows-closure` e **requalificada para PR (`M0.4.1`)** (`157/157` C++, `71/71` PowerShell, `InfVerif 7/7` e `2/2` execucoes controladas `9/9` E2E aprovadas, preservando duas reprovacoes sinteticas `p99` anteriores da `M0.4`).
- **Integracao em `dev` remoto (`origin/dev`) e fechamento formal:** **Ainda nao integrada em `dev` remoto (`M0_INTEGRATED_IN_DEV = False`)** e **`M0_FORMALLY_CLOSED = False`** (aguarda revisao/publicacao por merge commit e definicao/criacao de `LICENSE`, `NOTICE`/`THIRD_PARTY_NOTICES.md` e CI inicial em `.github/workflows/`).
- **M1 (Nucleo multiplataforma, `LBWP v1`, FFI e transporte):** **Ainda nao iniciada (`M1_STARTED = False`)** (arquitetura e roadmap formalizados para a proxima etapa apos a integracao/encerramento formal da `M0`).

## Documentacao Principal

- **Arquitetura Universal & ADRs:** [universal-platform-architecture.md](docs/architecture/universal-platform-architecture.md), [ADR-0003](docs/architecture/ADR-0003-universal-platform-vision.md), [ADR-0004](docs/architecture/ADR-0004-core-language-and-native-boundaries.md), [ADR-0005](docs/architecture/ADR-0005-transport-and-security-architecture.md) e [compatibility-matrix.md](docs/architecture/compatibility-matrix.md).
- **Protocolo de Rede (`LBWP v1`, Draft):** [wire-protocol-v1.md](docs/protocol/wire-protocol-v1.md) *(independente do IPC local Windows `LBIF`)*.
- **Planejamento e Migracao:** [UNIVERSAL_ROADMAP.md](docs/planning/UNIVERSAL_ROADMAP.md), [MIGRATION_PLAN.md](docs/planning/MIGRATION_PLAN.md), [RISK_REGISTER.md](docs/planning/RISK_REGISTER.md) e [LICENSE_COMPLIANCE_REVIEW.md](docs/planning/LICENSE_COMPLIANCE_REVIEW.md).
- **Emissor Windows (`IddCx` + `NVENC` + Validacao):** [windows/driver/README.md](windows/driver/README.md), [windows/host/README.md](windows/host/README.md), [windows/driver/tests/README.md](windows/driver/tests/README.md), [windows-gpu-shared-textures-nvenc.md](docs/architecture/windows-gpu-shared-textures-nvenc.md) e [windows-idd-functional-validation.md](docs/setup/windows-idd-functional-validation.md).
