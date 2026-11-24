# LumaBridge-Display

Plataforma open source em desenvolvimento para espelhamento, extensao real de area de trabalho na sessao grafica ativa e interacao remota entre dispositivos, com emissor virtual Windows 11 x64 (`LumaBridgeIddDriver` + `lumabridge-host`) e arquitetura multiplataforma planejada para Windows, Linux (Wayland/X11) e Android.

## Estado Atual do Projeto (`M0.6`)

- **M0 (Emissor Windows & Validacao Funcional):** **Funcionalmente aprovada** no commit funcional `6b297856` (`Benchmark30s` 30 s e `ProlongedStability` 180 s com `D3d11DxgiVSync`, transporte GPU compartilhado sem readback CPU e `NVENC H.264`), **integrada em `dev` remoto (`M0_INTEGRATED_IN_DEV = True`)** via [PR #37](https://github.com/Altaeir-13/LumaBridge-Display/pull/37) e **Merge commit `23a28046`** (preservando a arvore qualificada `7f1685f7`, o commit funcional `6b297856` e o head final da consolidacao `a9ad7e43`; historico local/revalidado `M0.4.1` com `157/157` C++, `71/71` PowerShell, `InfVerif 7/7` e `2/2` execucoes controladas `9/9` E2E aprovadas, preservando duas reprovacoes sinteticas `p99` anteriores da `M0.4`).
- **Governanca e fechamento formal (`M0.6`):** **`M0_FORMALLY_CLOSED = False`** — os entregaveis de governanca (`LICENSE` Apache-2.0, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `CONTRIBUTING.md` com DCO 1.1 prospectivo, matriz real de testes e workflows iniciais Windows/Linux em `.github/workflows/`) encontram-se preparados na branch `chore/m0-governance-closure` para revisao, confirmacao dos checks remotos e merge definitivo em `dev`. Qualificacao EV/WHQL de distribuicao em producao permanece fora do escopo da `M0` (`M6`).
- **M1 (Nucleo multiplataforma, `LBWP v1`, FFI e transporte):** **Ainda nao iniciada (`M1_STARTED = False`)** — sera aberta somente apos o encerramento formal da `M0`.

## Licenciamento, Contribuicao e CI

- **Licenca:** o codigo-fonte e a documentacao originais do LumaBridge Display sao licenciados sob a [**Apache License, Version 2.0**](LICENSE). Nem todos os arquivos do repositorio estao necessariamente sujeitos a Apache-2.0: componentes de terceiros incorporados permanecem regidos por suas respectivas licencas e avisos originais documentados em [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) e [NOTICE](NOTICE) (como [`windows/host/third_party/nvenc/nvEncodeAPI.h`](windows/host/third_party/nvenc/nvEncodeAPI.h), licenciado sob **MIT**).
- **Contribuicao (DCO 1.1):** consulte [CONTRIBUTING.md](CONTRIBUTING.md) para fluxo de branches/PRs, convencoes de commit, politica de dados sensiveis e certificação prospectiva **Developer Certificate of Origin (DCO 1.1)** via `git commit -s`.
- **Escopo do CI inicial:** consulte [ci-and-test-matrix.md](docs/setup/ci-and-test-matrix.md) para a separacao explicita entre verificacoes convencionais nao administrativas em CI hospedado e a trilha especializada local (`WDK`, GPU fisica, `NVENC`, `WUDFHost.exe`, `Benchmark30s` e `ProlongedStability`).

## Documentacao Principal

- **Arquitetura Universal & ADRs:** [universal-platform-architecture.md](docs/architecture/universal-platform-architecture.md), [ADR-0003](docs/architecture/ADR-0003-universal-platform-vision.md), [ADR-0004](docs/architecture/ADR-0004-core-language-and-native-boundaries.md), [ADR-0005](docs/architecture/ADR-0005-transport-and-security-architecture.md) e [compatibility-matrix.md](docs/architecture/compatibility-matrix.md).
- **Protocolo de Rede (`LBWP v1`, Draft):** [wire-protocol-v1.md](docs/protocol/wire-protocol-v1.md) *(independente do IPC local Windows `LBIF`)*.
- **Planejamento e Migracao:** [UNIVERSAL_ROADMAP.md](docs/planning/UNIVERSAL_ROADMAP.md), [MIGRATION_PLAN.md](docs/planning/MIGRATION_PLAN.md), [RISK_REGISTER.md](docs/planning/RISK_REGISTER.md) e [LICENSE_COMPLIANCE_REVIEW.md](docs/planning/LICENSE_COMPLIANCE_REVIEW.md).
- **Emissor Windows (`IddCx` + `NVENC` + Validacao & CI):** [windows/driver/README.md](windows/driver/README.md), [windows/host/README.md](windows/host/README.md), [windows/driver/tests/README.md](windows/driver/tests/README.md), [windows-gpu-shared-textures-nvenc.md](docs/architecture/windows-gpu-shared-textures-nvenc.md), [windows-idd-functional-validation.md](docs/setup/windows-idd-functional-validation.md) e [ci-and-test-matrix.md](docs/setup/ci-and-test-matrix.md).
