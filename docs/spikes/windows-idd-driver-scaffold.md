# Spike: scaffold minimo de driver IddCx

Data: 2026-06-30

Branch: `spike/windows-idd-driver-scaffold`

Issue planejada: Validar scaffold minimo de driver IddCx no Windows.

## 1. Objetivo do spike

Validar se o repositorio ja pode receber uma estrutura inicial para o futuro modulo `lumabridge-idd-driver` em `windows/driver`.

Este spike cria somente documentacao local do scaffold. Ele nao implementa driver funcional, nao cria monitor virtual, nao processa swapchain e nao cria projeto WDK compilavel.

## 2. Ambiente usado

Documentacao de base lida:

- `docs/setup/windows-wdk-environment.md`
- `docs/spikes/windows-idd-virtual-display.md`
- `docs/planning/MODULE_BREAKDOWN.md`
- `docs/planning/IMPLEMENTATION_SEQUENCE.md`
- `docs/planning/IMPLEMENTATION_PLAN.md`
- `docs/planning/NEXT_ACTIONS.md`
- `docs/architecture/ADR-0001-branching-strategy.md`
- `docs/architecture/ADR-0002-mvp-technical-scope.md`

Ambiente WDK registrado pela issue #12:

| Item | Resultado |
|---|---|
| Build Tools | Visual Studio Build Tools 18.x / VS2026 |
| MSVC | `14.51.36231` |
| SDK ativo | `10.0.28000.0` |
| Familia WDK validada | `10.0.28000.0` |
| `IddCx.h` | Encontrado |
| `Wdf.h` | Encontrado |
| `stampinf.exe` | Encontrado no Developer Command Prompt |
| `Inf2Cat.exe` | Encontrado por caminho completo no Windows Kits |

## 3. Arquivos criados

Arquivos criados neste spike:

- `windows/driver/README.md`
- `docs/spikes/windows-idd-driver-scaffold.md`

Nao foram criados:

- `.sln`
- `.vcxproj`
- `.inf`
- `.cpp`
- `.h`
- `.props`
- `.targets`
- instalador
- scripts de assinatura

## 4. Comandos executados

Comandos Git executados:

```text
git status --short --branch
git branch --show-current
git fetch origin
git checkout dev
git pull origin dev
git checkout -b spike/windows-idd-driver-scaffold
```

Comandos de leitura executados:

```text
rg --files docs
Get-Content docs\setup\windows-wdk-environment.md
Get-Content docs\spikes\windows-idd-virtual-display.md
Get-Content docs\planning\MODULE_BREAKDOWN.md
Get-Content docs\planning\IMPLEMENTATION_SEQUENCE.md
Get-Content docs\planning\IMPLEMENTATION_PLAN.md
Get-Content docs\planning\NEXT_ACTIONS.md
Get-Content docs\architecture\ADR-0001-branching-strategy.md
Get-Content docs\architecture\ADR-0002-mvp-technical-scope.md
Test-Path windows
rg --files windows
```

## 5. Avaliacao tecnica do scaffold

Resultado da avaliacao: criar apenas documentacao e a pasta `windows/driver` e seguro neste momento.

Motivos:

- O ambiente WDK foi aprovado na issue #12.
- O repositorio ja define `windows/driver` como pasta esperada para o modulo `lumabridge-idd-driver`.
- O spike anterior ja propunha uma estrutura futura para driver.
- Criar `.sln`, `.vcxproj`, `.inf` ou codigo C++ agora passaria do escopo deste spike e poderia sugerir um driver compilavel sem implementacao validada.

Decisao:

- Criar somente `windows/driver/README.md`.
- Registrar o spike em `docs/spikes/windows-idd-driver-scaffold.md`.
- Nao criar projeto WDK ainda.
- Nao tentar build de driver neste spike, porque nao ha projeto compilavel.

## 6. Resultado

Resultado: aprovado como scaffold documental minimo.

O repositorio agora possui um ponto inicial para o modulo `windows/driver`, com limites claros sobre o que pertence ao driver e o que fica fora dele.

Nao houve tentativa de build, porque este spike nao criou solucao, projeto, INF ou codigo de driver.

## 7. Conclusao

O scaffold minimo e seguro como documentacao inicial. A proxima etapa tecnica pode criar uma fundacao compilavel do driver em uma issue separada, usando WDK/IddCx e MSBuild.

Este spike nao valida monitor virtual funcional. Ele apenas desbloqueia a organizacao inicial do modulo.

## 8. Proximos passos

1. Criar uma issue separada para projeto WDK minimo compilavel.
2. Definir a estrutura real de `.sln`, `.vcxproj` e `.inf` com base no IddSample como referencia conceitual.
3. Adicionar codigo minimo apenas quando a issue permitir explicitamente implementacao.
4. Executar build MSBuild em Developer Command Prompt.
5. Documentar qualquer erro de build sem ativar instalacao, assinatura ou modo de teste nesta etapa.

## 9. Fora do escopo confirmado

Nao houve:

- driver funcional;
- monitor virtual funcional;
- processamento de swapchain real;
- host;
- client;
- protocolo;
- streaming;
- NVENC;
- instalador;
- assinatura de driver;
- copia de codigo proprietario;
- merge;
- push;
- PR.
