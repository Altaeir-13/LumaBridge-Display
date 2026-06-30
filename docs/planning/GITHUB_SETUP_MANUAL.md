# LumaBridge Display - Guia manual de governanca no GitHub

Este documento orienta a criacao manual de labels e milestones no GitHub para o projeto LumaBridge Display.

Ele nao substitui `docs/planning/LABELS.md` nem `docs/planning/MILESTONES.md`; ele transforma esses documentos em um roteiro operacional para execucao manual na interface do GitHub.

Regras desta etapa:

- Nao usar GitHub CLI.
- Nao criar labels automaticamente.
- Nao criar milestones automaticamente.
- Nao criar issues ainda.
- Nao abrir Pull Request automaticamente.
- Nao fazer merge automaticamente.
- Nao alterar `main`.

## 1. Criacao manual de labels

Fonte de verdade:

- `docs/planning/LABELS.md`

Passo a passo:

1. Abra o repositorio no GitHub.
2. Acesse `Issues`.
3. Acesse `Labels`.
4. Para cada label da tabela abaixo, clique em `New label`.
5. Copie exatamente o `Nome`.
6. Copie a `Descricao`.
7. Copie a `Cor hexadecimal`, sem alterar o valor.
8. Salve a label.
9. Repita seguindo a ordem sugerida de criacao.
10. Ao final, revise nomes, descricoes e cores antes de criar qualquer issue.

Recomendacao:

- Criar primeiro labels de tipo, depois modulo, prioridade, risco, status e milestone.
- Se uma label ja existir, atualize nome, descricao e cor para corresponder a tabela.

## 2. Tabela de labels

| Ordem | Nome | Descricao | Cor hexadecimal |
|---:|---|---|---|
| 1 | `type:epic` | Agrupamento grande de trabalho relacionado. | `#5319E7` |
| 2 | `type:feature` | Funcionalidade nova verificavel. | `#1D76DB` |
| 3 | `type:task` | Tarefa tecnica ou operacional. | `#C2E0C6` |
| 4 | `type:spike` | Investigacao tecnica com resultado documentado. | `#D4C5F9` |
| 5 | `type:test` | Testes automatizados, manuais ou infraestrutura de validacao. | `#0E8A16` |
| 6 | `type:docs` | Documentacao, ADRs, guias ou planejamento. | `#0075CA` |
| 7 | `type:infra` | Build, CI, templates, governanca ou ferramentas de repositorio. | `#FBCA04` |
| 8 | `type:bug` | Comportamento incorreto ou regressao. | `#D73A4A` |
| 9 | `module:protocol` | Trabalho no protocolo de comunicacao. | `#0052CC` |
| 10 | `module:idd-driver` | Trabalho no driver virtual Windows. | `#B60205` |
| 11 | `module:host` | Trabalho na aplicacao host Windows. | `#5319E7` |
| 12 | `module:client` | Trabalho no cliente Linux. | `#0E8A16` |
| 13 | `module:tools` | Ferramentas auxiliares e diagnostico. | `#006B75` |
| 14 | `module:docs` | Documentacao do projeto. | `#0075CA` |
| 15 | `module:github` | Templates, labels, milestones e workflows. | `#6F42C1` |
| 16 | `priority:P0` | Indispensavel para MVP. | `#B60205` |
| 17 | `priority:P1` | Importante para MVP utilizavel. | `#D93F0B` |
| 18 | `priority:P2` | Melhoria pos-MVP. | `#FBCA04` |
| 19 | `priority:P3` | Futuro ou expansao. | `#C5DEF5` |
| 20 | `risk:high` | Alto risco tecnico ou operacional. | `#B60205` |
| 21 | `risk:driver` | Risco relacionado a driver, WDK, IddCx ou assinatura. | `#D73A4A` |
| 22 | `risk:performance` | Risco de latencia, throughput, copia de memoria ou frame pacing. | `#F9D0C4` |
| 23 | `risk:security` | Risco de autenticacao, segredos, criptografia ou exposicao indevida. | `#5319E7` |
| 24 | `status:blocked` | Bloqueada por dependencia ou decisao externa. | `#000000` |
| 25 | `status:ready` | Pronta para execucao. | `#0E8A16` |
| 26 | `status:needs-review` | Requer revisao humana antes de continuar. | `#FBCA04` |
| 27 | `milestone:mvp` | Trabalho que compoe o MVP funcional. | `#1D76DB` |

## 3. Criacao manual de milestones

Fonte de verdade:

- `docs/planning/MILESTONES.md`

Passo a passo:

1. Abra o repositorio no GitHub.
2. Acesse `Issues`.
3. Acesse `Milestones`.
4. Clique em `New milestone`.
5. Copie o titulo da milestone exatamente como listado abaixo.
6. Copie a descricao sugerida correspondente.
7. Nao defina data de vencimento nesta etapa, salvo decisao humana posterior.
8. Salve a milestone.
9. Repita para as 10 milestones.
10. Revise se todas foram criadas antes de criar issues.

Ordem recomendada:

1. `M0 - Repository and Planning`
2. `M1 - Technical Spikes`
3. `M2 - Protocol Foundation`
4. `M3 - Windows Virtual Display`
5. `M4 - Windows Host Pipeline`
6. `M5 - Linux Client Pipeline`
7. `M6 - LAN MVP Integration`
8. `M7 - Security and Pairing`
9. `M8 - UX and Packaging`
10. `M9 - Optimization and Release Candidate`

## 4. Milestones para criar no GitHub

### M0 - Repository and Planning

Titulo:

`M0 - Repository and Planning`

Descricao sugerida para colar no GitHub:

```md
Estabelecer a estrutura documental, backlog, governanca e fluxo de trabalho do LumaBridge Display.

Issues incluidas: Issue 1, Issue 2, Issue 3, Issue 4, Issue 5, Issue 6, Issue 7, Issue 8, Issue 9.

Criterio de conclusao: documentos de planejamento revisados, estrategia de branches documentada, labels/milestones/issues prontas para criacao manual e nenhuma automacao criando push, PR ou issue real.
```

Objetivo:

- Estabelecer a estrutura documental, backlog, governanca e fluxo de trabalho.

Issues incluidas:

- Issue 1, Issue 2, Issue 3, Issue 4, Issue 5, Issue 6, Issue 7, Issue 8, Issue 9.

Criterio de conclusao:

- Documentos de planejamento revisados.
- Estrategia de branches documentada.
- Labels, milestones e issues prontas para criacao manual.
- Nenhum push, PR ou issue real criado pela automacao.

### M1 - Technical Spikes

Titulo:

`M1 - Technical Spikes`

Descricao sugerida para colar no GitHub:

```md
Provar isoladamente as tecnologias criticas antes da integracao do MVP.

Issues incluidas: Issue 15, Issue 20, Issue 26, Issue 32.

Criterio de conclusao: monitor virtual IddCx validado em spike, NVENC codificando frames sinteticos, VA-API decodificando sample H.264 e transporte LAN enviando payload sintetico com metricas basicas.
```

Objetivo:

- Provar isoladamente as tecnologias criticas antes da integracao.

Issues incluidas:

- Issue 15, Issue 20, Issue 26, Issue 32.

Criterio de conclusao:

- Monitor virtual IddCx validado em spike.
- NVENC codificando frames sinteticos.
- VA-API decodificando sample H.264.
- Transporte LAN enviando payload sintetico com metricas basicas.

### M2 - Protocol Foundation

Titulo:

`M2 - Protocol Foundation`

Descricao sugerida para colar no GitHub:

```md
Definir e testar os contratos de comunicacao entre host e cliente.

Issues incluidas: Issue 10, Issue 11, Issue 12, Issue 13, Issue 14.

Criterio de conclusao: handshake, versao, capabilities, controle de sessao, erros e estatisticas documentados e testados.
```

Objetivo:

- Definir e testar contratos de comunicacao host-cliente.

Issues incluidas:

- Issue 10, Issue 11, Issue 12, Issue 13, Issue 14.

Criterio de conclusao:

- Handshake, versao, capabilities, controle de sessao, erros e estatisticas documentados e testados.

### M3 - Windows Virtual Display

Titulo:

`M3 - Windows Virtual Display`

Descricao sugerida para colar no GitHub:

```md
Criar o monitor virtual real no Windows com base em IddCx.

Issues incluidas: Issue 16, Issue 17, Issue 18, Issue 19.

Criterio de conclusao: Windows 11 reconhece o monitor virtual, modo estendido funciona, modos minimos aparecem e o fluxo de instalacao/remocao de desenvolvimento esta documentado.
```

Objetivo:

- Criar o monitor virtual real no Windows com base em IddCx.

Issues incluidas:

- Issue 16, Issue 17, Issue 18, Issue 19.

Criterio de conclusao:

- Windows 11 reconhece monitor virtual.
- Modo estendido funciona.
- Modos minimos aparecem.
- Fluxo de instalacao/remocao de desenvolvimento esta documentado.

### M4 - Windows Host Pipeline

Titulo:

`M4 - Windows Host Pipeline`

Descricao sugerida para colar no GitHub:

```md
Construir o pipeline host para frames, NVENC, transporte e metricas.

Issues incluidas: Issue 21, Issue 22, Issue 23, Issue 24, Issue 25.

Criterio de conclusao: host inicia por CLI, codifica H.264 via NVENC, envia stream sintetico, integra frame real do monitor virtual em etapa controlada e reporta metricas de encode/envio.
```

Objetivo:

- Construir pipeline host para frames, NVENC, transporte e metricas.

Issues incluidas:

- Issue 21, Issue 22, Issue 23, Issue 24, Issue 25.

Criterio de conclusao:

- Host inicia por CLI.
- Codifica H.264 via NVENC.
- Envia stream sintetico.
- Integra frame real do monitor virtual em etapa controlada.
- Reporta metricas de encode e envio.

### M5 - Linux Client Pipeline

Titulo:

`M5 - Linux Client Pipeline`

Descricao sugerida para colar no GitHub:

```md
Construir o cliente Linux com recepcao, decode e render fullscreen.

Issues incluidas: Issue 27, Issue 28, Issue 29, Issue 30, Issue 31.

Criterio de conclusao: cliente conecta por IP, recebe stream sintetico, decodifica H.264 via VA-API quando disponivel, renderiza fullscreen no Hyprland e mostra metricas basicas.
```

Objetivo:

- Construir cliente Linux com recepcao, decode e render fullscreen.

Issues incluidas:

- Issue 27, Issue 28, Issue 29, Issue 30, Issue 31.

Criterio de conclusao:

- Cliente conecta por IP.
- Recebe stream sintetico.
- Decodifica H.264 via VA-API quando disponivel.
- Renderiza fullscreen no Hyprland.
- Mostra metricas basicas.

### M6 - LAN MVP Integration

Titulo:

`M6 - LAN MVP Integration`

Descricao sugerida para colar no GitHub:

```md
Integrar driver, host e cliente para exibir em LAN o conteudo real do monitor virtual.

Issues incluidas: Issue 35, Issue 36, Issue 37, Issue 38.

Criterio de conclusao: janela arrastada para o monitor virtual aparece no laptop Linux, 1080p60 funciona em LAN em condicoes boas, frames atrasados sao descartados e logs permitem diagnostico ponta a ponta.
```

Objetivo:

- Integrar driver, host e cliente para exibir conteudo real do monitor virtual em LAN.

Issues incluidas:

- Issue 35, Issue 36, Issue 37, Issue 38.

Criterio de conclusao:

- Janela arrastada para monitor virtual aparece no laptop Linux.
- 1080p60 funciona em LAN em condicoes boas.
- Frames atrasados sao descartados.
- Logs permitem diagnostico ponta a ponta.

### M7 - Security and Pairing

Titulo:

`M7 - Security and Pairing`

Descricao sugerida para colar no GitHub:

```md
Impedir conexoes acidentais e preparar autenticacao de sessao.

Issues incluidas: Issue 39, Issue 40, Issue 41.

Criterio de conclusao: pareamento por codigo, segredo local armazenado, cliente nao pareado rejeitado e revogacao documentada.
```

Objetivo:

- Impedir conexoes acidentais e preparar autenticacao de sessao.

Issues incluidas:

- Issue 39, Issue 40, Issue 41.

Criterio de conclusao:

- Pareamento por codigo.
- Segredo local armazenado.
- Cliente nao pareado rejeitado.
- Revogacao documentada.

### M8 - UX and Packaging

Titulo:

`M8 - UX and Packaging`

Descricao sugerida para colar no GitHub:

```md
Tornar o MVP mais operavel para uso diario e setup de desenvolvimento.

Issues incluidas: Issue 42, Issue 43, Issue 44, Issue 45.

Criterio de conclusao: CLI/configuracao documentada, guias de setup Windows e Arch criados, scripts de desenvolvimento nao destrutivos e troubleshooting cobrindo erros comuns.
```

Objetivo:

- Tornar o MVP mais operavel para uso diario e setup de desenvolvimento.

Issues incluidas:

- Issue 42, Issue 43, Issue 44, Issue 45.

Criterio de conclusao:

- CLI/configuracao documentada.
- Guias de setup Windows e Arch.
- Scripts de desenvolvimento nao destrutivos.
- Troubleshooting cobre erros comuns.

### M9 - Optimization and Release Candidate

Titulo:

`M9 - Optimization and Release Candidate`

Descricao sugerida para colar no GitHub:

```md
Otimizar latencia, qualidade, observabilidade e preparar a release candidate.

Issues incluidas: Issue 46, Issue 47, Issue 48, Issue 49, Issue 50.

Criterio de conclusao: latencia medida e documentada, NVENC ajustado para baixa latencia, buffer do cliente ajustado, documentacao/release notes prontas e dev candidata a merge futuro em main.
```

Objetivo:

- Otimizar latencia, qualidade, observabilidade e preparar release candidate.

Issues incluidas:

- Issue 46, Issue 47, Issue 48, Issue 49, Issue 50.

Criterio de conclusao:

- Latencia medida e documentada.
- NVENC ajustado para baixa latencia.
- Buffer do cliente ajustado.
- Documentacao e release notes prontas.
- `dev` pode ser considerada candidata a merge futuro em `main`.

## 5. Checklist de verificacao final

Antes de criar issues planejadas, confirme:

- [ ] Todas as labels foram criadas.
- [ ] Todas as cores das labels foram conferidas.
- [ ] Todos os nomes das labels foram conferidos.
- [ ] Todas as descricoes das labels foram conferidas.
- [ ] Todas as 10 milestones foram criadas.
- [ ] Todos os titulos das milestones foram conferidos.
- [ ] As descricoes das milestones foram coladas corretamente.
- [ ] Nenhuma issue foi criada ainda.
- [ ] Nenhuma alteracao foi feita em `main`.
- [ ] `dev` continua sendo a branch de integracao.
- [ ] `main` continua reservada para release funcional final.

## 6. Proxima etapa apos labels e milestones

Depois que labels e milestones forem criadas manualmente:

1. Abra `docs/planning/GITHUB_ISSUES.md`.
2. Crie as issues manualmente, uma por vez.
3. Aplique labels e milestones conforme cada issue.
4. Mantenha as issues pequenas e revisaveis.
5. Nao iniciar spikes tecnicos antes de concluir a governanca minima.
