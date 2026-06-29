# LumaBridge Display - Issues para criacao manual no GitHub

Estas issues devem ser revisadas por uma pessoa antes de serem criadas manualmente no GitHub. Nenhuma issue real deve ser criada automaticamente nesta etapa.

## Issue 1 - Criar estrutura documental de planejamento

Labels: `type:docs`, `module:docs`, `priority:P0`

Milestone: `M0 - Repository and Planning`

Branch sugerida: `docs/planning-foundation`

PR base futura: `dev`

### Contexto

O projeto precisa transformar `REQUISITOS_LUMABRIDGE.md` em documentos operacionais antes de qualquer implementacao.

### Objetivo

Criar a base documental de planejamento, incluindo plano de implementacao, modularizacao, backlog, milestones, labels, sequencia e ADRs iniciais.

### Escopo

- Criar documentos em `docs/planning`.
- Criar ADRs iniciais em `docs/architecture`.
- Registrar que nada sera enviado ao GitHub nesta etapa.

### Fora do escopo

- Implementar codigo funcional.
- Criar commits, branches, issues reais ou PRs reais.

### Criterios de aceite

- [ ] Todos os documentos obrigatorios existem localmente.
- [ ] Os 7 modulos obrigatorios aparecem no planejamento.
- [ ] A estrategia `main`/`dev` esta documentada.

### Testes esperados

- [ ] Revisar existencia dos arquivos.
- [ ] Revisar consistencia entre plano, backlog e milestones.
- [ ] Confirmar que nao houve alteracao remota.

### Documentacao

- [ ] Documentos de planejamento criados.

### Dependencias

Nenhuma.

### Observacoes tecnicas

Esta e a primeira issue recomendada e deve permanecer documental.

## Issue 2 - Revisar requisitos e mapa de modulos

Labels: `type:docs`, `module:docs`, `priority:P0`

Milestone: `M0 - Repository and Planning`

Branch sugerida: `docs/module-review`

PR base futura: `dev`

### Contexto

O projeto tem componentes com riscos e responsabilidades diferentes. O mapa de modulos reduz mistura de escopo.

### Objetivo

Validar que `lumabridge-protocol`, `lumabridge-idd-driver`, `lumabridge-host`, `lumabridge-client`, `lumabridge-tools`, `docs` e `.github` cobrem o escopo inicial.

### Escopo

- Revisar fronteiras dos 7 modulos.
- Confirmar responsabilidades e exclusoes.
- Ajustar referencias documentais se necessario.

### Fora do escopo

- Criar novos modulos.
- Implementar codigo.

### Criterios de aceite

- [ ] Todos os 7 modulos aparecem em `MODULE_BREAKDOWN.md`.
- [ ] Cada modulo tem responsabilidades e fora do escopo.
- [ ] Nao ha modulo generico para misturar driver, host e cliente.

### Testes esperados

- [ ] Revisao manual dos documentos.
- [ ] Comparacao com `REQUISITOS_LUMABRIDGE.md`.
- [ ] Verificar referencias no backlog.

### Documentacao

- [ ] `MODULE_BREAKDOWN.md` atualizado, se aplicavel.

### Dependencias

Issue 1.

### Observacoes tecnicas

Manter exatamente os 7 modulos definidos para o planejamento inicial.

## Issue 3 - Documentar estrategia de branches

Labels: `type:docs`, `module:docs`, `priority:P0`

Milestone: `M0 - Repository and Planning`

Branch sugerida: `docs/branching-strategy`

PR base futura: `dev`

### Contexto

O projeto precisa preservar `main` para release final e usar `dev` como integracao.

### Objetivo

Documentar a estrategia de branches, PRs e Conventional Commits.

### Escopo

- Definir `main` como release final.
- Definir `dev` como integracao.
- Definir branches por issue.

### Fora do escopo

- Criar branches localmente.
- Fazer push.

### Criterios de aceite

- [ ] ADR de branches existe.
- [ ] PRs futuros apontam para `dev`.
- [ ] Commits seguem Conventional Commits.

### Testes esperados

- [ ] Revisao manual da ADR.
- [ ] Verificar consistencia com `NEXT_ACTIONS.md`.
- [ ] Confirmar que nada foi executado no Git.

### Documentacao

- [ ] `ADR-0001-branching-strategy.md` atualizado.

### Dependencias

Issue 1.

### Observacoes tecnicas

Nao fazer checkout, merge, push ou commit automatico.

## Issue 4 - Documentar escopo tecnico do MVP

Labels: `type:docs`, `module:docs`, `priority:P0`

Milestone: `M0 - Repository and Planning`

Branch sugerida: `docs/mvp-technical-scope`

PR base futura: `dev`

### Contexto

O MVP precisa focar no fluxo tecnico minimo e evitar expansao prematura.

### Objetivo

Registrar o escopo tecnico inicial: Windows 11, Arch Linux + Hyprland, IDD/IddCx, NVENC H.264, VA-API e LAN.

### Escopo

- Documentar tecnologias do MVP.
- Documentar fora de escopo.
- Registrar criterio de sucesso do MVP.

### Fora do escopo

- NAT traversal.
- UI sofisticada.

### Criterios de aceite

- [ ] ADR de escopo tecnico existe.
- [ ] NAT traversal esta fora do MVP.
- [ ] O fluxo monitor virtual -> host -> cliente esta explicito.

### Testes esperados

- [ ] Revisao manual da ADR.
- [ ] Comparacao com requisitos.
- [ ] Verificar riscos registrados.

### Documentacao

- [ ] `ADR-0002-mvp-technical-scope.md` atualizado.

### Dependencias

Issue 1.

### Observacoes tecnicas

O produto nao deve virar apenas compartilhamento de tela.

## Issue 5 - Planejar templates de issue e PR

Labels: `type:infra`, `module:github`, `priority:P0`

Milestone: `M0 - Repository and Planning`

Branch sugerida: `infra/github-templates`

PR base futura: `dev`

### Contexto

Issues e PRs precisam registrar escopo, testes, riscos e evidencias.

### Objetivo

Criar templates futuros para GitHub Issues e Pull Requests.

### Escopo

- Planejar template de issue.
- Planejar template de PR.
- Exigir vinculo com issue.

### Fora do escopo

- Criar issues reais.
- Abrir PR real.

### Criterios de aceite

- [ ] Template de issue inclui contexto, objetivo, escopo e criterios.
- [ ] Template de PR inclui testes, riscos e evidencias.
- [ ] Templates nao exigem campos irrelevantes para docs.

### Testes esperados

- [ ] Revisao manual dos templates.
- [ ] Simular preenchimento de uma issue.
- [ ] Simular preenchimento de um PR.

### Documentacao

- [ ] Documentar uso dos templates.

### Dependencias

Issue 1.

### Observacoes tecnicas

Os templates devem apoiar PRs pequenos, nao burocracia excessiva.

## Issue 6 - Planejar labels do GitHub

Labels: `type:infra`, `module:github`, `priority:P0`

Milestone: `M0 - Repository and Planning`

Branch sugerida: `infra/github-labels`

PR base futura: `dev`

### Contexto

Labels consistentes ajudam a filtrar modulo, tipo, prioridade e risco.

### Objetivo

Definir labels sugeridas para criacao manual no GitHub.

### Escopo

- Labels por tipo.
- Labels por modulo.
- Labels por prioridade, risco e status.

### Fora do escopo

- Criar labels reais automaticamente.
- Alterar milestones.

### Criterios de aceite

- [ ] `LABELS.md` lista nome, descricao e cor.
- [ ] Labels obrigatorias estao incluidas.
- [ ] Labels cobrem driver, host, cliente, protocolo, tools e docs.

### Testes esperados

- [ ] Revisao manual.
- [ ] Conferir nomes contra backlog.
- [ ] Conferir cores em hexadecimal.

### Documentacao

- [ ] `LABELS.md` atualizado.

### Dependencias

Issue 1.

### Observacoes tecnicas

As labels devem ser criadas manualmente depois da revisao.

## Issue 7 - Planejar milestones do GitHub

Labels: `type:infra`, `module:github`, `priority:P0`

Milestone: `M0 - Repository and Planning`

Branch sugerida: `infra/github-milestones`

PR base futura: `dev`

### Contexto

O roadmap precisa de milestones coerentes para priorizar o MVP.

### Objetivo

Documentar as milestones M0 a M9.

### Escopo

- Definir objetivo de cada milestone.
- Listar issues incluidas.
- Registrar riscos e dependencias.

### Fora do escopo

- Criar milestones reais no GitHub.
- Alterar backlog sem revisao.

### Criterios de aceite

- [ ] Todas as 10 milestones obrigatorias existem.
- [ ] Cada milestone tem criterio de conclusao.
- [ ] Issues estao associadas a milestones.

### Testes esperados

- [ ] Revisao manual.
- [ ] Conferir M0 a M9.
- [ ] Conferir referencias no backlog.

### Documentacao

- [ ] `MILESTONES.md` atualizado.

### Dependencias

Issue 1.

### Observacoes tecnicas

M0 cobre planejamento; M9 cobre release candidate.

## Issue 8 - Planejar CI inicial

Labels: `type:infra`, `module:github`, `priority:P1`

Milestone: `M0 - Repository and Planning`

Branch sugerida: `infra/ci-plan`

PR base futura: `dev`

### Contexto

O projeto tera builds Windows e Linux, mas a toolchain ainda precisa ser definida.

### Objetivo

Planejar uma estrategia inicial de CI sem bloquear os spikes.

### Escopo

- Descrever jobs futuros de Linux.
- Descrever jobs futuros de Windows.
- Planejar lint, formatacao e testes.

### Fora do escopo

- Exigir CI funcional antes dos spikes.
- Instalar WDK no CI sem pesquisa.

### Criterios de aceite

- [ ] Estrategia de CI esta documentada.
- [ ] Limites do CI inicial estao claros.
- [ ] Spikes nao ficam bloqueados por CI prematuro.

### Testes esperados

- [ ] Revisao manual.
- [ ] Validacao de YAML apenas se workflow real for criado.
- [ ] Conferir se CI nao executa tarefas destrutivas.

### Documentacao

- [ ] Guia de CI planejado atualizado.

### Dependencias

Issue 1.

### Observacoes tecnicas

Workflow real deve vir depois da escolha de build system.

## Issue 9 - Criar guia de contribuicao inicial

Labels: `type:docs`, `module:docs`, `priority:P1`

Milestone: `M0 - Repository and Planning`

Branch sugerida: `docs/contributing-guide`

PR base futura: `dev`

### Contexto

Contribuicoes futuras precisam seguir issues, branches e PRs pequenos.

### Objetivo

Criar guia inicial de contribuicao.

### Escopo

- Explicar fluxo issue -> branch -> PR -> `dev`.
- Explicar Conventional Commits.
- Explicar evidencias e testes esperados.

### Fora do escopo

- Politicas legais completas.
- CODEOWNERS definitivo.

### Criterios de aceite

- [ ] Guia descreve branch por issue.
- [ ] Guia proibe commit direto em `main`.
- [ ] Guia define evidencias minimas por PR.

### Testes esperados

- [ ] Revisao manual.
- [ ] Conferir consistencia com ADR-0001.
- [ ] Conferir exemplos de commits.

### Documentacao

- [ ] `CONTRIBUTING.md` futuro ou doc equivalente atualizado.

### Dependencias

Issue 3.

### Observacoes tecnicas

O guia deve permanecer curto o suficiente para ser usado.

## Issue 10 - Definir mensagens base do protocolo

Labels: `type:feature`, `module:protocol`, `priority:P0`

Milestone: `M2 - Protocol Foundation`

Branch sugerida: `feature/protocol-messages`

PR base futura: `dev`

### Contexto

Host e cliente precisam de contratos estaveis para controle, sessao e diagnostico.

### Objetivo

Definir mensagens base do protocolo sem acoplar a driver, codec ou renderizador.

### Escopo

- Mensagens de controle.
- Mensagens de erro.
- Mensagens de estatisticas.

### Fora do escopo

- Transporte UDP/QUIC concreto.
- Encode/decode de video.

### Criterios de aceite

- [ ] Mensagens base estao documentadas.
- [ ] Campos obrigatorios estao definidos.
- [ ] O protocolo nao depende de Windows ou Linux.

### Testes esperados

- [ ] Testes de serializacao quando implementado.
- [ ] Testes de desserializacao quando implementado.
- [ ] Teste de rejeicao de mensagem invalida.

### Documentacao

- [ ] Documentacao do protocolo atualizada.

### Dependencias

Issue 2.

### Observacoes tecnicas

Evitar adicionar informacoes especificas de NVENC ou VA-API nesta camada.

## Issue 11 - Definir handshake e versionamento

Labels: `type:feature`, `module:protocol`, `priority:P0`

Milestone: `M2 - Protocol Foundation`

Branch sugerida: `feature/protocol-handshake`

PR base futura: `dev`

### Contexto

Host e cliente precisam negociar versao, capacidades e parametros de sessao.

### Objetivo

Definir handshake e regras de versionamento do protocolo.

### Escopo

- Versao de protocolo.
- Capabilities de host e cliente.
- Erro para versao incompativel.

### Fora do escopo

- Pareamento por codigo.
- Criptografia de trafego.

### Criterios de aceite

- [ ] Handshake possui versao explicita.
- [ ] Capabilities sao negociadas.
- [ ] Versao incompativel falha com erro claro.

### Testes esperados

- [ ] Teste de handshake valido.
- [ ] Teste de versao incompativel.
- [ ] Teste de capabilities ausentes.

### Documentacao

- [ ] Fluxo de handshake documentado.

### Dependencias

Issue 10.

### Observacoes tecnicas

Manter espaco para evolucao futura sem quebrar clientes antigos desnecessariamente.

## Issue 12 - Definir formato de pacotes de video

Labels: `type:feature`, `module:protocol`, `priority:P0`

Milestone: `M2 - Protocol Foundation`

Branch sugerida: `feature/video-packet-format`

PR base futura: `dev`

### Contexto

O transporte de video precisa identificar frames, ordem, timestamps e fragmentos.

### Objetivo

Definir metadados de pacote de video para baixa latencia em LAN.

### Escopo

- Frame ID.
- Numero de sequencia.
- Timestamp e flags de keyframe/fragmento.

### Fora do escopo

- Implementar encoder.
- Implementar decoder.

### Criterios de aceite

- [ ] Campos obrigatorios estao definidos.
- [ ] Perda e reordenacao podem ser detectadas.
- [ ] Frames atrasados podem ser descartados pelo cliente.

### Testes esperados

- [ ] Teste de pacote valido.
- [ ] Teste de sequencia fora de ordem.
- [ ] Teste de pacote incompleto.

### Documentacao

- [ ] Formato de pacote documentado.

### Dependencias

Issue 10.

### Observacoes tecnicas

O pacote nao deve carregar politica de renderizacao.

## Issue 13 - Implementar testes unitarios do protocolo

Labels: `type:test`, `module:protocol`, `priority:P0`

Milestone: `M2 - Protocol Foundation`

Branch sugerida: `test/protocol-unit-tests`

PR base futura: `dev`

### Contexto

O protocolo e compartilhado por host e cliente e precisa ser testado cedo.

### Objetivo

Adicionar testes unitarios para contratos basicos do protocolo.

### Escopo

- Serializacao e desserializacao.
- Handshake e versionamento.
- Erros e estatisticas.

### Fora do escopo

- Testes de driver.
- Testes de renderizacao.

### Criterios de aceite

- [ ] Testes executam localmente.
- [ ] Casos invalidos sao cobertos.
- [ ] Falhas geram mensagens claras.

### Testes esperados

- [ ] Teste de round-trip.
- [ ] Teste de versao incompativel.
- [ ] Teste de estatisticas.

### Documentacao

- [ ] Instrucoes para rodar testes documentadas.

### Dependencias

Issue 10, Issue 11, Issue 12.

### Observacoes tecnicas

Framework de teste deve seguir o build system escolhido.

## Issue 14 - Documentar ADR de transporte inicial

Labels: `type:docs`, `module:docs`, `priority:P1`

Milestone: `M2 - Protocol Foundation`

Branch sugerida: `docs/transport-adr`

PR base futura: `dev`

### Contexto

UDP/RTP e QUIC sao candidatos iniciais; TCP puro nao atende bem video interativo de baixa latencia.

### Objetivo

Documentar a escolha inicial de transporte apos spike.

### Escopo

- Comparar UDP/RTP e QUIC.
- Registrar escolha inicial.
- Documentar riscos e alternativas.

### Fora do escopo

- NAT traversal.
- WebRTC completo no MVP.

### Criterios de aceite

- [ ] ADR inclui alternativas consideradas.
- [ ] ADR registra por que TCP puro nao e solucao final.
- [ ] ADR limita escopo a LAN.

### Testes esperados

- [ ] Revisao de evidencias do spike.
- [ ] Revisao manual da ADR.
- [ ] Validar consistencia com protocolo.

### Documentacao

- [ ] ADR de transporte criada.

### Dependencias

Issue 32.

### Observacoes tecnicas

WebRTC pode voltar em fase futura se NAT traversal virar requisito.

## Issue 15 - Spike: validar monitor virtual com IddCx

Labels: `type:spike`, `module:idd-driver`, `priority:P0`

Milestone: `M1 - Technical Spikes`

Branch sugerida: `spike/windows-idd-monitor`

PR base futura: `dev`

### Contexto

O driver IDD e o maior risco tecnico e define se o produto sera monitor real ou apenas screen sharing.

### Objetivo

Validar que um monitor virtual 1080p60 pode ser reconhecido pelo Windows 11.

### Escopo

- Usar IddCx/WDK em ambiente de desenvolvimento.
- Criar monitor virtual minimo.
- Registrar evidencias manuais.

### Fora do escopo

- Streaming.
- NVENC.

### Criterios de aceite

- [ ] Windows lista o monitor virtual.
- [ ] Modo estendido pode ser selecionado.
- [ ] Evidencia manual foi registrada.

### Testes esperados

- [ ] Teste manual no Windows 11.
- [ ] Validar instalacao/remocao de desenvolvimento.
- [ ] Registrar logs relevantes.

### Documentacao

- [ ] Notas do spike documentadas.

### Dependencias

Issue 4.

### Observacoes tecnicas

Usar IddSample como referencia oficial, sem copiar codigo incompatível.

## Issue 16 - Criar base do driver IDD

Labels: `type:feature`, `module:idd-driver`, `priority:P0`

Milestone: `M3 - Windows Virtual Display`

Branch sugerida: `feature/idd-driver-foundation`

PR base futura: `dev`

### Contexto

Apos o spike, o projeto precisa de uma base de driver revisavel.

### Objetivo

Criar fundacao do driver IDD do LumaBridge.

### Escopo

- Estrutura do projeto de driver.
- Inicializacao IddCx minima.
- Logs basicos.

### Fora do escopo

- Transporte.
- Encoder.

### Criterios de aceite

- [ ] Driver compila no ambiente WDK previsto.
- [ ] Inicializacao minima esta isolada.
- [ ] Falhas sao registradas claramente.

### Testes esperados

- [ ] Build local no Windows.
- [ ] Teste manual de carga do driver.
- [ ] Revisao de logs.

### Documentacao

- [ ] Requisitos de build documentados.

### Dependencias

Issue 15.

### Observacoes tecnicas

Manter escopo pequeno para revisar risco de driver.

## Issue 17 - Expor modos de video iniciais

Labels: `type:feature`, `module:idd-driver`, `priority:P0`

Milestone: `M3 - Windows Virtual Display`

Branch sugerida: `feature/idd-video-modes`

PR base futura: `dev`

### Contexto

O MVP precisa de modos de video configuraveis, com foco em 1080p60.

### Objetivo

Expor modos 720p60, 1080p60 e 1440p60 quando suportado.

### Escopo

- Adicionar lista de modos.
- Validar 1080p60.
- Documentar limitacoes.

### Fora do escopo

- HDR.
- Multiplos monitores.

### Criterios de aceite

- [ ] 720p60 aparece quando configurado.
- [ ] 1080p60 aparece e funciona.
- [ ] 1440p60 aparece quando suportado.

### Testes esperados

- [ ] Teste manual no Windows.
- [ ] Validar configuracoes de display.
- [ ] Registrar evidencia.

### Documentacao

- [ ] Modos suportados documentados.

### Dependencias

Issue 16.

### Observacoes tecnicas

1440p60 pode depender de rede e cliente, mas o modo pode ser exposto para teste.

## Issue 18 - Processar swapchain do monitor virtual

Labels: `type:feature`, `module:idd-driver`, `priority:P0`

Milestone: `M3 - Windows Virtual Display`

Branch sugerida: `feature/idd-swapchain-processing`

PR base futura: `dev`

### Contexto

O host precisa receber frames reais do monitor virtual, nao capturar a tela principal.

### Objetivo

Processar a swapchain entregue ao driver e medir frames basicos.

### Escopo

- Receber/processar swapchain.
- Contar frames.
- Registrar timing basico.

### Fora do escopo

- Codificar com NVENC.
- Enviar pela rede.

### Criterios de aceite

- [ ] Frames do display virtual sao observados.
- [ ] Contador de frames funciona.
- [ ] Timing basico e registrado.

### Testes esperados

- [ ] Teste manual com conteudo no monitor virtual.
- [ ] Verificar que nao e captura da tela principal.
- [ ] Registrar logs.

### Documentacao

- [ ] Fluxo de frames documentado.

### Dependencias

Issue 16.

### Observacoes tecnicas

A integracao com host deve evitar copia GPU -> CPU desnecessaria.

## Issue 19 - Documentar instalacao de desenvolvimento do driver

Labels: `type:docs`, `module:docs`, `priority:P0`

Milestone: `M3 - Windows Virtual Display`

Branch sugerida: `docs/windows-driver-setup`

PR base futura: `dev`

### Contexto

Driver Windows exige setup cuidadoso com WDK, modo teste e remocao segura.

### Objetivo

Documentar instalacao e remocao do driver em ambiente de desenvolvimento.

### Escopo

- Requisitos de Visual Studio, SDK e WDK.
- Modo teste.
- Instalacao e remocao.

### Fora do escopo

- Assinatura de producao.
- Instalador publico.

### Criterios de aceite

- [ ] Guia lista pre-requisitos.
- [ ] Guia inclui remocao.
- [ ] Riscos de driver estao explicitos.

### Testes esperados

- [ ] Revisao manual.
- [ ] Execucao por uma pessoa em ambiente Windows.
- [ ] Validar que o guia nao promete assinatura publica.

### Documentacao

- [ ] `docs/setup/windows-host.md` atualizado.

### Dependencias

Issue 16.

### Observacoes tecnicas

Falhas no driver devem ser tratadas como risco alto.

## Issue 20 - Spike: validar encode NVENC com frames sinteticos

Labels: `type:spike`, `module:host`, `priority:P0`

Milestone: `M1 - Technical Spikes`

Branch sugerida: `spike/windows-nvenc-encoder`

PR base futura: `dev`

### Contexto

O host precisa codificar H.264 com baixa latencia usando NVENC na RTX 3060 Ti.

### Objetivo

Validar encode H.264 por NVENC com frames sinteticos.

### Escopo

- Inicializar NVENC.
- Codificar frames sinteticos.
- Registrar tempo de encode.

### Fora do escopo

- Driver IDD.
- Transporte final.

### Criterios de aceite

- [ ] NVENC e detectado.
- [ ] Bitstream H.264 e gerado.
- [ ] Erro claro aparece quando NVENC nao esta disponivel.

### Testes esperados

- [ ] Teste local no Windows com GPU NVIDIA.
- [ ] Registrar logs de inicializacao.
- [ ] Medir tempo de encode basico.

### Documentacao

- [ ] Resultado do spike documentado.

### Dependencias

Issue 4.

### Observacoes tecnicas

Usar preset de baixa latencia, B-frames 0 e lookahead desligado inicialmente.

## Issue 21 - Criar host CLI minimo

Labels: `type:feature`, `module:host`, `priority:P0`

Milestone: `M4 - Windows Host Pipeline`

Branch sugerida: `feature/windows-host-cli`

PR base futura: `dev`

### Contexto

O MVP pode usar CLI/configuracao antes de UI sofisticada.

### Objetivo

Criar aplicacao host minima para iniciar, parar, carregar configuracao e emitir logs.

### Escopo

- CLI inicial.
- Configuracao basica.
- Logs estruturados.

### Fora do escopo

- UI final.
- Driver completo.

### Criterios de aceite

- [ ] Host inicia por CLI.
- [ ] Configuracao invalida gera erro claro.
- [ ] Logs mostram estado da sessao.

### Testes esperados

- [ ] Teste unitario de config, se aplicavel.
- [ ] Teste manual de inicializacao.
- [ ] Teste manual de erro de config.

### Documentacao

- [ ] Uso da CLI documentado.

### Dependencias

Issue 10.

### Observacoes tecnicas

Manter host desacoplado de UI.

## Issue 22 - Integrar pipeline D3D de frames sinteticos

Labels: `type:feature`, `module:host`, `priority:P0`

Milestone: `M4 - Windows Host Pipeline`

Branch sugerida: `feature/host-synthetic-frames`

PR base futura: `dev`

### Contexto

Frames sinteticos permitem testar encoder e transporte antes do driver real estar pronto.

### Objetivo

Criar fonte de frames sinteticos no pipeline D3D do host.

### Escopo

- Gerar textura/frame sintetico.
- Medir timing.
- Encaminhar ao encoder.

### Fora do escopo

- Receber frame real do driver.
- Renderizar no cliente.

### Criterios de aceite

- [ ] Frames sinteticos sao gerados em FPS configuravel.
- [ ] Pipeline reporta contador de frames.
- [ ] Frames podem alimentar NVENC.

### Testes esperados

- [ ] Teste manual do pipeline.
- [ ] Teste de contador de frames.
- [ ] Medicao basica de timing.

### Documentacao

- [ ] Modo sintetico documentado.

### Dependencias

Issue 20, Issue 21.

### Observacoes tecnicas

Este modo ajuda a isolar problemas de driver.

## Issue 23 - Integrar NVENC H.264 ao host

Labels: `type:feature`, `module:host`, `priority:P0`

Milestone: `M4 - Windows Host Pipeline`

Branch sugerida: `feature/host-nvenc-h264`

PR base futura: `dev`

### Contexto

O host precisa codificar frames do pipeline com baixa latencia.

### Objetivo

Integrar NVENC H.264 ao host.

### Escopo

- Inicializar encoder.
- Enviar frames.
- Receber bitstream e metricas.

### Fora do escopo

- HEVC obrigatorio.
- AV1.

### Criterios de aceite

- [ ] NVENC codifica frames do host.
- [ ] Latencia de encode e registrada.
- [ ] Erros de NVENC sao claros.

### Testes esperados

- [ ] Teste com frames sinteticos.
- [ ] Teste de GPU sem suporte, se disponivel.
- [ ] Verificar parametros low latency.

### Documentacao

- [ ] Configuracao de encoder documentada.

### Dependencias

Issue 20, Issue 22.

### Observacoes tecnicas

HEVC pode ser adicionado depois; H.264 e o primeiro codec.

## Issue 24 - Implementar envio LAN inicial no host

Labels: `type:feature`, `module:host`, `priority:P0`

Milestone: `M4 - Windows Host Pipeline`

Branch sugerida: `feature/host-lan-send`

PR base futura: `dev`

### Contexto

O host precisa enviar bitstream e metadados ao cliente em LAN.

### Objetivo

Implementar envio LAN inicial para stream de video.

### Escopo

- Enviar pacotes com frame ID.
- Enviar sequencia e timestamp.
- Registrar perda/erros quando possivel.

### Fora do escopo

- NAT traversal.
- Relay pela internet.

### Criterios de aceite

- [ ] Pacotes contem metadados obrigatorios.
- [ ] Stream sintetico pode ser enviado.
- [ ] Falha de rede gera log claro.

### Testes esperados

- [ ] Teste local LAN.
- [ ] Teste de cliente mock ou ferramenta.
- [ ] Teste de perda simulada, se aplicavel.

### Documentacao

- [ ] Formato de envio documentado.

### Dependencias

Issue 12, Issue 23.

### Observacoes tecnicas

Evitar TCP puro como caminho final de baixa latencia.

## Issue 25 - Integrar frames reais do driver no host

Labels: `type:feature`, `module:host`, `priority:P0`

Milestone: `M4 - Windows Host Pipeline`

Branch sugerida: `feature/host-driver-frames`

PR base futura: `dev`

### Contexto

O MVP exige conteudo real do monitor virtual, nao apenas frames sinteticos.

### Objetivo

Integrar frames reais do driver ao pipeline do host.

### Escopo

- Receber frames/texturas do display virtual.
- Medir latencia de captura.
- Encaminhar para NVENC.

### Fora do escopo

- Renderizacao no Linux.
- UI sofisticada.

### Criterios de aceite

- [ ] Conteudo do monitor virtual chega ao host.
- [ ] Frames reais alimentam o encoder.
- [ ] Copias CPU/GPU sao medidas.

### Testes esperados

- [ ] Teste manual com janela no monitor virtual.
- [ ] Verificar que tela principal nao e capturada.
- [ ] Registrar timing de captura.

### Documentacao

- [ ] Fluxo driver-host documentado.

### Dependencias

Issue 18, Issue 23.

### Observacoes tecnicas

Evitar pipeline GPU -> CPU -> GPU.


## Issue 26 - Spike: validar decode VA-API no Arch Linux

Labels: `type:spike`, `module:client`, `priority:P0`

Milestone: `M1 - Technical Spikes`

Branch sugerida: `spike/linux-vaapi-decoder`

PR base futura: `dev`

### Contexto

O cliente Linux deve decodificar H.264 com VA-API na iGPU Intel quando disponivel.

### Objetivo

Validar decode H.264 via VA-API no Arch Linux.

### Escopo

- Instalar/verificar dependencias VA-API.
- Decodificar sample H.264.
- Registrar hardware decode ou fallback diagnostico.

### Fora do escopo

- Render fullscreen final.
- Recepcao de rede final.

### Criterios de aceite

- [ ] Sample H.264 decodifica.
- [ ] O cliente informa se VA-API esta ativo.
- [ ] Fallback software e tratado como diagnostico.

### Testes esperados

- [ ] Teste manual no Arch Linux.
- [ ] Verificar `vainfo` ou ferramenta equivalente.
- [ ] Registrar logs de decoder.

### Documentacao

- [ ] Resultado do spike documentado.

### Dependencias

Issue 4.

### Observacoes tecnicas

VA-API pode variar conforme geracao Intel e pacote instalado.

## Issue 27 - Criar cliente Linux CLI minimo

Labels: `type:feature`, `module:client`, `priority:P0`

Milestone: `M5 - Linux Client Pipeline`

Branch sugerida: `feature/linux-client-cli`

PR base futura: `dev`

### Contexto

O cliente precisa iniciar sem UI sofisticada e conectar por IP manual.

### Objetivo

Criar CLI minima do cliente Linux.

### Escopo

- Inicializacao do cliente.
- Configuracao basica.
- Conexao por IP manual.

### Fora do escopo

- Descoberta LAN automatica.
- UI grafica final.

### Criterios de aceite

- [ ] Cliente inicia por CLI.
- [ ] IP manual pode ser informado.
- [ ] Erros de conexao sao claros.

### Testes esperados

- [ ] Teste manual de CLI.
- [ ] Teste de configuracao invalida.
- [ ] Teste de host indisponivel.

### Documentacao

- [ ] Uso basico do cliente documentado.

### Dependencias

Issue 10.

### Observacoes tecnicas

Nao depender de X11; o alvo inicial e Wayland/Hyprland.

## Issue 28 - Implementar recepcao de pacotes no cliente

Labels: `type:feature`, `module:client`, `priority:P0`

Milestone: `M5 - Linux Client Pipeline`

Branch sugerida: `feature/client-packet-receiver`

PR base futura: `dev`

### Contexto

O cliente precisa receber pacotes do host e identificar perda, ordem e atraso.

### Objetivo

Implementar receiver de pacotes de video no cliente.

### Escopo

- Receber pacotes LAN.
- Validar metadados.
- Reportar perda e ordem.

### Fora do escopo

- Decode final.
- Render final.

### Criterios de aceite

- [ ] Pacotes sao recebidos continuamente.
- [ ] Sequencia fora de ordem e detectada.
- [ ] Pacotes invalidos sao rejeitados.

### Testes esperados

- [ ] Teste com host sintetico.
- [ ] Teste de perda simulada.
- [ ] Teste de pacote invalido.

### Documentacao

- [ ] Receiver documentado.

### Dependencias

Issue 12, Issue 27.

### Observacoes tecnicas

O receiver deve manter fila minima para baixa latencia.

## Issue 29 - Integrar decoder H.264 VA-API

Labels: `type:feature`, `module:client`, `priority:P0`

Milestone: `M5 - Linux Client Pipeline`

Branch sugerida: `feature/client-vaapi-h264`

PR base futura: `dev`

### Contexto

O cliente precisa transformar o bitstream recebido em frames renderizaveis.

### Objetivo

Integrar decoder H.264 com VA-API.

### Escopo

- Inicializar decoder.
- Alimentar bitstream.
- Emitir frames decodificados.

### Fora do escopo

- HEVC obrigatorio.
- Renderizador final sofisticado.

### Criterios de aceite

- [ ] H.264 decodifica com VA-API quando disponivel.
- [ ] Fallback software e identificado como diagnostico.
- [ ] Erros de driver ausente sao claros.

### Testes esperados

- [ ] Teste com sample H.264.
- [ ] Teste com stream sintetico.
- [ ] Verificar uso de CPU em condicao normal.

### Documentacao

- [ ] Dependencias VA-API documentadas.

### Dependencias

Issue 26, Issue 28.

### Observacoes tecnicas

Manter fallback software fora do caminho recomendado de uso.

## Issue 30 - Criar render fullscreen Wayland/Hyprland

Labels: `type:feature`, `module:client`, `priority:P0`

Milestone: `M5 - Linux Client Pipeline`

Branch sugerida: `feature/client-wayland-fullscreen`

PR base futura: `dev`

### Contexto

O laptop Linux deve exibir o monitor virtual em fullscreen no Hyprland.

### Objetivo

Criar renderizador fullscreen para frames do cliente.

### Escopo

- Abrir janela fullscreen.
- Preservar proporcao do frame.
- Implementar atalho de saida.

### Fora do escopo

- Captura de input global.
- UI sofisticada.

### Criterios de aceite

- [ ] Janela abre em fullscreen no Hyprland.
- [ ] Frame nao fica esticado incorretamente.
- [ ] Usuario consegue sair com atalho configuravel.

### Testes esperados

- [ ] Teste manual no Hyprland.
- [ ] Teste com frames sinteticos.
- [ ] Teste de redimensionamento/resolucao.

### Documentacao

- [ ] Requisitos de render documentados.

### Dependencias

Issue 27.

### Observacoes tecnicas

SDL2 + OpenGL/EGL, wgpu ou Vulkan devem ser escolhidos com base em simplicidade e latencia.

## Issue 31 - Implementar descarte de frames atrasados

Labels: `type:feature`, `module:client`, `priority:P0`

Milestone: `M5 - Linux Client Pipeline`

Branch sugerida: `feature/client-late-frame-drop`

PR base futura: `dev`

### Contexto

Video interativo nao deve acumular fila; frames muito atrasados devem ser descartados.

### Objetivo

Implementar politica de descarte de frames atrasados no cliente.

### Escopo

- Identificar frames atrasados.
- Descartar frames fora do limite.
- Registrar metrica de descarte.

### Fora do escopo

- Retransmissao bloqueante.
- Buffer grande para qualidade maxima.

### Criterios de aceite

- [ ] Frames atrasados sao descartados.
- [ ] Fila nao cresce indefinidamente.
- [ ] Contador de frames descartados e exibido.

### Testes esperados

- [ ] Teste com jitter simulado.
- [ ] Teste de perda simulada.
- [ ] Teste de recuperacao apos atraso.

### Documentacao

- [ ] Politica de descarte documentada.

### Dependencias

Issue 28, Issue 29.

### Observacoes tecnicas

Priorizar baixa latencia sobre exibicao tardia de frames antigos.

## Issue 32 - Spike: validar transporte LAN de baixa latencia

Labels: `type:spike`, `module:tools`, `priority:P0`

Milestone: `M1 - Technical Spikes`

Branch sugerida: `spike/lan-transport`

PR base futura: `dev`

### Contexto

O transporte define perda, jitter, latencia e estrategia de descarte.

### Objetivo

Validar transporte LAN inicial com payload sintetico.

### Escopo

- Testar UDP/RTP ou QUIC.
- Enviar payload com sequencia e timestamp.
- Medir perda, jitter e latencia.

### Fora do escopo

- NAT traversal.
- WebRTC completo.

### Criterios de aceite

- [ ] Payload sintetico trafega em LAN.
- [ ] Perda e jitter sao medidos.
- [ ] Resultado orienta ADR de transporte.

### Testes esperados

- [ ] Teste em localhost.
- [ ] Teste em LAN.
- [ ] Teste com perda simulada, se possivel.

### Documentacao

- [ ] Resultado do spike documentado.

### Dependencias

Issue 4.

### Observacoes tecnicas

TCP puro nao deve ser tratado como solucao final de baixa latencia.

## Issue 33 - Criar inspetor de codecs

Labels: `type:task`, `module:tools`, `priority:P1`

Milestone: `M8 - UX and Packaging`

Branch sugerida: `feature/codec-inspector`

PR base futura: `dev`

### Contexto

Usuarios precisam diagnosticar disponibilidade de NVENC e VA-API.

### Objetivo

Criar ferramenta de inspecao de codecs e ambiente.

### Escopo

- Verificar NVENC no host.
- Verificar VA-API no cliente.
- Gerar relatorio simples.

### Fora do escopo

- Corrigir drivers automaticamente.
- Alterar configuracao do sistema sem confirmacao.

### Criterios de aceite

- [ ] Relatorio indica suporte NVENC.
- [ ] Relatorio indica suporte VA-API.
- [ ] Dependencias ausentes sao listadas.

### Testes esperados

- [ ] Teste em ambiente com suporte.
- [ ] Teste em ambiente sem suporte.
- [ ] Verificar que segredos nao aparecem no relatorio.

### Documentacao

- [ ] Uso da ferramenta documentado.

### Dependencias

Issue 20, Issue 26.

### Observacoes tecnicas

Ferramentas auxiliares nao devem virar dependencia obrigatoria do runtime.

## Issue 34 - Criar medidor de latencia

Labels: `type:task`, `module:tools`, `priority:P1`

Milestone: `M9 - Optimization and Release Candidate`

Branch sugerida: `feature/latency-tester`

PR base futura: `dev`

### Contexto

O produto precisa medir latencia por etapa para otimizar de forma objetiva.

### Objetivo

Criar medidor de latencia para pipeline host-cliente.

### Escopo

- Registrar timestamps.
- Calcular latencia aproximada.
- Gerar relatorio.

### Fora do escopo

- Garantir sincronizacao perfeita de relogios.
- Otimizar automaticamente o pipeline.

### Criterios de aceite

- [ ] Relatorio mostra etapas medidas.
- [ ] Limitacoes de medicao estao documentadas.
- [ ] Saida pode ser anexada a PRs.

### Testes esperados

- [ ] Teste com stream sintetico.
- [ ] Teste com stream real quando disponivel.
- [ ] Validar unidades e timestamps.

### Documentacao

- [ ] Guia de interpretacao das metricas documentado.

### Dependencias

Issue 35.

### Observacoes tecnicas

Latencia fim-a-fim pode exigir calibracao ou estimativa por eventos visuais.

## Issue 35 - Integrar stream sintetico host-cliente

Labels: `type:feature`, `module:host`, `priority:P0`

Milestone: `M6 - LAN MVP Integration`

Branch sugerida: `feature/synthetic-stream-integration`

PR base futura: `dev`

### Contexto

Antes de integrar o driver real, host e cliente precisam provar o caminho de stream.

### Objetivo

Integrar host e cliente usando frames sinteticos em LAN.

### Escopo

- Host envia frames sinteticos.
- Cliente recebe, decodifica e renderiza.
- Metricas basicas sao registradas.

### Fora do escopo

- Monitor virtual real.
- Pareamento.

### Criterios de aceite

- [ ] Cliente renderiza frames sinteticos recebidos.
- [ ] Perda e atraso sao reportados.
- [ ] Sessao encerra sem travar.

### Testes esperados

- [ ] Teste em LAN.
- [ ] Teste de desconexao.
- [ ] Teste de perda simulada.

### Documentacao

- [ ] Fluxo sintetico documentado.

### Dependencias

Issue 24, Issue 28, Issue 30.

### Observacoes tecnicas

Este teste reduz variaveis antes da integracao com o driver.

## Issue 36 - Integrar monitor virtual real ao stream

Labels: `type:feature`, `module:host`, `priority:P0`

Milestone: `M6 - LAN MVP Integration`

Branch sugerida: `feature/virtual-display-stream`

PR base futura: `dev`

### Contexto

O criterio central do MVP e transmitir o conteudo do monitor virtual real.

### Objetivo

Transmitir frames reais do monitor virtual Windows para o cliente Linux.

### Escopo

- Conectar driver ao host.
- Codificar frames reais.
- Renderizar no cliente fullscreen.

### Fora do escopo

- UI sofisticada.
- Multiplos monitores.

### Criterios de aceite

- [ ] Janela arrastada para monitor virtual aparece no cliente.
- [ ] Conteudo corresponde ao display virtual.
- [ ] Tela principal nao e capturada por engano.

### Testes esperados

- [ ] Teste manual Windows + Arch/Hyprland.
- [ ] Teste de desconexao do cliente.
- [ ] Registro de FPS e bitrate.

### Documentacao

- [ ] Procedimento de teste manual documentado.

### Dependencias

Issue 25, Issue 29, Issue 30.

### Observacoes tecnicas

Esta e a entrega mais importante do MVP.

## Issue 37 - Testar 1080p60 em LAN

Labels: `type:test`, `module:tools`, `priority:P0`

Milestone: `M6 - LAN MVP Integration`

Branch sugerida: `test/lan-1080p60`

PR base futura: `dev`

### Contexto

O MVP mira 1920x1080@60fps em LAN em condicoes boas.

### Objetivo

Validar desempenho 1080p60 em LAN.

### Escopo

- Medir FPS medio e minimo.
- Medir bitrate e perda.
- Medir latencia aproximada.

### Fora do escopo

- Otimizacao final.
- Teste pela internet.

### Criterios de aceite

- [ ] 1080p60 roda em LAN cabeada em condicoes boas.
- [ ] Metricas sao registradas.
- [ ] Limitacoes sao documentadas.

### Testes esperados

- [ ] Teste LAN cabeada.
- [ ] Teste Wi-Fi bom, se disponivel.
- [ ] Registro de CPU/GPU host e cliente.

### Documentacao

- [ ] Relatorio de teste atualizado.

### Dependencias

Issue 36.

### Observacoes tecnicas

Meta inicial: abaixo de 50 ms em LAN cabeada quando possivel.

## Issue 38 - Adicionar overlay/log de metricas basicas

Labels: `type:feature`, `module:client`, `priority:P1`

Milestone: `M6 - LAN MVP Integration`

Branch sugerida: `feature/session-metrics`

PR base futura: `dev`

### Contexto

Metricas sao essenciais para diagnosticar latencia, perda e desempenho.

### Objetivo

Adicionar metricas basicas em overlay opcional e logs.

### Escopo

- FPS.
- Bitrate, perda, jitter e frames descartados.
- Encode/decode time quando disponivel.

### Fora do escopo

- Dashboard remoto.
- Telemetria externa.

### Criterios de aceite

- [ ] Metricas aparecem no cliente.
- [ ] Logs registram estatisticas periodicas.
- [ ] Overlay pode ser desativado.

### Testes esperados

- [ ] Teste com stream ativo.
- [ ] Teste com perda simulada.
- [ ] Verificar unidades e nomes.

### Documentacao

- [ ] Metricas documentadas.

### Dependencias

Issue 31, Issue 37.

### Observacoes tecnicas

Logs nao devem expor chaves ou segredos.

## Issue 39 - Implementar pareamento por codigo

Labels: `type:feature`, `module:protocol`, `priority:P1`

Milestone: `M7 - Security and Pairing`

Branch sugerida: `feature/pairing-code`

PR base futura: `dev`

### Contexto

O host deve evitar conexoes acidentais ou nao autorizadas na LAN.

### Objetivo

Implementar fluxo de pareamento por codigo temporario.

### Escopo

- Host exibe codigo.
- Cliente envia codigo.
- Segredo local e criado apos pareamento.

### Fora do escopo

- Criptografia completa do trafego.
- Servidor externo.

### Criterios de aceite

- [ ] Cliente com codigo correto e pareado.
- [ ] Codigo incorreto e rejeitado.
- [ ] Segredo local nao aparece em logs.

### Testes esperados

- [ ] Teste de pareamento valido.
- [ ] Teste de codigo invalido.
- [ ] Teste de expiracao do codigo.

### Documentacao

- [ ] Fluxo de pareamento documentado.

### Dependencias

Issue 36.

### Observacoes tecnicas

O codigo deve ser temporario e revogavel por reinicio/acao do host.

## Issue 40 - Autenticar sessoes pareadas

Labels: `type:feature`, `module:protocol`, `priority:P1`

Milestone: `M7 - Security and Pairing`

Branch sugerida: `feature/session-auth`

PR base futura: `dev`

### Contexto

Pareamento so e util se sessoes futuras forem autenticadas.

### Objetivo

Autenticar sessoes com segredo local de cliente pareado.

### Escopo

- Validar cliente pareado.
- Rejeitar cliente nao autorizado.
- Registrar falhas sem expor segredo.

### Fora do escopo

- Criptografia caseira.
- NAT traversal seguro.

### Criterios de aceite

- [ ] Cliente pareado conecta.
- [ ] Cliente nao pareado e rejeitado.
- [ ] Segredos nao aparecem em logs.

### Testes esperados

- [ ] Teste de sessao autenticada.
- [ ] Teste de cliente nao pareado.
- [ ] Teste de segredo corrompido.

### Documentacao

- [ ] Autenticacao de sessao documentada.

### Dependencias

Issue 39.

### Observacoes tecnicas

Usar HMAC ou biblioteca consolidada; nao inventar criptografia.

## Issue 41 - Implementar revogacao de clientes pareados

Labels: `type:feature`, `module:host`, `priority:P2`

Milestone: `M7 - Security and Pairing`

Branch sugerida: `feature/revoke-paired-clients`

PR base futura: `dev`

### Contexto

O usuario precisa remover clientes pareados.

### Objetivo

Permitir revogar clientes autorizados.

### Escopo

- Listar clientes pareados por CLI/config.
- Remover cliente pareado.
- Rejeitar cliente revogado.

### Fora do escopo

- UI grafica final.
- Sincronizacao em nuvem.

### Criterios de aceite

- [ ] Cliente pareado pode ser removido.
- [ ] Cliente revogado nao conecta.
- [ ] Acao de revogacao e registrada em log.

### Testes esperados

- [ ] Teste de revogacao.
- [ ] Teste de tentativa pos-revogacao.
- [ ] Teste de arquivo de pareamento invalido.

### Documentacao

- [ ] Revogacao documentada.

### Dependencias

Issue 40.

### Observacoes tecnicas

Nao registrar segredo bruto nos logs.

## Issue 42 - Criar configuracao persistente

Labels: `type:feature`, `module:host`, `priority:P1`

Milestone: `M8 - UX and Packaging`

Branch sugerida: `feature/runtime-config`

PR base futura: `dev`

### Contexto

Host e cliente precisam salvar configuracoes basicas sem recompilar.

### Objetivo

Criar configuracao persistente para parametros de runtime.

### Escopo

- Resolucao, FPS, codec e bitrate.
- Host/IP preferido.
- Caminhos de chaves de pareamento.

### Fora do escopo

- UI grafica de configuracao.
- Sincronizacao remota.

### Criterios de aceite

- [ ] Configuracao valida e carregada.
- [ ] Configuracao invalida gera erro claro.
- [ ] Valores padrao sao documentados.

### Testes esperados

- [ ] Teste de arquivo valido.
- [ ] Teste de campo ausente.
- [ ] Teste de valor invalido.

### Documentacao

- [ ] Exemplo de configuracao documentado.

### Dependencias

Issue 21, Issue 27.

### Observacoes tecnicas

Escolher formato simples e facil de validar.

## Issue 43 - Criar guia de setup Windows host

Labels: `type:docs`, `module:docs`, `priority:P1`

Milestone: `M8 - UX and Packaging`

Branch sugerida: `docs/windows-host-setup`

PR base futura: `dev`

### Contexto

Setup Windows envolve WDK, Visual Studio, NVIDIA SDK e driver em modo teste.

### Objetivo

Criar guia de setup do host Windows.

### Escopo

- Pre-requisitos.
- Build e execucao.
- Diagnostico de NVENC e driver.

### Fora do escopo

- Instalador publico assinado.
- Suporte a Windows antigo.

### Criterios de aceite

- [ ] Guia lista dependencias.
- [ ] Guia descreve fluxo de desenvolvimento.
- [ ] Guia inclui troubleshooting inicial.

### Testes esperados

- [ ] Revisao manual.
- [ ] Execucao por uma pessoa em Windows.
- [ ] Verificar comandos perigosos destacados.

### Documentacao

- [ ] `docs/setup/windows-host.md` criado ou atualizado.

### Dependencias

Issue 19, Issue 23.

### Observacoes tecnicas

Documentar claramente que assinatura de producao fica fora do MVP.

## Issue 44 - Criar guia de setup Arch Linux client

Labels: `type:docs`, `module:docs`, `priority:P1`

Milestone: `M8 - UX and Packaging`

Branch sugerida: `docs/arch-client-setup`

PR base futura: `dev`

### Contexto

O cliente alvo usa Arch Linux, Hyprland, Wayland e iGPU Intel.

### Objetivo

Criar guia de setup do cliente Arch Linux.

### Escopo

- Pacotes VA-API.
- FFmpeg/GStreamer conforme decisao.
- SDL2/Wayland/render dependencies.

### Fora do escopo

- Distros Linux nao alvo.
- Cliente Android/iOS.

### Criterios de aceite

- [ ] Guia lista pacotes Arch.
- [ ] Guia explica verificacao VA-API.
- [ ] Guia cobre fullscreen no Hyprland.

### Testes esperados

- [ ] Revisao manual.
- [ ] Validar comandos em ambiente Arch.
- [ ] Verificar diagnostico `vainfo` ou equivalente.

### Documentacao

- [ ] `docs/setup/arch-linux-client.md` criado ou atualizado.

### Dependencias

Issue 29, Issue 30.

### Observacoes tecnicas

Wayland pode restringir input futuro; documentar como risco.

## Issue 45 - Criar troubleshooting inicial

Labels: `type:docs`, `module:docs`, `priority:P1`

Milestone: `M8 - UX and Packaging`

Branch sugerida: `docs/troubleshooting`

PR base futura: `dev`

### Contexto

Driver, NVENC, VA-API, rede e fullscreen podem falhar por motivos diferentes.

### Objetivo

Criar guia inicial de troubleshooting.

### Escopo

- Problemas de driver.
- Problemas NVENC/VA-API.
- Problemas de rede e fullscreen.

### Fora do escopo

- Suporte a hardware nao alvo.
- Diagnostico automatico completo.

### Criterios de aceite

- [ ] Guia lista sintomas comuns.
- [ ] Guia inclui causas provaveis.
- [ ] Guia inclui verificacoes objetivas.

### Testes esperados

- [ ] Revisao manual.
- [ ] Validar contra falhas conhecidas dos spikes.
- [ ] Verificar que nao ha segredos em exemplos de logs.

### Documentacao

- [ ] `docs/troubleshooting.md` criado ou atualizado.

### Dependencias

Issue 37, Issue 38.

### Observacoes tecnicas

Troubleshooting deve separar falha de driver, falha de codec e falha de rede.

## Issue 46 - Medir latencia fim-a-fim

Labels: `type:test`, `module:tools`, `priority:P1`

Milestone: `M9 - Optimization and Release Candidate`

Branch sugerida: `test/end-to-end-latency`

PR base futura: `dev`

### Contexto

O MVP tem meta de baixa latencia e precisa de medicao reproduzivel.

### Objetivo

Medir latencia fim-a-fim em LAN.

### Escopo

- Medir encode, rede, decode e render quando possivel.
- Gerar relatorio.
- Comparar LAN cabeada e Wi-Fi bom.

### Fora do escopo

- Garantir latencia pela internet.
- Otimizacao automatica.

### Criterios de aceite

- [ ] Relatorio de latencia existe.
- [ ] LAN cabeada foi medida.
- [ ] Limitacoes da metodologia estao descritas.

### Testes esperados

- [ ] Teste 1080p60 LAN cabeada.
- [ ] Teste Wi-Fi bom, se disponivel.
- [ ] Verificar consistencia de metricas.

### Documentacao

- [ ] Relatorio de performance atualizado.

### Dependencias

Issue 34, Issue 37.

### Observacoes tecnicas

Meta inicial: abaixo de 50 ms em LAN cabeada em condicoes boas.

## Issue 47 - Otimizar configuracao NVENC

Labels: `type:task`, `module:host`, `priority:P1`

Milestone: `M9 - Optimization and Release Candidate`

Branch sugerida: `feature/nvenc-low-latency-tuning`

PR base futura: `dev`

### Contexto

NVENC precisa ser configurado para baixa latencia, nao apenas qualidade maxima.

### Objetivo

Ajustar parametros de NVENC com base em metricas.

### Escopo

- Preset low latency.
- GOP, bitrate e VBV.
- B-frames e lookahead.

### Fora do escopo

- AV1.
- Otimizacao para internet.

### Criterios de aceite

- [ ] Parametros escolhidos sao documentados.
- [ ] Comparativo antes/depois existe.
- [ ] Qualidade visual continua aceitavel.

### Testes esperados

- [ ] Teste 1080p60.
- [ ] Teste de cenas com texto.
- [ ] Medir latencia de encode.

### Documentacao

- [ ] Configuracao NVENC documentada.

### Dependencias

Issue 46.

### Observacoes tecnicas

Comecar com B-frames 0 e lookahead desativado.

## Issue 48 - Otimizar buffer e frame pacing do cliente

Labels: `type:task`, `module:client`, `priority:P1`

Milestone: `M9 - Optimization and Release Candidate`

Branch sugerida: `feature/client-frame-pacing`

PR base futura: `dev`

### Contexto

O cliente precisa equilibrar suavidade, jitter e baixa latencia.

### Objetivo

Ajustar buffer, descarte e frame pacing do cliente.

### Escopo

- Queue depth.
- Descarte de frames atrasados.
- Vsync/frame pacing configuravel.

### Fora do escopo

- Renderizador totalmente novo.
- HDR.

### Criterios de aceite

- [ ] Latencia diminui ou fica estavel.
- [ ] Jitter visual nao piora de forma relevante.
- [ ] Configuracoes sao documentadas.

### Testes esperados

- [ ] Teste com jitter simulado.
- [ ] Teste 1080p60.
- [ ] Comparativo antes/depois.

### Documentacao

- [ ] Parametros de buffer documentados.

### Dependencias

Issue 46.

### Observacoes tecnicas

Evitar filas longas que criem atraso perceptivel.

## Issue 49 - Preparar checklist de release candidate

Labels: `type:docs`, `module:docs`, `priority:P1`

Milestone: `M9 - Optimization and Release Candidate`

Branch sugerida: `docs/release-checklist`

PR base futura: `dev`

### Contexto

Antes de considerar merge futuro em `main`, o MVP precisa de checklist reproduzivel.

### Objetivo

Criar checklist de release candidate.

### Escopo

- Build e testes.
- Setup Windows e Arch.
- Metricas e riscos conhecidos.

### Fora do escopo

- Publicacao automatica.
- Assinatura publica de driver.

### Criterios de aceite

- [ ] Checklist cobre criterios do MVP.
- [ ] Checklist inclui testes manuais obrigatorios.
- [ ] Checklist inclui links para guias.

### Testes esperados

- [ ] Revisao manual.
- [ ] Execucao do checklist quando MVP existir.
- [ ] Verificar criterios nao aplicaveis.

### Documentacao

- [ ] Checklist de release criado.

### Dependencias

Issue 43, Issue 44, Issue 45.

### Observacoes tecnicas

`main` so deve receber release funcional final.

## Issue 50 - Preparar release notes do MVP

Labels: `type:docs`, `module:docs`, `priority:P1`

Milestone: `M9 - Optimization and Release Candidate`

Branch sugerida: `release/mvp-candidate`

PR base futura: `dev`

### Contexto

O MVP precisa comunicar funcionalidades, limitacoes e riscos conhecidos.

### Objetivo

Preparar release notes do MVP.

### Escopo

- Funcionalidades entregues.
- Limitacoes conhecidas.
- Requisitos de ambiente.

### Fora do escopo

- Marketing.
- Release publica assinada.

### Criterios de aceite

- [ ] Release notes listam funcionalidades do MVP.
- [ ] Limitacoes e riscos estao claros.
- [ ] Instrucoes apontam para guias de setup.

### Testes esperados

- [ ] Revisao manual.
- [ ] Conferir com checklist de release.
- [ ] Conferir com criterios do MVP.

### Documentacao

- [ ] Release notes criadas.

### Dependencias

Issue 49.

### Observacoes tecnicas

Nao fazer merge automatico em `main`; release final exige decisao humana.
