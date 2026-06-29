# LumaBridge Display - Milestones

## M0 - Repository and Planning

Objetivo:

- Estabelecer a estrutura documental, backlog, governanca e fluxo de trabalho.

Issues incluidas:

- Issue 1, Issue 2, Issue 3, Issue 4, Issue 5, Issue 6, Issue 7, Issue 8, Issue 9.

Criterio de conclusao:

- Documentos de planejamento revisados.
- Estrategia de branches documentada.
- Labels, milestones e issues prontas para criacao manual.
- Nenhum push, PR ou issue real criado pela automacao.

Riscos:

- Planejamento ficar amplo demais e pouco executavel.
- Criar governanca antes de validar necessidades reais de build.

Dependencias:

- `REQUISITOS_LUMABRIDGE.md`.

## M1 - Technical Spikes

Objetivo:

- Provar isoladamente as tecnologias criticas antes da integracao.

Issues incluidas:

- Issue 15, Issue 20, Issue 26, Issue 32.

Criterio de conclusao:

- Monitor virtual IddCx validado em spike.
- NVENC codificando frames sinteticos.
- VA-API decodificando sample H.264.
- Transporte LAN enviando payload sintetico com metricas basicas.

Riscos:

- Driver IDD bloquear o produto.
- NVENC/VA-API exigirem configuracao especifica.
- Transporte inicial mascarar problemas de latencia.

Dependencias:

- M0 aprovado.

## M2 - Protocol Foundation

Objetivo:

- Definir e testar contratos de comunicacao host-cliente.

Issues incluidas:

- Issue 10, Issue 11, Issue 12, Issue 13, Issue 14.

Criterio de conclusao:

- Handshake, versao, capabilities, controle de sessao, erros e estatisticas documentados e testados.

Riscos:

- Protocolo acoplado demais ao MVP.
- Versionamento insuficiente para evolucao.

Dependencias:

- M0.
- Evidencias iniciais dos spikes de transporte.

## M3 - Windows Virtual Display

Objetivo:

- Criar o monitor virtual real no Windows com base em IddCx.

Issues incluidas:

- Issue 16, Issue 17, Issue 18, Issue 19.

Criterio de conclusao:

- Windows 11 reconhece monitor virtual.
- Modo estendido funciona.
- Modos minimos aparecem.
- Fluxo de instalacao/remocao de desenvolvimento esta documentado.

Riscos:

- Instabilidade do driver.
- Assinatura de driver.
- Dependencia de WDK/Visual Studio.

Dependencias:

- Spike de IddCx da M1.

## M4 - Windows Host Pipeline

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

Riscos:

- Copias desnecessarias CPU/GPU.
- Configuracao errada de NVENC.
- Acoplamento forte com driver.

Dependencias:

- M2.
- M3 em progresso ou concluida para frames reais.

## M5 - Linux Client Pipeline

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

Riscos:

- Variacao de VA-API.
- Fullscreen e frame pacing no Hyprland.
- Buffer excessivo.

Dependencias:

- M2.
- Spike de VA-API da M1.

## M6 - LAN MVP Integration

Objetivo:

- Integrar driver, host e cliente para exibir conteudo real do monitor virtual em LAN.

Issues incluidas:

- Issue 35, Issue 36, Issue 37, Issue 38.

Criterio de conclusao:

- Janela arrastada para monitor virtual aparece no laptop Linux.
- 1080p60 funciona em LAN em condicoes boas.
- Frames atrasados sao descartados.
- Logs permitem diagnostico ponta a ponta.

Riscos:

- Latencia fim-a-fim acima da meta.
- Perda de pacotes causar travamentos.
- Falhas de sincronizacao entre encode/decode/render.

Dependencias:

- M3.
- M4.
- M5.

## M7 - Security and Pairing

Objetivo:

- Impedir conexoes acidentais e preparar autenticacao de sessao.

Issues incluidas:

- Issue 39, Issue 40, Issue 41.

Criterio de conclusao:

- Pareamento por codigo.
- Segredo local armazenado.
- Cliente nao pareado rejeitado.
- Revogacao documentada.

Riscos:

- Implementar criptografia caseira.
- Logs exporem segredos.
- Fluxo de pareamento ficar fragil.

Dependencias:

- M6.

## M8 - UX and Packaging

Objetivo:

- Tornar o MVP mais operavel para uso diario e setup de desenvolvimento.

Issues incluidas:

- Issue 42, Issue 43, Issue 44, Issue 45.

Criterio de conclusao:

- CLI/configuracao documentada.
- Guias de setup Windows e Arch.
- Scripts de desenvolvimento nao destrutivos.
- Troubleshooting cobre erros comuns.

Riscos:

- UI/empacotamento consumir tempo antes da estabilidade tecnica.
- Scripts alterarem ambiente sem clareza.

Dependencias:

- M6.

## M9 - Optimization and Release Candidate

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

Riscos:

- Otimizacoes prematuras ocultarem bugs.
- Metricas inconsistentes.
- Release sem checklist reproduzivel.

Dependencias:

- M6.
- M7 quando seguranca fizer parte do corte.
- M8 para documentacao e setup.
