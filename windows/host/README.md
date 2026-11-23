# `lumabridge-host` — Processo Consumidor Local de Frames (`M4.1` / `M4.1.1`)

Processo Windows separado de `WUDFHost.exe` que se conecta ao endpoint IPC local de `LumaBridgeIddDriver` (`SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, validado no servidor por token de acesso Windows, SID/broker `AuthorizedHostUserSid`, `TokenSessionId` e integridade `>= Medium`, sem segredo estatico), recebe os frames BGRA8/RGBA8 extraidos da swapchain virtual, verifica integridade de framing e CRC-32 (e padrao sintetico quando solicitado), envia confirmacoes (`FrameIpcFrameAck`) e expoe telemetria granular por estagio sem gravar pixels em disco.

## Compilacao

Em ambiente `x64` do Visual Studio (`VsDevCmd.bat -arch=x64 -host_arch=x64`):

```bat
cl /nologo /std:c++17 /W4 /WX /EHsc windows\host\main.cpp windows\host\FrameConsumer.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\lumabridge-host.exe /link advapi32.lib user32.lib gdi32.lib
cl /nologo /std:c++17 /W4 /WX /EHsc /O2 windows\host\main.cpp windows\host\FrameConsumer.cpp /Fowindows\driver\x64\Release\ /Fe:windows\driver\x64\Release\lumabridge-host.exe /link advapi32.lib user32.lib gdi32.lib
```

## Opcoes de linha de comando

- `--pipe <nome>`: caminho do Named Pipe local (padrao: `\\.\pipe\LumaBridgeFrameIpc_v1`)
- `--max-frames <N>`: encerra antecipadamente apos receber `N` frames validos (`0` = continuo ate `--duration-ms`, Ctrl+C ou desconexao)
- `--min-frames <N>`: exige no minimo `N` frames validos para retorno `ExitCode=0` mesmo que a meta `--max-frames` nao seja atingida antes de `--duration-ms` (Perfil A — smoke test)
- `--require-max-frames`: exige atingir a meta integral `--max-frames` para `ExitCode=0` (Perfil B — benchmark continuo)
- `--duration-ms <ms>`: tempo maximo de execucao em milissegundos
- `--connect-timeout-ms <ms>`: timeout de conexao ao pipe (padrao: `3000`)
- `--io-timeout-ms <ms>`: timeout por operacao I/O overlapped em ms (padrao: `500`)
- `--verify-synthetic-pattern`: valida padrao sintetico BGRA8 deterministico por pixel sem depender de imagens da area de trabalho
- `--reconnect`: reconecta automaticamente em caso de desconexao ou troca de modo/swapchain
- `--visual-stimulus`: renderiza janela de movimento sintetico diretamente no monitor virtual LumaBridge ativo (sem capturar pixels do desktop e recusando exibir em monitores fisicos caso o virtual nao seja identificado)
- `--require-virtual-stimulus`: falha com codigo de saida nao-zero se o estimulo visual nao conseguir identificar o display virtual
- `--stimulus-fps <fps>`: taxa alvo de atualizacao do estimulo visual (`1..120`, padrao `60`)
- `--stimulus-display <gdiName>`: override explicito opcional do display GDI (ex.: `\\.\DISPLAY2`)
- `--json-summary <caminho>`: grava resumo JSON nao visual com motivo de saida, breakdown QPC (min/avg/p50/p95/p99/max), separacao de frames pre-conexao vs. live, metricas de FPS e status do estimulo
- `--quiet`: omite log por frame no stdout

## Limites e privacidade

- Nenhum frame, screenshot ou buffer de pixels e salvo em disco nem lido da area de trabalho pelo estimulo diagnostico.
- Payload maximo por frame limitado a `4096 x 4096 x 4` bytes (`64 MiB`), com validacao de versao, sessao e CRC-32 por frame.
- Timeouts de espera ociosa no inicio de `FrameIpcEnvelope` (`0` bytes lidos) sao recuperaveis (`RecoverableIoTimeouts`); timeouts apos consumo parcial de cabecalho, payload ou ACK fecham o pipe imediatamente para impedir dessincronizacao do fluxo (`FatalIoTimeouts` / `PartialMessageTimeouts`).
- Em ambiente D3D11/staging + Named Pipe (`M4.1`/`M4.1.1`), frames enfileirados antes da conexao do cliente (`PreConnectQueuedFrame`) acumulam tempo de permanencia em fila (`QueueWaitLatency`), enquanto frames ao vivo apos a conexao medem a latencia real do pipeline (`LiveEndToEndLatency`). O caminho definitivo de zero-copy GPU (`HANDLE` NT compartilhado + `NVENC`) pertence a etapa `M4.2`.
