# `lumabridge-host` — Processo Consumidor Local de Frames (M4.1)

Processo Windows separado de `WUDFHost.exe` que se conecta ao endpoint IPC local de `LumaBridgeIddDriver` (`SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, validado no servidor por token de acesso Windows, SID/broker `AuthorizedHostUserSid`, `TokenSessionId` e integridade `>= Medium`, sem segredo estatico), recebe os frames BGRA8/RGBA8 extraidos da swapchain virtual, verifica integridade de framing e CRC-32 (e padrao sintetico quando solicitado), envia confirmacoes (`FrameIpcFrameAck`) e expoe telemetria de operacao sem gravar pixels em disco.

## Compilacao

Em ambiente `x64` do Visual Studio (`VsDevCmd.bat -arch=x64 -host_arch=x64`):

```bat
cl /nologo /std:c++17 /W4 /WX /EHsc windows\host\main.cpp windows\host\FrameConsumer.cpp /Fowindows\driver\x64\Debug\ /Fe:windows\driver\x64\Debug\lumabridge-host.exe /link advapi32.lib
cl /nologo /std:c++17 /W4 /WX /EHsc /O2 windows\host\main.cpp windows\host\FrameConsumer.cpp /Fowindows\driver\x64\Release\ /Fe:windows\driver\x64\Release\lumabridge-host.exe /link advapi32.lib
```

## Opcoes de linha de comando

- `--pipe <nome>`: caminho do Named Pipe local (padrao: `\\.\pipe\LumaBridgeFrameIpc_v1`)
- `--max-frames <N>`: encerra apos receber `N` frames (`0` = continuo ate Ctrl+C ou desconexao)
- `--duration-ms <ms>`: tempo maximo de execucao em milissegundos
- `--connect-timeout-ms <ms>`: timeout de conexao ao pipe (padrao: `3000`)
- `--io-timeout-ms <ms>`: timeout de leitura/escrita overlapped (padrao: `500`)
- `--verify-synthetic-pattern`: valida padrao sintetico BGRA8 deterministico por pixel sem depender de imagens da area de trabalho
- `--reconnect`: reconecta automaticamente em caso de desconexao ou troca de modo/swapchain
- `--json-summary <caminho>`: grava resumo JSON nao visual com contadores, resolucao, formato, CRC e latencias
- `--quiet`: omite log por frame no stdout

## Privacidade e limites

- Nenhum frame, screenshot ou buffer de pixels e salvo em disco.
- Payload maximo por frame limitado a `4096 x 4096 x 4` bytes (`64 MiB`), com validacao de versao, sessao e CRC-32 por frame.
