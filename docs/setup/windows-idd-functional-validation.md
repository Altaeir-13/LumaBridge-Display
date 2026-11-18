# Procedimento Controlado e Plano de Validacao Funcional (Windows 11 x64)

Data: 2026-11-18
Escopo: Preparacao documental para assinatura de teste, instalacao controlada, ativacao do monitor virtual e validacao funcional do `LumaBridgeIddDriver`.

> **Aviso de seguranca e governanca:** Nenhum comando abaixo deve ser executado automaticamente sem autorizacao explicita. Nao altere configuracoes de seguranca permanentemente nem desative o watchdog do IddCx. **Prerequisito obrigatorio antes da primeira instalacao em maquina pessoal:** concluir a issue #20 (instalacao das libs MSVC Spectre, reativar `Driver_SpectreMitigation=true` e recompilar).

## 1. Prerequisitos do ambiente de teste

1. Windows 11 x64 (build `22000` ou superior; validado localmente em build `26300`).
2. Issue #20 resolvida e pacote recompilado em `Release|x64` (`windows/driver/x64/Release/LumaBridgeIddDriver/` contendo `.dll`, `.inf` e `.cat`).
3. Recomendacao forte: executar a primeira validacao em VM Windows 11 dedicada (ou ponto de restauracao criado previamente) antes de testar em maquina de uso pessoal.
4. Conta com privilegios de Administrador local para assinatura de teste e instalacao PnP.

## 2. Assinatura de teste controlada (fora do build padrao)

Em ambiente de teste controlado (sem alterar `SignMode=Off` no `.vcxproj` nem commitar certificados no repositorio):

```powershell
# 1. Gerar certificado temporario de desenvolvimento (executar uma vez em ambiente de teste)
$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject "CN=LumaBridge Test Driver Signing" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -NotAfter (Get-Date).AddMonths(6)

# 2. Exportar o certificado publico (.cer) para pasta temporaria fora do repo
$cerPath = "$env:TEMP\LumaBridgeTest.cer"
Export-Certificate -Cert $cert -FilePath $cerPath

# 3. Confiar no certificado apenas durante os testes (Admin):
# certutil -addstore Root $cerPath
# certutil -addstore TrustedPublisher $cerPath

# 4. Assinar o catalogo e a DLL no pacote Release (nao versionado)
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe"
& $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /t http://timestamp.digicert.com `
  "windows\driver\x64\Release\LumaBridgeIddDriver\LumaBridgeIddDriver.dll"
& $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /t http://timestamp.digicert.com `
  "windows\driver\x64\Release\LumaBridgeIddDriver\lumabridgeidddriver.cat"
```

*Nota:* Em sistemas com Secure Boot ativo, o uso de driver assinado em modo de teste pode exigir **Test Signing** habilitado (`bcdedit /set testsigning on` apenas com autorizacao explicita e em ambiente dedicado, revertendo com `bcdedit /set testsigning off` ao concluir).

## 3. Instalacao controlada e ativacao do monitor virtual

O driver inicia com **ativacao do monitor virtual desabilitada por padrao** (`EnableVirtualMonitor` ausente ou `0`).

1. **Instalar pacote e criar dispositivo raiz (Admin):**
   ```bat
   pnputil /add-driver "windows\driver\x64\Release\LumaBridgeIddDriver\LumaBridgeIddDriver.inf" /install
   devcon install "windows\driver\x64\Release\LumaBridgeIddDriver\LumaBridgeIddDriver.inf" "Root\LumaBridgeIddDriver"
   ```
   Nesta fase inicial (`EnableVirtualMonitor` ausente), o adaptador `LumaBridge Indirect Display Adapter` deve aparecer em *Gerenciador de Dispositivos -> Adaptadores de video* sem erros, e o log `[LB-DRIVER]` deve registrar `"Virtual monitor activation is disabled by default; skipping IddCxMonitorCreate/Arrival"`.

2. **Habilitar monitor virtual de forma controlada:**
   Localizar a chave de hardware do dispositivo (`HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\DISPLAY\<id>\Device Parameters`) e definir `EnableVirtualMonitor` (`REG_DWORD = 1`), reiniciando o dispositivo pelo Gerenciador de Dispositivos (`pnputil /restart-device "<instance-id>"`).

3. **Coleta de diagnostico `[LB-DRIVER]`:**
   - Capturar logs UMDF via Sysinternals **DebugView** (habilitar *Capture Win32* e *Capture Global Win32*) filtrando por `[LB-DRIVER]`.
   - Verificar eventos de driver UMDF no Visualizador de Eventos (`Applications and Services Logs -> Microsoft -> Windows -> DriverFrameworks-UserMode -> Operational`).

## 4. Desinstalacao e rollback seguro

Para remover completamente o dispositivo, o monitor virtual e o pacote do Driver Store (Admin):

```bat
REM 1. Opcionalmente voltar EnableVirtualMonitor para 0 antes de remover
REM 2. Remover instancia do dispositivo raiz
pnputil /remove-device "ROOT\DISPLAY\<instance-id>"

REM 3. Identificar o oemXX.inf correspondente e remover do Driver Store
pnputil /enum-drivers
pnputil /delete-driver oemXX.inf /uninstall /force
```

Remover os certificados temporarios de teste das stores `Root` e `TrustedPublisher` (`certutil -delstore`) e restaurar `testsigning off` caso tenha sido alterado em VM.

## 5. Plano de testes funcionais (9 cenarios)

| # | Cenario | Procedimento | Criterio de aceitacao esperado |
|---|---|---|---|
| 1 | **Reconhecimento do monitor pelo Windows** | Definir `EnableVirtualMonitor = 1`, reiniciar dispositivo e abrir *Configuracoes -> Sistema -> Tela* e `dxdiag`. | Um unico monitor adicional (`ConnectorIndex = 0`) aparece ativo com nome do adaptador LumaBridge e modo preferencial `1920x1080@60Hz`; logs registram `MonitorCreate` e `MonitorArrival` com `STATUS_SUCCESS`. |
| 2 | **Extensao da area de trabalho** | Selecionar *Estender estes videos* nas Configuracoes de Tela do Windows. | Janelas podem ser movidas para a tela estendida; cursor e composicao DWM respondem sem travamentos ou tela preta no monitor fisico. |
| 3 | **Alternancia entre resolucoes** | Alternar entre `1920x1080 (60 Hz)` e `1280x720 (60 Hz)` e retornar para `1920x1080 (60 Hz)`. | `EvtIddCxAdapterCommitModes` aceita apenas modos anunciados (`vSyncFreqDivider = 1`); novo swapchain substitui o anterior sem leaks (`SwapChainDeletedCount` incrementa de 1 por transicao). |
| 4 | **Processamento de frames** | Movimentar janelas / reproduzir animacao no monitor estendido por 60 segundos. | `SwapChainProcessor` processa frames continuamente sem spin de CPU em `E_PENDING`; `FramesProcessed` cresce proporcionalmente as atualizacoes de desktop sem falhas fatais. |
| 5 | **Desativacao e reativacao do dispositivo** | Executar `pnputil /disable-device` seguido de `pnputil /enable-device` (3 ciclos). | Em cada desativacao ocorrem `MonitorDeparture`, `OnSuspend`/`Shutdown` e desaparecimento do monitor; na reativacao o monitor retorna com o mesmo `ContainerId` sem duplicacao. |
| 6 | **Suspensao e retomada do sistema** | Colocar o sistema em suspensao (`D0Exit`) e retomar (`D0Entry`). | Monitor parte ordenadamente em `D0Exit` e retorna em `D0Entry` (`OnResume` + `EnsureMonitorArrived`) sem timeout PnP ou `AdapterFailed`. |
| 7 | **Recuperacao de falhas graficas** | Simular reset de GPU / TDR controlado (ou troca de adaptador de renderizacao). | `DXGI_ERROR_DEVICE_REMOVED` / `DXGI_ERROR_DEVICE_RESET` encerra a thread trabalhadora limpando `hSwapChain` uma unica vez; circuit breaker (`kMaxConsecutiveSwapChainFailures = 5`) impede loop infinito caso a falha persista. |
| 8 | **Consumo de CPU, GPU e memoria** | Monitorar `WUDFHost.exe` no Gerenciador de Tarefas / Resource Monitor em idle (desktop estatico) e com movimento por 5 minutos. | Consumo proximo a `0%` de CPU com desktop estatico (sem busy-wait); memoria privada de `WUDFHost.exe` estavel sem crescimento continuo. |
| 9 | **Ausencia de monitores fantasmas e leaks** | Desabilitar `EnableVirtualMonitor = 0`, reiniciar e executar `pnputil /remove-device` + `/delete-driver`. | Nenhum monitor fantasma permanece listado em *Gerenciador de Dispositivos -> Monitores* ou Configuracoes de Tela; `WUDFHost.exe` encerra sem handles abertos ou crash dump. |
