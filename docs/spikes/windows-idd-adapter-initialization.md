# Relatorio tecnico: Inicializacao do adaptador de display indireto com IddCx

Data: 2026-11-18
Branch: `feature/windows-idd-adapter-initialization`
Issue relacionada: #19 (relacionada tambem a #16, #18, #20 e #21)

## 1. Objetivo

Implementar e validar a inicializacao do dispositivo WDF/IddCx e do adaptador de display indireto (`IDDCX_ADAPTER`) em `windows/driver`, garantindo correcao semantica dos contratos WDF/IddCx, seguranca de concorrencia, compatibilidade binaria comprovada com o Windows 11 host e diagnostico estruturado.

## 2. Auditoria de ambiente e compatibilidade binaria com o SO alvo

Alem da consulta ao registro (`WUDF\Services`), foi feita inspecao binaria direta das secoes `.data` e tabelas de exportacao/vinculacao dos binarios inbox em `System32` e da DLL compilada:

| Componente | Versao / Tabela observada |
|---|---|
| Sistema operacional host | Windows 11 Pro x64 (`OsBuildNumber = 26300`) |
| `C:\Windows\System32\WUDFx02000.dll` | Arquivo `10.0.26100.9818`; `WDF_LIBRARY_INFO` versao `2.35`, `287` (`0x11F`) funcoes |
| `C:\Windows\System32\drivers\UMDF\IddCx.dll` | Arquivo `10.0.26100.9818`; `WDF_CLASS_LIBRARY_INFORMATION` versao `1.12`, `42` (`0x2A`) funcoes |
| `_WDF_BIND_INFO` em `LumaBridgeIddDriver.dll` | UMDF `2.31` (`273` funcoes `<= 287`), `WdfMinimumVersionRequired = 25` (`2.25`) |
| `_IddCx_BIND_INFO` em `LumaBridgeIddDriver.dll` | IddCx `1.4` (`25` funcoes `<= 42`), `IddMinimumVersionRequired = 4` (`1.4`) |
| Secure Boot (`UEFISecureBootEnabled`) | `0` (desabilitado) |
| VBS / HVCI | Ativo (`SecurityServicesRunning = {2}`, `VirtualizationBasedSecurityStatus = 2`) |
| Bibliotecas Spectre MSVC (`14.51.36231`) | Ausentes (`lib\spectre` inexistente) |
| Toolchain WDK | VS Build Tools `18.7.3`, MSBuild `18.7.8+1ac568fee`, SDK/WDK `10.0.28000.0` |

### Verificacao efetiva das funcoes utilizadas

- Todas as funcoes WDF invocadas (`WdfDriverCreate`, `WdfDeviceInitSetPnpPowerEventCallbacks`, `WdfDeviceCreate`, `WdfObjectGetTypedContextWorker`, `WdfDeviceSetFailed`) possuem indice abaixo de `WDF_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`268`).
- Todas as funcoes IddCx invocadas (`IddCxDeviceInitConfig`, `IddCxDeviceInitialize`, `IddCxAdapterInitAsync`, `IddCxGetVersion`) possuem indice abaixo de `IDD_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`23`).
- `IddCx.dll` no host expoe `1.12` (`42` funcoes), confirmando suporte completo a IddCx `1.4` (`25` funcoes).

## 3. Problemas encontrados na revisao tecnica do PR #22 e correcoes aplicadas

1. **[Critico] Mascaramento de falha em `LumaBridgeStartAdapter` apos falha assincrona:**
   - *Problema original:* Se `IddCxAdapterInitAsync` retornasse `AdapterObject != nullptr`, mas `EvtIddCxAdapterInitFinished` falhasse assincronamente, um `D0Exit` subsequente sobrescrevia `AdapterFailed` com `DeviceStopped`, e o proximo `D0Entry` retornava `STATUS_SUCCESS` por encontrar `AdapterObject != nullptr`. Alem disso, `WdfDeviceSetFailed` nao era chamado na falha assincrona.
   - *Correcao:* `TransitionOnD0Exit` nao sobrescreve `AdapterFailed`; `TransitionOnD0EntryBegin` rejeita explicitamente `State == AdapterFailed` retornando o erro registrado (`FailPreviousError`); e `LumaBridgeEvtAdapterInitFinished` chama `WdfDeviceSetFailed(wdfDevice, WdfDeviceFailedNoRestart)` em falha.
2. **[Critico] Violacao do contrato de `EvtIddCxMonitorAssignSwapChain` (IddCx 1.4+):**
   - *Problema original:* `LumaBridgeEvtMonitorAssignSwapChain` retornava `STATUS_NOT_IMPLEMENTED`. Segundo a documentacao Microsoft (`idd-evtiddcxmonitorassignswapchain-error-handling`), desde o IddCx 1.4 (Windows 10 1903), retornar qualquer erro `NTSTATUS` diferente de `STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN` (`0xC01E0012L`) provoca **bugcheck imediato** do processo UMDF. `LumaBridgeEvtMonitorUnassignSwapChain` tambem retornava `STATUS_NOT_IMPLEMENTED`.
   - *Correcao:* `LumaBridgeEvtMonitorAssignSwapChain` passou a registrar aviso e retornar `STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN`; `LumaBridgeEvtMonitorUnassignSwapChain` passou a retornar `STATUS_SUCCESS`; e callbacks de descricao/modos passaram a retornar `STATUS_NOT_SUPPORTED` com contadores zerados.
3. **[Alto] Corrida entre retorno de `IddCxAdapterInitAsync` e `EvtIddCxAdapterInitFinished`:**
   - *Problema original:* Desmontagem de `IddCx.dll` (`IddCxAdapterInitAsync` em `0x180032F00`) confirmou que o IddCx cria o `IDDCX_ADAPTER` e dispara `IddAdapter::Initialize` antes de `IddCxAdapterInitAsync` retornar. Se `EvtIddCxAdapterInitFinished` rodasse antes de `LumaBridgeStartAdapter` preencher `adapterContext->WdfDevice` (ou concorresse com `new (adapterContext) LumaBridgeAdapterContext{}`), ocorreria falha espurea `STATUS_INVALID_DEVICE_STATE` ou corrida de memoria.
   - *Correcao:* Introducao de `g_AdapterInitGate` + `g_InFlightInitDevice` + `LumaBridgeBindAdapterAndResolveDeviceLocked`, remocao do placement-new apos `IddCxAdapterInitAsync` (aproveitando a inicializacao zerada do WDF) e preservacao do estado terminal em `TransitionOnAdapterInitAsyncSubmitted` caso `EvtIddCxAdapterInitFinished` ja tenha concluido antes do retorno.
4. **[Medio] Sobrescrita de `DeviceStopped` por conclusao assincrona tardia e falso positivo de `STATUS_PENDING`:**
   - *Problema original:* `EvtIddCxAdapterInitFinished` atribuia `AdapterReady` mesmo apos `D0Exit` (`DeviceStopped`), e `NT_SUCCESS(STATUS_PENDING)` (`0x00000103 >= 0`) avaliava como verdadeiro antes da conclusao assincrona.
   - *Correcao:* `TransitionOnAdapterInitFinished` verifica `IsInD0` antes de transicionar para `AdapterReady` (mantendo `DeviceStopped` fora de D0); `IsSucceededNonPendingStatus` exclui `STATUS_PENDING`; e `NormalizeFailureStatus` converte qualquer status nao negativo inesperado em `STATUS_UNSUCCESSFUL`.
5. **[Medio] Sincronizacao entre threads WDF/IddCx e ordem de cleanup pai/filho:**
   - *Correcao:* `DeviceContext::StateLock` (`SRWLOCK`) protege o tracker com hierarquia estrita `g_AdapterInitGate -> StateLock` (sem locks mantidos durante chamadas IddCx/WDF reentrantes). `LumaBridgeEvtDeviceContextCleanup` limpa `adapterContext->WdfDevice = nullptr` enquanto o filho `IDDCX_ADAPTER` ainda esta vivo.
6. **[Baixo] Observabilidade e testes automatizados:**
   - *Correcao:* Criados `Trace.h` (tracing `[LB-DRIVER]` via `OutputDebugStringA` + estagio/erro no contexto), `AdapterStateMachine.h` e a suite `windows/driver/tests/AdapterLifecycleTests.cpp` (11 cenarios deterministicos).

## 4. Evidencias de build, inspecao e testes

### Testes unitarios (`AdapterLifecycleTests.cpp`)

Comando executado:

```bat
cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\AdapterLifecycleTests.cpp /Fowindows\driver\x64\Debug\AdapterLifecycleTests.obj /Fe:windows\driver\x64\Debug\AdapterLifecycleTests.exe
windows\driver\x64\Debug\AdapterLifecycleTests.exe
```

Resultado observado: `Summary: 11 tests run, 0 assertion failures.` (codigo de saida `0`).

### Builds do driver (`Debug|x64` e `Release|x64`)

Comandos executados:

```bat
msbuild windows\driver\LumaBridgeIddDriver.sln /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 /v:minimal
msbuild windows\driver\LumaBridgeIddDriver.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 /v:minimal
```

Resultados observados apos as correcoes finais:

- `Debug|x64`: codigo de saida `0`, 0 warnings, 0 erros -> `windows\driver\x64\Debug\LumaBridgeIddDriver.dll`.
- `Release|x64`: codigo de saida `0`, 0 warnings, 0 erros -> `windows\driver\x64\Release\LumaBridgeIddDriver.dll`.
- `dumpbin.exe /exports` em ambas as DLLs: exporta `FxDriverEntryUm` (ordinal `1`).
- `dumpbin.exe /dependents` em ambas as DLLs: apenas bibliotecas user-mode padrao (`ntdll.dll`, `KERNEL32.dll`, `api-ms-win-core-*`).

## 5. Limitacoes e fora do escopo

- Nenhum monitor virtual e criado ou anunciado nesta entrega (`IddCxMonitorCreate`/`IddCxMonitorArrival` ficam para issue dedicada).
- O driver nao foi instalado, nao foi empacotado com `Inf2Cat` e nao foi assinado; nenhuma configuracao de boot, Secure Boot ou HVCI foi modificada.
- Execucao real em `WUDFHost.exe` sera validada apenas apos as etapas de pacote INF (#21), monitor virtual, modos de video e assinatura de teste controlada.

## 6. Conclusao

Aprovado para revisao e integracao na `dev`: todos os defeitos criticos, medios e de observabilidade identificados na revisao do PR #22 foram corrigidos, cobertos por testes unitarios deterministicos e validados em builds limpos `Debug|x64` e `Release|x64`.
