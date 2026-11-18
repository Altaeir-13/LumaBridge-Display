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

- Todas as funcoes WDF invocadas (`WdfDriverCreate`, `WdfDeviceInitSetPnpPowerEventCallbacks`, `WdfDeviceCreate`, `WdfObjectGetTypedContextWorker`, `WdfDeviceSetFailed`, `WdfObjectReferenceActual`, `WdfObjectDereferenceActual`) possuem indice abaixo de `WDF_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`268`).
- Todas as funcoes IddCx invocadas (`IddCxDeviceInitConfig`, `IddCxDeviceInitialize`, `IddCxAdapterInitAsync`, `IddCxGetVersion`) possuem indice abaixo de `IDD_ALWAYS_AVAILABLE_FUNCTION_COUNT` (`23`).
- `IddCx.dll` no host expoe `1.12` (`42` funcoes), confirmando suporte completo a IddCx `1.4` (`25` funcoes).
- **Nota de contrato:** a garantia de compatibilidade futura apoia-se exclusivamente nos contratos publicos e documentados do WDF e IddCx (macros de versao, indices `ALWAYS_AVAILABLE`, hierarquia de objetos WDF e referencia explicita de handles). A inspecao binaria de `WUDFx02000.dll` e `IddCx.dll` no host foi utilizada apenas como observacao diagnostica local, nunca como dependencia de offsets ou estruturas internas nao documentadas.

## 3. Problemas encontrados na revisao tecnica do PR #22 e correcoes aplicadas

1. **[Critico] Mascaramento de falha em `LumaBridgeStartAdapter` apos falha assincrona:**
   - *Problema original:* Se `IddCxAdapterInitAsync` retornasse `AdapterObject != nullptr`, mas `EvtIddCxAdapterInitFinished` falhasse assincronamente, um `D0Exit` subsequente sobrescrevia `AdapterFailed` com `DeviceStopped`, e o proximo `D0Entry` retornava `STATUS_SUCCESS` por encontrar `AdapterObject != nullptr`. Alem disso, `WdfDeviceSetFailed` nao era chamado na falha assincrona.
   - *Correcao:* `TransitionOnD0Exit` nao sobrescreve `AdapterFailed`; `TransitionOnD0EntryBegin` rejeita explicitamente `State == AdapterFailed` retornando o erro registrado (`FailPreviousError`); e `LumaBridgeEvtAdapterInitFinished` retem referencia via `WdfObjectReference(wdfDevice)` sob lock, libera os locks, chama `WdfDeviceSetFailed(wdfDevice, WdfDeviceFailedNoRestart)` e libera a referencia com `WdfObjectDereference(wdfDevice)`.
2. **[Critico] Violacao do contrato de `EvtIddCxMonitorAssignSwapChain` (IddCx 1.4+) e restricao de anuncio de monitor:**
   - *Problema original:* `LumaBridgeEvtMonitorAssignSwapChain` retornava `STATUS_NOT_IMPLEMENTED`. Segundo a documentacao Microsoft (`idd-evtiddcxmonitorassignswapchain-error-handling`), desde o IddCx 1.4 (Windows 10 1903), retornar qualquer erro `NTSTATUS` diferente de `STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN` (`0xC01E0012L`) provoca **bugcheck imediato** do processo UMDF. `LumaBridgeEvtMonitorUnassignSwapChain` tambem retornava `STATUS_NOT_IMPLEMENTED`.
   - *Correcao e restricao explicita:* `LumaBridgeEvtMonitorAssignSwapChain` passou a registrar aviso e retornar `STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN`, `LumaBridgeEvtMonitorUnassignSwapChain` retorna `STATUS_SUCCESS`, e callbacks de descricao/modos retornam `STATUS_NOT_SUPPORTED` com contadores zerados. Contudo, `STATUS_GRAPHICS_INDIRECT_DISPLAY_ABANDON_SWAPCHAIN` e **exclusivamente uma protecao defensiva** (nao uma implementacao funcional de swapchain, pois o Windows pode solicitar repetidamente uma nova swapchain). Por contrato do estagio atual, **nenhum monitor virtual (`IddCxMonitorCreate` / `IddCxMonitorArrival`) pode ser criado ou anunciado** ate que a negociacao de modos e o processamento real de swapchain estejam prontos.
3. **[Alto] Corrida entre retorno de `IddCxAdapterInitAsync`, `EvtIddCxAdapterInitFinished` e concorrencia multi-dispositivo:**
   - *Problema original:* Pelo contrato publico do IddCx, `EvtIddCxAdapterInitFinished` pode executar antes ou em paralelo com o pos-processamento do retorno de `IddCxAdapterInitAsync` (observacao tambem confirmada diagnosticamente no host). Alem disso, um ponteiro global unico `g_InFlightInitDevice` sem controle de entrada permitia que um dispositivo B sobrescrevesse o token em voo do dispositivo A antes da associacao do adaptador A no mesmo processo `WUDFHost.exe`, ou que um cleanup durante `IddCxAdapterInitAsync` liberasse o slot antes de `AdapterA` ser invalidado.
   - *Correcao:* Introducao de `InFlightAdapterBindingSlot` + `CONDITION_VARIABLE g_AdapterInitSlotCv` sob `g_AdapterInitGate`: a janela sem vinculo de `IddCxAdapterInitAsync` e serializada entre dispositivos distintos com espera limitada (`kAdapterInitSlotWaitTimeoutMs = 5000 ms`, retornando `STATUS_IO_TIMEOUT` e transicionando para `AdapterFailed` se excedida, respeitando limites de callbacks PnP/Power do WDF/WUDFRd) e sem manter `g_AdapterInitGate` preso durante a chamada `IddCxAdapterInitAsync`. Durante cleanup em voo, `MarkDeviceCleanedUp` e `HasBoundDevice` envenenam o `AdapterContext` antigo e impedem a entrada de outro dispositivo antes do retorno de `IddCxAdapterInitAsync(A)`, eliminando vinculacao cruzada por callbacks tardios.
4. **[Medio] Sobrescrita de `DeviceStopped`, falso positivo de `STATUS_PENDING` e callbacks tardios apos cleanup:**
   - *Problema original:* `EvtIddCxAdapterInitFinished` atribuia `AdapterReady` mesmo apos `D0Exit` (`DeviceStopped`), `NT_SUCCESS(STATUS_PENDING)` (`0x00000103 >= 0`) avaliava como verdadeiro antes da conclusao assincrona, e callbacks tardios (`EvtIddCxAdapterInitFinished` / `EvtIddCxAdapterCommitModes`) podiam ressuscitar ou alterar estados apos cleanup/falha.
   - *Correcao:* `TransitionOnAdapterInitFinished` verifica `IsInD0` e rejeita com `STATUS_INVALID_DEVICE_STATE` se `IsCleanedUp == true`, se a inicializacao ja foi concluida (`AdapterInitCompleted`) ou se nao ha inicializacao pendente; `TransitionOnCommitModes` retorna `STATUS_INVALID_DEVICE_STATE` apos cleanup/falha; `IsSucceededNonPendingStatus` exclui `STATUS_PENDING`; e `NormalizeFailureStatus` converte qualquer status nao negativo inesperado em `STATUS_UNSUCCESSFUL`.
5. **[Medio] Sincronizacao entre threads WDF/IddCx, validade de handles e ordem de cleanup:**
   - *Correcao:* `DeviceContext::StateLock` (`SRWLOCK`) protege o tracker com hierarquia estrita `g_AdapterInitGate -> StateLock` (sem locks mantidos durante chamadas IddCx/WDF reentrantes). `IsCleanedUp` nos contextos e no tracker bloqueia novos vinculos e callbacks apos cleanup; `LumaBridgeEvtDeviceContextCleanup` e `LumaBridgeEvtAdapterContextCleanup` marcam `MarkDeviceCleanedUp` e desconectam ponteiros cruzados simetricamente enquanto o objeto filho/pai ainda e valido.
6. **[Baixo] Observabilidade e testes automatizados:**
   - *Correcao:* Criados `Trace.h` (tracing `[LB-DRIVER]` via `OutputDebugStringA` + estagio/erro no contexto), `AdapterStateMachine.h` e a suite `windows/driver/tests/AdapterLifecycleTests.cpp` (16 cenarios deterministicos).

## 4. Evidencias de build, inspecao e testes

### Testes unitarios (`AdapterLifecycleTests.cpp`)

Escopo: testes unitarios deterministicos em C++ puro sobre a maquina de estados `AdapterLifecycleTracker` e a logica de associacao `InFlightAdapterBindingSlot` (**validado em compilacao e testes unitarios, nao ainda em runtime real no Windows dentro de `WUDFHost.exe`**).

Comando executado:

```bat
cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\AdapterLifecycleTests.cpp /Fowindows\driver\x64\Debug\AdapterLifecycleTests.obj /Fe:windows\driver\x64\Debug\AdapterLifecycleTests.exe
windows\driver\x64\Debug\AdapterLifecycleTests.exe
```

Resultado observado apos as correcoes finais: `Summary: 16 tests run, 0 assertion failures.` (codigo de saida `0`), cobrindo fluxo normal, conclusao/falha assincrona precoce, retentativas apos falha, `D0Exit` durante init pendente, rejeicao de `STATUS_PENDING`, suspend/resume/`CommitModes`, cleanup normal, isolamento multi-dispositivo A/B, regressao contra vinculacao cruzada apos cleanup em voo, cleanup durante init pendente e rejeicao de callbacks tardios apos cleanup/falha.

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

- Nenhum monitor virtual e criado ou anunciado nesta entrega (`IddCxMonitorCreate`/`IddCxMonitorArrival` permanecem explicitamente bloqueados ate a implementacao de modos e swapchain).
- Os testes automatizados desta etapa cobrem apenas a maquina de estados e a logica de associacao em memoria; nao ha execucao automatizada dentro de `WUDFHost.exe` nesta entrega.
- O driver nao foi instalado, nao foi empacotado com `Inf2Cat` e nao foi assinado; nenhuma configuracao de boot, Secure Boot ou HVCI foi modificada.
- Execucao real em `WUDFHost.exe` sera validada apenas apos as etapas de pacote INF (#21), monitor virtual, modos de video e assinatura de teste controlada.

## 6. Conclusao

Aprovado para revisao final e integracao na `dev`: os riscos residuais de associacao multi-dispositivo, envenenamento de slot em cleanup, espera limitada no callback de energia, retencao de handle antes de `WdfDeviceSetFailed`, callbacks tardios apos cleanup e restricao explicita de swapchain/monitor foram corrigidos, cobertos pelos 16 testes unitarios deterministicos e validados em builds limpos `Debug|x64` e `Release|x64` (sem execucao em runtime real no Windows nesta etapa).
