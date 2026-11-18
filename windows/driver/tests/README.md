# Testes do modulo `windows/driver`

## Escopo atual

`AdapterLifecycleTests.cpp` valida deterministicamente a maquina de estados `AdapterLifecycleTracker` compartilhada com o driver IddCx (`windows/driver/LumaBridgeIddDriver/AdapterStateMachine.h`), cobrindo:

- fluxo normal `DeviceConfigured -> DeviceInitialized -> AdapterInitPending -> AdapterReady`;
- conclusao assincrona (`EvtIddCxAdapterInitFinished`) chegando antes do retorno pos-processado de `IddCxAdapterInitAsync`;
- falha sincrona e falha assincrona preservando `AdapterFailed` entre `D0Exit` e novo `D0Entry`;
- `D0Exit` durante inicializacao pendente preservando `DeviceStopped` quando `EvtIddCxAdapterInitFinished` conclui fora de D0;
- rejeicao do falso positivo `NT_SUCCESS(STATUS_PENDING)` em reentrada D0;
- transicoes de suspensao/retomada (`D0Exit` -> `D0Entry`), contagem de paths e limpeza deterministica de contextos.

## Como compilar e executar

Em ambiente x64 do Visual Studio (`VsDevCmd.bat -arch=x64 -host_arch=x64`), os artefatos sao direcionados para `windows/driver/x64/Debug/` (ignorado por `windows/driver/.gitignore`):

```bat
cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\AdapterLifecycleTests.cpp /Fowindows\driver\x64\Debug\AdapterLifecycleTests.obj /Fe:windows\driver\x64\Debug\AdapterLifecycleTests.exe
windows\driver\x64\Debug\AdapterLifecycleTests.exe
```
