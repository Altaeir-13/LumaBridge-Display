# Empacotamento e Validacao do Pacote INF do Driver IddCx

Data: 2026-11-18
Branch: `feature/windows-idd-inf-validation`
Issue relacionada: #21 (depende de #12, #16, #18 e #19; relacionada tambem a #20)

## 1. Objetivo e escopo

Este documento descreve a estrutura, as diretivas INF, a integracao WDK no MSBuild e os procedimentos operacionais do pacote de desenvolvimento do driver virtual `LumaBridgeIddDriver` (UMDF 2.31 / IddCx 1.4+).

Nesta etapa:

- O projeto gera `LumaBridgeIddDriver.dll`, `LumaBridgeIddDriver.inf` (carimbado pelo `StampInf`) e `LumaBridgeIddDriver.cat` (gerado pelo `Inf2Cat` e anotado pelo `DrvCat`).
- O pacote e **validado estaticamente** (`StampInf`, `InfVerif`, `Inf2Cat`, `DrvCat` e testes automatizados de pacote).
- O pacote permanece **nao assinado** (`SignMode=Off`, `EnableTestSign=false`) e **nao instalado** no sistema operacional.

> **Importante:** A geracao do arquivo `.cat` e a aprovacao no `InfVerif` nao significam que o pacote esteja pronto para instalacao sem assinatura nem que o driver ja tenha sido validado em runtime dentro de `WUDFHost.exe`.

## 2. Estrutura do pacote gerado

### Arquivos fonte versionados

```text
windows/
  driver/
    .gitignore
    README.md
    LumaBridgeIddDriver.sln
    LumaBridgeIddDriver/
      LumaBridgeIddDriver.vcxproj
      LumaBridgeIddDriver.vcxproj.filters
      LumaBridgeIddDriver.inf
      Driver.h / Driver.cpp
      Adapter.h / Adapter.cpp
      AdapterStateMachine.h
      Trace.h
    tests/
      README.md
      AdapterLifecycleTests.cpp
      DriverPackageValidationTests.cpp
```

### Saida local de build e empacotamento (ignorada pelo Git)

Para `Configuration` em `{Debug, Release}` e `Platform=x64`:

- Intermediarios de compilacao e stamping (`$(IntDir)`): `windows/driver/x64/<Configuration>/obj/LumaBridgeIddDriver/`
- Diretorio de saida principal (`$(OutDir)`): `windows/driver/x64/<Configuration>/`
  - `LumaBridgeIddDriver.dll`
  - `LumaBridgeIddDriver.inf`
  - `LumaBridgeIddDriver.cat`
  - `LumaBridgeIddDriver.pdb`, `.lib`, `.exp` e binarios de teste local em `Debug`
- Diretorio isolado do pacote para o `Inf2Cat` (`$(PackageDir)`): `windows/driver/x64/<Configuration>/LumaBridgeIddDriver/`
  - `LumaBridgeIddDriver.dll`
  - `LumaBridgeIddDriver.inf`
  - `lumabridgeidddriver.cat` (`Inf2Cat` escreve o nome do catalogo em minusculas; o target `CopyCatalogToOutDir` copia para `$(OutDir)LumaBridgeIddDriver.cat` apos `DrvCat`)

A separacao explicita entre `$(IntDir)` (`obj/$(ProjectName)/`) e `$(PackageDir)` (`$(OutDir)$(ProjectName)/`) garante que arquivos `.obj`, `.tlog` e logs intermediarios nao contaminem o diretorio processado pelo `Inf2Cat`.

## 3. Diretivas INF e justificativas tecnicas

| Secao / Diretiva | Valor configurado | Justificativa tecnica |
|---|---|---|
| `[Version] Signature` | `"$WINDOWS NT$"` | Assinatura padrao exigida para INFs Windows NT modernos. |
| `[Version] Class` / `ClassGuid` | `Display` / `{4d36e968-e325-11ce-bfc1-08002be10318}` | Classe oficial de adaptadores de video onde drivers IddCx devem ser registrados. |
| `[Version] ClassVer` | `2.0` | Requisito dos drivers universais da classe Display WDDM/IddCx modernos. |
| `[Version] Provider` | `%ManufacturerName%` (`"LumaBridge"`) | Provedor proprio do projeto (requisito INF Universal; valores genericos como `"Microsoft"` falham em `InfVerif` regra 1204). |
| `[Version] CatalogFile` | `LumaBridgeIddDriver.cat` | Vincula o catalogo de seguranca gerado pelo `Inf2Cat`. |
| `[Version] DriverVer` | Fonte `07/01/2026,0.1.0.0`; carimbado por `StampInf` | Atualizado automaticamente no build (`-d "*" -v "*"`) para garantir carimbo valido de data/versao. |
| `[Version] PnpLockdown` | `1` | Impede modificacoes diretas nos binarios do driver fora dos pacotes no Driver Store (requisito Universal INF). |
| `[Manufacturer]` / `[Standard.NT$ARCH$.10.0...18362]` | `Standard,NTamd64.10.0...18362` (apos `StampInf`) | Restringe a instalacao ao Windows 10 1903 (build `18362`) ou superior em `amd64`, satisfazendo a exigencia de versao minima de `DIRID 13 (UMDF)` (`10.0.17134`), `UMDF 2.25+` e `IddCx 1.4` (`10.0.18362`) sem erros 1199 no `InfVerif`. |
| Hardware ID exclusivo | `Root\LumaBridgeIddDriver` | Hardware ID dedicado do LumaBridge para enumeracao virtual futura, sem colisao com drivers inbox ou Parsec. |
| `[SourceDisksNames]` / `[SourceDisksFiles]` | `1 = %DiskName%` / `LumaBridgeIddDriver.dll = 1` | Mapeia explicitamente todos os binarios do pacote (obrigatorio para validacao no `InfVerif` / `Inf2Cat`). |
| `[DestinationDirs]` / `[UMDriverCopy]` | `UMDriverCopy = 13` / `LumaBridgeIddDriver.dll,,,0x00000100` | Usa `DIRID 13` (Driver Store — Run from Driver Store) em vez de copiar manualmente para `System32\drivers\UMDF`, com `COPYFLG_NOPRUNE` (`0x100`). |
| `Include = wudfrd.inf` / `Needs` | `WUDFRD.NT`, `WUDFRD.NT.HW`, `WUDFRD.NT.Services` | Delega ao INF inbox `C:\Windows\INF\wudfrd.inf` a instalacao e configuracao correta do servico kernel reflector `WUDFRd.sys`, eliminando referencia direta invalida a `%12%\WUDFRd.sys` (`ERROR(2084)`). |
| `UmdfService` / `UmdfServiceOrder` | `LumaBridgeIddDriver,LumaBridge_UMDF_Service` | Registra o servico UMDF do driver LumaBridge e sua ordem na pilha do dispositivo. |
| `UmdfKernelModeClientPolicy` | `AllowKernelModeClients` | Obrigatorio porque a comunicacao IddCx / `IndirectKmd` envolve clientes em kernel-mode interagindo com o driver user-mode via `WUDFRd`. |
| `UmdfHostProcessSharing` | `ProcessSharingDisabled` | Isola o `WUDFHost.exe` do LumaBridge de outros dispositivos UMDF nao relacionados. |
| `UmdfLibraryVersion` | `$UMDFVERSION$` -> `2.31.0` via `StampInf` | Mantido sincronizado com `<UMDF_VERSION_MINOR>31</UMDF_VERSION_MINOR>` do `.vcxproj` sem coinstaladores (`-x`). |
| `ServiceBinary` | `%13%\LumaBridgeIddDriver.dll` | Executa o binario diretamente a partir do Driver Store (`DIRID 13`). |
| `UmdfExtensions` | `IddCx0102` | Habilita o carregamento da extensao de classe Indirect Display (`IddCx`) pelo host UMDF. |
| `UpperFilters` (`.NT.hw` `AddReg`) | `HKR,, "UpperFilters", %REG_MULTI_SZ%, "IndirectKmd"` | Adiciona o filtro superior `IndirectKmd` no stack PnP do dispositivo, integrando o adaptador ao subsistema grafico Dxgkrnl/WDDM. |
| `DeviceGroupId` (`.NT.hw` `AddReg`) | `HKR, "WUDF", "DeviceGroupId", %REG_SZ%, "LumaBridgeIddGroup"` | Agrupamento WUDF proprio sob a chave de hardware (`.NT.hw`). |

### Diretivas do `rdpidd.inf` intencionalmente NAO copiadas

A comparacao com o driver inbox `C:\Windows\INF\rdpidd.inf` identificou diretivas especificas de sessao RDP ou legadas para INFs inbox da Microsoft que nao devem ser copiadas para o LumaBridge:

- `PreConfigureDriver = *`: marcador interno de pre-configuracao do sistema; inadequado para pacote externo.
- `[*.Events]` / `AddAutoLogger` e provedores ETW internos da Microsoft (`RdpIdd`, `RdpAvenc`, `IddCx`): exclusivos da telemetria interna de RDP e dependentes de recursos da build 22000+.
- `HKR,, Security, , "D:P(A;;GA;;;WD)"`: concede acesso generico total a `Everyone` (`WD`), contrariando o principio do menor privilegio.
- `DeviceGroupId` dentro de `AddReg` de secao de servico (`[...Install.AddReg]`): reprovado por `InfVerif /h` com `ERROR(1323)` (*Service registry key 'DeviceGroupId' must be under the Parameters subkey*); no LumaBridge foi colocado na chave de hardware `.NT.hw` junto com `ProcessSharingDisabled`.
- `UmdfDumpMode = HeapDump` e `UmdfImpersonationLevel = Identification`: nao requeridos nesta etapa e nao adicionados sem necessidade comprovada.

## 4. Referencias oficiais consultadas

- Microsoft Learn — *Indirect Display Driver Model Overview* e *Developing Indirect Display Drivers with IddCx*.
- Microsoft *Windows Driver Samples* — referencia conceitual de `IddSampleDriver` (INF de adaptador IddCx com `wudfrd.inf`, `IddCx0102`, `IndirectKmd`).
- Arquivo inbox do Windows 11 host: `C:\Windows\INF\wudfrd.inf` (contrato oficial de `Include`/`Needs` para `[WUDFRD.NT]`, `[WUDFRD.NT.HW]` e `[WUDFRD.NT.Services]`).
- Ferramentas oficiais WDK `10.0.28000.0`: `StampInf`, `InfVerif` (`10.0.28000.1839`), `Inf2Cat` e `DrvCat`.

## 5. Compatibilidade de versoes e propriedades de build

- **UMDF compilado/alinhado:** `2.31` com `UMDF_MINIMUM_VERSION_REQUIRED=25` (`2.25`).
- **IddCx compilado/alinhado:** `1.4` com `IDDCX_MINIMUM_VERSION_REQUIRED=4`.
- **INF TargetOSVersion:** `NTamd64.10.0...18362` (Windows 10 versao 1903 ou superior, incluindo Windows 11 Pro x64 target build `26300`).
- **Catalogo `Inf2Cat`:** `Inf2CatWindowsVersionList = 10_19H1_X64`, `Inf2CatUseLocalTime = true`.

### Papel de `EnableInf2cat`, `SignMode` e `EnableTestSign`

A auditoria de `WindowsDriver.Common.targets` e `WindowsDriver.Shared.props` (WDK `10.0.28000.0`) confirmou:

- `<SignMode>Off</SignMode>` e `<EnableTestSign>false</EnableTestSign>` desativam apenas os targets de assinatura (`DriverTestSign` / `DriverProductionSign`), garantindo que nenhum certificado seja criado/instalado e que `.dll`/`.cat` permaneçam nao assinados.
- `<EnableInf2cat>true</EnableInf2cat>` e `<DriverCatalog_Enable>true</DriverCatalog_Enable>` permanecem independentes da assinatura e executam os targets `Inf2Cat` e `DrvCat` apos `DriverPackageTarget`.
- Integrar `<Inf Include="LumaBridgeIddDriver.inf" />` e `<FilesToPackage Include="$(TargetPath)" />` no `.vcxproj` ativa automaticamente a cadeia `StampInf -> InfVerif -> ClCompile -> Link -> DriverPackageTarget -> Inf2Cat -> DrvCat`.

## 6. Comandos de build e validacao

Em Developer Command Prompt / Visual Studio x64 (`VsDevCmd.bat -arch=x64 -host_arch=x64`):

```bat
msbuild windows\driver\LumaBridgeIddDriver.sln /t:Rebuild /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 /v:minimal
msbuild windows\driver\LumaBridgeIddDriver.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 /v:minimal
```

Validacoes diretas do INF e testes automatizados (a partir da raiz do repositorio):

```bat
"C:\Program Files (x86)\Windows Kits\10\Tools\10.0.28000.0\x64\infverif.exe" /v /u /stampinf windows\driver\LumaBridgeIddDriver\LumaBridgeIddDriver.inf
"C:\Program Files (x86)\Windows Kits\10\Tools\10.0.28000.0\x64\infverif.exe" /v /u windows\driver\x64\Debug\LumaBridgeIddDriver\LumaBridgeIddDriver.inf
"C:\Program Files (x86)\Windows Kits\10\Tools\10.0.28000.0\x64\infverif.exe" /v /h windows\driver\x64\Debug\LumaBridgeIddDriver\LumaBridgeIddDriver.inf
"C:\Program Files (x86)\Windows Kits\10\Tools\10.0.28000.0\x64\infverif.exe" /v /w windows\driver\x64\Debug\LumaBridgeIddDriver\LumaBridgeIddDriver.inf
"C:\Program Files (x86)\Windows Kits\10\Tools\10.0.28000.0\x64\infverif.exe" /v /u windows\driver\x64\Release\LumaBridgeIddDriver\LumaBridgeIddDriver.inf
"C:\Program Files (x86)\Windows Kits\10\Tools\10.0.28000.0\x64\infverif.exe" /v /h windows\driver\x64\Release\LumaBridgeIddDriver\LumaBridgeIddDriver.inf
"C:\Program Files (x86)\Windows Kits\10\Tools\10.0.28000.0\x64\infverif.exe" /v /w windows\driver\x64\Release\LumaBridgeIddDriver\LumaBridgeIddDriver.inf

cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\AdapterLifecycleTests.cpp /Fowindows\driver\x64\Debug\AdapterLifecycleTests.obj /Fe:windows\driver\x64\Debug\AdapterLifecycleTests.exe
windows\driver\x64\Debug\AdapterLifecycleTests.exe

cl /nologo /std:c++17 /W4 /WX /EHsc windows\driver\tests\DriverPackageValidationTests.cpp /Fowindows\driver\x64\Debug\DriverPackageValidationTests.obj /Fe:windows\driver\x64\Debug\DriverPackageValidationTests.exe
windows\driver\x64\Debug\DriverPackageValidationTests.exe
```

## 7. Resultados efetivamente obtidos

| Verificacao | Escopo | Resultado observado |
|---|---|---|
| `MSBuild` `Debug|x64` (`Rebuild`) | `StampInf`, `InfVerif`, `ClCompile`, `Link`, `DriverPackageTarget`, `Inf2Cat`, `DrvCat`, `CopyCatalogToOutDir` | Exit `0`, `0` avisos, `0` erros. Gerados `LumaBridgeIddDriver.dll` (`155648` B), `LumaBridgeIddDriver.inf` (`1833` B), `lumabridgeidddriver.cat` (`1392` B). |
| `MSBuild` `Release|x64` (`Rebuild`) | `StampInf`, `InfVerif`, `ClCompile`, `Link`, `DriverPackageTarget`, `Inf2Cat`, `DrvCat`, `CopyCatalogToOutDir` | Exit `0`, `0` avisos, `0` erros. Gerados `LumaBridgeIddDriver.dll` (`150016` B), `LumaBridgeIddDriver.inf` (`1833` B), `lumabridgeidddriver.cat` (`1392` B). |
| `infverif.exe /v /u /stampinf` | `windows/driver/LumaBridgeIddDriver/LumaBridgeIddDriver.inf` | Exit `0` — `INF is VALID`. |
| `infverif.exe /v /u`, `/v /h`, `/v /w` | INFs carimbados de `Debug` e `Release` (regras OS build `10.0.28000`) | Exit `0` em todos os 6 modos — `INF is VALID`. |
| `Inf2Cat` + `DrvCat` + `certutil -dump` | Catalogos `Debug` e `Release` | `Errors: None`, `Warnings: None`; registra `lumabridgeidddriver.inf`, `lumabridgeidddriver.dll`, `_v100_X64_19H1`, `HWID1=root\lumabridgeidddriver`, `WdkVersion=10.0.28000.0`; `Nenhum signatario` (`Status: NotSigned`). |
| `AdapterLifecycleTests.exe` | Maquina de estados e sincronizacao em C++ puro | `Summary: 16 tests run, 0 assertion failures.` (exit `0`). |
| `DriverPackageValidationTests.exe` | Consistencia estatica de DLL/INF/CAT em `Debug` e `Release` | `Summary: 4 tests run, 0 assertion failures.` (exit `0`). |

## 8. Limitacoes

- Nao ha assinatura digital nos arquivos `.dll` ou `.cat` (`NotSigned`).
- O pacote nao foi instalado no sistema operacional; portanto **nao ha validacao em runtime** de `SetupAPI`, `WUDFRd.sys`, `IndirectKmd.sys` ou `WUDFHost.exe` nesta entrega.
- Nenhum monitor virtual (`IddCxMonitorCreate`/`IddCxMonitorArrival`) nem processamento de swapchain esta ativo; instalar este pacote apenas exercitaria a criacao de dispositivo/adaptador sem display funcional ate que as proximas issues sejam concluidas.

## 9. Estrategia futura de assinatura de desenvolvimento e compatibilidade com HVCI

### Compatibilidade com HVCI / VBS / Secure Boot

- No host Windows 11 de referencia (`OsBuildNumber = 26300`), observou-se `UEFISecureBootEnabled = 0` e **VBS/HVCI ativo** (`SecurityServicesRunning = {2}`, `VirtualizationBasedSecurityStatus = 2`).
- Porque o LumaBridge e um driver **UMDF 2 / IddCx**:
  - Os modulos kernel da pilha (`WUDFRd.sys` e `IndirectKmd.sys`) ja sao binarios inbox assinados pela Microsoft e compativeis com HVCI.
  - A DLL do LumaBridge (`LumaBridgeIddDriver.dll`) executa em user-mode dentro de `WUDFHost.exe` e e compilada com `/guard:cf` (Control Flow Guard), sem secoes gravaveis e executaveis simultaneamente e sem dependencias kernel nao suportadas.
- Ainda assim, o carregamento do pacote no Windows exige confianca de assinatura valida:
  - Em **desenvolvimento controlado** (issue futura dedicada): exige Test Signing habilitado (`bcdedit /set testsigning on`, incompativel com alguns ambientes que impoem Secure Boot estrito sem politica apropriada) ou instalacao explicita de certificado de teste na store `Trusted Root` + `Trusted Publishers` via `SignTool` sobre o `.cat` (e `.dll`).
  - Em **distribuicao para producao futura**: requer assinatura de codigo / attestacao ou certificacao WHQL junto a Microsoft para operar com HVCI e Secure Boot ativos sem modo de teste.

Nenhuma alteracao em certificados, `bcdedit`, Secure Boot ou HVCI foi executada nesta etapa.

## 10. Procedimentos futuros de instalacao, diagnostico, desinstalação, rollback e recuperacao

> Os comandos abaixo sao referencia documentada para a **futura etapa de instalacao controlada**, devendo ser executados somente quando houver decisao explicita de testar o driver em maquina alvo ou VM com assinatura de desenvolvimento configurada.

### Instalacao controlada (futuro, apos assinatura de teste)

1. Confirmar em snapshot/VM ou ponto de restauracao criado previamente que drivers existentes (incluindo Parsec) nao compartilham o Hardware ID `Root\LumaBridgeIddDriver`.
2. Adicionar o pacote assinado ao Driver Store sem forcar instalacao cega:

```powershell
pnputil /add-driver ".\windows\driver\x64\Release\LumaBridgeIddDriver\LumaBridgeIddDriver.inf"
```

3. A criacao da instancia de dispositivo `Root\LumaBridgeIddDriver` deve preferir a API moderna `SwDeviceCreate` em um executavel de controle dedicado (mantendo isolamento do ciclo de vida do dispositivo), ou ferramenta WDK apropriada em ambiente de teste isolado.

### Diagnostico de falhas

- **Logs de instalacao PnP / INF:** inspecionar `C:\Windows\INF\setupapi.dev.log` procurando `LumaBridgeIddDriver` e `Root\LumaBridgeIddDriver`.
- **Visualizador de Eventos:** `Applications and Services Logs -> Microsoft -> Windows -> DriverFrameworks-UserMode -> Operational` e `System` (`Kernel-PnP`).
- **Logs de runtime UMDF (`[LB-DRIVER]`):** capturar `OutputDebugStringA` (DebugView elevado com captura global/session-0) durante inicializacao do `WUDFHost.exe`.
- **Estado no Driver Store e dispositivos:**

```powershell
pnputil /enum-drivers | Select-String -Pattern "LumaBridge" -Context 2,4
pnputil /enum-devices /class Display
```

### Desinstalacao e rollback

1. Remover eventual dispositivo virtual instanciado:

```powershell
# Identificar o Instance ID exato via pnputil /enum-devices /class Display
pnputil /remove-device "<INSTANCE_ID>"
```

2. Identificar o nome publicado `oemXX.inf` em `pnputil /enum-drivers` e remover o pacote do Driver Store (com rollback automatico para versao anterior, se aplicavel):

```powershell
pnputil /delete-driver oemXX.inf /uninstall /force
```

### Recuperacao em caso de falha critica de video

Caso uma build futura provoque instabilidade no subsistema grafico ou falha persistente no login:

1. Reiniciar em **Modo de Seguranca (Safe Mode)** ou **Ambiente de Recuperacao do Windows (WinRE)** -> Prompt de Comando.
2. Em Safe Mode (sistema online): listar e remover o pacote `oemXX.inf`:

```bat
pnputil /enum-drivers
pnputil /delete-driver oemXX.inf /uninstall /force
```

3. Em WinRE (imagem offline em `C:\`, se o sistema nao inicializar): remover o pacote diretamente da imagem offline:

```bat
dism /Image:C:\ /Get-Drivers
dism /Image:C:\ /Remove-Driver /Driver:oemXX.inf
```

4. O LumaBridge nao altera nem sobrescreve o adaptador fisico (RTX 3060 Ti), o driver basico do Windows nem drivers de terceiros (como Parsec), garantindo retorno imediato do video primario apos remocao do `oemXX.inf`.
