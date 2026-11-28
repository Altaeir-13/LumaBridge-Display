# Guia de Execução e Qualificação `M2` (`Windows 11 → Linux` em LAN)

Este guia descreve como compilar, configurar e executar o primeiro fluxo completo ponta-a-ponta do **LumaBridge Display (`M2`)**: captura GPU no host **Windows 11** (`LumaBridgeIddDriver` + D3D11 compartilhado sem readback CPU + `NVENC H.264`), transporte autenticado (`SPAKE2` + `mTLS` `TLS 1.3` sobre `QUIC` ou `TCP+TLS`) e apresentação hardware **VA-API / Wayland / X11** no receptor **Arch Linux** (ou Linux compatível).

---

## 1. Requisitos de Ambiente

### 1.1 Receptor Linux (Arch Linux / Hyprland / Wayland / X11)

- Kernel Linux com driver Mesa / Intel / AMD VA-API funcional:
  ```bash
  sudo pacman -S --needed base-devel cmake ninja pkgconf ffmpeg sdl2 libva libva-utils
  vainfo
  ```
- Confirme no `vainfo` suporte a **`VAProfileH264High`** (`VAEntrypointVLD`).
- Toolchain Rust fixada (`1.100.0`) para compilar `liblumabridge_ffi.so`.

### 1.2 Emissor Windows 11 (Host GPU + IddCx)

- Windows 11 x64 com Visual Studio / Build Tools MSVC C++20, Rust `1.100.0` e driver NVIDIA atualizado com suporte NVENC (`H.264`).
- Para uso com monitor virtual real (`IddCx`): seguir [`windows-driver-development-setup`](./windows-idd-driver-packaging.md) e [`windows-idd-functional-validation.md`](./windows-idd-functional-validation.md).

---

## 2. Compilação

### 2.1 No Receptor Linux

```bash
cd core
cargo build --locked --release -p lumabridge-ffi -p lumabridge-core --bin lumabridge_node
cd ..

cmake -S linux/receiver -B build/linux-rx -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/linux-rx
./build/linux-rx/lumabridge-linux-receiver-tests
```

### 2.2 No Host Windows 11

1. **Compilar a biblioteca FFI (`lumabridge_ffi.dll`):**

```powershell
cd core
cargo build --locked --release -p lumabridge-ffi
cd ..
```

2. **Compilar e validar o host FFI PoC (`lumabridge-host-ffi-poc.exe`) + testes C11/C++20:**

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/ci/Invoke-LumaBridgeFfiPocCi.ps1 -RepoRoot . -SkipBenchmark -BuildRoot .\build\win-host
```

Validação local GPU RTX (D3D11 textura GPU → NVENC H.264 → QUIC/TLS 1.3 → Decode MF MFT + reconfiguração dinâmica de bitrate + `ProtectedBlank`, usando `SelftestOnlyLoopbackApprovalCallback` isolado ao autoteste):

```powershell
.\build\win-host\release\lumabridge-host-ffi-poc.exe --m2-nvenc-loopback-selftest
```

---

## 3. Configuração Persistente (`key=value`) e Execução em LAN

Exemplo de arquivo de configuração persistente do receptor (`/etc/xdg/lumabridge-rx.conf` ou local):

```ini
role=receiver
friendly_name=Arch-Hyprland-Display
transport=quic-datagram
bind_addr=0.0.0.0:4242
width=1920
height=1080
fps=60
fullscreen=true
overlay=true
vsync=true
allow_sw_decode_fallback=false
mdns=true
```

### 3.1 Iniciar Receptor Linux (Wayland / X11 automático)

```bash
./build/linux-rx/lumabridge-linux-receiver --config ./lumabridge-rx.conf --json-report ./rx-telemetry.json
```

O receptor exibe no terminal o endereço de pareamento/sessão, um prefixo abreviado do `DeviceId` (com `...`) e o **PIN de 8 dígitos** de uso limitado (máximo 3 tentativas, janela monotônica independente do relógio de parede). Caso informe `--endpoint-out <arquivo>`, o arquivo gravado atomicamente com permissão `0600` (`open` com `S_IRUSR|S_IWUSR` + `fsync` + `rename`) contém um registro único delimitado por pipe (`pair_addr|op_addr|device_id_hex|pin`), expondo o **`device_id_hex` completo de 64 caracteres** para verificação/pinning sem exibir o PIN em argumentos de linha de comando.
- **Consentimento Bilateral Obrigatório em LAN Real (`TTY` interativo):** tanto o receptor Linux (`PromptLocalReceiverPairingApproval`) quanto o host Windows (`PromptLocalHostPairingApproval`) exigem entrada interativa no console (`[y/N]`) após exibição de `attempt`, `peer_id`, `fingerprint` e `untrusted_name` (falha fechada em `stdin` não interativo). A flag `--ci-auto-approve-pairing` é restrita exclusivamente a CI/autotestes sintéticos e **rejeitada** em arquivos `.conf`.
- Atalho **`F12`**: alterna o overlay diagnóstico **`BRIDGE_TERMINAL`** (sem expor pixels ou segredos).  
- Atalho **`Esc`** ou **`Ctrl+Shift+Q`**: encerra com segurança.
- Por política (`ADR-0005` / Roadmap `M2`), se o VA-API não inicializar, o receptor recusa iniciar decodificação por software a menos que `--allow-sw-fallback` seja explicitamente informado para diagnóstico.

### 3.2 Iniciar Emissor Host Windows 11 apontando para a LAN

**Modo recomendado (prompt interativo sem eco no console — sem passar segredos em `argv`):**

```powershell
.\build\win-host\release\lumabridge-host-ffi-poc.exe `
  --transport gpu `
  --require-gpu-shared `
  --nvenc `
  --nvenc-bitrate-bps 15000000 `
  --lan-remote 192.168.1.50 `
  --lan-pair-port <PAIR_PORT> `
  --lan-op-port <OP_PORT> `
  --lan-peer-id <DEVICE_ID_HEX_64_CHARS> `
  --lan-transport quic-datagram
```

Alternativamente, para scripts/automação segura sem eco em argumentos, forneça o PIN via entrada padrão (`--lan-pin-stdin`):

```powershell
$pinFileContents | .\build\win-host\release\lumabridge-host-ffi-poc.exe `
  --transport gpu --require-gpu-shared --nvenc --nvenc-bitrate-bps 15000000 `
  --lan-remote 192.168.1.50 --lan-pair-port <PAIR_PORT> --lan-op-port <OP_PORT> `
  --lan-peer-id <DEVICE_ID_HEX_64_CHARS> --lan-pin-stdin --lan-transport quic-datagram
```

> - `--lan-peer-id` é recomendado sempre que o `device_id_hex` completo do receptor for obtido, adicionando pinning SPKI explícito junto ao pareamento SPAKE2.
> - `--lan-pin` está **depreciado** para uso normal e emite aviso de segurança por expor o PIN em argumentos de processo; em CI sintético, `lumabridge_node` separa explicitamente `--ci-synthetic-pin` e `--rendezvous-in`.

---

## 4. Roteiro de Aceite Físico em Duas Fases (`Windows 11 → Linux LAN`, 12 Etapas)

Execute todas as etapas abaixo em ambiente físico dedicado com ambas as máquinas conectadas à mesma LAN (`M2_COMPLETE = False` até conclusão). **Não** altere drivers, firewall, BCD, Secure Boot, `TestSigning` ou configuração administrativa de rede em estação não autorizada sem aprovação explícita.

### Fase A — Primeiro Teste Funcional em LAN Física (Etapas 1–6)

1. **Identificação de binários e commits:** registre `git rev-parse HEAD` no repositório, `rustc --version` e o hash SHA-256 dos executáveis/bibliotecas (`Get-FileHash -Algorithm SHA256` no Windows; `sha256sum` no Linux) em `lumabridge-host-ffi-poc.exe`, `lumabridge_ffi.dll`, `lumabridge-linux-receiver` e `liblumabridge_ffi.so`.
2. **Preflight Windows e Linux (somente leitura antes de alterações):**
   - No Linux: confirme kernel/GPU, grupo `video`/`render`, `timedatectl status` (NTP sincronizado) e portas UDP/TCP disponíveis (`ss -tulnp`).
   - No Windows: confirme adaptador GPU NVIDIA ativo (`nvidia-smi`), versão do sistema operacional (`winver`), sincronização horária (`w32tm /query /status`), perfil/estado de firewall atual (`Get-NetFirewallProfile`) e ausência de alterações não autorizadas em BCD/Secure Boot/`TestSigning` (`bcdedit /enum` / `Confirm-SecureBootUEFI`).
3. **Verificação nativa `VA-API`:** no receptor Linux, execute `vainfo` confirmando `VAProfileH264High` (`VAEntrypointVLD`) em `/dev/dri/renderD128` (ou `--vaapi-device`). Nas execuções físicas deste roteiro, **omita `--allow-sw-fallback`** para garantir falha fechada caso hardware decode não inicialize.
4. **Pareamento autenticado (`SPAKE2` + `mTLS`) com consentimento bilateral:** inicie `lumabridge-linux-receiver` em terminal interativo (`TTY`) com `--config` persistente e opcionalmente `--endpoint-out ./rdv.txt` (`0600`); leia `pair_addr`, `op_addr`, `device_id_hex` (64 hex chars) e `pin` apenas para digitação manual no prompt sem eco do host Windows (ou `--lan-pin-stdin`), e confirme `[y/N]` em ambos os terminais após conferir `attempt`, `peer_id` e `fingerprint`.
5. **Monitor virtual real (`IddCx`) em estação Windows autorizada:** seguindo [`windows-idd-driver-packaging.md`](./windows-idd-driver-packaging.md) e [`windows-idd-functional-validation.md`](./windows-idd-functional-validation.md), confirme o monitor virtual `1920×1080 @ 60 Hz` em Configurações de Vídeo, execute `lumabridge-host-ffi-poc.exe` com `--transport gpu --require-gpu-shared --nvenc`, e arraste uma janela real com movimento contínuo para a tela estendida.
6. **Teste sustentado `1080p60` (`Wayland/Hyprland` e `X11`):** execute por **`>= 60 s`** primeiro em sessão `Wayland` (ex.: `Hyprland`) e repita em sessão `X11`, alternando **`F12` (`BRIDGE_TERMINAL`)** e inspecionando `rx-telemetry.json`. Verifique `MeasurementOrigin` (`encode`, `decode` como `"measured"`, `clock_sync_origin: "measured"`, `network`/`end_to_end` como `"estimated"`), `p50`/`p95`/`p99` (`p95 <= 100 ms` esperado em Ethernet), CPU, GPU, RAM e VRAM.

### Fase B — Qualificação Completa (Etapas 7–12)

7. **Comparação por meio físico (`Ethernet` e `Wi-Fi` conforme disponíveis):** execute o ensaio de 60 s em cabo Ethernet e em Wi-Fi (5/6 GHz), arquivando `rx-telemetry.json` e métricas de interface em relatórios separados sem misturar resultados entre meios.
8. **Perda e jitter controlados no sentido Windows → Linux (`tc netem` L3 equivalente, com autorização administrativa):**
   - **Atenção (`egress`-only):** `tc qdisc ... netem` atua **exclusivamente na fila de saída (`egress`)** da interface onde é aplicado. Aplicar `tc netem` diretamente na NIC do receptor Linux afeta apenas o tráfego de retorno (`Linux → Windows`, feedback/ACKs) e **não** simula perda/atraso no fluxo de vídeo `Windows → Linux`.
   - Para simular perda/jitter reais no fluxo `Windows → Linux` sem alterar o host Windows, interponha uma ponte/roteador L3 em namespace Linux (`ip netns` + par `veth` com roteamento dedicado) aplicando `tc netem` no `egress` da interface `veth` voltada ao receptor (ou utilize um shaper L3 equivalente no lado Windows):
   ```bash
   # Exemplo no roteador/namespace L3 intermediário (interface egress voltada ao receptor):
   sudo ip netns exec lb-router tc qdisc replace dev veth-to-rx root netem delay 6ms 3ms loss 2%
   # Transmitir fluxo Windows -> Linux por >= 60 s e coletar rx-telemetry-netem.json
   sudo ip netns exec lb-router tc qdisc del dev veth-to-rx root
   ```
   Verifique contagem não nula de `idr_requests`, controle de `dropped_frames`, recuperação limpa de GOP sem artefatos persistentes e isolamento da fila de controle.
9. **Verificação visual e de telemetria de `ProtectedBlank`:** acione `ProtectedBlank` durante sessão ativa e confirme tela limpa (`ProtectedBlank` visível sem quadro residual), incremento de `protected_blanks` em `rx-telemetry.json` e ausência de P-frames órfãos após o blank.
10. **Desconexão limpa e abrupta:** valide encerramento gracioso (`Esc` ou `Ctrl+Shift+Q` no receptor / interrupção normal no host) e desconexão abrupta de rede (`ip link set <iface> down` temporário ou cabo desconectado por 5 s), registrando tempo de detecção de timeout/fechamento.
11. **Recuperação e auditoria de vazamentos:** reconecte a sessão após queda e, ao encerrar, verifique saída `leaked_bufs == 0`, desmontagem do monitor virtual no Windows sem handles órfãos (`nvidia-smi` / Gerenciador de Tarefas) e ausência de processos pendentes.
12. **Limpeza e *rollback*:** remova `tc qdisc` e `netns` temporários (`sudo ip netns del lb-router 2>/dev/null || true`), apague arquivos temporários de rendezvous (`shred -u ./rdv.txt` ou `Remove-Item`), desative/remova o monitor virtual de teste conforme guia `IddCx` e preserve somente os JSONs/hashes sanitizados de evidência.

---

## 5. Solução de Problemas Comuns

- **`VA-API hardware decode initialization failed`:** Verifique permissões em `/dev/dri/renderD128` (grupo `render`/`video`), execute `vainfo` ou especifique `--vaapi-device /dev/dri/renderD129`.
- **Firewall UDP bloqueando `QUIC`:** Confirme regras autorizadas para as portas UDP de pareamento/operação ou utilize `--lan-transport tcp-tls` / `--transport tcp-tls`.
- **Diferença de relógio entre Windows e Linux:** Os certificados autoassinados operacionais toleram até 300 s de skew inicial; diferenças maiores exigem sincronização NTP nas máquinas.
