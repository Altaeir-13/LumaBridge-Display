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

Execute a qualificação FFI + compilação MSVC:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/ci/Invoke-LumaBridgeFfiPocCi.ps1 -RepoRoot . -SkipBenchmark -BuildRoot .\build\win-host
```

Validação local GPU RTX (D3D11 textura GPU → NVENC H.264 → QUIC/TLS 1.3 → Decode MF MFT + reconfiguração dinâmica de bitrate + `ProtectedBlank`):

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

O receptor exibe no terminal o endereço de pareamento/sessão, um prefixo abreviado do `DeviceId` (com `...`) e o **PIN de 8 dígitos** de uso limitado (máximo 3 tentativas). Caso informe `--endpoint-out <arquivo>`, o JSON gravado nesse arquivo (permissão `0600`) contém o **`device_id_hex` completo de 64 caracteres** para verificação ou pinning.
- Atalho **`F12`**: alterna o overlay diagnóstico **`BRIDGE_TERMINAL`** (sem expor pixels ou segredos).  
- Atalho **`Esc`** ou **`Ctrl+Shift+Q`**: encerra com segurança.
- Por política (`ADR-0005` / Roadmap `M2`), se o VA-API não inicializar, o receptor recusa iniciar decodificação por software a menos que `--allow-sw-fallback` seja explicitamente informado para diagnóstico.

### 3.2 Iniciar Emissor Host Windows 11 apontando para a LAN

```powershell
.\build\win-host\release\lumabridge-host-ffi-poc.exe `
  --transport gpu `
  --require-gpu-shared `
  --nvenc `
  --nvenc-bitrate-bps 15000000 `
  --lan-remote 192.168.1.50 `
  --lan-pair-port <PAIR_PORT> `
  --lan-op-port <OP_PORT> `
  --lan-pin <PIN_8_DIGITOS> `
  --lan-peer-id <DEVICE_ID_HEX_64_CHARS> `
  --lan-transport quic-datagram
```

> `--lan-peer-id` é recomendado sempre que o `device_id_hex` completo do receptor for conhecido via `--endpoint-out`, adicionando pinning SPKI explícito junto ao pareamento SPAKE2.

---

## 4. Qualificação em LAN com `tc netem` (Wi-Fi / Perda Simulada)

No Linux, para medir recuperação de GOP (`AwaitingIdr` / `RequestForceIdr`) sob perda de 2% e jitter controlado na interface de rede `<iface>`:

```bash
sudo tc qdisc add dev <iface> root netem delay 6ms 3ms loss 2%
# Executar stream Windows -> Linux por >= 60s e inspecionar rx-telemetry.json (p50/p95/p99, idr_requests, dropped_frames)
sudo tc qdisc del dev <iface> root
```

---

## 5. Solução de Problemas Comuns

- **`VA-API hardware decode initialization failed`:** Verifique permissões em `/dev/dri/renderD128` (grupo `render`/`video`), execute `vainfo` ou especifique `--vaapi-device /dev/dri/renderD129`.
- **Firewall UDP bloqueando `QUIC`:** Libere as portas UDP de pareamento/operação ou utilize `--lan-transport tcp-tls` / `--transport tcp-tls`.
- **Diferença de relógio entre Windows e Linux:** Os certificados autoassinados operacionais toleram até 300 s de skew inicial; diferenças maiores exigem sincronização NTP nas máquinas.
