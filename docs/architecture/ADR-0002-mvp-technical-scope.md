# ADR-0002 - Escopo tecnico do MVP

## Status

Aceita para planejamento inicial.

## Contexto

O objetivo do LumaBridge Display e fazer um laptop Linux funcionar como monitor secundario real para um PC Windows 11. O requisito central e que o Windows reconheca um monitor virtual adicional. O produto nao deve se limitar a screen sharing da tela principal.

O hardware inicial informado e:

- Host Windows 11 com NVIDIA RTX 3060 Ti.
- Cliente Arch Linux + Hyprland com iGPU Intel.

## Decisao

O MVP tera o seguinte escopo tecnico:

- Windows 11 como host.
- Arch Linux + Hyprland como cliente.
- IDD/IddCx para criar monitor virtual no Windows.
- NVENC H.264 como encoder inicial.
- HEVC opcional depois que H.264 estiver estavel.
- VA-API como decode preferencial no cliente Linux.
- LAN como rede inicial.
- Transporte de baixa latencia por UDP/RTP ou QUIC, com decisao final apos spike.
- NAT traversal fora do MVP.
- STUN/TURN/ICE fora do MVP.
- UI sofisticada fora do MVP.
- Configuracao por CLI/arquivo aceitavel no MVP.
- Foco em validar o fluxo completo: Windows reconhece monitor virtual, host transmite, Linux exibe em fullscreen.

## Fora do escopo desta decisao

- Cliente Android/iOS/macOS.
- HDR.
- Audio multicanal.
- Multiplos monitores virtuais simultaneos.
- Driver assinado para producao.
- Instalador publico assinado.
- Compatibilidade com jogos protegidos por anti-cheat.

## Consequencias

Beneficios:

- Reduz escopo para validar a parte mais arriscada primeiro.
- Mantem foco no monitor virtual real.
- Aproveita NVENC da RTX 3060 Ti e VA-API da iGPU Intel.
- Evita complexidade de internet/NAT antes de LAN estar funcional.

Custos:

- Uso inicial limitado a LAN.
- Setup de desenvolvimento do driver Windows continua exigente.
- UI inicial pode ser menos amigavel.
- Distribuicao publica exigira trabalho posterior de assinatura e empacotamento.

## Criterios de validade

Esta decisao deve ser revisada se:

- IddCx bloquear completamente o monitor virtual.
- NVENC nao atender requisitos de latencia no hardware alvo.
- VA-API se mostrar inviavel no cliente alvo.
- O transporte escolhido nao suportar baixa latencia em LAN.
- O produto deixar de exigir monitor virtual real e mudar de estrategia.
