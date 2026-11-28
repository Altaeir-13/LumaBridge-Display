---
name: lumabridge-performance
description: Reproducible benchmarking, latency/jitter/loss evaluation, queue bounding, and ADR-0005 transport comparison methodology for LumaBridge Display.
---

# LumaBridge Performance & Benchmark Discipline

Use this skill for Criterion microbenchmarks, `ADR-0005` comparative transport benchmarks (`QUIC` datagrams vs `QUIC` streams vs `TCP/TLS 1.3`), backpressure tuning, and hot-path regression checks.

## 1. Benchmark Standards

- Run with `--locked --release` (or `cargo bench --locked -p <crate>`) with zero synthetic sleep inflation.
- Record:
  - Hardware/OS environment (CPU, OS, loopback vs virtual interface, simulated impairments).
  - Exact benchmark command and commit SHA.
  - Distribution percentiles (`p50`, `p95`, `p99`), max observed tail latency, throughput (fps / Mbps), frame drops, and IDR recovery time.
  - Allocation profile and peak bounded queue depth on the media hot path.

## 2. Transport Hot-Path & Congestion Requirements (`ADR-0005`)

- Avoid per-frame heap copies or unbounded buffering on Channel 1 (`Media`).
- Enforce explicit queue capacities, MTU-derived fragmentation (`effective_lbwp_packet_budget`), and pre-socket drop/pacing rules under congestion.
- Under `QUIC` datagram transport vs stream fallback vs `TCP/TLS 1.3`, measure behavior across:
  - Clean loopback baseline (1080p60 synthetic encoded frames).
  - Jittered LAN (`10–30 ms` variable delay) and packet loss (`0.5%`, `2%`, `5%`), packet reordering, and duplicate packets.
  - Bandwidth throttling / saturation, ensuring Channel 0 (`Control`, including `ProtectedBlank`) and Channel 3 (`Input`) remain responsive without head-of-line stalling by stale video frames.
  - GOP recovery latency (`RequestForceIdr` cooldown + next IDR arrival).

## 3. Anti-Cheating Rule

- Never weaken latency budgets, packet-drop assertions, or frame-budget expectations to make a noisy or unoptimized implementation look green.
- Optimize the actual bottleneck (allocations, lock contention, fragmentation, pacing) and re-run benchmarks end-to-end.
