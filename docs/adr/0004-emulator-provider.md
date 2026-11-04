# ADR 0004: Emulator provider

Status: accepted · 2026-11-04

## Context

decovery needs CPU emulation for two jobs: running original DOS compilers (Watcom WCC386 under a Phar Lap /
DOS/4GW-style host, 16-bit real-mode tools) and executing single functions for behavioural equivalence
(`verify`). The predecessor Decomp does both with unicorn (`nachbau/emu_dos.py`, `entpacken.py`) and the unicorn
DLL 2.1.1 for speed.

Facts checked on 2026-11-04:

- **unicorn** (github.com/unicorn-engine/unicorn): licence GPL-2.0 (`COPYING`, GitHub API `GPL-2.0`), active
  (last push 2026-10-18). Supports x86 16/32/64 including real mode; proven for this exact workload in Decomp.
- **icicle-emu** (github.com/icicle-emu/icicle-emu): licence Apache-2.0 / MIT (`LICENCE-APACHE`, `LICENCE-MIT`),
  active (last push 2026-11-03), 316 stars. Self-described as an *experimental, fuzzing-specific* emulator built on
  SLEIGH/p-code with a JIT; used as a git dependency (not on crates.io); its README shows x86-64 Linux userspace,
  AArch64, MIPS and MSP430 targets. Real-mode and segmented 16/32-bit x86 with the descriptor handling a DOS
  extender host needs is not documented.

decovery is licensed `Apache-2.0 OR MIT` (ADR 0003): linking GPL code into the binary is not allowed.

## Decision

1. unicorn is used **out of process**: a separate provider binary `plugins/decovery-unicorn` (Rust, licensed
   GPL-2.0, its own crate outside the main workspace's default build) implements the `Runner` (unicorn tool host
   for DOS/extender programs) and `FunctionExec` contracts over the plugin protocol. It is introduced in phase 2
   by porting `emu_dos.py`.
2. Calls are coarse (one per compile, one per batch of cases), so the process boundary is not a bottleneck.
3. icicle-emu is re-evaluated by a spike when phase 5 (`verify`) starts: if it runs x86 16-bit real mode and the
   Watcom host at acceptable speed, an in-process permissive provider may replace or complement unicorn (new ADR).

## Consequences

- The main binary stays permissively licensed and has no emulator inside; users who want emulation install or
  build the GPL provider, which is clearly separated in `plugins/`.
- The `Runner` and `FunctionExec` contracts must not assume in-process access to emulator memory; memory images
  travel as blobs by path + hash.
