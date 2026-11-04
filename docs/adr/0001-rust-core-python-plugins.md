# ADR 0001: Rust core, plugins in Rust or Python

Status: accepted · 2026-11-04

## Context
decovery coordinates decompilers, emulators, compilers and differs and must be fast, compact and shareable with
the matching-decompilation community, which works mostly in Rust (objdiff, decomp-toolkit) and Python (m2c,
decomp-permuter, pyghidra).

## Decision
The core is a Rust workspace producing one binary. Capabilities on hot paths are implemented in Rust in-process.
Third-party tools are reached through out-of-process plugins speaking the decovery plugin protocol (JSON-RPC 2.0
over stdio); Python plugins use the `decovery-plugin` SDK.

## Consequences
One binary without runtime for the core; Ghidra and other Python/Java tools stay optional. Plugin calls must be
coarse-grained; large data is passed by path and hash.
