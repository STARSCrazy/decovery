# ADR 0015: Aztec C86 assembler sources

Status: accepted · 2026-11-19

## Context

Aztec C86 workspaces keep hand-written functions in `.asm` files. `build` handed every `.asm` to the built-in
assembler first (byte listings, OMF output) and fell back to the profile's `[assembler]` only for a line outside its
subset; the Aztec profiles had no `[assembler]`, so a real source (`push bp`, labels) was skipped. The Aztec assembler
AS writes named, non-public symbols for local labels, and the function view split a code section at every named
symbol: a function was compared only up to its first local label.

## Decision

1. `aztec-c86-4.2b` gets `[assembler] command = "AS {input}"`: AS runs through the profile's runners, prelude and job
   prelude (it is in `D:\BIN` like CC) and writes `X.O` in the profile's object format. Only 4.2b's AS is verified;
   3.4b and 5.2a keep no assembler until checked.
2. Order: for a profile whose objects are not OMF, an `.asm` source goes to the profile's assembler when its toolchain
   is there; the built-in assembler (which writes OMF) is the fallback. OMF profiles keep the built-in assembler first.
3. Function boundaries in objects built from assembler sources: a function runs from a public label to the next public
   label, or the end of the code section (`public_functions` in `decovery-objects`). Non-public labels and data in
   the code section between them belong to the function. C objects keep the old rule (every named symbol starts a
   function: a `static` function is a function). The end is the next start or the section end in both cases, as
   before; the analysis' function end is not used. Code before the first public label is not compared as a
   function (see 5).
4. An assembler failure with AS error lines (`ERROR:<file>:<line>: <text>`) is reported as `line <line>: <text>`
   first, as the built-in assembler words its errors, followed by the assembler's output.
5. The bytes before the first public label of an assembler object's code section (mode bytes, pointer tables: data
   in the code segment that belongs to no function) are compared as one block. The object start is placed by the
   first placed public function of that section: its address minus its offset. The block is compared against the
   original there with its relocated fields as link gaps, like a function. `build` reports it per file
   (`files[].leading`: `bytes`, `state` = `equal` | `differs` | `unchecked`, `address`, `differing`, `gaps`,
   `reason`, `first_difference`) and in the summary (`dsasm.asm: 310 bytes before the first public label: equal`).
   A differing block counts in `counts.leading_differs` and fails the build like a differing function. Without a
   placed public function (or without the original's bytes there) the block is unchecked with the reason. It is
   not recorded as a rebuild record.

## Consequences

A profile schema change is not needed (`[assembler]` exists). Assembler functions are compared over their full
extent with the relocated fields as link gaps (`compare_aztec`), like C functions. A record of an assembler function
names the profile as `compiler`.
