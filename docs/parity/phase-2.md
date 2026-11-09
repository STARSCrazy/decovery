# Phase-2 parity against Decomp

Checked on 2026-11-09 by `crates/decovery-cli/tests/build_parity_local.rs` and
`crates/decovery-cli/tests/link_local.rs` (`#[ignore]`, need private workspaces, the original programs and the
compilers).

- **Baseline:** Decomp commit `0ef288f41b68e6b557edcb86f844fa9ce9725c41`. Each private workspace is migrated with
  `decovery migrate` into a temporary directory; `[rebuild] tool_dir` points at the local compiler.
- **Targets:** first target: a Watcom 9.5 LE game (32-bit, 34 rebuild sources, two of them assembler); second
  target: a Turbo C 2.0 MZ tool (16-bit, small model, one rebuild source).
- **Runner:** `unicorn-dos` for every compile and link (WCC386 9.5 and WLINK 9.5 under the Phar Lap host, TCC 2.0
  and TLINK under the real-mode host). No DOSBox run was needed.
- **Build check:** `decovery build --json` over all sources. Every function Decomp records as identical must get
  `verdict = identical`; a mismatch fails the test unless it is listed, with evidence that decovery is right, in the
  private deviation file. Functions of sources the build skips (assembler files, no assembler run yet) are counted
  and not compared.
- **Link check:** `decovery link --json`. Second target: `REBUILD.EXE` must equal the original byte for byte. First
  target: the outcome is recorded (see below).

## Build

| Target | Decomp identical | decovery identical too | not built (assembler) | mismatches |
|---|---|---|---|---|
| first (LE, Watcom 9.5) | 497 | 346 | 150 | 1 (listed deviation) |
| second (MZ, Turbo C 2.0) | 14 | 14 | 0 | 0 |

First target, whole build: `34 files: 379 functions, 346 identical, 33 differ; 2 skipped`. The 32 other differing
functions are functions Decomp records as differing too; no function Decomp records as differing became identical.

On the second target the test runs `decovery link` before `build`, as an agent would: the identical link records
the addresses of library publics (`__streams`, `__ctype`) from the TLINK map (`source = link`). Without them three
functions reference data decovery cannot place, and ADR 0006 rule 5 keeps those fields unchecked (`differs`).

## Deviation list

One function of the first target. Its bytes equal the original's; one string literal reference is a `data-layout`
blocker. In the rebuild the literal is an item of the module's constant data, right after the module's other
strings. In the original that place holds another module's data, and the literal lies elsewhere in the data
object, among strings of another module. Linking the rebuilt module would therefore not reproduce the original
image: decovery's `differs` is right, Decomp only compared bytes. The fix is on the source side (the literal belongs
to the module that owns its data).

The detailed list with function names, addresses and evidence is kept privately
(`$DECOVERY_GOLDEN_DIR/parity-phase-2.md`, `$DECOVERY_GOLDEN_DIR/phase-2-deviations.txt`).

## Link

- **Second target (TCC 2.0 + TLINK):** `identical`; `REBUILD.EXE` equals the original byte for
  byte. From the map, the link records 71 public symbols the knowledge lacked; three map entries conflict with or
  duplicate existing knowledge and are reported as hints, not recorded.
- **First target (WLINK 9.5, `[rebuild.link] profile = "watcom-9.5"`):** `differs`. 346 identical functions
  are inserted into the original image and linked as one module. Stub, LE header, page table, fixup
  page table and every code and data page are identical. Two differences remain, both from the
  linker version: the preload flag (0x40) is missing on all four objects, and the fixup records of 57 pages are in
  another order (same content). The original was linked with WLINK 10.6, which is not available here; an identical
  link needs it. Decomp's own link inserted 494 functions, about 150 of them from assembler sources, which decovery
  cannot assemble yet.

## Performance (risk checkpoint R4)

Release build, 16 logical cores (8 physical). CPU is the CPU time of the decovery and Python processes, sampled
every 250 ms; busy cores = CPU seconds / wall seconds.

| Run | Wall | CPU | Busy cores (avg / peak) | `timing` |
|---|---|---|---|---|
| first target, cold build after migrate | 6.6 s | 41.4 s | 6.3 / 12.9 | compile 4 410 ms (32 jobs), compare 312, record 1 186, total 5 995 |
| first target, warm build (object cache) | 1.3 s | 2.9 s | 2.2 / 3.4 | compile 30 ms (0 jobs), compare 303, record 406, total 842 |
| first target, cold build, object cache deleted | 4.2 s | 34.0 s | 8.1 / 15.2 | compile 3 232 ms (32 jobs), compare 258, record 229, total 3 776 |
| first target, link (WLINK 9.5) | 1.3 s | 0.9–1.0 s | 0.7 / 1.1 | module 92 ms, link 568, compare 30, total 728 |
| second target, link (TCC + TLINK) | 1.3 s | 0.7 s | 0.5 / 1.0 | build 778 ms, compare 8, total 807 |
| second target, build after link (cached) | 0.7 s | — | — | compile 2 ms, compare 11, record 53, total 71 |

The cold first-target build uses most of the machine while compiling (peak 13–15 busy cores); the first build after
migration spends another second rewriting every function file. The compile tail (the largest sources finish last)
and the serial record phase bound the cold wall time. Warm builds start no compiler. Links are single jobs and
take about a second. Timings vary by ±50 % with machine load (the test runs measured a cold build at 10.7 s while
other work ran).

## Other local checks

`show_parity_local` reports 2 of 678 functions with a different `@called-by` line. Decomp's generated output is
stale there: its call graph has the edges, but its last incremental update did not rewrite the callers' files. This
is a Decomp-side item (a full regeneration of its output fixes it), not a decovery defect.
