# Phase 4 progress ledger

Plan: `docs/plans/2026-11-18-phase-4.md`. Worktree `.worktrees/phase-4-build`, branch `phase-4-build`.

## Task 1: Aztec C86 profiles — done

- `profiles/aztec-c86-{3.4b,4.2b,5.2a}.toml`: `CC -n {flags} {input}`, prelude `SET CLIB=D:\LIB\`,
  `SET INCLUDE=D:\INCLUDE\`, `SET PATH=D:\BIN` (as in Decomp `_aztec`), `.O`, decoration `{name}_` for functions and
  data, no linker, no prologue, fingerprint `BIN/CC.EXE`, `[search] flag_sets = [["", "+b"], ["+h", "-z"]]`.
- `ObjectFormat::Aztec`, `SearchSpec` / `Profile::search`. No `match` on `ObjectFormat` existed, so no
  `Unsupported` arm was needed (reader dispatch comes with Task 2).
- Tests: `aztec_profiles_parse`, `aztec_compile_line`, `aztec_object_name`,
  `trailing_underscore_decoration_round_trips`, `undecorated_symbol_is_kept_verbatim`, `aztec_flag_sets`.
- Commit `feat(toolchain): Aztec C86 profiles`.

## Task 2: object reader — not started (comes later)

## Task 3: runner checkpoint R1 — done with the fallback

Checkpoint (trivial `T.C`, `CC -n`, 4.2b; by hand through each plugin's `runner/run`, then through
`decovery_toolchain::compile`):

| Runner | Result | Wall time |
|---|---|---|
| unicorn-dos | fails: exit 254, CGEN prints internal compiler errors; no object | ~8 s (CPU bound) |
| dosbox-lab | works for 3.4b, 4.2b and 5.2a; object written | ~1.0–1.4 s per single-file request (first cold start ~4 s); 3 W7 sources in one request ~3 s |

Why unicorn-dos fails (traced INT 21h calls):
- Pass 1 (`CC.EXE`) works: it reads the source and writes `ctmp1`/`ctmp2`.
- CC does not use EXEC (4Bh). It loads the next pass itself: copies a loader to the top of memory (AH=4Ah to
  9F00h paragraphs), opens `D:\BIN\CGEN.EXE`, reads the image to PSP+10h, applies the relocations, writes the new
  command tail (length 43, no CR after it) into the PSP and jumps in. The same CGEN started directly by unicorn-dos
  with the same arguments does open its input files; chained, it opens none and runs on garbage (exit 254).
  The chained PSP differs from the direct one only in the bytes after the tail (no CR terminator, stack garbage) and
  the FCBs; the exact cause inside CGEN's startup was not pinned down. Not a missing interrupt handler: not small.
- Second, independent gap: CGEN deletes `ctmp2` while it still holds it open (legal in DOS); unicorn-dos's AH=41h
  fails on a Windows host (`PermissionError`, WinError 32). Small, but only matters once the chain runs.
- Fallback applied as the plan states: the three profiles list only `dosbox-lab`. Owner to decide whether unicorn-dos
  gets the in-place chain later.

Found and fixed on the way: CC puts its work files where `CCTEMP` points, not into `TMP`, and names them after the time
of day; parallel jobs in one request collided (AS reported 133 undefined symbols). New profile key `job_prelude`
(lines with `{tmp}` = the job's own temp directory), Aztec: `SET CCTEMP=C:\{tmp}\`; part of the object cache key only
when non-empty (keys of the other profiles unchanged). `job_commands` + unit test `job_prelude_gets_the_job_temp_dir`.

Cache key includes the prelude (checked: `ObjectCache::key`).

Local test `crates/decovery-toolchain/tests/aztec_compile_local.rs` (not `decovery-cli/tests` as planned: migrating
the private workspace needs overlay addresses, Task 5/9, and `build` needs the Task 2 reader; the toolchain crate's
`compile` is the pipeline that matters for R1). Env: `DECOVERY_LOCAL_WORKSPACE_AZTEC`, `DECOVERY_TOOLCHAIN_AZTEC42`,
optional `DECOVERY_AZTEC_RUNNER`, `DECOVERY_GOLDEN_DIR` (`aztec/objects/<NAME>.O`). Compiles the three smallest sources
with Decomp's flags (global and per file). Result: PASS with dosbox-lab (3 objects, Aztec magic). The object of one
source equalled an object compiled by hand in DOSBox with the same command; Decomp's own objects for these sources are
not on disk, so the golden comparison is skipped until `DECOVERY_GOLDEN_DIR/aztec/objects` is filled.
With `DECOVERY_AZTEC_RUNNER=unicorn-dos`: fails (exit 254), as above.

No plugin code changed.

Commit `feat(runners): run the Aztec C86 compiler chain`.
