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

## Task 2: Aztec object and library reader — done

- `crates/decovery-objects/src/aztec.rs`: `read_aztec` (objects 0x5466 / 0x020C, libraries 0xEC62), written from the
  compiler's object format description; three sections per module (CODE, DATA, BSS), named code/data/BSS symbols
  as `ObjSymbol` (static functions `public: false`), externals only as `RefTarget::Symbol`, unnamed labels as
  `RefTarget::Section` targets (not as symbols: `functions()` would split at every label), self-relative refs as
  `Relative` relocs, `seg`/paragraph items as `Selector`, 32-bit refs as `FarPointer`, integer part of an
  expression in the field, start item → `ObjectModule::start`, debug/line items skipped. Unsupported items
  (segment-relative, common segment, interpreter call) are `Malformed` with the offset.
- R3 checkpoint, ADR 0012: one model change, additive — `Section::size` (+ `Section::with_size`) for the BSS size
  (the model had no size for a section without bytes; Task 8 needs it). OMF reader now fills it from SEGDEF.
  Deviation from decision 3: unnamed symbols are section-position targets, not synthetic `@sec:off` symbols.
- `ObjectFormat` moved to `decovery-objects` (re-exported by the toolchain); `read_object(format, ..)` replaces
  the direct `read_omf` calls in `cli/compare.rs` and `facade/tools/{build,diagnose,link,variants}.rs` (build: the
  built-in assembler's objects stay OMF; link: LE linking is OMF only).
- Test writer `aztec_write.rs` (feature `test-writer`, enabled for the crate's own tests via a self dev-dependency):
  `AztecModuleSpec` (named symbols as `AztecSymbolSpec` structs with a `public` flag instead of tuples),
  `write_aztec`, `write_aztec_library`.
- Tests `tests/aztec_synthetic.rs` (15): the planned ten plus `integer_encodings_and_section_references`,
  `items_past_header_size_are_error`, `truncated_library_never_panics`, `corrupt_bytes_never_panic`,
  `deeply_nested_expression_is_error`.
- Local: `tests/aztec_local.rs` (every `.O`/`.LIB` under `DECOVERY_TOOLCHAIN_AZTEC42/LIB` and under
  `DECOVERY_AZTEC_OBJECT_OUT`; counts against `DECOVERY_GOLDEN_DIR/aztec/reader-counts.json`, written by a scratch
  script running Decomp's reader). `aztec_compile_local.rs` now reads each object with the reader, optional
  `DECOVERY_AZTEC_ALL=1` and `DECOVERY_AZTEC_OBJECT_OUT`.
  Result: all 8 sources of the third target compiled (dosbox-lab, ~4.4 s) and read; all 32 4.2b library/object
  files read without error, no unknown targets. Cross-check with Decomp on 23 files (8 compiled objects, 15
  small-model libraries/objects): function counts equal on all 23; reference counts equal as well (compiled
  objects: 3/46/16/42/49/50/74/42 functions). Not compared: large-model files (Decomp rejects magic 0x020C) and
  C/C86/CLD/GL/GLC.LIB, which contain large-model modules Decomp skips (decovery reads them: one extra module
  `fcall` in C.LIB and C86.LIB, otherwise equal).
- Commit `feat(objects): Aztec C86 object and library reader`.

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

## R1 follow-up: unicorn-dos runs the Aztec C86 pass chain — done

Root cause: stale translated code in unicorn, not DOS semantics. CC reads CGEN's image with INT 21h AH=3Fh over its
own code at PSP+10h and jumps in. The emulated DOS writes the read bytes with `mem_write` from the interrupt hook,
which does not drop unicorn's translation blocks for that range, so CGEN's startup partly ran CC's old translated
code (memory at CGEN's entry was byte-identical to a direct CGEN start, yet it still failed: "no operand", exit
254). Command tail CR, tail garbage, FCBs and environment were each patched to the direct values: no effect.
Fix: `write_linear` (real mode and Phar Lap) calls `ctl_remove_cache` for the written range.

Second gap fixed: AH=41h on a file that is still open (CGEN deletes `ctmp1`/`ctmp2` while holding them) now
removes the name for DOS at once and the host file when its last handle closes (or at program end); a create under
that name starts a new file.

Tests (synthetic): `test_code_read_over_executed_code_runs` (realmode), three delete-while-open tests (dosfs); all
red without the fix. Plugin suite: 89 passed, 3 skipped.

Result through `runner/run` of both plugins (worktree unicorn-dos, `CC -n +b`, the third target's sources):
- 4.2b: all 8 sources, objects byte-identical to dosbox-lab's. Request with 8 jobs: unicorn-dos 2.7 s, dosbox-lab
  4.7 s; single jobs in unicorn-dos 0.3–2.6 s (farmem 0.3 s, vmele 1.4 s) vs ~1.0–1.4 s per dosbox-lab request.
  The three smallest: unicorn-dos 1.6 s, dosbox-lab 3.4 s.
- 5.2a: three smallest identical (1.8 s vs 3.7 s). 3.4b: farmem identical (0.35 s vs 1.3 s); vinit/vmele time out
  in dosbox-lab with 3.4b, not compared.
- Profiles: `runners = ["unicorn-dos", "dosbox-lab"]` for all three.
- Note: the user config runs an installed copy of unicorn-dos (`extern/unicorn-venv`); it needs the new plugin
  code (reinstall after merge) before the Aztec profiles work with unicorn-dos first.
