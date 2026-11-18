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

## Task 4: first verdicts on main-program functions — done, owner gate A

- Baseline frozen 2026-11-18: `tools/parity/aztec_baseline.py` read Decomp's function export (`ausgabe/funktionen`,
  `@adresse`/`@name`/`@nachbau`) and wrote `$DECOVERY_GOLDEN_DIR/aztec/baseline-2026-11-18.json`
  (`functions` {address: verdict}, `names` {address: name}). Counts: 1144 functions, 322 identisch, 822 nicht-versucht
  (equal to Decomp's `stand.json`); main program 217 functions, 3 identisch, 214 nicht-versucht. Decomp has no
  `abweichend`/`fehler` verdicts recorded.
- `decovery_diff::compare_with_gaps(object, image, image_base)` (`gaps.rs`): relocated fields are gaps; bytes
  outside must be equal; self-relative fields to the own section (unnamed labels, own symbols) are checked against
  the original's target; other refs count as `refs_unchecked`, not blocking (no symbol view). Facade `build` uses it
  for `ObjectFormat::Aztec` instead of the module comparison.
- Tests `tests/gaps_synthetic.rs`: `relocated_word_is_a_gap`, `self_relative_call_to_unnamed_symbol_compares`,
  `gap_does_not_hide_opcode_difference`, plus `short_image_is_unavailable`.
- Local test `crates/decovery-cli/tests/aztec_verdicts_local.rs` (not through `build`/workspace: migration of the
  Decomp workspace fails on `ovl:` addresses until Task 9; scratch workspace in a temp dir, runner forced to
  dosbox-lab because the user's installed unicorn-dos copy predates 56b7603). Compiles all 8 sources (4.25 s wall),
  compares every object function the baseline places at a `rel:` address with the MZ image.
  Result: 3 compared (far_alloc 19 B = 15 equal + 4 gaps, far_copy 28 B = 24 + 4, far_free 19 B = 15 + 4; Decomp:
  "15 fest + 4 Linker" etc.), all identisch; 217/217 main-program verdicts equal Decomp's, 0 disagreements.
  Overlay functions (319 identisch in Decomp) wait for Task 6.
- Commit `feat(diff): object-against-image verdicts with link gaps`.

## Task 5: overlay addresses (ADR 0011) — done

- `Address::Ovl { overlay: OverlayName, seg, off }`, text `ovl:NAME:SSSS:OOOO`; `OverlayName` = `[A-Za-z0-9_]{1,16}`
  in a fixed 16-byte array (Address stays `Copy`), stored/printed upper case, lower case input normalised.
  `linear()` = None, `offset_by` moves `off`, `address_key` = `ovl_NAME_SSSS_OOOO`, sorts after the other kinds.
  New `Address::bytes_from(start)` (distance within one space) replaces the hand-written Sel/linear matches in
  facade output (files, header span), find, resolve (`in_segment`, `nearest`). Default names `fun_NAME_SSSS_OOOO`
  (as Decomp's `standardname`) parse back. Migration: `ovl:` maps 1:1 (also in mixed text fields).
- Workspace `[[overlay]]` (`name`, `file`, `sha256`, `format`, optional `file_offset`, `size`, optional `entry`);
  overlay memory segments are `[[target.segment]]` with `ovl:` starts. `Workspace::save_config`.
  Deviation from the plan's `name, file_offset, size`: overlays of this target are separate files, so `file` and
  `sha256` are added (as Decomp's entries).
- `locate`: an `ovl:` address with an unconfigured name → error listing the known overlays; `file:` offsets never
  map into overlay segments (they are offsets in the main file).
- CLI `decovery overlay add FILE.. [--format aztec-c86] | list | remove NAME` (Task 5: registers files; Task 6
  adds header checks and segments).
- Ghidra plugin: `GhidraAddress.space` (overlay space name, text `NAME::SSSS:OOOO`), `ovl:` mapping for
  `x86-real-16`, one overlay space per overlay created before its blocks (`createOverlaySpace`), back-mapping of
  overlay-space addresses through the overlay's blocks (`overlay_address`). Not yet run against a real Ghidra
  with overlays (needs Task 6 regions); plugin suite 40 passed, 2 skipped.
- Tests: `tests/address_overlay.rs` (`ovl_address_round_trips`, `ovl_has_no_linear_address`, `overlay_name_rules`,
  `address_key_of_ovl`, ordering), `address_key_covers_every_address_kind` extended, `overlays_round_trip`,
  facade `unknown_overlay_name_is_named`, CLI `overlay_add_list_remove`. No schema bump (addresses are text).
- Commit `feat(core): overlay addresses (ADR 0011)`.

## Task 6: overlay loading — done

- `decovery_loaders::overlay`: `read_overlay(bytes, name)` (14-byte header, magic 0xF2; truncated code/data →
  `Truncated { offset }`, code past 64 KiB → `Malformed { offset: 2 }`, data+BSS past 64 KiB → `Malformed { offset: 6 }`,
  entry outside the code → `Malformed { offset: 12 }`; new `LoadError::Malformed { offset, detail }`),
  `read_overlays` (one result per file), `find_overlay_loader(code)` (unique `ovloader_` match),
  `aztec_data_segment(image, cs, ip)` (`mov bp, <seg>` at the entry). Put in `overlay.rs`, not `mz.rs`.
- `overlay add` now checks the header against the MZ main program (CS from the header, DS from the startup code or
  `--ds SSSS`) and writes `NAME.code` (`ovl:NAME:CS:corg`, rwx, file offset 14) and, when dsize+bss > 0,
  `NAME.data` (`ovl:NAME:DS:dorg`, length dsize+bss, file_length dsize, rw) plus `entry`; reports the loader
  address. Segment names are English (`.data`, Decomp: `.daten`).
- Facade `program::load` appends overlay regions (`overlay_regions`: bytes from each overlay file per `ovl:`
  segment; an unreadable overlay is a warning, the others still load) and the overlay entries. `Program::read` /
  `region_at` work by `Address::bytes_from`, so `ovl:` (and `sel:`) regions are readable.
- Tests `tests/overlay_synthetic.rs`: `overlay_header_fields`, `bad_magic_is_error_with_offset`,
  `overlay_past_file_end_is_error` (+ every prefix, no panic), `bad_overlay_does_not_hide_the_others`,
  `loader_pattern_found`; facade `overlay_segments_become_readable_regions`; CLI test extended (segments, bad header).
- Local `crates/decovery-cli/tests/overlay_local.rs` (in the CLI crate, not loaders: it goes through
  `overlay add`), scratch workspace, `DECOVERY_LOCAL_WORKSPACE_AZTEC`: 13 overlays added, loader `ovloader_`
  found once, entry and both segments (start, length, file offset, file length) equal Decomp's `[[overlay]]`
  entries for all 13, 0 mismatches, no load warnings.
- Not done: Ghidra analysis of a workspace with overlays (the plugin's overlay spaces are untested against a real
  Ghidra); overlay migration from Decomp stays Task 9.
- Commit `feat(loaders): Aztec overlays`.

## Task 7: prologue search with placeholders, 386 prefixes in 16-bit code (R2) — done

- `decovery_x86::{PatternByte, ProloguePattern, PatternError, find_prologues}` (`prologue.rs`, port of Decomp's
  `prologe.py`): hex text with `??`; with a call target the last two bytes must be `??` (the call displacement);
  the destination is computed in the match address's own kind (Seg/Ovl: 16-bit wrap in the same segment, Flat:
  32-bit) and handed to the resolver, which names it (for an overlay the resolver maps seg:off into the main
  program itself, as Decomp's "only segment and offset count"). Overlapping matches count each; addresses past the
  segment end are skipped; never panics. `decovery-x86` now depends on `decovery-core` (for `Address`).
- Profiles: `prologue_pattern = "B8 ?? ?? E8 ?? ??"`, `prologue_call = "$csav"` in all three Aztec profiles;
  `Profile::prologue_pattern: Option<ProloguePattern>` validated at parse (call without pattern, or a call pattern
  without trailing `??`, is `Invalid`). `decovery-toolchain` depends on `decovery-x86`. Nothing consumes the
  pattern yet (function search goes through Ghidra; the migrated workspace's analysis keeps Decomp's list).
- R2: iced-x86 decodes 66h/67h prefixed instructions in 16-bit mode with the right lengths; no decoder change was
  needed. Address-width fields stay 2-byte only (a 67h 32-bit displacement is not taken for a relocatable field).
  Shapes of `mov ax,1` and `66 mov eax,1` differ.
- Tests `crates/decovery-x86/tests/prologue_synthetic.rs`: `pattern_text_parses`, `placeholder_bytes_match_any`,
  `call_target_must_resolve`, `call_target_in_an_overlay_uses_the_processor_address`, `no_match_in_data`,
  `prefixed_386_instructions_in_16_bit_code`; profile tests `aztec_prologue_pattern`,
  `prologue_call_without_pattern_is_invalid`.
- Local `crates/decovery-cli/tests/prologue_local.rs` (CLI crate: needs `overlay add`), call target from Decomp's
  `[analyse] prologe` address: per overlay prologue matches ⊆ baseline functions (0 false matches), 902 of 927
  baseline overlay functions found; the 25 missing are the frameless library functions behind each C module
  (`$ovbgn` at the entry, `$cswt`, `swapmem`, …), which Decomp found by calls, not by the pattern. Decoding every
  overlay's code function by function: decoded length sum = code size for all 13 overlays; 386-prefixed
  instructions in VPCLV 3, VMAZE 2, VMEXT 2, VMEXE 3, VTREA 3; undecodable bytes 0–20 per overlay (data inside the
  code, e.g. switch tables). R2 closed.
- Commit `feat(x86): prologue search with placeholders`.

## Task 8: overlay module build and compare — done

- `decovery_diff::{compare_overlay_module, ModuleVerdict}` (`module.rs`; port of Decomp's
  `tools/pruefe_wizardry7_overlay.py`). Named `compare_overlay_module`, not `compare_module` as in the plan: that
  name is the existing OMF module comparison. Takes `&[&ObjectFile]` (source order). Placement: code from corg,
  data from dorg, BSS from dorg + header dsize; the module must end at the overlay entry (`$ovbgn`), data and code
  of the library behind it are not compared. All references resolved: internal (any object's public symbols, own
  locals, unnamed positions) computed and checked; externals bound from the original field, every further use of
  the name must agree (else `ambiguous`, wrong ref); selector / far-pointer fields are gaps. `identical` = code
  equal and size = entry − corg, data equal, BSS = header, no ambiguity. Fields beyond the plan: `code_size`,
  `data_size`, `externals`, `ambiguous`.
- Tests `crates/decovery-diff/tests/overlay_module_synthetic.rs` (plan's `module_synthetic.rs` exists for the OMF
  module compare): `module_of_two_objects_places_in_order`, `data_difference_is_reported_with_offset`,
  `module_with_different_bss_is_not_identical`, `relocated_data_word_is_a_gap`,
  `wrong_internal_reference_is_reported`, `code_that_does_not_end_at_the_entry_is_not_identical`.
- Facade `build`: for Aztec profiles the objects whose placed functions lie in an overlay are grouped per overlay
  (source order) and compared; response `modules` [{overlay, identical, code{…}, data{…}, bss, externals,
  ambiguous}] and a summary note; unreadable overlay → warning. `program::read_overlay_of`. Unit tests
  `overlay_module_verdict_is_reported`, `unreadable_overlay_is_a_warning`. `show` unchanged (no module view yet).
- Local `crates/decovery-cli/tests/aztec_overlay_local.rs` (scratch workspace, dosbox-lab, 8 sources 9.7 s wall):
  per function compare_with_gaps at the baseline's overlay address, per module compare_overlay_module.

  | overlay | functions | Decomp identical | decovery identical | not tried | equal verdicts |
  |---|---|---|---|---|---|
  | VBASE | 77 | 0 | 0 | 77 | 77 |
  | VDOPT | 48 | 46 | 46 | 2 | 48 |
  | VINIT | 17 | 16 | 16 | 1 | 17 |
  | VMAZE | 138 | 0 | 0 | 138 | 138 |
  | VMELE | 44 | 42 | 42 | 2 | 44 |
  | VMEXE | 78 | 0 | 0 | 78 | 78 |
  | VMEXT | 50 | 49 | 49 | 1 | 50 |
  | VMNPC | 132 | 0 | 0 | 132 | 132 |
  | VPCLV | 51 | 50 | 50 | 1 | 51 |
  | VPCMK | 76 | 74 | 74 | 2 | 76 |
  | VPCVW | 84 | 0 | 0 | 84 | 84 |
  | VPOPS | 43 | 42 | 42 | 1 | 43 |
  | VTREA | 89 | 0 | 0 | 89 | 89 |

  927/927 overlay verdicts equal (319 identical; with Task 4's 3 main-program functions 322 = baseline), 0
  differ. Modules (code / data / BSS / resolved refs, all identical, numbers equal Decomp's notes):
  VINIT 5623 / 302 / 0x2 / 618; VDOPT 18123 / 19 / 0xCDE / 1658; VMELE 14082 / 20 / 0x1A / 1244;
  VMEXT 21005 / 221 / 0x99C / 2189; VPCLV 21570 / 869 / 0x3A4 / 1832; VPCMK 28581 / 1189 / 0x268 / 2361;
  VPOPS 20111 / 51 / 0x2B8 / 1434. Externals bound per module 96–131, 0 ambiguous.
- One harness finding, not a verdict disagreement: Decomp names the C function `ovmain` of every overlay
  `<OVERLAY>_ovmain` (names must be unique across overlays); the local test looks up `<OVERLAY>_<name>` as a
  fallback. Task 9 (migration) must handle this: the object's `ovmain_` has to place at the overlay's
  `<OVERLAY>_ovmain` (facade `place_objects` looks names up globally).
- Commit `feat(diff): overlay module compare with data and BSS`.
