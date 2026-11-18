# Parity phase 4: Aztec C86 and the overlay target

Numbers only; no function names, no addresses, no private paths. Details stay in the private ledger.

## Baseline

Decomp's verdicts on the third target (an MZ program with 13 overlays, small model, Aztec C86 4.2b), frozen on
**2026-11-18** (plan decision 6, risk R4): 1144 functions, 322 identical, 822 not tried; no differing or failed
verdicts recorded. Main program 217 functions (3 identical), overlays 927 functions (319 identical). Decomp keeps
working on the target; later changes there do not move this baseline.

## Migration (Task 9)

`decovery migrate` of the Decomp workspace into a scratch directory, 2026-11-18:

| Item | Count |
|---|---:|
| analysis functions imported | 1144 |
| overlays (`[[overlay]]`) | 13 |
| overlay memory segments (`[[target.segment]]` with `ovl:` starts) | 26 |
| compiler rules (`knowledge/compiler-rules.toml`) | 30 |
| rebuild sources | 8 |
| attempt lines | 0 (the workspace has no attempt memory) |
| archive entries | 0 |
| overlay attempts | 0 (none recorded; synthetic tests cover the path) |
| unmapped keys | 0 |
| untranslated free texts copied | 634 |

Migration wall time 16 s (debug build).

## Build and comparison (Task 10)

Normal `decovery build` on the migrated workspace, runner `dosbox-lab`, debug build:

| | Count |
|---|---:|
| sources compiled | 8 |
| functions built | 322 |
| identical | 322 |
| differing / failed / unchecked | 0 |
| overlay modules compared (code, data, BSS) | 7 |
| overlay modules identical | 7 |

Wall time 6.5 s (compile 4.5 s for 8 jobs, compare 0.1 s, record and attempts 1.6 s).

Verdicts against the frozen baseline, all 1144 functions (a function the build does not place counts as not tried):

| Baseline | decovery | Functions |
|---|---|---:|
| identical | identical | 322 |
| not tried | not tried | 822 |
| any | different | 0 |

**Deviations: none.** 1144 of 1144 verdicts equal Decomp's.

## Notes

- Decomp names the C function every overlay defines with the same name `<OVERLAY>_<name>` in its analysis (names must
  be unique across overlays). `build` now places such a function by that qualified name inside the overlay that holds
  the object's other functions.
- The length of an original overlay function is taken within its own address space (overlay addresses have no linear
  address).
