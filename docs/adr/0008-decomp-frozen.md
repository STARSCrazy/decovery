# ADR 0008: Decomp is frozen; decovery is the base

Status: accepted · 2026-11-16

## Context

decovery reached parity with Decomp for `show`, `build` and `link` on both reference targets (phase 2, refreshed
2026-11-16: 617 of Decomp's 618 identical functions confirmed, the remaining one a listed deviation where decovery
is right). Since ADR 0007, decovery also reaches Decomp's search, register/slot models and behavioural checks
through the `decomp-legacy` bridge. Keeping two tools growing side by side doubles the work and lets them drift.

## Decision

1. **Decomp is frozen.** New tool features go into decovery only. Decomp gets fixes that running work needs, and
   its target content (knowledge, rebuild sources) keeps growing until a target is migrated.
2. **Exception: the Aztec C86 / overlay target** (a 16-bit game with overlays) keeps being worked on in Decomp,
   because decovery cannot build it yet. In parallel, Aztec C86 and overlays are ported to decovery; that target is
   the test case for decovery's intermediate states (each ported step is checked against Decomp's verdicts there).
3. **Order of work:**
   1. close the phase-2 parity gap (618 of 618);
   2. phase 3 (agent loop, `bench`) as planned, so that later changes are measured;
   3. everything the Aztec C86 / overlay target needs (amended 2026-11-16, owner): the Aztec C86 profile and object
      reader, overlay loading and addresses, its prologue search, building and comparing its overlay modules
      including data, relocations and BSS, and whatever else its migration needs; done when decovery's verdicts on
      that target equal Decomp's (or differ only in listed deviations where decovery is right);
   4. port by use: the bridge's most-called Decomp tools first (register/slot models, search chain, equivalence),
      each replacing the bridge backend behind the unchanged tool surface;
   5. port what decovery still lacks, written more generally than in Decomp: GCC 1.40/EMX with a.out, unpacking,
      signatures, runtime import, understanding and structure recovery.
4. **Retirement.** A Decomp feature is retired when decovery's port reaches parity on the targets that use it.
   Decomp is archived when no target needs it any more (bridge unused, all targets migrated).

## Consequences

- Agents working in Decomp must not add tool features there; the Decomp `CLAUDE.md` says so.
- Every port gets a parity check against Decomp on a migrated workspace, as in phases 0–2.
- The bridge stays until its last caller is ported.
