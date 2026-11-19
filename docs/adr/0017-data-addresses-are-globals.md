# ADR 0017: Data addresses are globals

Status: accepted · 2026-11-19

## Context

`annotate` chose a new record's `kind` from the memory map alone: an address in an executable segment became a
`function`. An MZ program has one `rwx` image segment, so a global in DS (`seg:0FF6:830E`) became a `function` named
after its `fun_…` default. `build` then counted such records as functions no source and no library rebuilds.

## Decision

1. An address is **data** when no analyzed function starts there and it lies in a segment without `x`, or, in real
   mode, its segment part is a data frame: `[rebuild] frames` named `DATA`, `BSS`, `CONST`, `STACK` or `DGROUP`
   (paragraph `seg:XXXX:0000`), or, on an MZ target without a `DATA` frame, the segment the Aztec startup code loads.
2. A new record at a data address gets `kind = "global"`; its default name in messages is `DAT_<address>`, as `find`
   shows it. Functions starting there and labels inside analyzed functions stay as before.
3. Existing records are not changed silently. `annotate --kind function|global|label` corrects a record's kind as
   an ordinary claim: a claim ranked below the record needs `force`, and the old kind goes to the record's history
   (`note = "kind function changed to global"`) with the claim's evidence. `status` lists active `function` records
   at data addresses (`functions_in_data`) and names the command.

## Consequences

The knowledge schema is unchanged; `kind` gains a writer. A frame named otherwise (`CODE`, `TEXT`, overlay frames)
does not make data. Records written before this change stay as they are until someone runs `annotate --kind`.
