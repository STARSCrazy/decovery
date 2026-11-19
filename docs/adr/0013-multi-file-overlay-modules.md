# ADR 0013: Overlay modules from several source files, common symbols

Status: accepted · 2026-11-19

## Context

The Aztec C86 4.10d assembler stops with "Out of memory!" on large modules, so one overlay's C code has to be split
into several source files (e.g. `npc.c` and `npc_b.c`). Until now
the overlay module comparison (ADR 0012, phase 4 Task 8) took the objects of one build whose functions lie in the
overlay, in source order. Building one file compared only that file's object against the whole overlay, so the
module verdict stayed "not identical" although every function matched.

Variables shared between the files must be global. Aztec emits an uninitialised global as a *common symbol*: a
named symbol of type undefined whose value is the size in bytes. The reader dropped them like externs; the module
comparison bound them from the original field and counted none of them into the BSS size.

## Decision

### `[[rebuild.module]]`

```toml
[[rebuild.module]]
overlay = "NPC"
files = ["npc.c", "npc_b.c"]   # link order
```

- The key is singular, as `[[target.segment]]` and `[[overlay]]`: each table is one module. `overlay` names a
  configured `[[overlay]]`; `files` are source file names in `src/` (compared case-insensitively, as DOS does), in
  link order.
- The address ranges are not configured: they follow from the functions of each file. The build warns when the code
  of one file does not end where the first placed function of the next file begins (gap or overlap, with the byte
  count), and when a listed file has no object in the build.
- Building any listed file builds the module's other files too (their objects usually come from the object cache),
  so the module is always compared whole. Their functions are compared and recorded like any built function.
- The module comparison takes the listed files' objects in link order, followed by objects of other files whose
  functions lie in the same overlay (source order, as before). Code, data and BSS are the concatenation of the
  objects in that order; every object's data starts on a word (the linker puts one zero byte behind an object
  with an odd data size: third target, VMAZE, 229 data bytes of the first file, then a pad byte, then the data of
  the next file). Code is not aligned (odd code sizes are followed directly by the next file's code).

### Common symbols

- `ObjectModule::commons` (additive model field): the module's common symbols, name and size, in named-symbol-table
  order. Only the Aztec reader fills it.
- Placement follows the Aztec linker rule as observed on the third target (one overlay, two objects: the DS
  addresses of the commons of two objects follow this rule up to two places where the source declares a size the
  original does not have, and the total after them equals the overlay header's BSS size):
  a name some object defines (code, data or BSS symbol) binds to that definition; every other common name is placed
  once, behind the BSS of all objects of the module, in the order of its first appearance (objects in link order,
  each in its symbol-table order), with the largest size any object declares, without alignment.
- The BSS size the module comparison reports and checks against the overlay header includes the commons, and every
  reference to a common is checked against its computed address (a wrong layout is a wrong reference).

## Consequences

- A configuration without `[[rebuild.module]]` behaves as before.
- The compiler writes the symbol table in reverse declaration order, so the first declared global gets the highest
  address; sources that declare globals from high to low addresses (as decompiled sources usually do) match.
- Aztec libraries that declare commons are not part of an overlay module (the library is not linked in, plan
  decision 5); a common that only the library declares is not placed.
