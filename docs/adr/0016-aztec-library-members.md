# ADR 0016: Aztec C86 library members in `build`

Status: accepted · 2026-11-19

## Context

An Aztec C86 program links library code from the toolchain: members of `LIB/C.LIB` (`$csav`, `strcmp_`, `$begin`,
the I/O layer) and single objects outside the libraries (`LIB/OVLD.O`, `LIB/OVBGN.O`, copied into every overlay).
Once every C and assembler function of a target is identical, these functions are what is left, and they were only
checked by hand (`compare --object C.LIB --function …`). The library reader existed (ADR 0012), but `build` never
looked at a library, and `compare` found a member function only when the knowledge named it like the object
(`$csav` is `aztec_csav` in a knowledge migrated from Decomp, `$ovbgn` is `VBASE_ovbgn` in overlay VBASE).

The libraries are commercial: nothing read from them may enter the repository. They are read at run time from the
user's toolchain directory.

## Decision

1. **Reader.** `read_aztec_library` (decovery-objects) lists a library's members: module, header name (`strcmp`),
   offset and length in the file, public symbols. A single `.O` reads as a library of one member. Malformed input is
   `Truncated` / `Malformed` with the byte offset.
2. **Configuration.** `[rebuild] libraries = ["C.LIB"]` and `[rebuild] library_objects = ["OVLD.O", "OVBGN.O"]`.
   A bare file name lies in the toolchain's `LIB` directory (`[rebuild] tool_dir`, else the user config's
   `[toolchains]` entry); a name with a path separator is relative to the workspace root. Both lists are read alike
   (a single object reads as a library of one member); records name a library member `C.LIB(strcmp)` and a single
   object by its file name (`OVBGN.O`). Without either key nothing changes.
3. **Which members belong to the program** is derived, not listed:
   - by name: a code symbol of the member (public or static) names a knowledge function, as is, undecorated through
     the profile's `[decoration]` (`strcmp_` → `strcmp`), or as the overlay-qualified knowledge name
     `<OVERLAY>_<name>`; the member is placed so that the symbol lies at that function;
   - by bytes: the member's whole code section matches the original at a knowledge function that no source of the
     build rebuilds, placed so that one of its code symbols lies there: every byte outside a relocated field equal,
     at least 6 such bytes. A shorter member (`$fltinit`, two bytes) is placed only where it fills the room between
     a placed member and the next function exactly and no other member's code fits there.

   A member is never placed over a function a source rebuilds, and placed members never overlap: matching
   placements before differing ones, name before bytes, more matched bytes first, then configuration order. The
   same member is placed as often as the program holds it (`$cswt` and `OVBGN.O` in each overlay).
4. **What is compared.** Every knowledge function that starts inside a placed member is one function: it runs to
   the next knowledge function inside the member or the member's end, so the knowledge's partition decides
   (`aztec_csav` = `$csav` + `$cret`; `*_ovbgn` = `$ovbgn` + `ovexit_`; a static helper with its own knowledge
   entry is its own function). It is compared like an Aztec object function (`compare_with_gaps`: relocated fields
   are link gaps). Code before the first knowledge function of a member is part of the placement check only.
5. **When.** Only a full `build` (no files, no `--function`) compares the libraries, after the sources, so that the
   functions the sources rebuild are known. Records: `file = "C.LIB(strcmp)"`, `compiler` = the profile, empty
   `flags`, the member's symbol at the function start as `symbol`. A file build keeps them; a full build without the
   keys drops them. No attempt is written (there is no source).
6. **Report.** The summary says `library: N of M functions identical` (with the first names that are not) and how
   many knowledge functions neither a source nor a library rebuilds. The data `library` lists the files, each placed
   member (`source`, `address`, `bytes`, `anchor` = `name <symbol>` or `bytes`, its functions) and the remaining
   functions (`remaining`, first 50, and `remaining_total`).
7. **`compare`.** `--symbol` is an alias of `--function`. With an Aztec library or library object as `--object`, a
   name the knowledge does not know is looked up as a member's object symbol (also undecorated; `$cret` finds the
   function that holds it), and a knowledge name the object does not define is found by the member placed at its
   address. The member is placed as in 3; of several placements (one per overlay) the first is compared.

## Consequences

- Tests use synthetic libraries from the test-only writer; the real libraries are read only by `#[ignore]` local
  tests and at run time.
- References inside library functions are not checked (link gaps, as for every Aztec object function).
- A byte match says that a member's code is there, not that the program was linked with that member. For a member
  of at least 6 matched bytes at a function start this is the evidence a human uses, too.
- A `--function` build of a library function, and libraries of other object formats (OMF `.LIB`), are not covered.
