# ADR 0006: 16-bit references are checked against anchors

Status: accepted · 2026-11-05

## Context

decovery's verdict (design 5.11 item 1) checks every relocated field of a rebuilt function against the original's
relocation at the same place. A linked LE image carries a fixup for every absolute field, so the rule works for
the first target. An MZ image carries relocations only for segment words (`Selector`); a 16-bit offset (`mov ax,
[_g]`, `mov dx, offset string`) is a plain word in the image, relative to a frame that the linker chose. Under the
current rule every such field would be a `WrongAbsoluteRef`, and no 16-bit function with a data reference could
become identical. Decomp did not check 16-bit data references at all: its byte comparison treats fixup fields as
gaps and checks only self-relative references by name, so a rebuilt function referring to the wrong variable
passed.

The offset in the original is `linear(target) - frame base`. The target's address is known for named symbols (the
knowledge base); the frame base (DGROUP, a code segment) is not recorded anywhere in an MZ file. Unnamed targets
(string literals in `_DATA`, statics without a public) have neither an address nor a name; only their position
inside their OBJ section is known.

## Decision

Fields of 16-bit functions whose original has no relocation at the same place (absolute 16-bit offsets, the
offset word of a 16:16 far pointer) are checked against **anchors** that one comparison establishes over all
functions it compares (`compare_module`: first pass collects, second pass checks).

1. **Frame of a field.** `Frame::Group(name)` is that group; `Frame::Section(i)` is section `i`'s own frame (named
   by the section name); `Frame::Target` and `Frame::Unknown` are the group of the target's section if that
   section is a group member, else the target section. A field whose frame cannot be named (an external symbol
   with a target frame) is an `UncheckedRef`, except a far pointer to a known address, whose segment and offset
   give its linear address directly.
2. **Frame anchor** per frame name: every field with a known target address proposes the base
   `linear(target) - field` (the original's word). `[rebuild.frames]` in `decovery.toml` (`ModuleOptions.frames`)
   overrides the consensus for a frame.
3. **Section anchor** per OBJ section (and frame) for fields whose target is a section position without a name:
   each proposes `field - (section_offset + addend + content)`, a frame-relative offset (16-bit wrapping).
4. **Consensus.** One vote per distinct (target, proposed base) pair, so a variable referenced a hundred times
   does not outvote a hundred variables referenced once. The value with most votes is the anchor; a tie goes to
   the lowest value. Fields proposing the anchor match; all others are `WrongAbsoluteRef`. Each anchor reports its
   votes, its dissent (votes for other values) and its source (configuration or consensus).
   *Amendment 2026-11-09 (no self-confirmation):* a frame base from consensus is accepted only with at least two
   votes and more votes than dissent; there is no tie-break for frames. Otherwise the frame has no anchor, the
   comparison carries a warning naming the frame, and its fields are `UncheckedRef` (as in item 5); a field
   proposing a negative base stays `WrongAbsoluteRef`. A lone vote proposes the base that makes its own field
   right, and a 1:1 tie gave the base to the lower value whichever field was wrong: a reference to the wrong
   variable came out `identical` (and its right neighbour `differs`). Configured (`[rebuild.frames]`) and startup
   (item 10) bases are fixed and unaffected. A far pointer into a frame without an anchor is judged by its linear
   address (the original's relocated segment plus its offset word must be the target's), as in item 1.
   *Section anchors (item 3) under the same amendment:* the same rule applies: a section anchor needs at least
   two votes and more votes than dissent, with no tie-break. Otherwise the section has no anchor, a warning names
   it, and its fields are `UncheckedRef`, even when the item bytes at the position a field names equal the
   original; a field whose item differs from the original at its own position is `WrongAbsoluteRef` (wrong
   wherever the section lies). Equal item bytes are no evidence of the position: another item with the same value
   passes the same way. Probes before the amendment: a lone 16-bit or 32-bit reference into `_BSS` was `identical`
   wherever the original pointed (even into code); of two references tied 1:1 the lower one was `identical`, in
   `_BSS` and in a data section whose two items hold the same value (16-bit with a configured frame and 32-bit LE),
   while the right one became `DataLayout`. 32-bit frames are flat (base 0) and never take a consensus; 32-bit
   section anchors follow the section rule. On the first parity target five functions whose module holds a single
   reference into its constant data became `unchecked-ref` (`docs/parity/phase-2.md`).
5. **Item bytes.** When the frame anchor is known, the bytes of each referenced item of an anchored data section
   must equal the original at `frame + section anchor + item offset`. An item reaches from its referenced offset to
   the next boundary: the next distinct referenced offset into the same section (over all compared functions of
   the module), the next symbol of the section, or the end of the section's initialised bytes, whichever comes
   first; the section's own fixup fields inside it are not compared. A field is `WrongAbsoluteRef` only if its own
   item differs, so a difference elsewhere in the section (another function's string) does not mark it. Without a
   frame anchor the byte check is skipped and the comparison carries a warning naming the section and the frame.
   *Amendment 2026-11-09 (fail closed):* a field whose item cannot be compared because the frame has no anchor is
   an `UncheckedRef`, even when its offset agrees with the section anchor; the warning stays. The section anchor
   alone only shows that the rebuild's references are consistent with each other, not that they name the
   original's data: a wrong string at the right offset passed as identical. Design 5.11 item 1 requires every
   relocated field to be checked, and a false `identical` is the outcome decovery must never produce.
6. **Selector fields** need the original's MZ relocation at the same place; its segment value times 16 must equal
   the frame anchor's base. Without a frame anchor a selector field is an `UncheckedRef`. Selector fields do not
   vote.
7. **32-bit.** LE behaviour is unchanged, with one exception: a field whose target is an unnamed position in
   another section, previously an `UncheckedRef`, now proposes a section anchor from the original's relocation
   target (frame base 0) and gets the same consensus and byte check.
8. **Data layout** (amendment 2026-11-06, Task 11 ruling). A dissenting field whose item is byte-equal to the
   original at the position the field itself proposes is not a wrong reference but a `DataLayout` blocker: the
   item exists unchanged, only the section's layout differs from the original. The verdict stays `Differs`.
9. **Own jump table** (amendment 2026-11-06, Task 11 ruling). A 32-bit field into the function's own section
   before the function start (Watcom's jump table) is matched by the table, not its address: the original's
   relocation must point at a table whose consecutive entries lead to the same offsets relative to the function
   start as the rebuild's entries.
10. **Startup frames** (amendment 2026-11-09). A frame base can come from the program's startup code instead of
    votes. For an MZ target, `build` reads the startup object (`[rebuild.link] startup`, else the profile linker's
    `startup`; none for a toolchain without one) from the profile's library directory and places its start
    address (OMF `MODEND`) at the program's entry point. The startup gives frame bases only if its code section equals the original there outside its own fixup fields and
    each of its 16-bit selector fields has a segment relocation of the original at the same place; the
    original's segment value times 16 is then the base of the field's frame (a selector that targets a group,
    `mov dx, DGROUP`, names the group). A frame whose selector fields give different bases gets none. The base is
    fixed like a configured one (source `startup`): it overrides the consensus of rule 2, and `[rebuild.frames]`
    overrides it, with a warning when the two differ. Rule 6 is unchanged: selector fields of the compared
    functions still do not vote.

    Why it is sound: no rebuilt code takes part, so no rebuild, right or wrong, can move the base. A wrong
    selector in a compared function would vote for the very base it is then checked against; a lone one would
    prove itself, which is why rule 6 stays. The startup object is the toolchain's library object, not a rebuild;
    byte equality at the entry point plus a segment relocation exactly at each selector field means the original
    loads that segment value for that frame. A startup from another library version differs in its bytes and
    gives nothing. With the base known, rule 5 compares the referenced items, so a wrong string stays a
    `WrongAbsoluteRef`.

    Rejected: letting selector fields of compared functions vote (self-confirming, see above); searching the
    image for the section's bytes (it picks the base that makes the rebuild match, and costs a scan of the
    program); a program-wide consensus over all modules of a build (helps only when some module has named
    targets with known addresses); deriving the base from the knowledge base (it records no frames; the segment
    part of a recorded address is notation). `[rebuild.frames]` remains the way to pin a frame by hand.

## Consequences

- A single function compared alone (`compare`) anchors only on its own fields; one reference to one variable
  stays unchecked (item 4, amendment 2026-11-09) unless a configured or startup base decides its frame; a lone
  reference into a section stays unchecked as well. The check
  grows stronger with the number of functions compared together, which is why `build` compares whole OBJs
  (`compare_module`) and why a frame can be pinned in `[rebuild.frames]`.
- A rebuild that consistently refers to the wrong variable in most of its fields moves the consensus; the
  dissent count and a configured frame are the guards against that.
- Self-relative 16-bit fields keep the existing rule (the original's target read from its bytes); unnamed
  self-relative targets stay unchecked.
- Anchors and warnings are part of the module comparison result, so the parity report can show them.
