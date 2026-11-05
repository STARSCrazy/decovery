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
5. **Item bytes.** When the frame anchor is known, the bytes of each referenced item of an anchored data section
   must equal the original at `frame + section anchor + item offset`. An item reaches from its referenced offset to
   the next boundary: the next distinct referenced offset into the same section (over all compared functions of
   the module), the next symbol of the section, or the end of the section's initialised bytes, whichever comes
   first; the section's own fixup fields inside it are not compared. A field is `WrongAbsoluteRef` only if its own
   item differs, so a difference elsewhere in the section (another function's string) does not mark it. Without a
   frame anchor the byte check is skipped and the comparison carries a warning naming the section and the frame.
6. **Selector fields** need the original's MZ relocation at the same place; its segment value times 16 must equal
   the frame anchor's base. Without a frame anchor a selector field is an `UncheckedRef`. Selector fields do not
   vote.
7. **32-bit.** LE behaviour is unchanged, with one exception: a field whose target is an unnamed position in
   another section, previously an `UncheckedRef`, now proposes a section anchor from the original's relocation
   target (frame base 0) and gets the same consensus and byte check.

## Consequences

- A single function compared alone (`compare`) anchors only on its own fields; one reference to one variable
  always agrees with itself. The check grows stronger with the number of functions compared together, which is
  why `build` compares whole OBJs (`compare_module`) and why a frame can be pinned in `[rebuild.frames]`.
- A rebuild that consistently refers to the wrong variable in most of its fields moves the consensus; the
  dissent count and a configured frame are the guards against that.
- Self-relative 16-bit fields keep the existing rule (the original's target read from its bytes); unnamed
  self-relative targets stay unchecked.
- Anchors and warnings are part of the module comparison result, so the parity report can show them.
