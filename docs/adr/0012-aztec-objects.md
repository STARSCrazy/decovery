# ADR 0012: Aztec C86 objects in the neutral object model

Status: accepted · 2026-11-18

## Context

Manx Aztec C86 (3.4b, 4.2b, 5.2a) writes its own object format, not OMF. A module is a 30-byte header (magic,
eight-byte name, code/data/BSS sizes, position and count of the named and of the unnamed symbol tables, end of the
symbol tables, distance to the next module, a count of segment fixes), a stream of load items up to an end item, and
the two symbol tables. A symbol entry is a type byte, a flag byte, a 16-bit value, an optional segment byte, and (named
table only) a NUL-terminated name. Libraries (`.LIB`) start with 2048-byte dictionary blocks (magic, next block, then
pairs of "module position / 128" and symbol name), the modules follow, aligned to 128 bytes, with their symbol tables
in front of their load items.

The assembler does not resolve references inside a module itself: even a short jump to a label of the same function
is a self-relative reference to an unnamed symbol in the stream. Phase 4 plan decision 3 and risk R3 ask whether
the neutral model (`ObjectModule`: sections, symbols, relocations) can hold every load item.

The reader is written from the compiler's own object format description (the layout of the header, symbol table
entries and the item codes); Decomp's reader (`nachbau/aztec.py`) and its tests serve only as a behavioural oracle
(it was checked there against Manx's object dumper).

## Decision

Every module gets three sections in fixed order: 0 `CODE` (class `CODE`, `Code`), 1 `DATA` (`Data`), 2 `BSS`
(`Bss`), all 16 bit. Code and data hold header-size bytes (bytes the stream does not write stay zero); BSS holds no
bytes. No group is created.

| Aztec element | Model element |
|---|---|
| header code/data size | `Section::data` of `CODE`/`DATA`, zero-filled to that size; a stream writing past it is an error |
| header BSS size | `Section::size` of `BSS` (**model change**, see below) |
| named symbol of type code, data or BSS | `ObjSymbol { section, offset: value, public: global flag }` (static functions keep their name, `public: false`) |
| named symbol of type undefined (extern, common) | no `ObjSymbol`; references to it are `RefTarget::Symbol(name)` |
| named symbol of type absolute | no `ObjSymbol` (has no section); a reference adds its value as a number |
| unnamed symbol (label, string literal) | no `ObjSymbol`; a reference to it is `RefTarget::Section { index, offset }` |
| raw data item, blank-space item, origin item | bytes and position in the current section |
| switch to code / data | current section |
| reference item (expression, named or unnamed symbol, code/data/BSS reference with small or large offset, integers) | `ObjReloc` at the current position; the integer part of the expression is written into the field (`addend: 0`), as an OMF object stores it |
| fixup modifier byte/word self-relative | `ObjReloc { kind: Relative, width: 1 or 2 }`; a section target then carries the full target offset (label + integer part) |
| fixup modifier byte / 32-bit absolute; none (= word absolute) | `ObjReloc { kind: Absolute, width: 1, 4 or 2 }` |
| paragraph of code / data segment, `seg` operator | `ObjReloc { kind: Selector, width: 2, target: Section { index, offset: 0 } }` (or the symbol for `seg sym`) |
| start address item | `ObjectModule::start` (section, offset) when it names a section position |
| line and debug items | skipped |
| segment-relative reference, common-segment switch, interpreter call, other extended items | `ObjectError::Malformed` naming the offset (not produced by the DOS compilers) |

All relocations have `frame: Frame::Target`.

Deviation from plan decision 3: unnamed symbols do **not** become `ObjSymbol { public: false, name: "@<section>:<offset>" }`.
`functions()` splits a code section at every symbol, so a symbol per jump label would cut functions into basic
blocks. A section-position target (`RefTarget::Section`) is what the model already uses for unnamed targets (OMF
segment-relative fixups, ADR 0006 item 3), and the comparison already handles self-relative references into the
own section. The reader leaves the field content as the stream wrote it; it does not resolve those references.

### Model change: `Section::size`

The model had no place for the size of a section without bytes: OMF `SEGDEF` lengths were dropped, and an Aztec
module's BSS size would be lost. Task 8 must not call a module identical when its BSS size differs. Smallest
additive change: `Section` gets `pub size: u32`, the size of the section in memory (`>= data.len()`).
`Section::new` sets it to `data.len()`; `Section::with_size` overrides it. The OMF reader now fills it from the
`SEGDEF` length. No existing reader of the model changes behaviour.

### Format-neutral entry point

`ObjectFormat` moves from `decovery-toolchain` to `decovery-objects` (the toolchain re-exports it), and
`read_object(format, bytes, name)` dispatches to `read_omf` or `read_aztec`. The CLI and facade call `read_object`
with the profile's format.

## Consequences

- Malformed objects and libraries return `Truncated` / `Malformed` with the file offset; the reader never panics
  (every prefix of a valid object is tested).
- Large-code-model modules (magic `0x020C`) are read with the same item rules. The large-model libraries of 4.2b
  (and single large-model modules inside the small-model libraries) read without error, but Decomp's reader skips
  them, so their content has no oracle yet; the third target is small model.
- Public tests use objects from a test-only writer (feature `test-writer`); real objects stay in local tests.
