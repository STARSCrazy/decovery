# ADR 0014: Compiler flags in the source file

Status: accepted · 2026-11-19

## Context

`[rebuild.file_flags]` in `decovery.toml` gives a source file its own compiler flags. The table is one place that
every file's author edits, so parallel work on different files collides in merges, and an entry is lost when its file
is renamed (the table silently stops applying).

## Decision

A source file may carry its flags itself: a comment in its first ten lines,

```c
/* decovery: flags = +b +c */
```

(`//` and a line inside a block comment work too; the value is the rest of the line). It is read from `.c` files.

- A comment replaces the default `[rebuild] flags` for that file, exactly as a `[rebuild.file_flags]` entry does.
- When the table has an entry for the file as well (matched by name, DOS name or case-insensitively) and the flags
  differ, the source comment wins and the build warns. Equal flags are silent.
- A comment that starts with `decovery:` but is not `flags = …` is a warning; the file then uses the table or the
  default.
- A `[rebuild.file_flags]` entry that names no file in `src/` is a warning (an orphan after a rename).

`decovery.toml` keeps its schema; the table stays valid. The flags are part of the object cache key already, so a
changed comment rebuilds the file.

## Consequences

Flags can live next to the code they belong to and follow it through renames and merges. Two places can disagree; the
warning names both values, and the source comment is the one that applies.
