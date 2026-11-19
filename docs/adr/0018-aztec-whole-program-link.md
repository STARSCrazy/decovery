# ADR 0018: Aztec C86 whole-program link in `build`

Status: accepted · 2026-11-19

## Context

Once every function, data module and library member of an Aztec C86 target is compared, one question is left:
does the toolchain's linker turn these objects into the original files, byte for byte? The root program is an MZ
file; each overlay is a file of its own, linked against the root's symbols. The link order is part of the result:
the Aztec linker LN places commons in the order of their first appearance (an extern counts), reversed within one
module, so a commons-only module has to come first. The existing `link` tool links a Turbo C or Watcom program from
`[rebuild.link]`; it knows neither overlays nor LN's symbol file.

LN (4.10d) takes `-o` (output), `-f <file>` (a control file of inputs), `-l<name>` (a library from `CLIB`),
`+c n` and `+d n` (bytes after the code and the udata) and `-r` (write `<output>.RSM`, the root's symbols for the
overlay links). Its output holds no date and no path: two links give identical files. The DOS command line is too
short for a long object list.

## Decision

1. **Configuration.** A top-level `[link]` in `decovery.toml`:
   - `output`: the root program's file name (default: the target's file name, upper case);
   - `objects`: the root's inputs in link order. An entry is a source file name in `src/` (its object, `main.c` →
     `MAIN.O`) or a name from `[rebuild] library_objects` (`OVLD.O` → `D:\LIB\OVLD.O`);
   - `flags`: the root's linker flags (`+c 8000 +d 1000 -r`); with overlays, `-r` is added when missing;
   - `libraries`: searched last (default `[rebuild] libraries`, `C.LIB` → `-lc`);
   - `overlay_objects`: inputs every overlay gets after its own objects (`["OVBGN.O"]`);
   - `overlay_flags`: flags of every overlay without its own;
   - `[[link.overlay]]`: `name` (an `[[overlay]]`), `output` (default `<name>.OVR`), `objects` (default: the files
     of its `[[rebuild.module]]`, else `<name>.c`), `flags`. The order of the entries is the link order.

   Unknown keys are refused: a misspelt key must not silently change the order.
2. **Profile.** `aztec-c86-4.2b` gets `[linker]`: `command = "LN {flags} -o {output} {objects} {libraries}"`,
   `library_flag = "-l{name}"`, `control_file = "-f {file}"`, `line_limit = 126`. A line longer than `line_limit`
   lists the configured objects in `<output stem>.LNK` (CRLF lines) and names it with `-f`; the extra inputs
   (`overlay_objects`, the `.RSM`) and the libraries stay on the line.
3. **When.** Only a full `build` (no files, no `--function`) with `[link]` links, after compiling and comparing:
   one runner job for the root, then one per overlay in the same build directory, each reading the root's `.RSM`.
   An overlay is not linked when the root did not link. The runners are the profile's (`unicorn-dos` first).
4. **Comparison.** Each linked file against the original file (`[target] file`, the `[[overlay]]` file):
   - root (MZ): the 14 header words by name (`signature`, `last_page_bytes`, `pages`, `relocations`,
     `header_paragraphs`, `min_alloc`, `max_alloc`, `ss`, `sp`, `checksum`, `ip`, `cs`, `relocation_offset`,
     `overlay_number`), then the relocation table, the rest of the header, the image;
   - overlay: the 7 header words (`magic`, `code_origin`, `code_length`, `data_origin`, `data_length`,
     `udata_length`, `entry`), then code (`code_length` bytes), then data.
   The first difference gets its region, its address through the configured `[[target.segment]]` entries (the root
   falls back to the image offset) and the nearest knowledge name at or before it (`vone+0x2`).
5. **Report.** The summary adds `link: root equal; overlays N of M equal` (`root differs` / `root error`, and the
   first overlays that are not equal); `data.link` holds `equal`, `root`, `overlays` (per file: `result`
   `equal`/`differs`/`error`, sizes, `differing`, differing `header` fields, `first_difference`, the `line`, or the
   `message`), `overlays_equal`, `overlays_total`. Each file that is not equal adds a hint. The CLI build fails
   (exit 1) when `link.equal` is false. The linked files are kept in `cache/rebuild/link/`.
6. **`link`.** The `link` tool refuses Aztec C86 workspaces and points to `[link]`.

## Consequences

- Tests use a fake LN in the test runner and synthetic files; the real linker runs only on the user's machine.
- The root data module is still compared before the link as main-program data; the link closes the remaining gaps
  (order of commons, library placement, headers).
- Library objects with a path (relative to the workspace) cannot be linked yet; they must lie in the toolchain's
  `LIB` directory.
