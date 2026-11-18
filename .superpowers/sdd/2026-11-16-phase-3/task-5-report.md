# Task 5 — suites and isolated task copies

Status: DONE_WITH_CONCERNS; uncommitted for the coordinator. Task 6 has not started. No model driver, private workspace, push, merge or Git mutation was used.

## Result

- Added `decovery-bench`, with schema-one suites, default budgets, optional task starts/tags, relative path resolution, unique task ids, `core` / `core-legacy` tool sets and the `core+legacy` input alias. Selection requires a native identical verdict and exactly one source definition; imported identical evidence alone is insufficient.
- Copies start from the original declaration head and an empty stub or the provider's pseudo-C body, falling back to a stub with a warning. The evaluation-only solution stays in memory and `TaskCopy` is deliberately not serializable.
- Copies include knowledge, sources, unrelated kept objects and other-function attempt shards. They exclude the target rebuild record/shard, its module's kept object/metadata, **all** archives, outputs, handles, object/shrink/run caches, jobs, calls, exemplars, Git metadata and legacy shadows. Omitting every archive implements binding P7 and prevents sibling `module.c` and migrated `input/` leaks.
- Copied auxiliary text and structured TOML/JSON string fields redact the hidden definition (whitespace normalized) and code hash. The target module is generated directly from the start point; its hidden definition is not first copied onto disk. Unknown structured fields are otherwise retained. Final checks scan every resource, including linked backend resources, without modifying link targets. Scanning is streamed, handles UTF-8 boundaries and CP437, and retains pattern state across buffers.
- Relative target and tool paths become absolute references to their originals. Targets are read in place rather than copied. Destination ancestors are checked both lexically and canonically for `CLAUDE.md` and repositories before creating directories. Existing destinations are refused; source and original Decomp trees are protected before any write.
- A `core-legacy` task has its own sibling `legacy-view`, stripped of the target's rebuild entry and source/cache solutions. It contains rewritten absolute Decomp target paths, sanitized knowledge and the unpacked original when present. Ghidra projects and recordings are linked. Project lookup follows the bridge's dotted-path redirection, including stale local-project folders. Native and legacy address spelling variants cannot preserve the withheld rebuild record.
- The bridge now preserves explicit project aliases before resolution. This also fixes an existing safety defect: resolving a destination link first lost the link check and could replace its target. Source aliases still work; linked destinations are refused. Both behaviors have RED-to-GREEN Python regressions.
- Added the suite schema and the design's crate-layout entry. Cargo's existing `crates/*` member glob includes the crate; the root workspace dependency entry was added for later tasks. No new fixed dependency kind was introduced.

## TDD and checks

- Initial `cargo test -p decovery-bench --test copy_synthetic`: RED, missing suite/copy API. Evidence: `target/task-5-red.log`.
- Initial implementation: 8 passed, 2 failed on Windows extended-path spelling; canonical public/config paths were corrected, then all 10 planned tests passed.
- Additional isolation regressions: RED for native short-form addresses retaining the target record, legacy short-form addresses retaining it, and creating directories inside the original Decomp source before rejection. GREEN after typed address matching and source prevalidation. A redirected-project unit test started RED with the missing helper and now passes, including a stale regular local folder.
- Streaming scan unit test: RED, missing streaming reader; GREEN for definitions, hashes and objects across 64 KiB boundaries, including split UTF-8 characters and the analysis-byte exemption.
- `cargo test -p decovery-bench`: **15 passed**, no failures (13 integration tests, 2 unit tests). Includes a real facade build using the existing synthetic fake runner to retain other functions' native identical verdicts.
- Python explicit-link regressions: RED, alias was resolved and linked destination was replaced; GREEN, **2 passed** after the bridge fix.
- `cargo fmt --all --check`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass.
- `cargo test --workspace --no-fail-fast`: **628 passed, 1 failed, 17 ignored**, exit 101. Sole failure: unchanged `shutdown_of_a_hung_plugin_kills_its_workers`, with Windows process access denied, as already diagnosed and accepted for continuation. All doctests pass. Evidence: `target/task-5-workspace-tests.log`, `.exit`.
- `python -m unittest discover -s tests` in `plugins/decomp-legacy`: **32 run, 30 passed, 1 error, 1 skipped**. Error: unchanged `test_changed_sources_wait_for_the_running_command`, missing second reply (`KeyError: 2`). Its focused rerun reproduces in 66.438 s. The unchanged Windows tree-kill helper waits 30 s after denied `taskkill`; the first timeout and two such waits exceed the test harness's 60 s reply wait.
- A read-only baseline probe replaced **only** `ghidra_project_dir` in a separate interpreter with its committed `HEAD` AST, without modifying repository files. The same test reproduces the same error in 66.435 s. This confirms that the Task 5 Python change is not its cause. Evidence: `target/task-5-baseline-probe.py`, `.log`. No test was disabled or weakened. Coordinator should run the complete Python suite outside the restricted sandbox as well as the full Rust checks.

All new build/test logs and the baseline probe are under ignored `target/`; none belongs in the commit. Human SDD records remain in the SDD directory.

## Rulings and concerns

- Binding P7 choice: omit the complete archive. Other-function attempt records can retain historical archive ids whose payloads are absent; fetching one reports a missing entry. No target-function history or archive is retained. Later harness code must not copy the archive back.
- To meet the leak criterion across notes and other copied artifacts, hidden definitions/hashes are redacted from copied text/structured values; unmodifiable linked resources containing them cause copy rejection. This can remove quoted context from a task copy, while originals remain untouched.
- An intentionally generated empty stub or provider start point can equal a trivial solution. Only the generated source definition is allowed in that case; surrounding module text is redacted, and object/hash checks remain active. This is an input start point, not an archive/source leak.
- P13 remains a Task 6 requirement: each task/repeat needs a unique safe-key parent containing `{workspace,legacy-view}`. Do not derive directories directly from ids containing `/` or `:`. P14 is implemented by validating the actual `into` directory, so Task 6 can pass a configured parent without changing `copies_dir()`.
- P15: no exemplar-removal hook was added; the entire exemplar cache is excluded. P25 target paths, unpacked originals, redirected projects and auxiliary legacy knowledge are covered.
- `copy.rs` is large (copy selection, sanitization and final verification in the planned file). It was kept in the specified file structure rather than split without plan guidance. Review the isolation boundary carefully before wiring a driver to it.
- No private backend run was performed. R5's real legacy-view cost/startup measurement remains at Task 9. The final scan uses bounded input buffers; copied text files still require their full contents for structured redaction.

## Coordinator handoff

Use the exact file list and proposed commit message in progress.md. No staging or commit was attempted in this continuation. After external verification/commit, continue at Task 6 with its binding preflight rows; owner/model-spending gates remain unchanged.
