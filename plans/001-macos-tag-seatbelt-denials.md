# Plan 001: macOS denials name the rule that caused them in the unified log

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a5c8219..HEAD -- crates/guardrail-macos crates/guardrail-napi/README.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: direction
- **Planned at**: commit `a5c8219`, 2026-11-14

## Why this matters

Guardrail sandboxes LLM agents. Operators (especially enterprise ones) need to
know when an agent hit a sandbox rule, and which rule. The design decision is
that guardrail does **not** collect, parse, or expose logs: the operating
system already logs every Seatbelt denial to the macOS unified log, and
operators read that log with their own tools. Guardrail's only job is to
leave a marker in each denial line so those lines can be filtered and
attributed. Today the lines carry no marker, so an operator cannot tell a
guardrail denial from any other sandboxed app's denial, nor which rule fired.

Seatbelt's profile language (SBPL) lets a rule carry a `(with message "…")`
modifier; the kernel appends that text to the denial's log line. After this
plan, every denial produced by the generated profile ends with either
`guardrail:fs[N]` (denied by the deny rule at index `N` of
`SandboxConfig::fs`) or `guardrail:default` (no allow rule matched).

## Current state

This crate is **native-only**: it compiles and tests only on macOS. You must
run this plan on a macOS host.

- `crates/guardrail-macos/src/profile.rs` — pure-Rust generator for the SBPL
  profile text. All changes to behavior happen here.
- `crates/guardrail-macos/src/seatbelt.rs` — passes the profile to
  `/usr/bin/sandbox-exec -p PROFILE`. One unit test there asserts generated
  text exactly.
- `crates/guardrail-macos/src/lib.rs` — crate docs.
- `crates/guardrail-macos/tests/generated_profile.rs` — integration tests that
  spawn the probe binary under generated profiles. They prove `sandbox-exec`
  still accepts the profile, so they are the syntax gate for this change.
- `crates/guardrail-napi/README.md` — the user documentation.

`crates/guardrail-macos/src/profile.rs:29-36` (start of the generator):

```rust
pub(crate) fn build_policy_rules(config: &SandboxConfig) -> Result<String> {
    let mut source = String::from("(deny default)\n(debug deny)\n");

    for (index, rule) in config.fs.iter().enumerate() {
        let later_rules = &config.fs[index + 1..];
        match rule {
            FsAccess::ReadAllow(path) => {
                let exclusions = read_deny_paths(later_rules);
                push_path_rules(&mut source, "allow", &["file-read*"], path, &exclusions)?;
            }
            FsAccess::ReadDeny(path) => {
                let exclusions = read_allow_paths(later_rules);
                push_path_rules(&mut source, "deny", &["file-read*"], path, &exclusions)?;
            }
```

The same `match` has four more arms with the same shape: `WriteAllow` /
`WriteDeny` use `&["file-write*"]`; `ExecuteAllow` / `ExecuteDeny` use
`&["file-map-executable", "process-exec*"]`.

`crates/guardrail-macos/src/profile.rs:92-118` (rule emission):

```rust
fn push_path_rules(
    source: &mut String,
    action: &str,
    operations: &[&str],
    path: &Path,
    exclusions: &[PathBuf],
) -> Result<()> {
    for path in path_variants(path) {
        push_path_rule(source, action, operations, &path, exclusions)?;
    }
    Ok(())
}

fn push_path_rule(
    source: &mut String,
    action: &str,
    operations: &[&str],
    path: &Path,
    exclusions: &[PathBuf],
) -> Result<()> {
    for operation in operations {
        source.push_str(&format!("({action} {operation} "));
        push_subpath_filter(source, path, exclusions)?;
        source.push_str(")\n");
    }
    Ok(())
}
```

So a deny rule currently renders as, for example:

```
(deny file-read* (subpath "/tmp/secret"))
```

Existing unit tests that assert this text and must be updated (line numbers at
commit `a5c8219`):

| Location | Current expectation |
|---|---|
| `profile.rs:301` | `"(version 1)\n(deny default)\n(debug deny)\n"` (exact `assert_eq!`) |
| `profile.rs:334`, `profile.rs:619` | `"(deny default)\n"` inside `assert_substrings_in_order` |
| `profile.rs:484` | `.contains("(deny file-read* (subpath \"/tmp/secret\"))\n")` |
| `profile.rs:532` | `.contains("(deny file-write* (subpath \"/tmp/work\"))\n")` |
| `profile.rs:585` | `.contains("(deny file-map-executable (subpath \"/tmp/bin\"))\n")` |
| `profile.rs:590` | `.contains("(deny process-exec* (subpath \"/tmp/bin\"))\n")` |
| `seatbelt.rs:255` | `(deny default)\n\` inside an exact `format!` |

`seatbelt.rs:169` and `seatbelt.rs:189` contain the literal
`"(version 1)\n(deny default)\n"` but those are hand-written profiles, not
generated ones. Do not change them.

Repo conventions that apply:

- KISS: "No glue code, no over-engineering." Do not add a config option, a
  log reader, or any new public API. The tags are always on.
- Commit messages use scoped-commits form: `<scope>: <description>`, lowercase,
  no trailing period, no `feat:`/`fix:` prefixes. Example from this repo's
  log: `linux: make policy paths durable against sandbox-staged decoys`.
- Workspace clippy lints warn on `unwrap_used`, `panic`, `indexing_slicing`
  in non-test code. The existing `config.fs[index + 1..]` line is
  pre-existing; do not add new indexing.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Unit + integration tests (macOS only) | `cargo test -p guardrail-macos --all-targets` | all pass |
| Default workspace tests | `cargo test --all-targets` | all pass |
| Read recent tagged denials | `log show --last 5m --style compact --predicate 'eventMessage CONTAINS "guardrail:"'` | prints lines (after tests ran) |

These are the commands CI runs (`.github/workflows/test.yml`). They were not
executed while writing this plan, because the plan was written on a Linux
host. Run `cargo test -p guardrail-macos --all-targets` once **before**
changing anything and record the pass count as your baseline.

## Scope

**In scope** (the only files you should modify):
- `crates/guardrail-macos/src/profile.rs`
- `crates/guardrail-macos/src/seatbelt.rs` (one test expectation only)
- `crates/guardrail-macos/src/lib.rs` (docs only)
- `crates/guardrail-napi/README.md` (docs only)

**Out of scope** (do NOT touch):
- `crates/guardrail-core` — no new config field. A host-supplied label was
  considered and explicitly deferred by the maintainer.
- Any code that reads, streams, or parses the unified log. The maintainer's
  decision is that operators retrieve logs themselves.
- Allow rules: they must stay untagged (allowed operations are not logged).
- The `(debug deny)` line: keep it exactly as is.
- Imported profiles (`darwin_sandbox_profiles`): their denials stay untagged.
- `crates/guardrail-linux`, `crates/guardrail-windows`.

## Git workflow

- This repo uses jj colocated with git. If a `.jj` directory exists, use
  `jj describe -m "…"`; otherwise use git on a branch named
  `advisor/001-macos-tag-seatbelt-denials`.
- One commit. Message: `macos: tag seatbelt denials with the deciding rule`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Record the baseline

Run `cargo test -p guardrail-macos --all-targets`.

**Verify**: all tests pass. Note the counts. If any fail, STOP.

### Step 2: Emit the tags

In `crates/guardrail-macos/src/profile.rs`:

1. Add near the top of the file (after the `use` lines):

   ```rust
   /// Tag carried by denials that no allow rule matched. Every tag starts
   /// with `guardrail:` so one unified-log predicate finds them all.
   const DEFAULT_DENY_TAG: &str = "guardrail:default";

   /// Tag carried by denials from the deny rule at `index` of
   /// `SandboxConfig::fs`.
   fn rule_tag(index: usize) -> String {
       format!("guardrail:fs[{index}]")
   }
   ```

2. In `build_policy_rules`, replace the first line with:

   ```rust
   let mut source =
       format!("(deny default (with message \"{DEFAULT_DENY_TAG}\"))\n(debug deny)\n");
   ```

3. Add a final parameter `message: Option<&str>` to both `push_path_rules`
   and `push_path_rule`. `push_path_rules` forwards it unchanged. In
   `push_path_rule`, emit it between the filter and the closing parenthesis:

   ```rust
   for operation in operations {
       source.push_str(&format!("({action} {operation} "));
       push_subpath_filter(source, path, exclusions)?;
       if let Some(message) = message {
           source.push_str(&format!(" (with message \"{message}\")"));
       }
       source.push_str(")\n");
   }
   ```

4. In the `match` inside `build_policy_rules`: the three **deny** arms
   (`ReadDeny`, `WriteDeny`, `ExecuteDeny`) pass `Some(&rule_tag(index))`;
   the three **allow** arms pass `None`.

The tag text is built only from a constant and an integer, so it needs no
escaping. Do not route it through `sbpl_string` (that function is for paths
and rejects non-absolute strings).

A deny rule now renders as:

```
(deny file-read* (subpath "/tmp/secret") (with message "guardrail:fs[1]"))
```

**Verify**: `cargo build -p guardrail-macos` → exit 0, no new warnings.

### Step 3: Update the existing expectations

Update the seven expectations listed in the "Current state" table:

- `(deny default)\n` becomes
  `(deny default (with message \"guardrail:default\"))\n` in `profile.rs:301`,
  `:334`, `:619`, and `seatbelt.rs:255`.
- Each `.contains("(deny … (subpath \"…\"))\n")` gains
  ` (with message \"guardrail:fs[N]\")` before the final `)`, where `N` is the
  0-based position of that deny rule in **that test's own** `fs: vec![…]`.
  Read each test's `fs` vector to get `N`; do not guess.

Leave the `!profile.source.contains("(deny file-read*")` assertions
(`profile.rs:528`, `:581`) unchanged.

**Verify**: `cargo test -p guardrail-macos --lib` → all pass.

### Step 4: Add tests

In the existing `#[cfg(test)] mod tests` of `profile.rs`, add three tests.
Model them on `default_config_denies_by_default` (`profile.rs:296`) and reuse
the module's existing config-literal style (every `SandboxConfig` field is
written out; copy a literal from a neighboring test).

1. `deny_rules_carry_their_rule_index` — `fs` = `[ReadAllow("/tmp"),
   ReadDeny("/tmp/secret"), WriteDeny("/tmp/locked")]`; assert the source
   contains `(with message "guardrail:fs[1]")` on a `deny file-read*` line and
   `(with message "guardrail:fs[2]")` on a `deny file-write*` line.
2. `allow_rules_are_untagged` — same config; assert no line that starts with
   `(allow ` contains `with message`.
3. `execute_deny_tags_both_operations` — `fs` = `[ExecuteDeny("/tmp/bin")]`;
   assert both the `file-map-executable` line and the `process-exec*` line
   contain `(with message "guardrail:fs[0]")`.

**Verify**: `cargo test -p guardrail-macos --all-targets` → all pass, pass
count = baseline + 3. The integration tests in `tests/generated_profile.rs`
passing is the proof that `sandbox-exec` accepts the new syntax.

### Step 5: Confirm the tag reaches the unified log

The integration tests you just ran triggered real denials. Within five
minutes of that run, execute:

```
log show --last 5m --style compact --predicate 'eventMessage CONTAINS "guardrail:"' | grep -c 'guardrail:'
```

**Verify**: the count is at least 1, and at least one line contains
`guardrail:fs[` and one contains `guardrail:default`. If the command prints
`0`, retry once with `sudo`. If it is still `0`, STOP (see STOP conditions).
Copy two sample lines (one of each kind) into your report; you will quote
them in the README in step 6.

### Step 6: Document

1. `crates/guardrail-macos/src/lib.rs`: add a crate-doc section immediately
   before `//! # Tips: common macOS runtime grants`:

   ```rust
   //! # Denial log tags
   //!
   //! Guardrail does not read or expose sandbox logs. Each denial produced by
   //! the generated profile ends with a tag in the macOS unified log:
   //! `guardrail:fs[N]` when the deny rule at index `N` of
   //! [`guardrail_core::SandboxConfig::fs`] refused it, `guardrail:default`
   //! when no allow rule matched. Filter with
   //! `log stream --predicate 'eventMessage CONTAINS "guardrail:"'`. Denials
   //! from imported profiles carry no tag.
   //!
   ```

2. `crates/guardrail-napi/README.md`: if a `## Auditing Denials` section does
   not exist yet, create it immediately before `## Platform Capability Matrix`
   with this opening paragraph:

   > Guardrail does not collect or expose denial logs. It leaves markers in
   > each platform's own log so you can filter and attribute denials with the
   > tools you already run.

   Then add a `### macOS` subsection stating: the two tag forms and what each
   means; that `N` is the index into the `fs` array; the `log stream` command
   above; that denials from `darwinSandboxProfiles` imports are untagged; and
   a `Tested result:` line quoting the two sample log lines from step 5 with
   the macOS version (`sw_vers -productVersion`). The README's existing setup
   guides use `Tested result:` lines — match that convention.

**Verify**: `grep -c 'guardrail:fs\[' crates/guardrail-napi/README.md` ≥ 1 and
`cargo test --doc -p guardrail-macos` → pass.

## Test plan

- Three new unit tests in `crates/guardrail-macos/src/profile.rs` (step 4).
- Seven updated expectations (step 3).
- Existing integration tests (`tests/generated_profile.rs`,
  `tests/custom_profile.rs`) must pass unchanged — they are the syntax gate.
- Verification: `cargo test -p guardrail-macos --all-targets` → all pass.

## Done criteria

- [ ] `cargo test -p guardrail-macos --all-targets` exits 0 with baseline + 3 tests
- [ ] `cargo test --all-targets` exits 0
- [ ] `grep -c 'with message' crates/guardrail-macos/src/profile.rs` ≥ 2
- [ ] Step 5 produced at least one `guardrail:fs[` line and one `guardrail:default` line
- [ ] README has a `## Auditing Denials` → `### macOS` subsection with a `Tested result:` line
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- You are not on a macOS host.
- The code at the locations in "Current state" doesn't match the excerpts.
- After step 2, integration tests fail with a `sandbox-exec` profile parse
  error. The `(with message …)` modifier is undocumented SBPL; it is used in
  production by Anthropic's `sandbox-runtime` in exactly this position, but it
  was not tested on a Mac while writing this plan. Report the macOS version
  and the error text.
- Step 5 shows no tagged lines even with `sudo`. Do not ship tags nobody can
  see; report what `log show --last 5m --predicate 'sender == "Sandbox"'`
  prints instead.
- You find yourself wanting to add a config field or a log reader.

## Maintenance notes

- The tag is the 0-based index into `fs`. If rule normalization or reordering
  is ever introduced before profile generation, the index must still refer to
  the caller's original array.
- A host-supplied label (to tell two concurrent sandboxes apart) was deferred.
  If it is added later, append it to the same message text; keep the
  `guardrail:` prefix so existing filters still match.
- Reviewer: check that allow rules are untagged and that `(debug deny)` was
  not removed.
