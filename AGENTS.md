# Working in Quartermaster

## Design and evidence

Read [security boundaries](docs/security-boundaries.md) before security-sensitive
changes and [architecture](docs/architecture.md) for intended product behaviour.
Keep security rules in those documents; reference them rather than maintaining
another copy here. Resolve conflicting requirements explicitly before changing
authority or component ownership.

Follow the active local implementation plan for task scope. Phase reports record
observed evidence, not blanket product acceptance. Distinguish executed tests,
source inspection, inferred behaviour and deferred qualification. A successful
probe does not establish the corresponding integration or release behaviour.

## Plans and experiments

- Never commit agent process documents: implementation plans, phase reports,
  discoveries, review findings or qualification logs. Keep them in local scratch
  directories excluded through `.git/info/exclude`, not `.gitignore`.
- Keep one-off probes, research notes, captures and historical experimental code
  in those local scratch directories. Never make developer workflows depend on
  agent artefacts or their locations.
- Only enduring developer workflows belong in `Justfile` or permanent scripts.
  Do not add recipes or scripts for an agent's individual test rounds.

## Builds and tests

- Use `just test` for Rust and Swift tests and `just check` for Rust
  formatting, Clippy, Swift formatting and Gazelle consistency via
  `prek run --all-files`. Keep static checks independent of tests so test failures
  do not block them. Bazel is the only build/test path; Cargo manifests and lockfile remain
  dependency metadata. Run `bazelisk run //:gazelle` after changing build inputs.
  Keep hook definitions in native `prek.toml` configs, with Swift hooks under `macos/`.
  Inspect recipes before running interactive commands.
- Test substantive, reusable authorization, parsing, cryptographic and lifecycle
  behaviour with native Rust tests and Swift Testing. Do not commit tests for
  experimental probes or build orchestration.
- Keep Rust unit tests in inline `#[cfg(test)]` modules alongside their
  implementation. Reserve crate `tests/` directories for integration tests and
  fixtures; use normal modules under `src/` for shared unit-test helpers.
- Record hardware and live-provider qualification separately from automated
  fixture tests. Skipped tests and mocked authentication do not qualify OS
  behaviour.
- Keep platform-independent behaviour in platform-independent modules. Nix
  wrapper handling is not inherently macOS-specific.
- Use Python only where justified, with Python 3.12+ and `uv run python` rather
  than invoking `python` or `python3` directly.

## Signing and interactive tests

- Select the exact development certificate through root `signing.local.toml`.
  Never substitute a generic certificate name, private-key label or team match.
  Machine-specific certificate fingerprints and signing settings stay out of Git.
- Confirm user readiness before running a test that may trigger an OS fingerprint
  prompt. Use an interactive question/activity prompt when available so the wait
  is visible. Continue independent work that requires no authentication while
  waiting; ordinary builds and noninteractive checks need no readiness question.
- Build-signing authorization and runtime biometric approval are separate. Do
  not change certificate trust or signing-key ACLs unless explicitly instructed.
- Hardware tests must use scoped dummy data and keys. Clean up test-created
  services and resources; preserve retained enrolment keys and unrelated state.
  Never reboot without explicit authorization.

## Repository operations

- Preserve unrelated working-tree changes. Never reset or unstage files; the
  index belongs to the user. Never use `git add -A`; stage specific files only.
- Never push or create pull requests. The user handles remote Git writes.
- Use the existing worktree unless another is needed. Create any new worktree
  under `.worktrees/<name>` and run commands from its root.
- Never use `sed` to edit files.
- Use plain commit subjects without conventional-commit prefixes.

Use British English in prose, comments, text shown to users and commit messages.
Keep API identifiers, protocol fields and persisted names unchanged.
