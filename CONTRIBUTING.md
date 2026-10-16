# Contributing to Transit Community Edition

Thanks for considering a contribution. This is a desktop SSH client with
an embedded read-only AI agent, and most of its value is in a handful of
security invariants that are easy to break by accident. The process
below exists to protect those, not to slow you down.

## The short version

1. **Open an issue first.** Every pull request must reference an issue
   that was opened and discussed before the PR. Drive-by PRs with no
   issue are closed without review.
2. **Agree the approach in the issue** before writing code for anything
   beyond a typo or a one-line fix. A maintainer will say whether the
   change fits and which invariants it touches.
3. **Open the PR** with `Closes #<issue>` in the description, the filled
   PR template, and the tests you actually ran.
4. **Pass the review checklist** below. CI enforces the mechanical parts;
   a maintainer checks the rest.

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE) (its §5 says exactly this). Every commit
must carry a `Signed-off-by:` line (`git commit -s`), which is your
[Developer Certificate of Origin](https://developercertificate.org/)
attestation that you have the right to submit it.

## Before you open an issue

- Search existing issues, including closed ones.
- **Security bugs do not go in issues.** Use GitHub private vulnerability
  reporting as described in [SECURITY.md](SECURITY.md).
- Read [`CLAUDE.md`](CLAUDE.md) §3 (the Three Inviolable Rules) and §4
  (the Fourth Rule). If your idea needs one of them to bend, say so in
  the issue; that is a design conversation, not a PR.

Use the issue templates: **Bug report** (with the exact version, OS,
device vendor, and a redacted reproduction) or **Feature request** (the
problem first, your proposed change second).

## What we will not merge

Some requests come up often enough to answer here:

- **A seventh agent tool, or any widening of what the agent can reach.**
  The tool surface is exactly six by design (`CLAUDE.md` §3 Rule 2, §8).
  Proposals are welcome as issues; they need a threat-model entry and
  explicit maintainer sign-off before any code.
- **Anything that lets a `propose_command` skip the policy gate or the
  approval modal**, including "trusted" commands, "approve once" caches,
  or auto-approve for unrestricted vendors (Rule 3).
- **Any outbound connection the user did not configure**: telemetry,
  update checks, crash reporting, analytics, a hosted service of any
  kind. `scripts/no-phone-home-scan.sh` fails the release build on these
  (the Fourth Rule).
- **A command or IPC path that returns a credential to the webview**
  (Rule 1). `enroll_secret` and the write-only key/token setters are the
  whole list.
- **Dependencies outside the license allowlist** in `deny.toml` and
  `package.json`'s license check, or GitHub Actions referenced by a
  floating tag instead of a SHA.
- **An Anthropic consumer-plan sign-in.** Anthropic's terms prohibit it;
  the issue is closed (see README → *Sign in with ChatGPT*).

## Pull request checklist

A PR is reviewed only when every item is checked. CI runs the first two
groups on Ubuntu, macOS and Windows; the rest are yours and the
reviewer's.

**References**
- [ ] `Closes #<issue>` is in the description, and the issue was open
      before the PR.
- [ ] Every commit is signed off (`git commit -s`).

**Gates (all must pass locally before you push)**
- [ ] `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo test --workspace`, `cargo deny check` (run from `src-tauri/`).
- [ ] `npm run lint`, `npm run format:check`, `npm run test`,
      `npm run build`, `npm run react-doctor`.
- [ ] `npm audit --audit-level=high`, `npm run license:check`,
      `gitleaks detect --source . --no-banner`.

**Tests performed**
- [ ] New behaviour has a test; a bug fix has a regression test that
      fails without the fix.
- [ ] The PR says what was verified by hand and on which OS: the app
      launched, the feature exercised, the vendor or device used (real
      hardware or a lab VM; say which).
- [ ] Vendor policy changes: the allowed and blocked corpus tests under
      `src-tauri/crates/transit_policy/tests/` are updated and
      `cargo mutants --package transit_policy --in-place --test-package transit_policy`
      leaves no surviving mutants.

**Security-sensitive paths** (the list is `CLAUDE.md` §9)
- [ ] If the diff touches any §9 file, the PR says which invariant it
      affects and why it still holds, and
      `docs/security/threat-model.md` is updated when a threat changes.
- [ ] Agent-touching diffs (`transit_agent`, `agent_dispatch`,
      `chat.rs`): the tool count is still 6
      (`const_assert_eq!(TOOL_CALL_VARIANT_COUNT, 6)`), `transit_agent`
      gained no dependency on `transit_auth`, `keyring`, `transit_api`,
      `transit_files`, `transit_localpty` or `transit_pcap`, and
      `cargo test -p transit_agent --test prompt_injection_corpus` passes.
- [ ] Anything that adds an outbound host: a threat-model entry and a
      documented allowance in `scripts/no-phone-home-scan.sh` in the
      same PR, and the scan passes on a release build.
- [ ] No new `tauri::command` returns a secret-shaped type; new
      capabilities in `src-tauri/capabilities/` are justified in the PR.

**Documentation**
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]`.
- [ ] `README.md` is updated for any user-visible change.
- [ ] New direct dependencies are listed in `docs/security/licenses.md`.

## Development setup

See README → *Build from source*. The pinned Rust toolchain in
`rust-toolchain.toml` and Node 22+ are required; `npm install` sets up
the pre-commit hook, which runs the formatters, clippy, eslint and
gitleaks on every commit. Do not bypass it.

Useful references while you work:

- [`CLAUDE.md`](CLAUDE.md): the crate map and the runbooks (adding a
  vendor policy, a secret backend, a terminal feature).
- [`docs/security/threat-model.md`](docs/security/threat-model.md): every
  attack surface and its mitigation, numbered; cite the number in your PR.
- [`policies/`](policies/): the bundled vendor policies and their
  READMEs, the easiest place to make a first contribution.

## Review and merge

Maintainers review in the order PRs become checklist-complete. Expect
requests for a test or a threat-model line rather than style nits; the
formatters own style. Squash merges are the default so one issue maps
to one commit on `main`. A release is cut by tagging `vX.Y.Z` (see
`CLAUDE.md` §18).

## Code of conduct

Be direct and be kind. Review the code, not the person. Maintainers
remove anyone who makes this unpleasant for others.
