<!-- An issue must exist and have been discussed BEFORE this PR.
     PRs without a referenced issue are closed without review. -->

Closes #

## Summary

<!-- What changed — 1-3 bullets -->

## Why

<!-- Why this change, why now; link the issue discussion that agreed the approach -->

## Tests performed

<!-- What CI covers is implied. Say what YOU ran and saw:
     - OS(es) you launched the app on
     - the feature exercised by hand, and against what (vendor / OS version / lab VM)
     - new or changed tests, and that the regression test fails without the fix -->

## Checklist

The full list, with the commands, is in CONTRIBUTING.md.

- [ ] `Closes #<issue>` above; the issue predates this PR; every commit is signed off (`git commit -s`)
- [ ] `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check` pass
- [ ] `npm run lint`, `npm run format:check`, `npm run test`, `npm run build`, `npm run react-doctor` pass
- [ ] `npm audit --audit-level=high`, `npm run license:check`, `gitleaks detect` clean
- [ ] New behaviour has a test; a bug fix has a regression test
- [ ] Security-load-bearing paths (`CLAUDE.md` §9): which invariant is affected and why it holds is written above; threat model updated if a threat changed
- [ ] Agent-touching diffs: tool count still 6, no new `transit_agent` dependency on the banned crates, `prompt_injection_corpus` passes
- [ ] New outbound host: threat-model entry + documented scan allowance in the same PR
- [ ] Vendor policy changes: corpus tests updated, `cargo mutants` leaves no survivors
- [ ] `CHANGELOG.md` `[Unreleased]` and `README.md` updated for user-visible changes
- [ ] New GitHub Action references are SHA-pinned; new deps are in `docs/security/licenses.md`
