#!/usr/bin/env bash
# Verify that a release binary of Transit Community Edition contains NO
# trace of any hosted infrastructure: no proprietary-edition cloud
# hostname, no sign-in/billing vendor, no update endpoint. This is the
# "no phone-home" promise made checkable — the binary can talk only to
# the devices, local endpoints and AI providers the user configures.
#
# What we look for:
#   - String literals for every host the proprietary edition used
#     (its cloud API, downloads/updater host, auth + billing vendors)
#     and for the GitHub API (so an update check cannot creep back in
#     unnoticed — the edition has NO updater by decision).
#   - Symbol names of the proprietary cloud client types.
#
# What is EXPECTED and therefore not banned: `api.anthropic.com`,
# `api.openai.com` (the direct provider clients — the whole point),
# `auth.openai.com` (Sign in with ChatGPT: the authorize page opens in
# the system browser and the token exchange runs from Rust on the
# transit_tls client — threat-model T55; the ONLY host beyond the two
# provider APIs), `127.0.0.1:11434` (Ollama), and
# `github.com/transit-community` (the About tab's repository link,
# opened in the system browser via the opener plugin; never fetched).
#
# Run locally:
#   cargo build --release --manifest-path src-tauri/Cargo.toml --bin transit_app
#   ./scripts/no-phone-home-scan.sh src-tauri/target/release/transit_app
#
# Run in CI: the Linux leg of ci.yml, and every release leg.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <release-binary-path>" >&2
    exit 64
fi

BIN="$1"
if [[ ! -f "$BIN" ]]; then
    echo "no-phone-home-scan: binary not found at $BIN" >&2
    exit 1
fi

FORBIDDEN_STRINGS=(
    "transitai.app"
    "clerk.accounts.dev"
    "clerk.com"
    "stripe.com"
    "api.github.com"
    "updates/dev/latest.json"
    "updates/prod/latest.json"
)

FORBIDDEN_SYMBOLS=(
    "TransitCloudClient"
    "TransitCloudAnthropic"
    "TransitCloudOpenAI"
    "tauri_plugin_updater"
    "tauri_plugin_deep_link"
)

fail=0

if command -v strings >/dev/null 2>&1; then
    STRS=$(strings "$BIN")
    for s in "${FORBIDDEN_STRINGS[@]}"; do
        if grep -q -F -- "$s" <<<"$STRS"; then
            echo "FAIL: forbidden string '$s' present in $BIN" >&2
            fail=1
        else
            echo "ok: string '$s' absent"
        fi
    done
else
    echo "FAIL: \`strings\` not available; the scan cannot run" >&2
    fail=1
fi

if command -v nm >/dev/null 2>&1; then
    SYMS=$(nm "$BIN" 2>/dev/null || true)
    if [[ -z "$SYMS" ]]; then
        # A stripped binary has no symbol table; the string scan above
        # still covers the hostnames, which is the half that matters
        # for the promise. Say so rather than passing vacuously.
        echo "note: nm produced no symbols (stripped binary); symbol half skipped"
    else
        for sym in "${FORBIDDEN_SYMBOLS[@]}"; do
            if grep -q -- "$sym" <<<"$SYMS"; then
                echo "FAIL: forbidden symbol '$sym' present in $BIN" >&2
                fail=1
            else
                echo "ok: symbol '$sym' absent"
            fi
        done
    fi
else
    echo "warning: \`nm\` not available; skipping symbol scan" >&2
fi

if [[ "$fail" -ne 0 ]]; then
    echo
    echo "no-phone-home-scan: the binary references hosted infrastructure." >&2
    exit 1
fi

echo
echo "no-phone-home-scan: clean. $BIN knows no host but the user's own."
