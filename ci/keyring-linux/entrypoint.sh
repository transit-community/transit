#!/bin/bash
# Bootstrap script for the Linux keyring CI image.
#
# Sequence:
#   1. Create $XDG_RUNTIME_DIR with the right perms so dbus + the
#      keyring daemon can drop their sockets there.
#   2. Open a `dbus-run-session` so a fresh session bus is alive for
#      the duration of this script's PID.
#   3. Start `gnome-keyring-daemon` with `--unlock` reading a known,
#      non-empty password from stdin. The login keyring is created
#      on first access. We use a known password (not empty) because
#      Ubuntu 22.04 + gnome-keyring 40 invokes a GTK prompter when
#      the password is empty AND no keyring exists yet — and GTK
#      can't open a display in a headless container, so the prompt
#      is dismissed and the unlock fails.
#   4. Sanity-check via `secret-tool` (libsecret CLI) that the
#      default collection accepts a write/read round-trip. Fail
#      loudly here rather than letting cargo test fail downstream
#      with a confusing "no entry" error.
#   5. Exec the command-line args ("$@") in the same session — env
#      vars from `gnome-keyring-daemon --start` are exported into
#      the surrounding shell so child processes (cargo test)
#      inherit `DBUS_SESSION_BUS_ADDRESS` + `GNOME_KEYRING_CONTROL`.
#
# Why a non-empty password: gnome-keyring's `--unlock` of a
# nonexistent keyring with empty password falls through to the
# GTK prompter to confirm "really no password?". In a headless
# container that prompter dies with `cannot open display`. Picking
# any non-empty password sidesteps the prompter entirely. Password
# strength is moot — the keyring lives only inside this container.

set -euo pipefail

mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"

# gnome-keyring writes to ~/.local/share/keyrings; create the dir
# explicitly so the daemon doesn't error on first write.
mkdir -p "$HOME/.local/share/keyrings"

# Wrap the rest in a fresh dbus session bus.
exec dbus-run-session -- bash -c '
set -euo pipefail

KEYRING_PASS="ci-keyring-bootstrap"

# Start the daemon with --unlock so the login keyring is created
# (or unlocked) using the supplied password. --replace + --daemonize
# guarantees a clean background daemon. `eval` because the daemon
# prints `KEY=VALUE` exports we need in env.
eval "$(echo -n "$KEYRING_PASS" | gnome-keyring-daemon --replace --daemonize --components=secrets --unlock)"

# Sanity-check via secret-tool (libsecret CLI). A successful round
# trip proves the daemon is running, the default collection exists,
# and SSS API is reachable.
echo -n "ok" | secret-tool store --label=bootstrap-probe service ci-bootstrap account probe
got=$(secret-tool lookup service ci-bootstrap account probe)
if [ "$got" != "ok" ]; then
    echo "ERROR: secret-tool round-trip returned \"$got\", expected \"ok\"" >&2
    exit 2
fi
echo "keyring bootstrap OK: secret-tool round-trip succeeded"

# Hand off to whatever command CI passed in (cargo test ...).
exec "$@"
' bash "$@"
