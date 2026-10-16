# Linux CI image for `transit_auth` keyring round-trip tests.
#
# Phase 2a accepted that GitHub Actions' headless Ubuntu runner
# couldn't bootstrap a usable Secret Service collection (no XDG
# runtime dir, no logged-in user, dbus-send doesn't fluently
# construct the variant dict for CreateCollection). Phase 2d closes
# the gap by running those tests inside this container, which ships
# with `gnome-keyring-daemon` + `dbus` + `libsecret` pre-installed
# and an entrypoint that bootstraps an unlocked "login" collection
# before exec'ing the test command.
#
# The image is CI-only. It is NOT consumed by any release artifact
# and is NOT distributed to users. Rebuilt inline on every CI run
# (no GHCR push) — see docs/security/secrets.md for the rebuild
# runbook + when to bump pinned versions.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# System packages:
#   - gnome-keyring + libsecret-1-dev: the Secret Service daemon and
#     the C lib our `keyring` Rust crate links against.
#   - dbus-x11: provides `dbus-launch` / `dbus-run-session`. The base
#     `dbus` package alone doesn't ship those wrappers.
#   - python3 + python3-secretstorage: used by entrypoint.sh to
#     verify the SSS API is reachable before running tests.
#   - build-essential + pkg-config: needed to compile the `keyring`
#     crate's C bindings.
#   - ca-certificates + curl: for rustup bootstrap.
#   - git: cargo sometimes needs it to fetch dependencies (less
#     relevant here since the workspace is mounted, but harmless).
RUN apt-get update && apt-get install -y --no-install-recommends \
    gnome-keyring \
    libsecret-1-dev \
    libsecret-1-0 \
    libsecret-tools \
    libdbus-1-dev \
    dbus \
    dbus-x11 \
    python3 \
    python3-secretstorage \
    build-essential \
    pkg-config \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user. gnome-keyring-daemon refuses to run as
# root, and our entrypoint needs a real $HOME to drop the keyring
# state into. Install rustup AS this user so $CARGO_HOME is owned
# correctly — cargo writes the registry index + crate cache under
# $CARGO_HOME at run time, and a root-owned $CARGO_HOME makes that
# fail with EACCES.
RUN useradd -m -u 1001 -s /bin/bash runner
USER runner
WORKDIR /home/runner

# Install the Rust toolchain via rustup. `stable` matches the
# dtolnay/rust-toolchain action used by the rest of CI.
ENV RUSTUP_HOME=/home/runner/.rustup \
    CARGO_HOME=/home/runner/.cargo \
    PATH=/home/runner/.cargo/bin:$PATH \
    RUST_VERSION=stable
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --profile minimal --no-modify-path \
    && rustup component add rustfmt clippy

# XDG_RUNTIME_DIR is where dbus-launch puts its session bus socket
# and where gnome-keyring-daemon expects its control socket. The
# directory must be 0700 owned by the user — entrypoint.sh creates
# it on each run since /tmp gets wiped between containers.
ENV XDG_RUNTIME_DIR=/tmp/runtime-1001

# Copy the entrypoint as root (USER runner doesn't have permission
# under /usr/local/bin), then switch back so the container actually
# runs as the runner user.
USER root
COPY entrypoint.sh /usr/local/bin/keyring-entrypoint
RUN chmod 0755 /usr/local/bin/keyring-entrypoint
USER runner

ENTRYPOINT ["/usr/local/bin/keyring-entrypoint"]
CMD ["bash"]
