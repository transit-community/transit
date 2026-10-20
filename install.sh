#!/bin/sh
# Transit Community Edition — macOS + Linux installer.
#
#   curl -fsSL https://raw.githubusercontent.com/transit-community/transit/main/install.sh | sh
#
# Linux: installs with the system's own package manager, so the result is an
# ordinary tracked package (`dpkg -l`, `rpm -q`, `pacman -Q` all see it and
# the normal uninstall works); where no supported package manager exists it
# falls back to the AppImage under ~/.local.
# macOS: mounts the .dmg, copies the app into /Applications (or
# ~/Applications when that is not writable) and clears the quarantine flag,
# because the builds are not Apple-signed.
# Windows: see install.ps1.
#
# Re-running this script UPDATES an existing install.
#
# Two deliberate properties, because this is piped into a shell:
#   * it prints exactly what it will run and waits for confirmation (-y to
#     skip); with no terminal available it refuses rather than assuming yes.
#   * it never runs itself as root. Only the package-manager step is sudo'd,
#     so `curl … | sudo sh` is never the documented form.
#
# The published sha256 is checked, which catches a truncated or mismatched
# download. It is NOT independent provenance: the checksum and the package
# come from the same GitHub release over the same TLS.

set -eu

REPO="${TRANSIT_REPO:-transit-community/transit}"
DL="https://github.com/${REPO}/releases/download"
ASSUME_YES=0
PIN_VERSION=""
DRY_RUN=0

# ---------------------------------------------------------------- helpers

say()  { printf '%s\n' "$*"; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<USAGE
Transit Community Edition installer

  -y, --yes            do not ask for confirmation
      --version X.Y.Z  install a specific version (default: newest release)
      --dry-run        download and verify, but do not install
  -h, --help           show this

Environment:
  TRANSIT_FORCE_PM   force apt|dnf|pacman|appimage instead of detecting
  TRANSIT_REPO       GitHub owner/repo to install from (testing)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)    ASSUME_YES=1 ;;
    --dry-run)   DRY_RUN=1 ;;
    --version)   shift; [ $# -gt 0 ] || die "--version needs a value"; PIN_VERSION="$1" ;;
    --version=*) PIN_VERSION="${1#*=}" ;;
    -h|--help)   usage; exit 0 ;;
    *)           die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

[ "$(id -u)" -ne 0 ] || die "do not run this as root. It will ask for sudo only where a package manager needs it."
have curl || die "curl is required."
if have sha256sum; then SHASUM="sha256sum"
elif have shasum; then SHASUM="shasum -a 256"
else die "sha256sum or shasum is required."; fi

# ------------------------------------------------------- what system is this

# Matched by package manager rather than by /etc/os-release ID, because the
# derivatives outnumber the bases (Omarchy and EndeavourOS are pacman, Mint
# and Pop!_OS are apt, Nobara is dnf). Anything else gets the AppImage.
if   [ -n "${TRANSIT_FORCE_PM:-}" ]; then PM="$TRANSIT_FORCE_PM"
elif [ "$(uname -s)" = Darwin ]; then PM=macos
elif have pacman; then PM=pacman
elif have apt;    then PM=apt
elif have dnf;    then PM=dnf
else PM=appimage
fi
case "$PM" in apt|dnf|pacman|appimage|macos) ;; *) die "TRANSIT_FORCE_PM must be apt, dnf, pacman, appimage or macos." ;; esac

if [ "$PM" = macos ]; then
  PRETTY="macOS $(sw_vers -productVersion 2>/dev/null || echo '?')"
else
  PRETTY=$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-Linux}") || PRETTY=Linux
fi

# ------------------------------------------------------------ which machine

case "$(uname -m)" in
  x86_64|amd64)  ARCH=x86_64; DEB_ARCH=amd64; RPM_ARCH=x86_64;  APP_ARCH=amd64;   PKG_ARCH=x86_64;  MAC_ARCH=x64 ;;
  aarch64|arm64) ARCH=arm64;  DEB_ARCH=arm64; RPM_ARCH=aarch64; APP_ARCH=aarch64; PKG_ARCH=aarch64; MAC_ARCH=aarch64 ;;
  *) die "unsupported architecture: $(uname -m).
Transit Community Edition publishes x86_64 and aarch64 builds only." ;;
esac

# ------------------------------------------------------------- what to fetch

# Newest version from the releases/latest redirect: its target URL ends in
# the tag, needs no JSON parser and no token, and is not subject to the
# API rate limit that shared CI runner addresses routinely exhaust.
resolve_latest() {
  _u=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest") \
    || die "could not reach GitHub. Check the network and try again."
  _v=$(printf '%s' "$_u" | sed -n 's|.*/releases/tag/v\([0-9][0-9.]*\)$|\1|p')
  [ -n "$_v" ] || die "could not determine the newest release from: $_u"
  printf '%s' "$_v"
}

# MATCH selects this machine's package out of SHA256SUMS.txt; it pins BOTH
# the format and the arch so an aarch64 machine never gets the x86_64 file.
case "$PM" in
  apt)      EXT=deb;      MATCH="_${DEB_ARCH}\.deb\$" ;;
  dnf)      EXT=rpm;      MATCH="\.${RPM_ARCH}\.rpm\$" ;;
  pacman)   EXT=deb;      MATCH="_${DEB_ARCH}\.deb\$" ;;   # repackaged into a pacman package
  appimage) EXT=AppImage; MATCH="_${APP_ARCH}\.AppImage\$" ;;
  macos)    EXT=dmg;      MATCH="_${MAC_ARCH}\.dmg\$" ;;
esac

VERSION="${PIN_VERSION:-$(resolve_latest)}"

SUMS=$(curl -fsSL "${DL}/v${VERSION}/SHA256SUMS.txt") \
  || die "no published release v${VERSION} (or it has no SHA256SUMS.txt)."
MATCHES=$(printf '%s\n' "$SUMS" | grep -iE "$MATCH" || true)
COUNT=$(printf '%s' "$MATCHES" | grep -c . || true)
[ "$COUNT" -ne 0 ] || die "release v${VERSION} publishes no ${ARCH} .${EXT}."
[ "$COUNT" -eq 1 ] || die "release v${VERSION} lists ${COUNT} ${ARCH} .${EXT} files — refusing to guess. Please report this."
LINE="$MATCHES"
SHA=$(printf '%s' "$LINE" | awk '{print $1}' | tr 'A-F' 'a-f')
# The filename may contain spaces ("Transit Community Edition_…"): take
# everything after the checksum + two-space separator.
FILE=$(printf '%s' "$LINE" | sed 's/^[0-9A-Fa-f]*  *//')
# GitHub serves release assets with spaces replaced by dots.
ASSET=$(printf '%s' "$FILE" | tr ' ' '.')
URL="${DL}/v${VERSION}/${ASSET}"

# ------------------------------------------------------------ already here?

PKG=transit-community-edition
MAC_APP="Transit Community Edition.app"
installed_version() {
  case "$PM" in
    pacman)   pacman -Q "${PKG}-bin" 2>/dev/null | awk '{print $2}' | cut -d- -f1 ;;
    apt)      dpkg-query -W -f='${Version}' "$PKG" 2>/dev/null ;;
    dnf)      rpm -q --qf '%{VERSION}' "$PKG" 2>/dev/null ;;
    appimage) cat "${HOME}/.local/share/transit-community/version" 2>/dev/null ;;
    macos)    for d in "/Applications" "${HOME}/Applications"; do
                if [ -d "${d}/${MAC_APP}" ]; then defaults read "${d}/${MAC_APP}/Contents/Info" CFBundleShortVersionString 2>/dev/null; break; fi
              done ;;
  esac
}
CURRENT=$(installed_version 2>/dev/null || true)

APT_EXTRA=""
if [ -z "$CURRENT" ]; then
  ACTION="install"
elif [ "$CURRENT" = "$VERSION" ]; then
  ACTION="reinstall"
elif [ "$(printf '%s\n%s\n' "$CURRENT" "$VERSION" | sort -V | tail -n 1)" = "$CURRENT" ]; then
  [ -n "$PIN_VERSION" ] || die "Transit Community Edition ${CURRENT} is already installed, which is newer than the published ${VERSION}.
Nothing to do. To go back deliberately, re-run with --version ${VERSION}."
  ACTION="downgrade"
  APT_EXTRA="--allow-downgrades"
else
  ACTION="update"
fi

# ------------------------------------------------------------------- plan

WORK=$(mktemp -d "${TMPDIR:-/tmp}/transit-install.XXXXXX")
MNT="${WORK}/mnt"
MOUNTED=0
cleanup() {
  # Detach a still-mounted image BEFORE removing the work dir, or rm walks
  # into the read-only volume and the image stays attached.
  if [ "$MOUNTED" -eq 1 ]; then hdiutil detach "$MNT" -force >/dev/null 2>&1 || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

APP_DIR="${HOME}/.local/share/transit-community"
APP_BIN="${HOME}/.local/bin/transit-community"
case "$PM" in
  apt)      METHOD="download the .deb and install it with apt";  STEPS="  sudo apt install -y ${APT_EXTRA:+$APT_EXTRA }\"${WORK}/${ASSET}\"" ;;
  dnf)      METHOD="download the .rpm and install it with dnf";  STEPS="  sudo dnf install -y \"${WORK}/${ASSET}\"" ;;
  pacman)   METHOD="build a pacman package from the .deb, then install it"; STEPS="  makepkg --syncdeps --install   (in ${WORK})" ;;
  appimage) METHOD="place the AppImage under ~/.local and add a desktop entry (no root needed)"
            STEPS="  install -m 755 AppImage ${APP_BIN}
  write ${HOME}/.local/share/applications/transit-community.desktop" ;;
  macos)    if [ -w /Applications ]; then MAC_DEST=/Applications; else MAC_DEST="${HOME}/Applications"; fi
            METHOD="mount the .dmg, copy the app to ${MAC_DEST}, clear the quarantine flag (unsigned build)"
            STEPS="  hdiutil attach (read-only) … cp -R \"${MAC_APP}\" ${MAC_DEST}/ … xattr -dr com.apple.quarantine" ;;
esac

echo
bold "Transit Community Edition ${VERSION} — $([ "$PM" = macos ] && echo macOS || echo Linux) installer"
echo
printf '  %-10s %s\n' "Detected" "$PRETTY ($ARCH)"
printf '  %-10s %s\n' "Action"   "$ACTION${CURRENT:+ (currently ${CURRENT})}"
printf '  %-10s %s\n' "Method"   "$METHOD"
printf '  %-10s %s\n' "Source"   "$URL"
printf '  %-10s %s\n' "sha256"   "$SHA"
echo
say "Will run:"
say "$STEPS"
echo

if [ "$PM" = dnf ] && grep -qiE 'platform:el|Red Hat|AlmaLinux|Rocky' /etc/os-release 2>/dev/null; then
  say "Note: on Enterprise Linux 10 this needs EPEL for webkit2gtk4.1:  sudo dnf install epel-release"
  echo
fi
if [ "$PM" = pacman ]; then
  say "Note: the PCaps surface needs tcpdump, which some Arch-based systems"
  say "      (Omarchy included) do not ship:  sudo pacman -S tcpdump"
  echo
fi
if [ "$PM" = appimage ]; then
  say "Note: AppImages need FUSE 2 (libfuse2 / fuse2). Without it, run the"
  say "      file with --appimage-extract-and-run."
  echo
fi
if [ "$PM" = macos ]; then
  say "Note: the build is not Apple-signed or notarized. Clearing the quarantine"
  say "      flag is what lets it open without the 'unidentified developer' block;"
  say "      the checksum above is verified first."
  echo
fi

if [ "$ASSUME_YES" -eq 0 ]; then
  if ! { printf 'Continue? [y/N] ' >/dev/tty; } 2>/dev/null; then
    die "no terminal available to confirm. Re-run with -y to proceed unattended."
  fi
  reply=""
  read -r reply </dev/tty || reply=""
  case "$reply" in
    y|Y|yes|YES) ;;
    *) say "Cancelled."; exit 1 ;;
  esac
  echo
fi

# ---------------------------------------------------------------- install

if [ "$PM" = pacman ]; then
  [ "$DRY_RUN" -eq 1 ] || have makepkg || die "makepkg not found (install base-devel: sudo pacman -S --needed base-devel)."
  cat > "${WORK}/PKGBUILD" <<PKGBUILD
# Generated by the Transit Community Edition installer. Repackages the .deb.
pkgname=${PKG}-bin
_pkgname=${PKG}
pkgver=${VERSION}
pkgrel=1
pkgdesc="SSH client for network engineers with an embedded read-only AI agent (Community Edition)"
arch=('${PKG_ARCH}')
url="https://github.com/${REPO}"
license=('Apache-2.0')
depends=('webkit2gtk-4.1' 'gtk3' 'dbus')
optdepends=(
  'gnome-keyring: Secret Service provider for storing device credentials'
  'libsecret: Secret Service client tooling'
  '1password-cli: alternative credential backend (op:// references)'
  'tcpdump: required for the PCaps live-capture surface'
)
provides=("\${_pkgname}=\${pkgver}")
conflicts=("\${_pkgname}")
options=('!strip' '!debug' '!lto')
source=("\${_pkgname}-\${pkgver}.deb::${URL}")
sha256sums=('${SHA}')
noextract=("\${_pkgname}-\${pkgver}.deb")

package() {
  bsdtar -xf "\${srcdir}/\${_pkgname}-\${pkgver}.deb" -C "\${srcdir}"
  bsdtar -xf "\${srcdir}"/data.tar.* -C "\${pkgdir}"
}
PKGBUILD
  if [ "$DRY_RUN" -eq 1 ]; then
    say "--dry-run: generated PKGBUILD, stopping before makepkg."
    say "---"; cat "${WORK}/PKGBUILD"; say "---"
    exit 0
  fi
  ( cd "$WORK" && makepkg --syncdeps --install --noconfirm )
else
  say "Downloading ${ASSET} …"
  curl -fSL --progress-bar "$URL" -o "${WORK}/${ASSET}" || die "download failed."
  GOT=$($SHASUM "${WORK}/${ASSET}" | awk '{print $1}' | tr 'A-F' 'a-f')
  [ "$GOT" = "$SHA" ] \
    || die "checksum mismatch — the download does not match the published sha256. Not installing."
  say "Checksum OK."
  if [ "$DRY_RUN" -eq 1 ]; then
    say "--dry-run: verified ${ASSET}, stopping before install."
    exit 0
  fi
  case "$PM" in
    apt) sudo apt install -y $APT_EXTRA "${WORK}/${ASSET}" ;;
    dnf) sudo dnf install -y "${WORK}/${ASSET}" ;;
    appimage)
      mkdir -p "${HOME}/.local/bin" "${HOME}/.local/share/applications" "$APP_DIR"
      install -m 755 "${WORK}/${ASSET}" "$APP_BIN"
      # Pull the icon out of the AppImage when FUSE is absent-tolerant extraction works.
      ( cd "$WORK" && "$APP_BIN" --appimage-extract transit_app.png >/dev/null 2>&1 \
          && install -m 644 squashfs-root/transit_app.png "${APP_DIR}/icon.png" ) || true
      printf '%s' "$VERSION" > "${APP_DIR}/version"
      cat > "${HOME}/.local/share/applications/transit-community.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Transit Community Edition
Comment=SSH client for network engineers with an embedded read-only AI agent
Exec=${APP_BIN} %U
Icon=${APP_DIR}/icon.png
Terminal=false
Categories=Network;Development;
DESKTOP
      have update-desktop-database && update-desktop-database "${HOME}/.local/share/applications" >/dev/null 2>&1 || true
      ;;
    macos)
      mkdir -p "$MNT"
      hdiutil attach -nobrowse -readonly -mountpoint "$MNT" "${WORK}/${ASSET}" >/dev/null 2>&1 \
        || die "could not mount the disk image."
      MOUNTED=1
      [ -d "${MNT}/${MAC_APP}" ] || die "the disk image holds no ${MAC_APP}."
      mkdir -p "$MAC_DEST"
      rm -rf "${MAC_DEST}/${MAC_APP}"
      cp -R "${MNT}/${MAC_APP}" "${MAC_DEST}/" || die "copy failed."
      hdiutil detach "$MNT" >/dev/null 2>&1 || true
      MOUNTED=0
      xattr -dr com.apple.quarantine "${MAC_DEST}/${MAC_APP}" 2>/dev/null || true
      ;;
  esac
fi

echo
bold "Transit Community Edition ${VERSION} installed."
case "$PM" in
  appimage) say "Launch it from your application menu, or run: ${APP_BIN}" ;;
  macos)    say "Launch it from ${MAC_DEST}, or run: open \"${MAC_DEST}/${MAC_APP}\"" ;;
  *)        say "Launch it from your application menu, or run: transit_app" ;;
esac
say "Update later by re-running this installer."
