#!/bin/sh
# SPDX-License-Identifier: MIT
# a22x-phrog-package.sh: Phrog from the project's packages, built once for this distribution and its
# Phosh on GitHub's arm64 machines (packaging/phrog), instead of 30-40 minutes on the phone
# (2026-11-22, the owner).
#
# Reads the release's index (one line per package: target, Phosh version, file, SHA-256), takes the
# package made for this distribution and the Phosh installed now, checks its SHA-256 and installs it
# with the distribution's package manager. The files are those of a22x-build-phrog.sh, with the same
# built-for marker, so the greeter, the build cache and the rebuild after an update treat both alike.
#
# Exit status: 0 installed (or already the one for this Phosh), 1 no package for this system (build
# it instead), 2 a package was found but could not be installed.
set -u
RELEASE=${A22X_PHROG_RELEASE:-https://github.com/Dodaskot/mainline-recovery/releases/download/phrog-0.53.0-a22x1}
PHROG_VERSION=0.53.0
PHROG_A22X=2  # the A22x revision the release carries (2: the keypad's back button)
LIBDIR=/usr/local/lib/a22x-phrog
CACHE=/var/cache/a22x-build/packages
log() { echo "a22x-phrog-package: $*"; }

[ "$(id -u)" = 0 ] || { log "run this as root"; exit 2; }
[ "$(uname -m)" = aarch64 ] || exit 1
. /etc/os-release
# Arch Linux ARM and Manjaro are rolling: no VERSION_ID (live 2026-11-22: "unbound variable" under set -u).
VERSION_ID=${VERSION_ID:-}
major=${VERSION_ID%%.*}
case "${ID:-}" in
debian|mobian)
    # Mobian is Debian with its own repository (and its own Phosh)
    if [ "$ID" = mobian ] || grep -rqs repo.mobian.org /etc/apt/sources.list /etc/apt/sources.list.d; then
        target=mobian-${major:-13}
    else
        target=debian-${major:-13}
    fi
    phosh=$(dpkg-query -W -f='${Version}' phosh 2>/dev/null) ;;
ubuntu) target=ubuntu-$VERSION_ID; phosh=$(dpkg-query -W -f='${Version}' phosh 2>/dev/null) ;;
fedora) target=fedora-$VERSION_ID; phosh=$(rpm -q --qf '%{VERSION}' phosh 2>/dev/null) ;;
arch|archarm) target=archlinuxarm; phosh=$(pacman -Q phosh 2>/dev/null | awk '{print $2}') ;;
manjaro|manjaro-arm) target=manjaro-arm; phosh=$(pacman -Q phosh 2>/dev/null | awk '{print $2}') ;;
*) log "no packages for ${ID:-this system}"; exit 1 ;;
esac
phosh=$(echo "$phosh" | sed 's/^[0-9]*://; s/[-~+].*$//')
case "$phosh" in *[!0-9.]*|'') log "Phosh is not installed"; exit 1 ;; esac
want="phrog $PHROG_VERSION-a22x$PHROG_A22X phosh $phosh"
if [ -x /usr/local/bin/phrog ] && [ "$(cat "$LIBDIR/built-for" 2>/dev/null)" = "$want" ]; then
    log "already there: $want"
    exit 0
fi
command -v curl >/dev/null || { log "curl is missing"; exit 1; }
index=$(curl -fsSL --retry 4 --retry-delay 3 --max-time 120 "$RELEASE/phrog-packages.txt") || { log "the index cannot be read"; exit 1; }
line=$(printf '%s\n' "$index" | awk -v t="$target" -v p="$phosh" '$1 == t && $2 == p { print; exit }')
[ -n "$line" ] || { log "no package for $target with Phosh $phosh"; exit 1; }
file=$(printf '%s\n' "$line" | awk '{print $3}')
sum=$(printf '%s\n' "$line" | awk '{print $4}')
case "$file" in */*|''|.*) log "bad index line"; exit 2 ;; esac
case "$sum" in *[!0-9a-f]*|'') log "bad index line"; exit 2 ;; esac
[ ${#sum} -eq 64 ] || { log "bad index line"; exit 2; }
mkdir -p "$CACHE"
path=$CACHE/$file
if ! echo "$sum  $path" | sha256sum -c - >/dev/null 2>&1; then
    curl -fsSL --retry 4 --retry-delay 3 --max-time 900 -o "$path.part" "$RELEASE/$file" || { rm -f "$path.part"; log "download failed"; exit 2; }
    mv -f "$path.part" "$path"
fi
echo "$sum  $path" | sha256sum -c - >/dev/null 2>&1 || { rm -f "$path"; log "$file is not the published one"; exit 2; }
log "installing $file for $target, Phosh $phosh"
case "$target" in
debian-*|mobian-*|ubuntu-*) DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$path" ;;
fedora-*) dnf install -y "$path" ;;
# The files of a Phrog built here earlier belong to no package; pacman refuses those unless told
# (live 2026-11-22). The package installs only under /usr/local, its own files.
*) pacman -U --noconfirm --needed --overwrite '/usr/local/*' "$path" ;;
esac || { log "the package manager refused $file"; exit 2; }
[ -x /usr/local/bin/phrog ] && [ "$(cat "$LIBDIR/built-for" 2>/dev/null)" = "$want" ] || { log "installed, but not for $want"; exit 2; }
log "done: $want"
