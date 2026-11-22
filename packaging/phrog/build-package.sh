#!/bin/sh
# SPDX-License-Identifier: MIT
# build-package.sh OUTDIR TARGET: Phrog for one distribution, as a package of that distribution.
#
# Run as root inside an aarch64 system of the target (a container or a root filesystem in CI,
# .github/workflows/phrog-packages.yml). It installs that distribution's Phosh and the build tools,
# builds libphosh from the signed source of exactly that Phosh version and Phrog 0.53.0 against it
# (the steps of platform/build/a22x-build-phrog.sh, which the phone ran for 30-40 minutes), and
# packs both as "a22x-phrog" for the distribution's package manager: .deb (Debian, Ubuntu, Mobian),
# .rpm (Fedora) or .pkg.tar.zst (Arch Linux ARM, Manjaro ARM).
#
# The files are where the phone's own build puts them (/usr/local/bin/phrog,
# /usr/local/lib/a22x-phrog, ...), so the A22x greeter treats a package and a build alike, and
# /usr/local/lib/a22x-phrog/built-for names the Phosh it was built for: when the distribution
# updates Phosh, the system fetches or builds a matching one again. The package depends on Phosh
# without a version, so that it never holds back an update of the distribution.
set -eu
OUT=$1
TARGET=$2
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
PHROG_VERSION=0.53.0
PHROG_SHA256=42d3b9153d60cbfc130d19e3531776887755cba9ca5734c4c4e21ec6944d1197
PHROG_URL=https://github.com/samcday/phrog/archive/refs/tags/$PHROG_VERSION.tar.gz
RUST_TOOLCHAIN=${RUST_TOOLCHAIN:-stable}
LIBDIR=/usr/local/lib/a22x-phrog
log() { echo "build-package[$TARGET]: $*"; }

[ "$(id -u)" = 0 ] || { log "run this as root"; exit 2; }
[ "$(uname -m)" = aarch64 ] || { log "run this on aarch64"; exit 2; }
. /etc/os-release
case "$ID" in
debian|ubuntu) family=deb ;;
fedora) family=rpm ;;
arch|archarm|manjaro|manjaro-arm) family=pacman ;;
*) log "no packaging for $ID"; exit 1 ;;
esac
mkdir -p "$OUT"
work=$(mktemp -d /var/tmp/a22x-phrog-package.XXXXXX)
stage=$work/stage

# --- Phosh and the build tools of this distribution --------------------------------------------
case $family in
deb)
    export DEBIAN_FRONTEND=noninteractive
    if [ "$TARGET" = mobian-13 ]; then
        # Mobian's own repository carries the Phosh a Mobian phone runs.
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl gnupg >/dev/null
        curl -fsSL https://repo.mobian.org/mobian.gpg -o /usr/share/keyrings/mobian.gpg
        echo "deb [signed-by=/usr/share/keyrings/mobian.gpg] http://repo.mobian.org/ trixie main non-free-firmware" \
            > /etc/apt/sources.list.d/mobian.list
        printf 'Package: *\nPin: origin repo.mobian.org\nPin-Priority: 700\n' > /etc/apt/preferences.d/mobian
    fi
    # deb-src for build-dep
    for f in /etc/apt/sources.list.d/*.sources; do
        [ -f "$f" ] && sed -i 's/^Types: deb$/Types: deb deb-src/' "$f"
    done
    [ -f /etc/apt/sources.list ] && sed -n 's/^deb /deb-src /p' /etc/apt/sources.list >> /etc/apt/sources.list.d/src.list || true
    [ -f /etc/apt/sources.list.d/mobian.list ] && sed 's/^deb /deb-src /' /etc/apt/sources.list.d/mobian.list \
        > /etc/apt/sources.list.d/mobian-src.list
    apt-get update -qq
    apt-get install -y -qq phosh build-essential meson ninja-build pkg-config curl ca-certificates gpgv xz-utils \
        dpkg-dev file >/dev/null
    apt-get build-dep -y -qq phosh >/dev/null
    phosh_full=$(dpkg-query -W -f='${Version}' phosh)
    ;;
rpm)
    dnf -y -q install phosh dnf-plugins-core rpm-build meson ninja-build gcc curl gnupg2 xz file >/dev/null
    dnf -y -q builddep phosh >/dev/null
    phosh_full=$(rpm -q --qf '%{VERSION}-%{RELEASE}' phosh)
    ;;
pacman)
    # Manjaro ARM stable has Phosh 0.37, without libphosh; its Phosh images (manjaro-pinephone) follow
    # the unstable branch, whose Phosh has it (CI 2026-11-22). The index still pins the exact version.
    if [ "$TARGET" = manjaro-arm ] && [ -f /etc/pacman.d/mirrorlist ]; then
        sed -i 's#/stable/#/unstable/#g; s#arm-stable#arm-unstable#g' /etc/pacman.d/mirrorlist
        [ -f /etc/pacman-mirrors.conf ] && sed -i 's/^Branch *= *.*/Branch = arm-unstable/' /etc/pacman-mirrors.conf
    fi
    # The keyring first: Manjaro ARM's root filesystem has none set up ("keyring is not writable").
    pacman-key --init >/dev/null 2>&1 || true
    case "$ID" in arch|archarm) pacman-key --populate archlinuxarm >/dev/null 2>&1 || true ;;
    *) pacman-key --populate archlinuxarm manjaro manjaro-arm >/dev/null 2>&1 || true ;; esac
    # Manjaro ARM's minimal root filesystem lacks even sed (2026-11-22, CI).
    command -v sed >/dev/null 2>&1 && command -v awk >/dev/null 2>&1 ||
        pacman -Sy --noconfirm --needed --disable-sandbox sed gawk grep >/dev/null 2>&1 ||
        pacman -Sy --noconfirm --needed sed gawk grep >/dev/null
    # In a container: no Landlock sandbox for downloads, no free-space check of the overlay.
    grep -q '^DisableSandbox' /etc/pacman.conf || sed -i 's/^\[options\]$/[options]\nDisableSandbox/' /etc/pacman.conf
    sed -i 's/^CheckSpace/#CheckSpace/' /etc/pacman.conf
    pacman-key --init >/dev/null 2>&1 || true
    case "$ID" in arch|archarm) pacman-key --populate archlinuxarm >/dev/null 2>&1 || true ;;
    *) pacman-key --populate archlinuxarm manjaro manjaro-arm >/dev/null 2>&1 || true ;; esac
    pacman -Sy >/dev/null
    # glib2-devel is split off on Arch Linux ARM; Manjaro's glib2 still carries the headers (CI 2026-11-22).
    devel=; pacman -Si glib2-devel >/dev/null 2>&1 && devel=glib2-devel
    # shellcheck disable=SC2086
    pacman -Syu --noconfirm --needed phosh base-devel meson ninja rust $devel wayland-protocols curl xz file >/dev/null
    phosh_full=$(pacman -Q phosh | awk '{print $2}')
    ;;
esac
# The upstream version: no epoch, no packaging revision, no Debian repack suffix.
phosh=$(echo "$phosh_full" | sed 's/^[0-9]*://; s/[-~+].*$//')
case "$phosh" in *[!0-9.]*|'') log "Phosh is not installed ($phosh_full)"; exit 1 ;; esac
log "Phosh $phosh ($phosh_full)"

# --- Rust: a current toolchain, the same for every distribution --------------------------------
if ! command -v cargo >/dev/null 2>&1 || [ "$family" != pacman ]; then
    export RUSTUP_HOME=$work/rustup CARGO_HOME=$work/cargo
    curl -fsSL --retry 5 https://sh.rustup.rs -o "$work/rustup.sh"
    sh "$work/rustup.sh" -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN" --no-modify-path >/dev/null
    PATH=$CARGO_HOME/bin:$PATH
fi
log "$(rustc --version)"

# --- libphosh from Phosh's signed source, Phrog by its SHA-256 (as a22x-build-phrog.sh) --------
url=https://sources.phosh.mobi/releases/phosh/phosh-$phosh.tar.xz
curl -fsSL --retry 5 --retry-delay 3 -o "$work/phosh.tar.xz" "$url"
curl -fsSL --retry 5 --retry-delay 3 -o "$work/phosh.tar.xz.asc" "$url.asc"
gpgv --keyring "$REPO/platform/build/keys/phosh.gpg" "$work/phosh.tar.xz.asc" "$work/phosh.tar.xz"
curl -fsSL --retry 5 --retry-delay 3 -o "$work/phrog.tar.gz" "$PHROG_URL"
echo "$PHROG_SHA256  $work/phrog.tar.gz" | sha256sum -c - >/dev/null || { log "Phrog's archive is not the expected one"; exit 1; }
tar -xJf "$work/phosh.tar.xz" -C "$work"
tar -xzf "$work/phrog.tar.gz" -C "$work"
psrc=$work/phosh-$phosh
rsrc=$work/phrog-$PHROG_VERSION
sed -i 's/^\([[:space:]]*\)char \*last_component;/\1const char *last_component;/' "$psrc/src/util.c"
sed -i 's/^if enable_introspection or bindings_lib$/if enable_introspection/' "$psrc/src/meson.build"
sed -i 's/^    sessions\.values()\.cloned()\.collect()$/    let mut list: Vec<SessionObject> = sessions.values().cloned().collect();\n    list.sort_by_key(|s| s.name());\n    list/' "$rsrc/src/sessions.rs"
grep -q 'list.sort_by_key' "$rsrc/src/sessions.rs" || log "sessions stay in Phrog's own order (no sort patch for this version)"
api=$(sed -n "s/^libphosh_api_version = '\([0-9.]*\)'.*/\1/p" "$psrc/meson.build")
[ -n "$api" ] || { log "no libphosh API version in Phosh $phosh"; exit 1; }
# Only the options this Phosh version has (0.46 has no searchd, vapi or status-icon-plugins: 2026-11-22, CI).
optfile=$psrc/meson.options; [ -f "$optfile" ] || optfile=$psrc/meson_options.txt
opts=
for o in bindings-lib=true introspection=false vapi=false tests=false phoc_tests=disabled gtk_doc=false man=false \
         tools=false searchd=false abi-check=false callui-i18n=false lockscreen-plugins=false \
         quick-setting-plugins=false status-icon-plugins=false; do
    grep -q "option('${o%%=*}'" "$optfile" && opts="$opts -D$o"
done
case "$opts" in *bindings-lib*) ;; *) log "Phosh $phosh has no bindings-lib option (no libphosh)"; exit 1 ;; esac
# shellcheck disable=SC2086
meson setup "$work/pbuild" "$psrc" --prefix=/usr --buildtype=release -Dwerror=false --wrap-mode=nodownload $opts
jobs=$(nproc 2>/dev/null || echo 4)
ninja -C "$work/pbuild" -j "$jobs" "src/libphosh-$api.so.0"
lib=$work/pbuild/src/libphosh-$api.so.0
[ -f "$lib" ] || { log "the build made no libphosh-$api.so.0"; exit 1; }
[ -e "$work/pbuild/src/libphosh-$api.so" ] || ln -s "libphosh-$api.so.0" "$work/pbuild/src/libphosh-$api.so"
(
    cd "$rsrc"
    export CARGO_TARGET_DIR="$work/target" PKG_CONFIG_PATH="$work/pbuild/meson-uninstalled"
    export RUSTFLAGS="-C link-arg=-Wl,-rpath,$LIBDIR -L native=$work/pbuild/src"
    cargo build --release --locked -j "$jobs"
)
bin=$work/target/release/phrog
[ -x "$bin" ] || { log "the build made no phrog"; exit 1; }

# --- The files, where the phone's build puts them ------------------------------------------------
d=$rsrc/data
install -Dm755 "$bin" "$stage/usr/local/bin/phrog"
install -Dm644 "$lib" "$stage$LIBDIR/libphosh-$api.so.0"
strip --strip-unneeded "$stage/usr/local/bin/phrog" "$stage$LIBDIR/libphosh-$api.so.0"
install -Dm644 "$d/mobi.phosh.phrog.gschema.xml" "$stage/usr/local/share/glib-2.0/schemas/mobi.phosh.phrog.gschema.xml"
install -Dm644 "$d/00_mobi.phosh.Phrog.gschema.override" "$stage/usr/local/share/glib-2.0/schemas/00_mobi.phosh.Phrog.gschema.override"
install -Dm644 "$d/phrog.session" "$stage/usr/local/share/gnome-session/sessions/phrog.session"
mkdir -p "$stage/usr/local/share/applications" "$stage/usr/local/lib/systemd/user/gnome-session@phrog.target.d"
sed 's#^Exec=phrog$#Exec=/usr/local/bin/phrog#' "$d/mobi.phosh.Phrog.desktop" > "$stage/usr/local/share/applications/mobi.phosh.Phrog.desktop"
sed 's#^ExecStart=phrog$#ExecStart=/usr/local/bin/phrog#' "$d/mobi.phosh.Phrog.service" > "$stage/usr/local/lib/systemd/user/mobi.phosh.Phrog.service"
install -Dm644 "$d/mobi.phosh.Phrog.target" "$stage/usr/local/lib/systemd/user/mobi.phosh.Phrog.target"
install -Dm644 "$d/systemd-session.conf" "$stage/usr/local/lib/systemd/user/gnome-session@phrog.target.d/session.conf"
echo "phrog $PHROG_VERSION phosh $phosh" > "$stage$LIBDIR/built-for"
LD_LIBRARY_PATH="$stage$LIBDIR" ldd "$stage/usr/local/bin/phrog" | grep 'not found' && { log "phrog lacks libraries"; exit 1; }
"$stage/usr/local/bin/phrog" --version 2>/dev/null || log "phrog --version needs a session (not checked here)"

version="$PHROG_VERSION+phosh$phosh"
summary="Phrog $PHROG_VERSION, the touch login screen made of Phosh, built for Phosh $phosh (A22x)"
case $family in
deb)
    mkdir -p "$stage/DEBIAN"
    # shared libraries the binary needs, as Debian computes them
    mkdir -p "$work/shl/debian"
    printf 'Source: a22x-phrog\n\nPackage: a22x-phrog\nArchitecture: arm64\n' > "$work/shl/debian/control"
    deps=$(cd "$work/shl" && dpkg-shlibdeps -O --ignore-missing-info -l"$stage$LIBDIR" -e "$stage/usr/local/bin/phrog" \
        -e "$stage$LIBDIR/libphosh-$api.so.0" 2>/dev/null | sed -n 's/^shlibs:Depends=//p') || deps=
    arch=$(dpkg --print-architecture)
    cat > "$stage/DEBIAN/control" <<EOF
Package: a22x-phrog
Version: $version-1
Architecture: $arch
Maintainer: A22x Mainline Recovery <noreply@github.com>
Depends: phosh, greetd${deps:+, $deps}
Section: x11
Priority: optional
Description: $summary
 Built by the A22x Mainline Recovery project (github.com/Dodaskot/mainline-recovery) so that a
 phone installs it instead of building it for 30-40 minutes.
EOF
    printf '#!/bin/sh\nset -e\nglib-compile-schemas /usr/local/share/glib-2.0/schemas || true\n' > "$stage/DEBIAN/postinst"
    printf '#!/bin/sh\nset -e\nglib-compile-schemas /usr/local/share/glib-2.0/schemas 2>/dev/null || true\n' > "$stage/DEBIAN/postrm"
    chmod 755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/postrm"
    name="a22x-phrog_${version}-1_${TARGET}_${arch}.deb"
    dpkg-deb --root-owner-group -Zxz --build "$stage" "$OUT/$name" >/dev/null
    ;;
rpm)
    mkdir -p "$work/rpm/SPECS"
    tar -C "$stage" -cf "$work/stage.tar" .
    cat > "$work/rpm/SPECS/a22x-phrog.spec" <<EOF
Name: a22x-phrog
Version: $(echo "$version" | tr '+' '_')
Release: 1%{?dist}
Summary: $summary
License: GPL-3.0-or-later
Requires: phosh greetd
%description
Built by the A22x Mainline Recovery project so that a phone installs it instead of building it.
%install
mkdir -p %{buildroot}
tar -C %{buildroot} -xf $work/stage.tar
%post
glib-compile-schemas /usr/local/share/glib-2.0/schemas || :
%postun
glib-compile-schemas /usr/local/share/glib-2.0/schemas 2>/dev/null || :
%files
/usr/local/bin/phrog
$LIBDIR
/usr/local/share/glib-2.0/schemas/mobi.phosh.phrog.gschema.xml
/usr/local/share/glib-2.0/schemas/00_mobi.phosh.Phrog.gschema.override
/usr/local/share/gnome-session/sessions/phrog.session
/usr/local/share/applications/mobi.phosh.Phrog.desktop
/usr/local/lib/systemd/user/mobi.phosh.Phrog.service
/usr/local/lib/systemd/user/mobi.phosh.Phrog.target
/usr/local/lib/systemd/user/gnome-session@phrog.target.d
EOF
    rpmbuild --define "_topdir $work/rpm" --define '__strip /bin/true' --define 'debug_package %{nil}' \
        -bb "$work/rpm/SPECS/a22x-phrog.spec" >/dev/null
    for f in "$work"/rpm/RPMS/*/*.rpm; do cp "$f" "$OUT/$(basename "$f" .rpm | sed "s/\.aarch64$//").${TARGET}.aarch64.rpm"; done
    ;;
pacman)
    useradd -m builder 2>/dev/null || true
    chmod 755 "$work"  # mktemp made it 0700: the builder could not reach pkg/ (2026-11-22, CI)
    mkdir -p "$work/pkg"
    tar -C "$stage" -cf "$work/pkg/stage.tar" .
    cat > "$work/pkg/PKGBUILD" <<EOF
pkgname=a22x-phrog
pkgver=$(echo "$version" | tr '+' '_')
pkgrel=1
pkgdesc="$summary"
arch=('aarch64')
url='https://github.com/Dodaskot/mainline-recovery'
license=('GPL-3.0-or-later')
depends=('phosh' 'greetd')
options=('!strip' '!debug')
install=a22x-phrog.install
source=('stage.tar')
noextract=('stage.tar')
sha256sums=('SKIP')
package() { tar -C "\$pkgdir" -xf "\$srcdir/stage.tar"; }
EOF
    printf 'post_install() {\n  glib-compile-schemas /usr/local/share/glib-2.0/schemas\n}\npost_upgrade() {\n  post_install\n}\npost_remove() {\n  glib-compile-schemas /usr/local/share/glib-2.0/schemas 2>/dev/null || true\n}\n' > "$work/pkg/a22x-phrog.install"
    chown -R builder "$work/pkg"
    (cd "$work/pkg" && su builder -c 'PKGEXT=.pkg.tar.zst makepkg -d --noconfirm' >/dev/null)
    for f in "$work"/pkg/*.pkg.tar.zst; do cp "$f" "$OUT/$(basename "$f" .pkg.tar.zst)-$TARGET.pkg.tar.zst"; done
    ;;
esac
echo "$TARGET phosh $phosh ($phosh_full) $(rustc --version)" > "$OUT/$TARGET.built-for"
ls -l "$OUT"
log "done"
