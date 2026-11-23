#!/usr/bin/env bash
# Build on Ubuntu 22.04 for a glibc baseline shared by Debian/Ubuntu/Kali.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')
arch=$(dpkg --print-architecture)
[[ "$arch" == amd64 ]] || { echo 'Only amd64 packaging is tested' >&2; exit 1; }
binary=target/release/nostoi
test -x "$binary"
"$binary" --version | grep -Fx "nostoi $version"
mkdir -p dist
install -m 0755 "$binary" "dist/nostoi-${version}-linux-${arch}"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/share/doc/nostoi"
install -m 0755 "$binary" "$stage/usr/bin/nostoi"
install -m 0644 README.md LICENSE-MIT LICENSE-APACHE "$stage/usr/share/doc/nostoi/"
mkdir -p "$stage/debian"
printf 'Source: nostoi\n\nPackage: nostoi\nArchitecture: any\n' > "$stage/debian/control"
depends=$(cd "$stage" && dpkg-shlibdeps -O -eusr/bin/nostoi | sed -n 's/^shlibs:Depends=//p')
test -n "$depends"
rm "$stage/debian/control"
rmdir "$stage/debian"
cat > "$stage/DEBIAN/control" <<EOF
Package: nostoi
Version: $version
Section: utils
Priority: optional
Architecture: $arch
Maintainer: RAGBAZ <noreply@ragbaz.cc>
Depends: $depends, openssh-client
Homepage: https://github.com/tabenius/nostoi
Description: Tamper-evident audit chain verifier, CLI and TUI
 Verify, append, inspect and browse Nostoi, WeftMark and Ephor audit chains.
 Includes SQLite support and the terminal UI (nostoi tui).
 Hash chains need independently trusted anchors to detect rewritten history.
EOF
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
dpkg-deb --build --root-owner-group "$stage" "dist/nostoi_${version}_${arch}.deb"
dpkg-deb --info "dist/nostoi_${version}_${arch}.deb"
(cd dist && sha256sum "nostoi-${version}-linux-${arch}" "nostoi_${version}_${arch}.deb" > SHA256SUMS)
(cd dist && sha256sum --check --strict SHA256SUMS)
