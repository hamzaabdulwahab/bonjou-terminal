#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST_DIR="$ROOT_DIR/dist"
BIN_DIR="$DIST_DIR/bin"
DEB_WORK="$DIST_DIR/deb"
VERSION=$(tr -d ' \n\r' < "$ROOT_DIR/VERSION")

"$ROOT_DIR/scripts/build.sh"

mkdir -p "$DEB_WORK"
DEB_DIR="$DEB_WORK/bonjou_${VERSION}_amd64"
CONTROL_DIR="$DEB_DIR/DEBIAN"
BIN_TARGET="$DEB_DIR/usr/local/bin"

rm -rf "$DEB_DIR"
mkdir -p "$CONTROL_DIR" "$BIN_TARGET"
cp "$BIN_DIR/bonjou-linux" "$BIN_TARGET/bonjou"
chmod 0755 "$BIN_TARGET/bonjou"
cat >"$CONTROL_DIR/control" <<EOF
Package: bonjou
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Maintainer: Bonjou Team <support@bonjou.local>
Description: Bonjou terminal-based LAN chat and transfer tool
EOF

if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --build "$DEB_DIR" "$DEB_WORK/bonjou_${VERSION}_amd64.deb"
  echo "Created Debian package at $DEB_WORK/bonjou_${VERSION}_amd64.deb"
else
  echo "dpkg-deb not found; skipping .deb creation."
fi

mkdir -p "$DIST_DIR/homebrew" "$DIST_DIR/scoop"
cp "$ROOT_DIR/packaging/homebrew/bonjou.rb" "$DIST_DIR/homebrew/bonjou.rb"
cp "$ROOT_DIR/packaging/scoop/bonjou.json" "$DIST_DIR/scoop/bonjou.json"

echo "Packaging complete."
