#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST_DIR="$ROOT_DIR/dist"
BIN_DIR="$DIST_DIR/bin"
TARGET_BIN="/usr/local/bin/bonjou"

if [[ ! -d "$BIN_DIR" ]]; then
  echo "No build artifacts found. Run scripts/build.sh first." >&2
  exit 1
fi

LATEST="$BIN_DIR/bonjou-linux"
if [[ "$OSTYPE" == "darwin"* ]]; then
  LATEST="$BIN_DIR/bonjou-macos"
elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32"* ]]; then
  LATEST="$BIN_DIR/bonjou.exe"
  TARGET_BIN="/c/Tools/bonjou.exe"
fi

if [[ ! -f "$LATEST" ]]; then
  echo "Expected binary $LATEST missing." >&2
  exit 1
fi

echo "Installing $LATEST -> $TARGET_BIN"
if [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32"* ]]; then
  install -m 0755 "$LATEST" "$TARGET_BIN"
else
  sudo install -m 0755 "$LATEST" "$TARGET_BIN"
fi

echo "Bonjou updated."
