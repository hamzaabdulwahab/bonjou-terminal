#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST_DIR="$ROOT_DIR/dist"
BIN_DIR="$DIST_DIR/bin"
mkdir -p "$BIN_DIR"

pushd "$ROOT_DIR" >/dev/null

echo "Building Bonjou binaries..."
GOOS=linux GOARCH=amd64 go build -o "$BIN_DIR/bonjou-linux" ./cmd/bonjou
GOOS=darwin GOARCH=arm64 go build -o "$BIN_DIR/bonjou-macos" ./cmd/bonjou
GOOS=windows GOARCH=amd64 go build -o "$BIN_DIR/bonjou.exe" ./cmd/bonjou

echo "Build artifacts stored in $BIN_DIR"
popd >/dev/null
