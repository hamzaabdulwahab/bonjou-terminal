# Repository Guidelines

## Project Structure & Module Organization
Bonjou is a Go CLI application. The executable entrypoint lives in `cmd/bonjou`, with OS-specific signal handling split into `signals_windows.go` and `signals_other.go`. Core behavior is organized under `internal/`: command handling, configuration, event types, history, logging, network discovery/transfer, queue management, sessions, UI, and version metadata. Tests are colocated with packages as `*_test.go`, currently under `internal/commands`, `internal/network`, and `internal/queue`. Documentation and release notes live in `docs/`, visual assets in `docs/assets/`, packaging manifests in `packaging/`, and release/install automation in `scripts/`.

## Build, Test, and Development Commands
- `go run ./cmd/bonjou` runs the CLI locally.
- `go build ./cmd/bonjou` builds the current platform binary.
- `go test ./...` runs the full Go test suite.
- `go test ./internal/network -run TestName` runs a targeted package test.
- `./scripts/build.sh` cross-compiles Linux, macOS, and Windows binaries into `dist/bin/`.
- `./scripts/package.sh` builds release artifacts and package metadata under `dist/`.

Use Go 1.24.0 or newer, matching `go.mod`.

## Coding Style & Naming Conventions
Format Go code with `gofmt` before committing. Use tabs for Go indentation and keep package names short, lowercase, and domain-focused, such as `queue` or `network`. Export only APIs needed across packages; keep helpers unexported. Follow existing OS-specific filename suffixes such as `_windows.go`, `_unix.go`, and `_other.go`. CLI commands exposed to users use the documented `@command` pattern, for example `@queue` and `@approve`.

## Testing Guidelines
Use the standard Go `testing` package. Add tests beside the package being changed and name them `TestXxx` in `*_test.go` files. Prefer focused unit tests for command parsing, queue state, transfer metadata, and approval/rejection behavior. Run `go test ./...` before opening a pull request, and add regression tests for bug fixes.

## Commit & Pull Request Guidelines
Recent history uses short, imperative Conventional Commit-style prefixes, including `feat:`, `chore:`, `release:`, and `merge:`. Keep subjects concise, for example `feat: add metadata-first approval workflow`.

Pull requests should include a clear summary, test results, linked issues when applicable, and screenshots or terminal recordings for visible CLI/TUI changes. For release or packaging changes, mention affected package managers and generated files under `dist/` only when intentionally included.

## Security & Configuration Tips
Bonjou uses UDP `46320` for peer discovery and TCP `46321` for transfers. Preserve the metadata-first approval flow: incoming files should not be written until the user explicitly approves them. Local state and received files belong under `~/.bonjou/`; avoid committing generated config, received payloads, or release artifacts.
