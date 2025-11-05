# Bonjou

Bonjou is a cross-platform, terminal-based LAN chat and transfer application written in Go. It keeps teams chatting and sharing files even when the wider Internet is offline, as long as devices share the same local network.

## Features

- 🔌 Works entirely on LAN – no central server required.
- 💬 Low-friction terminal UI with command-driven interactions.
- ⌨️ Rich line editing with history, arrow keys, and familiar shortcuts (Ctrl+A/E/U, Home/End, etc.).
- 📁 Fast file and folder transfer with automatic compression, checksums, and progress updates.
- 📡 Peer discovery over UDP broadcasts; encrypted integrity checks over TCP for data transport.
- 🗃️ Persistent logs and received files stored under `~/.bonjou/`.
- 📦 Cross-compiled binaries for Linux, macOS, and Windows with packaging artefacts for APT, Homebrew, and Scoop.

## Getting Started

### Prerequisites

- Go 1.21+
- Optional: `dpkg-deb` for building `.deb` packages on Linux or macOS.

### Build from Source

```bash
cd bonjou-terminal
./scripts/build.sh
```

The script cross-compiles Bonjou for Linux, macOS, and Windows. You can also
directly compile individual targets into `bin/` with:

```bash
GOOS=linux   GOARCH=amd64 go build -o bin/bonjou-linux ./cmd/bonjou
GOOS=darwin  GOARCH=amd64 go build -o bin/bonjou-macos ./cmd/bonjou
GOOS=windows GOARCH=amd64 go build -o bin/bonjou.exe   ./cmd/bonjou
```

Compress each artifact before distribution:

```bash
cd bin
tar -czf bonjou-linux.tar.gz  bonjou-linux
tar -czf bonjou-macos.tar.gz  bonjou-macos
zip bonjou-windows.zip bonjou.exe
```

### Package for Distribution

```bash
./scripts/package.sh
```

Outputs:

- Debian package: `dist/deb/bonjou_1.0.2_amd64.deb`
- Homebrew formula: `dist/homebrew/bonjou.rb`
- Scoop manifest: `dist/scoop/bonjou.json`

Update the placeholder download URLs and SHA256 values in the manifests before publishing.

### Install

Pre-built packages are published on the
[GitHub releases page](https://github.com/hamzaabdulwahab/bonjou-terminal/releases).

#### Linux (.deb)

```bash
wget https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.2/bonjou_1.0.2_amd64.deb
sudo dpkg -i bonjou_1.0.2_amd64.deb
```

If dependency errors occur, run `sudo apt -f install` and re-run the `dpkg -i`
command. Launch with:

```bash
bonjou
```

#### macOS (Homebrew)

```bash
brew tap hamzaabdulwahab/bonjou https://github.com/hamzaabdulwahab/homebrew-bonjou
brew install bonjou
```

Homebrew downloads `bonjou-macos.tar.gz` from the release and installs the
`bonjou` CLI into your PATH.

Update to the latest release with:

```bash
brew update
brew upgrade bonjou
```

#### Windows (Scoop)

```powershell
scoop bucket add bonjou https://github.com/hamzaabdulwahab/scoop-bonjou
scoop install bonjou
```

The Scoop bucket tracks the latest release zip and exposes `bonjou.exe` as a
command.

Upgrade with the latest manifest by running:

```powershell
scoop update
scoop update bonjou
```

### Offline / LAN Distribution

Share the `dist/` folder on the local network (via SMB/NFS/HTTP). Peers can install using the same steps above, pointing to the shared path. For updates, publish a refreshed build into the shared folder and run `@update` inside Bonjou to execute the supplied update script (`bonjou-update` or `~/.bonjou/update.sh`).
The provided [`scripts/update.sh`](scripts/update.sh) can be adapted and hosted centrally as `bonjou-update` for automatic LAN updates.

## Usage

Launch Bonjou after installation:

```bash
bonjou
```

Check the currently installed version without launching the UI:

```bash
bonjou --version
```

Opening banner:

```
🌐 Welcome to Bonjou v1.0.2
👤 User: <username> | IP: <ip>
📡 LAN: Connected
Type @help for commands.
```

All interactions rely on `@commands`. See [HELP.md](HELP.md) for the complete reference. Common examples:

```
@send alice Hello from lab PC!
@file 192.168.1.23 ~/Documents/report.pdf
@folder alice ./project-notes
@broadcast Evening maintenance window starts in 10 minutes.
@history
```

✳️ Tip: wait for peers to appear in `@users` before targeting them by username or IP, and make sure both
devices run the same Bonjou version. Discovery carries the credentials needed for secure message verification.
Progress indicators refresh roughly every 5% to keep the prompt readable during large transfers.

Received files arrive under:

```
~/.bonjou/received/files
~/.bonjou/received/folders
```

Logs live in `~/.bonjou/logs`. Use `@setpath <dir>` to move incoming storage elsewhere.

### Troubleshooting

- If you see `Rejected incoming payload` errors, the receiving side has not discovered you yet or is running an older Bonjou build. Wait for the peer to appear in `@users` and ensure both machines are using v1.0.2 or newer.
- `write: broken pipe` typically indicates the connection dropped mid-transfer; double-check both hosts are still connected to the LAN and re-send once discovery refreshes (announcements repeat every 5 seconds).

## Architecture Overview

- **cmd/bonjou** – entry point wiring configuration, services, and UI.
- **internal/config** – persistent configuration management.
- **internal/network** – UDP peer discovery and TCP transfer server/client.
- **internal/commands** – command parser and dispatcher.
- **internal/ui** – ANSI-enhanced terminal interface and event loop.
- **internal/history** – log persistence for chats and transfers.
- **internal/events** – typed event bus used by background services.

Discovery broadcasts JSON beacons over UDP port `46320`. Transfers occur over TCP port `46321` with HMAC-SHA256 integrity checks. Folder deliveries are zipped on the fly, transferred, then extracted when received.

## Testing

Manual testing is the most representative. Try the [demo scenario](docs/demo-simulation.md) to simulate two hosts on the same network. Automated coverage can be expanded with Go unit tests for configuration, command parsing, and protocol helpers.

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Run `gofmt ./...` and `go test ./...`.
4. Submit a pull request with a clear summary.

## License

MIT. See `LICENSE` (add one if redistributing publicly).
