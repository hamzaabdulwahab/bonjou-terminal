# Bonjou

Bonjou is a terminal-based chat app for local networks. You can send messages and files to other computers on the same WiFi or LAN without needing internet.

## What It Does

- Chat with people on the same network
- Send files and folders
- Works on Mac, Linux, and Windows
- No server needed - everything stays on your local network
- Simple commands starting with `@`
- Auto-discovers users on the same subnet

## Quick Start

### Install

**One command installer scripts:**

macOS/Linux:
```bash
curl -fsSL https://raw.githubusercontent.com/hamzaabdulwahab/bonjou-cli/main/scripts/install.sh | bash
```

Windows (PowerShell):
```powershell
iwr https://raw.githubusercontent.com/hamzaabdulwahab/bonjou-cli/main/scripts/install.ps1 -useb | iex
```

**Mac (Homebrew):**
```bash
brew install hamzaabdulwahab/bonjou/bonjou
```

If you prefer the classic two-step flow:
```bash
brew tap hamzaabdulwahab/bonjou https://github.com/hamzaabdulwahab/homebrew-bonjou
brew install bonjou
```

**Windows (WinGet — pre-installed on Windows 10/11):**
```powershell
winget install HamzaAbdulWahab.Bonjou
```

**Windows (Scoop):**
```powershell
scoop install https://raw.githubusercontent.com/hamzaabdulwahab/scoop-bonjou/main/bonjou.json
```

If you prefer the classic two-step flow:
```powershell
scoop bucket add bonjou https://github.com/hamzaabdulwahab/scoop-bonjou
scoop install bonjou
```

**Linux (Ubuntu/Debian):**
```bash
# For Intel/AMD (most PCs, cloud VMs)
wget https://github.com/hamzaabdulwahab/bonjou-cli/releases/download/v1.1.0/bonjou_1.1.0_amd64.deb
sudo dpkg -i bonjou_1.1.0_amd64.deb

# For ARM64 (Mac with Docker/Parallels, Raspberry Pi)
wget https://github.com/hamzaabdulwahab/bonjou-cli/releases/download/v1.1.0/bonjou_1.1.0_arm64.deb
sudo dpkg -i bonjou_1.1.0_arm64.deb
```

Or download from [Releases](https://github.com/hamzaabdulwahab/bonjou-cli/releases).

### Run

```bash
bonjou
```

You will see:
```
🌐 Welcome to Bonjou v1.1.0
👤 User: hamza | IP: 192.168.1.5
📡 LAN: Connected
Type @help for commands.
```

### Basic Commands

```
@users                          # see who is on the network
@send alex Hello!               # send message to alex
@file alex ~/report.pdf         # send a file
@folder alex ./my-folder        # send a folder
@wizard                         # guided send flow (peer + action + confirm)
@broadcast Meeting in 5 mins    # message everyone
@help                           # see all commands
@exit                           # quit
```

You can also run `@send`, `@file`, `@folder`, `@setname`, or `@setpath` without full arguments to open guided prompts.

To exit wizard mode at any step, press `Ctrl+C`. You will return to the main command prompt and nothing is sent unless you confirm.

## Transfer Status Semantics

When you send a file or folder, Bonjou now uses clear end-state messaging:

- Progress line while uploading bytes
	- Example: `✓ Sent 🗂️ Folder → abd@192.168.1.3:46321 ... 100%`
	- This shows sender-side upload completion.

- Final success confirmation
	- Example: `Delivered: Folder 'Books' to abd`
	- This is the receiver-confirmed result (app-level ACK).

- Final failure confirmation
	- Example: `Failed to send Folder 'Books' to abd: receiver did not confirm the transfer in time ...`
	- Errors are translated to user-friendly language.

You should rely on `Delivered: ...` as the definitive success signal.

Repeated sends are allowed. If the same name already exists, Bonjou saves into a unique destination (for example `Books`, then `Books_1`, `Books_2`, ...).

## Discovery Scope

Bonjou is designed to work when devices are on the same subnet (same LAN/Wi‑Fi network segment). It uses UDP broadcast for discovery, which generally does not cross routers.

## Build From Source

Need Go 1.21 or newer.

```bash
git clone https://github.com/hamzaabdulwahab/bonjou-cli.git
cd bonjou-cli
go run ./cmd/bonjou
```

To build binaries:
```bash
./scripts/build.sh
```

## How It Works

- Bonjou finds other users using UDP on port 46320
- Messages and files go through TCP on port 46321
- Files you receive go to `~/.bonjou/received/`
- Settings saved in `~/.bonjou/config.json`

## Troubleshooting

**Can not see other users in same lab?**
- Make sure you are on the same network
- Check if firewall is blocking ports 46320 and 46321

**Can not see users in different lab?**
- Bonjou discovery is same-subnet only
- Make sure both devices are on the same Wi‑Fi/LAN and not separated by a router/VLAN

**File transfer failed?**
- Wait for user to show up in @users first
- Check version with `bonjou --version`

## More Info

- [Commands](HELP.md)
- [Install Guide](docs/install-guide.md)
- [Demo](docs/demo-simulation.md)
- [Package Registry Submission](docs/package-registry-submission.md)

## License

MIT
