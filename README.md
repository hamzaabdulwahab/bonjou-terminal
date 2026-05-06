<div align="center">
  <img src="logowithtxt.png" alt="Bonjou logo" width="300"/>

  ### Serverless, internet-free LAN chat and file transfers directly from your terminal.

  [![Go Version](https://img.shields.io/github/go-mod/go-version/hamzaabdulwahab/bonjou-cli?style=flat-square&logo=go)](https://golang.org/)
  [![Release](https://img.shields.io/github/v/release/hamzaabdulwahab/bonjou-cli?style=flat-square)](https://github.com/hamzaabdulwahab/bonjou-cli/releases)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
  [![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey?style=flat-square)]()
</div>

---

<div align="center">
  <img src="bonjou-demo.gif" alt="Bonjou Demo" width="800"/>
</div>

---

**Bonjou** (derived from *Bonjour*, French for *Hello*) is a fast, lightweight terminal application that lets you instantly chat and share files with anyone on your local network (WiFi/LAN). 

No servers to configure. No internet connection required. No accounts to create. Just open your terminal and start typing.

## 📋 Table of Contents

- [✨ Why Bonjou?](#-why-bonjou)
- [🚀 Quick Start](#-quick-start)
- [📖 Usage & Commands](#-usage--commands)
- [📦 Advanced Installation](#-advanced-installation)
- [🛠️ Architecture & Security](#️-architecture--security)
- [💻 Development](#-development)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## ✨ Why Bonjou?

- 🔌 **Zero Config:** Auto-discovers users on your subnet via UDP.
- 🗂️ **Seamless File Transfers:** Send files and entire directories over TCP.
- 🔒 **Secure-by-Design:** Metadata-first approval queue means no files are written to your machine without your explicit permission.
- 💻 **Cross-Platform:** Works flawlessly across macOS, Windows, and Linux.
- 🪄 **Interactive TUI:** Built on the beautiful [Charmbracelet](https://charm.sh/) stack. Features a guided `@wizard` mode if you prefer menus over commands.

---

## 🚀 Quick Start

Get Bonjou running in under 30 seconds.

### 1. Install

**macOS / Linux (One-line install):**
```bash
curl -fsSL https://raw.githubusercontent.com/hamzaabdulwahab/bonjou-cli/main/scripts/install.sh | bash
```

**Windows (PowerShell):**
```powershell
iwr https://raw.githubusercontent.com/hamzaabdulwahab/bonjou-cli/main/scripts/install.ps1 -useb | iex
```

*(See [Advanced Installation](#-advanced-installation) below for Homebrew, WinGet, Scoop, and Debian packages).*

### 2. Run
```bash
bonjou
```
You will be dropped into the Bonjou prompt. It will automatically detect other users running Bonjou on your network.

### 3. Send
```bash
# See who is online
@users

# Say hello
@send alex Hey, are you in the meeting?

# Send a document
@file alex ~/report.pdf
```

---

## 📖 Usage & Commands

Bonjou uses simple `@` commands. Press `Tab` for autocomplete, or run `@wizard` for an interactive, guided menu.

### Communication
| Command | Description |
|---|---|
| `@users` | List all discovered users on your network |
| `@send <user> <msg>` | Send a direct message |
| `@broadcast <msg>` | Send a message to everyone on the network |

### File Transfers
| Command | Description |
|---|---|
| `@file <user> <path>` | Send a single file |
| `@folder <user> <path>`| Send an entire directory |
| `@queue` | View incoming file/folder transfer requests |
| `@view <id>` | Inspect a pending transfer's metadata |
| `@approve <id>` | Accept an incoming transfer |
| `@reject <id>` | Decline an incoming transfer |

### Utilities
| Command | Description |
|---|---|
| `@wizard` | Open the interactive TUI flow |
| `@help` | See all available commands |
| `@exit` | Quit the application |

---

## 📦 Advanced Installation

<details>
<summary><b>macOS (Homebrew)</b></summary>

```bash
brew install hamzaabdulwahab/bonjou/bonjou
```
Or the classic tap method:
```bash
brew tap hamzaabdulwahab/bonjou https://github.com/hamzaabdulwahab/homebrew-bonjou
brew install bonjou
```
</details>

<details>
<summary><b>Windows (WinGet & Scoop)</b></summary>

**WinGet:**
```powershell
winget install HamzaAbdulWahab.Bonjou
```

**Scoop:**
```powershell
scoop install https://raw.githubusercontent.com/hamzaabdulwahab/scoop-bonjou/main/bonjou.json
```
</details>

<details>
<summary><b>Linux (Debian/Ubuntu)</b></summary>

**AMD64 (Most PCs):**
```bash
wget https://github.com/hamzaabdulwahab/bonjou-cli/releases/download/v1.1.0/bonjou_1.1.0_amd64.deb
sudo dpkg -i bonjou_1.1.0_amd64.deb
```

**ARM64 (Raspberry Pi / Mac VMs):**
```bash
wget https://github.com/hamzaabdulwahab/bonjou-cli/releases/download/v1.1.0/bonjou_1.1.0_arm64.deb
sudo dpkg -i bonjou_1.1.0_arm64.deb
```
</details>

---

## 🛠️ Architecture & Security

Bonjou is designed to be trustless and secure on local networks.

*   **Discovery Engine:** Peers are discovered using UDP broadcast on port `46320`. (Note: This generally does not cross routers/VLANs).
*   **Transfer Protocol:** Messages and files are transmitted via TCP on port `46321`.
*   **Metadata-First Transfers:** When a peer sends you a file, you receive a manifest preview first. The actual payload is only transferred over TCP *after* you explicitly run `@approve <id>`.
*   **Storage Locations:** 
    * Approved files: `~/.bonjou/received/files/`
    * Approved folders: `~/.bonjou/received/folders/`
    * Config & State: `~/.bonjou/config.json`

---

## 💻 Development

Bonjou requires **Go 1.24.0** or newer.

To build and run the project locally:

```bash
# 1. Clone the repository
git clone https://github.com/hamzaabdulwahab/bonjou-cli.git
cd bonjou-cli

# 2. Run the application
go run ./cmd/bonjou

# 3. (Optional) Build binaries for your platform
./scripts/build.sh
```

---

## 🤝 Contributing

Contributions are heavily encouraged! Bonjou is built to be simple, hackable, and maintainable. 

1. Check the [Issue Tracker](https://github.com/hamzaabdulwahab/bonjou-cli/issues) for `good first issue` tags.
2. Fork the repository.
3. Create your feature branch (`git checkout -b feature/amazing-feature`).
4. Commit your changes (`git commit -m 'feat: add amazing feature'`).
5. Push to the branch (`git push origin feature/amazing-feature`).
6. Open a Pull Request.

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more information.