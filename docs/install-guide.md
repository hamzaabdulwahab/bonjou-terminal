# Bonjou Installation Guide

This document walks through every supported way to install Bonjou v1.0.9 on macOS, Linux, and Windows. Pick the option that best matches your environment. Each path ends with Bonjou available on your `PATH` so you can launch it with a simple `bonjou` command.

> **Tip:** If you are transferring the app to offline hosts, jump to [Offline Distribution](#offline-distribution) for AirDrop/USB steps.

---

## macOS

### 1. Homebrew (Recommended)

1. Tap the official Bonjou formula:
   ```bash
   brew tap hamzaabdulwahab/bonjou https://github.com/hamzaabdulwahab/homebrew-bonjou
   ```
2. Install Bonjou:
   ```bash
   brew install bonjou
   ```
3. Launch:
   ```bash
   bonjou
   ```
4. Update later with:
   ```bash
   brew update && brew upgrade bonjou
   ```

### 2. Download Release Artifact

1. Fetch the tarball from the latest release:
   ```bash
       curl -L -o bonjou-macos.tar.gz \
          https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.9/bonjou-macos.tar.gz
   ```
2. Verify checksum (optional, recommended):
   ```bash
   echo "3a5df10f7a75e38ce64fe3d7f57c6b5ebaa6cc3542b30f3c5d5f868ece567bdf  bonjou-macos.tar.gz" | shasum -a 256 --check
   ```
3. Extract and place on `PATH`:
   ```bash
   tar -xzf bonjou-macos.tar.gz
   sudo mv bonjou-macos /usr/local/bin/bonjou
   sudo chmod +x /usr/local/bin/bonjou
   ```
4. Launch with `bonjou`.

### 3. Build From Source

1. Install Go 1.21+.
2. Clone the repository:
   ```bash
   git clone https://github.com/hamzaabdulwahab/bonjou-terminal.git
   cd bonjou-terminal
   ```
3. Build the macOS binary:
   ```bash
   GOOS=darwin GOARCH=amd64 go build -o bonjou ./cmd/bonjou
   ```
4. Move it into a directory on your `PATH` (for example `/usr/local/bin`):
   ```bash
   sudo mv bonjou /usr/local/bin/
   ```
5. Run `bonjou`.

---

## Linux

### 1. Debian/Ubuntu Package (.deb)

1. Download the package:
   ```bash
         wget https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.9/bonjou_1.0.9_amd64.deb
   ```
2. Verify checksum:
   ```bash
   echo "7e436fcdcc26dcd97404f667b9c0c7d60a17678c4200c8f96291deea3039c3ac  bonjou_1.0.9_amd64.deb" | sha256sum --check
   ```
3. Install:
   ```bash
   sudo dpkg -i bonjou_1.0.9_amd64.deb
   ```
4. Resolve dependencies if prompted:
   ```bash
   sudo apt -f install
   ```
5. Launch `bonjou`.

### 2. Manual Tarball Install

1. Fetch the Linux tarball:
   ```bash
   curl -L -o bonjou-linux.tar.gz \
   https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.9/bonjou-linux.tar.gz
   ```
2. Check the SHA256:
   ```bash
   echo "3f250ea9a23d4e31f743647c9655db3881a0008eea2c6357ff90c5693d18bfb0  bonjou-linux.tar.gz" | sha256sum --check
   ```
3. Extract and install:
   ```bash
   tar -xzf bonjou-linux.tar.gz
   sudo mv bonjou-linux /usr/local/bin/bonjou
   sudo chmod +x /usr/local/bin/bonjou
   ```
4. Run `bonjou`.

### 3. Build From Source

1. Install Go 1.21+ and Git.
2. Clone and build:
   ```bash
   git clone https://github.com/hamzaabdulwahab/bonjou-terminal.git
   cd bonjou-terminal
   GOOS=linux GOARCH=amd64 go build -o bonjou ./cmd/bonjou
   ```
3. Install the binary to `/usr/local/bin` (or another directory in `PATH`):
   ```bash
   sudo mv bonjou /usr/local/bin/
   ```
4. Launch with `bonjou`.

---

## Windows

### 1. Scoop (Recommended)

1. Add the Bonjou bucket:
   ```powershell
   scoop bucket add bonjou https://github.com/hamzaabdulwahab/scoop-bonjou
   ```
2. Install:
   ```powershell
   scoop install bonjou
   ```
3. Launch Bonjou:
   ```powershell
   bonjou
   ```
4. Update later:
   ```powershell
   scoop update
   scoop update bonjou
   ```
5. If a download aborts mid-way, clear the cache before retrying:
   ```powershell
   scoop cache rm bonjou
   scoop install bonjou
   ```

### 2. Manual Zip Install

1. Download the Windows zip:
   ```powershell
   Invoke-WebRequest -Uri https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.9/bonjou-windows.zip -OutFile bonjou-windows.zip
   ```
2. Verify checksum (PowerShell):
   ```powershell
   Get-FileHash .\bonjou-windows.zip -Algorithm SHA256 | Select-Object Hash
   # Compare with: 1adb0e5df7b258b987d743f271647804fff9113bc2d6d0c030f987e445242df5
   ```
3. Extract:
   ```powershell
   Expand-Archive .\bonjou-windows.zip -DestinationPath .\bonjou
   ```
4. Add to `PATH`:
   - Move `bonjou.exe` into a folder already on your `PATH` (e.g. `C:\Windows`) **or**
   - Create `C:\Tools\Bonjou`, move the exe there, then add it to PATH:
     ```powershell
     $env:Path += ";C:\Tools\Bonjou"
     [Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)
     ```
5. Launch `bonjou` in a new terminal.

### 3. Build From Source (PowerShell)

1. Install Go 1.21+ and Git.
2. Clone:
   ```powershell
   git clone https://github.com/hamzaabdulwahab/bonjou-terminal.git
   cd bonjou-terminal
   ```
3. Build:
   ```powershell
   go build -o bonjou.exe .\cmd\bonjou
   ```
4. Move the executable into a directory listed in `PATH`.
5. Launch `bonjou` from a new terminal window.

---

## Offline Distribution

When installing on machines without internet access, carry the release artifacts and this guide on removable media.

### Prepare Installer Media

1. On an online machine, download all relevant files:
   - `bonjou-linux.tar.gz`
   - `bonjou-macos.tar.gz`
   - `bonjou-windows.zip`
   - `bonjou_1.0.9_amd64.deb`
   - `checksums.txt`
2. Copy them to a USB drive or network share.

### AirDrop (macOS to macOS)

1. Place `bonjou-macos.tar.gz` on the source Mac desktop.
2. Use AirDrop to send the tarball to the target Mac.
3. On the receiving Mac, follow the [macOS Release Artifact](#2-download-release-artifact) steps starting at extraction.

### USB Drive (Cross-platform)

1. Copy the appropriate artifact(s) and `checksums.txt` onto the drive.
2. Safely eject and mount the drive on the target machine.
3. Move the files locally (e.g. to `~/Downloads` on macOS/Linux or `C:\Temp` on Windows).
4. Follow the OS-specific manual install steps above using the copied files instead of downloading.

### LAN Share

1. Host the `dist/` folder from the online machine via SMB, NFS, or a simple HTTP server:
   ```bash
   python3 -m http.server 8080 --directory /path/to/dist
   ```
2. On the target machine, download from the LAN host (e.g. `http://<host-ip>:8080/bin/bonjou-linux.tar.gz`).
3. Proceed with the manual installation instructions for the OS.

---

## Post-Install Verification

After any install method, verify the version:
```bash
bonjou --version
```
Expect `Bonjou v1.0.9`. Launch `bonjou` to enter the full-screen UI. If the command is not found, re-check that the binary is located in a directory included in your shell's `PATH`.

## Running Directly From Source

During development you can execute Bonjou without packaging it:

```bash
cd bonjou-terminal
go run ./cmd/bonjou
```

Set `BONJOU_HOME` to separate the state for multiple test instances on the same machine.
