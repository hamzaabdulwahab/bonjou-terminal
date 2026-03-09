# How to Install Bonjou

Pick your operating system and follow the steps.

## One Command Installer (Auto-detect)

macOS/Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/hamzaabdulwahab/bonjou-cli/main/scripts/install.sh | bash
```

Windows (PowerShell):

```powershell
iwr https://raw.githubusercontent.com/hamzaabdulwahab/bonjou-cli/main/scripts/install.ps1 -useb | iex
```

What this does:
- Uses Homebrew on macOS if available
- Uses WinGet on Windows if available (pre-installed on Windows 10/11)
- Falls back to Scoop on Windows if WinGet is not available
- Falls back to direct binary install when no package manager is found

## Mac

### Option 1: Homebrew (easiest)

```bash
brew install hamzaabdulwahab/bonjou/bonjou
```

If you prefer the classic two-step flow:
```bash
brew tap hamzaabdulwahab/bonjou https://github.com/hamzaabdulwahab/homebrew-bonjou
brew install bonjou
```

Run it:
```bash
bonjou
```

Update later:
```bash
brew update && brew upgrade bonjou
```

### Option 2: Download manually

1. Download from releases:
```bash
curl -L -o bonjou https://github.com/hamzaabdulwahab/bonjou-cli/releases/download/v1.1.0/bonjou-macos
```

2. Install:
```bash
sudo mv bonjou /usr/local/bin/bonjou
sudo chmod +x /usr/local/bin/bonjou
```

3. Run:
```bash
bonjou
```

### Option 3: Build from source

```bash
git clone https://github.com/hamzaabdulwahab/bonjou-cli.git
cd bonjou-cli
go build -o bonjou ./cmd/bonjou
sudo mv bonjou /usr/local/bin/
```

---

## Linux

### Option 1: Debian/Ubuntu package

**Intel/AMD (most PCs):**
```bash
wget https://github.com/hamzaabdulwahab/bonjou-cli/releases/download/v1.1.0/bonjou_1.1.0_amd64.deb
sudo dpkg -i bonjou_1.1.0_amd64.deb
```

**ARM64 (Mac with Docker/Parallels, Raspberry Pi):**
```bash
wget https://github.com/hamzaabdulwahab/bonjou-cli/releases/download/v1.1.0/bonjou_1.1.0_arm64.deb
sudo dpkg -i bonjou_1.1.0_arm64.deb
```

If you get dependency errors:
```bash
sudo apt -f install
```

Run:
```bash
bonjou
```

### Option 2: Download manually

**Intel/AMD:**
```bash
curl -L -o bonjou https://github.com/hamzaabdulwahab/bonjou-cli/releases/download/v1.1.0/bonjou-linux-amd64
sudo mv bonjou /usr/local/bin/bonjou
sudo chmod +x /usr/local/bin/bonjou
```

**ARM64:**
```bash
curl -L -o bonjou https://github.com/hamzaabdulwahab/bonjou-cli/releases/download/v1.1.0/bonjou-linux-arm64
sudo mv bonjou /usr/local/bin/bonjou
sudo chmod +x /usr/local/bin/bonjou
```

### Option 3: Build from source

```bash
git clone https://github.com/hamzaabdulwahab/bonjou-cli.git
cd bonjou-cli
go build -o bonjou ./cmd/bonjou
sudo mv bonjou /usr/local/bin/
```

---

## Windows

### Option 1: WinGet (pre-installed on Windows 10/11)

WinGet ships with every modern Windows installation. Open PowerShell or Command Prompt:

```powershell
winget install HamzaAbdulWahab.Bonjou
```

Run:
```powershell
bonjou
```

Update later:
```powershell
winget upgrade HamzaAbdulWahab.Bonjou
```

Uninstall:
```powershell
winget uninstall HamzaAbdulWahab.Bonjou
```

> **Note:** The package must be published in the [winget-pkgs community repository](https://github.com/microsoft/winget-pkgs) for this to work.
> The submission manifest lives at `packaging/winget/HamzaAbdulWahab.Bonjou.yaml` in this repo.

### Option 2: Scoop

If you have [Scoop](https://scoop.sh) installed, open PowerShell:
```powershell
scoop install https://raw.githubusercontent.com/hamzaabdulwahab/scoop-bonjou/main/bonjou.json
```

If you prefer the classic two-step flow:
```powershell
scoop bucket add bonjou https://github.com/hamzaabdulwahab/scoop-bonjou
scoop install bonjou
```

Run:
```powershell
bonjou
```

Update later:
```powershell
scoop update bonjou
```

If download fails, clear cache first:
```powershell
scoop cache rm bonjou
scoop install bonjou
```

### Option 3: Download manually

1. Download from releases:
```powershell
Invoke-WebRequest -Uri https://github.com/hamzaabdulwahab/bonjou-cli/releases/download/v1.1.0/bonjou-windows.zip -OutFile bonjou-windows.zip
```

2. Extract:
```powershell
Expand-Archive bonjou-windows.zip -DestinationPath C:\Tools\Bonjou
```

3. Add to PATH:
   - Open System Properties > Environment Variables
   - Add `C:\Tools\Bonjou` to your Path

4. Open new terminal and run:
```powershell
bonjou
```

### Option 4: Build from source

```powershell
git clone https://github.com/hamzaabdulwahab/bonjou-cli.git
cd bonjou-cli
go build -o bonjou.exe .\cmd\bonjou
```

Move bonjou.exe to a folder in your PATH.

---

## Check if it worked

```bash
bonjou --version
```

Should show: `Bonjou v1.1.0`

---

## Offline Install (USB/AirDrop)

If you dont have internet on the target machine:

1. Download the right file on another computer:
   - Mac: `bonjou-macos.tar.gz`
   - Linux: `bonjou-linux.tar.gz`
   - Windows: `bonjou-windows.zip`

2. Copy to USB or use AirDrop

3. Follow the manual install steps above

---

## Firewall

Bonjou needs these ports open:
- UDP 46320 (finding other users)
- TCP 46321 (sending messages and files)

If you cant see other users, check your firewall settings.

## Want `brew install bonjou` and `scoop install bonjou`?

See:

- [Package Registry Submission Guide](package-registry-submission.md)
