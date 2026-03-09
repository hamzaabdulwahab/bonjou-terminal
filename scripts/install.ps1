Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo = 'hamzaabdulwahab/bonjou-cli'
$WinGetId = 'HamzaAbdulWahab.Bonjou'
$ScoopManifestUrl = 'https://raw.githubusercontent.com/hamzaabdulwahab/scoop-bonjou/main/bonjou.json'

function Write-Info {
    param([string]$Message)
    Write-Host $Message
}

function Get-LatestVersion {
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    $release = Invoke-RestMethod -Uri $api
    if (-not $release.tag_name) {
        throw 'Could not resolve latest release version from GitHub API.'
    }
    return ($release.tag_name -replace '^v', '')
}

function Add-ToUserPathIfMissing {
    param([string]$Dir)

    $currentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ([string]::IsNullOrWhiteSpace($currentPath)) {
        [Environment]::SetEnvironmentVariable('Path', $Dir, 'User')
        return
    }

    $parts = $currentPath.Split(';')
    if ($parts -notcontains $Dir) {
        [Environment]::SetEnvironmentVariable('Path', "$currentPath;$Dir", 'User')
    }
}

function Install-Direct {
    $version = Get-LatestVersion
    $url = "https://github.com/$Repo/releases/download/v$version/bonjou.exe"

    $installDir = Join-Path $env:LOCALAPPDATA 'Programs\Bonjou'
    $target = Join-Path $installDir 'bonjou.exe'

    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Write-Info "Downloading Bonjou v$version..."
    Invoke-WebRequest -Uri $url -OutFile $target

    Add-ToUserPathIfMissing -Dir $installDir
    Write-Info "Installed to $target"
    Write-Info 'Path updated for current user. Restart terminal to use bonjou.'
}

if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Info 'WinGet found. Installing via WinGet...'
    winget install $WinGetId --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -eq 0) {
        Write-Info 'Installed successfully via WinGet.'
        exit 0
    }
    Write-Info 'WinGet could not find the package (may not be published yet). Trying Scoop...'
}

if (Get-Command scoop -ErrorAction SilentlyContinue) {
    Write-Info 'Scoop found. Installing via manifest URL...'
    scoop install $ScoopManifestUrl
} else {
    Install-Direct
}
