# Package Registry Submission Guide

This guide explains how to get to the final user commands:

- `brew install bonjou`
- `scoop install bonjou`

Until these submissions are accepted, use:

- `brew install hamzaabdulwahab/bonjou/bonjou`
- `scoop install https://raw.githubusercontent.com/hamzaabdulwahab/scoop-bonjou/main/bonjou.json`

## Homebrew Core (`homebrew-core`)

### 1. Prepare formula

Use the source-build draft formula in:

- `packaging/homebrew-core/bonjou.rb`

Why this matters: `homebrew-core` generally expects source builds (not prebuilt binaries from custom URLs).

### 2. Run checks locally

```bash
brew style --fix packaging/homebrew-core/bonjou.rb
brew audit --strict --online packaging/homebrew-core/bonjou.rb
brew install --build-from-source packaging/homebrew-core/bonjou.rb
brew test bonjou
```

### 3. Submit PR

1. Fork `https://github.com/Homebrew/homebrew-core`
2. Create a branch
3. Add formula at `Formula/b/bonjou.rb`
4. Open a PR
5. Address CI and maintainer review comments

### 4. After merge

Users can install with:

```bash
brew install bonjou
```

## Scoop Main (`ScoopInstaller/Main`)

### 1. Ensure your manifest is ready

Current manifest file:

- `packaging/scoop/bonjou.json`

### 2. Validate manifest

```powershell
scoop install scoop
scoop update
scoop install sudo
scoop bucket add extras
scoop bucket add versions
scoop bucket add main
scoop install git

# Validate with your local manifest file
scoop install .\packaging\scoop\bonjou.json
```

### 3. Submit PR

1. Fork `https://github.com/ScoopInstaller/Main`
2. Add `bonjou.json` in `bucket/`
3. Open a PR
4. Address CI/reviewer feedback

### 4. After merge

Users can install with:

```powershell
scoop install bonjou
```
