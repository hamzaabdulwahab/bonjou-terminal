# Upstream PR Patches

These patches are ready to apply in forked upstream repositories.

## 1) Homebrew Core

Target repository:

- https://github.com/Homebrew/homebrew-core

Apply patch in your local `homebrew-core` clone:

```bash
git apply /path/to/bonjou-cli/packaging/upstream-pr/homebrew-core.patch
brew style --fix Formula/b/bonjou.rb
brew audit --strict --online Formula/b/bonjou.rb
brew install --build-from-source Formula/b/bonjou.rb
brew test bonjou
```

Then commit and open PR.

## 2) Scoop Main

Target repository:

- https://github.com/ScoopInstaller/Main

Apply patch in your local `ScoopInstaller/Main` clone:

```powershell
git apply C:\path\to\bonjou-cli\packaging\upstream-pr\scoop-main.patch
```

Optional local test from your cloned main bucket:

```powershell
scoop install .\bucket\bonjou.json
```

Then commit and open PR.

## Notes

- Replace `/path/to/bonjou-cli` and `C:\path\to\bonjou-cli` with your real path.
- `index` hashes in patch files are placeholders and harmless for `git apply`.
- If maintainers request style changes, keep version/hash/url the same and adjust formatting only.
