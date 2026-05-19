package commands

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// cmdSetPath updates the receive directory after validating that the new
// destination is sane. By default we refuse paths outside the user's home
// (with --force as an explicit override) and reject system roots outright.
func (h *Handler) cmdSetPath(arg string) (Result, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return Result{Output: "Usage: @setpath <dir>  (use @setpath --force <dir> to accept a non-home destination)"}, nil
	}
	force := false
	if strings.HasPrefix(arg, "--force ") {
		force = true
		arg = strings.TrimSpace(strings.TrimPrefix(arg, "--force "))
	}
	if arg == "" {
		return Result{Output: "Usage: @setpath <dir>"}, nil
	}
	dir, err := normalizePathArg(arg)
	if err != nil {
		return Result{}, err
	}
	if err := validateReceivePath(dir, force); err != nil {
		return Result{Output: err.Error()}, nil
	}
	cfg := h.session.Config
	cfg.SaveDir = dir
	cfg.ReceivedFilesDir = filepath.Join(dir, "files")
	cfg.ReceivedFoldersDir = filepath.Join(dir, "folders")
	if err := cfg.EnsureDirectories(); err != nil {
		return Result{}, err
	}
	if err := cfg.Save(); err != nil {
		return Result{}, err
	}
	return Result{Output: fmt.Sprintf("Receive directory set to %s", dir)}, nil
}

// validateReceivePath blocks @setpath targets that would land incoming files
// in places they shouldn't go. System roots are rejected outright (no
// override) because writing peer-supplied filenames there is dangerous
// regardless of intent. Paths outside the user's home directory are
// allowed only with --force, to prevent a confused user from typing a
// random absolute path.
func validateReceivePath(dir string, force bool) error {
	clean := filepath.Clean(dir)
	if clean == "" || clean == "." {
		return errors.New("receive path cannot be empty")
	}
	if isBlockedSystemPath(clean) {
		return fmt.Errorf("refusing to set receive directory to a system path: %s", clean)
	}
	if force {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return nil
	}
	homeClean := filepath.Clean(home)
	if clean == homeClean {
		return nil
	}
	rel, relErr := filepath.Rel(homeClean, clean)
	if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf(
			"refusing to set receive directory outside home (%s): %s\nUse @setpath --force <dir> if you really mean this",
			homeClean, clean,
		)
	}
	return nil
}

// isBlockedSystemPath reports whether the cleaned path is a sensitive
// system directory that must never become Bonjou's receive root.
func isBlockedSystemPath(clean string) bool {
	if clean == "" {
		return false
	}
	if clean == "/" || clean == `\` {
		return true
	}
	if runtime.GOOS == "windows" {
		upper := strings.ToUpper(filepath.Clean(clean))
		for _, blocked := range []string{
			`C:\`, `C:\WINDOWS`, `C:\PROGRAM FILES`, `C:\PROGRAM FILES (X86)`,
			`C:\PROGRAMDATA`, `C:\USERS`,
		} {
			if upper == blocked {
				return true
			}
		}
		return false
	}
	for _, blocked := range []string{
		"/etc", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/usr/local",
		"/var", "/var/log", "/var/lib", "/var/run", "/lib", "/lib64", "/boot",
		"/dev", "/proc", "/sys", "/run", "/tmp",
		"/System", "/Library", "/Applications", "/private", "/cores", "/Volumes",
	} {
		if clean == blocked {
			return true
		}
	}
	return false
}
