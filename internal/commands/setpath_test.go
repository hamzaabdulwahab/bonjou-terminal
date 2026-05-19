package commands

import (
	"runtime"
	"testing"
)

func TestIsBlockedSystemPath(t *testing.T) {
	blocked := map[string]bool{
		"/":    true,
		"/etc": true,
		"/usr": true,
		"/var": true,
	}
	if runtime.GOOS == "windows" {
		blocked = map[string]bool{
			`C:\`:        true,
			`C:\WINDOWS`: true,
		}
	}
	for path, want := range blocked {
		if got := isBlockedSystemPath(path); got != want {
			t.Errorf("isBlockedSystemPath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestIsBlockedSystemPathAllowsHomeAndSubdirs(t *testing.T) {
	allowed := []string{
		"/home/alice",
		"/home/alice/Downloads",
		"/tmp/scratch", // /tmp itself is blocked, but subpaths are fine
	}
	if runtime.GOOS == "windows" {
		allowed = []string{`C:\Users\alice`, `C:\Users\alice\Downloads`}
	}
	for _, path := range allowed {
		if isBlockedSystemPath(path) {
			t.Errorf("isBlockedSystemPath(%q) = true, want false", path)
		}
	}
}

func TestValidateReceivePathRejectsSystemRoots(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("platform-specific roots are covered above")
	}
	for _, dir := range []string{"/", "/etc", "/var"} {
		if err := validateReceivePath(dir, false); err == nil {
			t.Errorf("validateReceivePath(%q) = nil, want error", dir)
		}
		// --force should not override system-root rejection.
		if err := validateReceivePath(dir, true); err == nil {
			t.Errorf("validateReceivePath(%q, force) = nil, want error", dir)
		}
	}
}
