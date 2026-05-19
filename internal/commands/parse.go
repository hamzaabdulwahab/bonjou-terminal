package commands

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// ansiPrefixPattern matches leading CSI sequences that may sneak into
// command input (e.g. the trailing cursor-position report after a paste).
var ansiPrefixPattern = regexp.MustCompile(`^(?:\x1b\[[0-9;?]*[A-Za-z])+`)

// sanitizeCommandInput strips leading ANSI escapes and control characters
// before the @command parser sees the line. Without this, a stray cursor
// report after a paste would cause "Commands must start with @" errors on
// otherwise valid input.
func sanitizeCommandInput(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return ""
	}
	trimmed = ansiPrefixPattern.ReplaceAllString(trimmed, "")
	trimmed = strings.TrimLeftFunc(trimmed, func(r rune) bool {
		if unicode.IsSpace(r) {
			return true
		}
		return unicode.IsControl(r)
	})
	return trimmed
}

// splitMultiArgs splits the @multi argument into a target list and the
// trailing payload. Targets are comma-separated; the payload starts at the
// first whitespace that isn't part of the comma-separated target list.
func splitMultiArgs(input string) (string, string, bool) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", "", false
	}
	lastNonSpace := rune(0)
	for idx, r := range trimmed {
		if unicode.IsSpace(r) {
			if lastNonSpace != ',' {
				targets := strings.TrimSpace(trimmed[:idx])
				payload := strings.TrimSpace(trimmed[idx:])
				if targets == "" || payload == "" {
					return "", "", false
				}
				return targets, payload, true
			}
			continue
		}
		lastNonSpace = r
	}
	return "", "", false
}

// normalizePathArg turns a user-supplied path into an absolute, cleaned
// path. Supports ~ home expansion, ' or " quote stripping, and resolves
// relative paths against the process working directory.
func normalizePathArg(input string) (string, error) {
	path := strings.TrimSpace(input)
	if path == "" {
		return "", errors.New("empty path")
	}
	if len(path) >= 2 {
		if (path[0] == '"' && path[len(path)-1] == '"') || (path[0] == '\'' && path[len(path)-1] == '\'') {
			path = strings.TrimSpace(path[1 : len(path)-1])
		}
	}
	if path == "" {
		return "", errors.New("empty path")
	}
	if strings.HasPrefix(path, "~") {
		if len(path) > 1 && path[1] != '/' && path[1] != '\\' {
			return "", fmt.Errorf("unsupported home expansion for %s", path)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			path = home
		} else {
			cleaned := strings.TrimPrefix(path, "~")
			cleaned = strings.TrimPrefix(cleaned, "/")
			cleaned = strings.TrimPrefix(cleaned, "\\")
			path = filepath.Join(home, cleaned)
		}
	}
	if !filepath.IsAbs(path) {
		cwd, _ := os.Getwd()
		path = filepath.Join(cwd, path)
	}
	return filepath.Clean(path), nil
}
