package config

// SecretStore abstracts where the long-term identity secret lives. In
// the current build we still persist the secret inside ~/.bonjou/config.json
// (mode 0600), but routing access through this interface lets a future
// release plug in an OS keychain backend (Keychain on macOS, Secret
// Service on Linux, DPAPI on Windows) without touching every caller.
//
// Today's implementation is a thin shim around the Config struct: Load
// returns the secret already on disk and Save writes the in-memory
// Config back to disk via its existing Save() method. The "where does
// the byte live" decision sits behind one indirection.
type SecretStore interface {
	// Load reads the persisted secret. An empty string with no error means
	// "no secret stored yet"; callers should generate one.
	Load() (string, error)
	// Save persists the secret. Implementations must use restrictive
	// permissions / OS-level protection where available.
	Save(secret string) error
}

// FileSecretStore is the default implementation: the secret lives inside
// the JSON config file. The whole file is mode 0600, which on Unix
// blocks other users but not other processes running as the same user.
//
// TODO(secretstore-keychain): on macOS use Security.framework
// (golang.org/x/sys/keychain or 99designs/keyring), on Linux use the
// Secret Service via D-Bus, on Windows use DPAPI. Fall through to this
// file-backed store if the platform-specific store is unavailable.
type FileSecretStore struct {
	cfg *Config
}

// NewFileSecretStore binds a SecretStore to the given Config so its
// in-memory Secret field stays in sync with what's persisted.
func NewFileSecretStore(cfg *Config) *FileSecretStore {
	return &FileSecretStore{cfg: cfg}
}

func (s *FileSecretStore) Load() (string, error) {
	if s == nil || s.cfg == nil {
		return "", nil
	}
	return s.cfg.Secret, nil
}

func (s *FileSecretStore) Save(secret string) error {
	if s == nil || s.cfg == nil {
		return nil
	}
	s.cfg.Secret = secret
	return s.cfg.Save()
}
