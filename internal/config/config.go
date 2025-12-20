package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const configFileName = "config.json"

// Config captures runtime and persistent settings for Bonjou.
type Config struct {
	Username           string `json:"username"`
	ListenPort         int    `json:"listen_port"`
	DiscoveryPort      int    `json:"discovery_port"`
	BaseDir            string `json:"base_dir"`
	SaveDir            string `json:"save_dir"`
	LogDir             string `json:"log_dir"`
	ReceivedFilesDir   string `json:"received_files_dir"`
	ReceivedFoldersDir string `json:"received_folders_dir"`
	Secret             string `json:"secret"`
	LastUpdated        int64  `json:"last_updated"`
	configPath         string `json:"-"`
}

// Load retrieves persisted configuration or writes defaults if missing.
func Load() (*Config, error) {
	base, err := defaultBaseDir()
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(base, configFileName)
	cfg := &Config{configPath: cfgPath}
	if _, err := os.Stat(cfgPath); errors.Is(err, os.ErrNotExist) {
		cfg = Default()
		cfg.configPath = cfgPath
		if err := cfg.Save(); err != nil {
			return nil, err
		}
		return cfg, nil
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.configPath = cfgPath
	cfg.populateDerived()
	return cfg, nil
}

// Default assembles a usable configuration with sensible defaults.
func Default() *Config {
	base, _ := defaultBaseDir()
	username := os.Getenv("BONJOU_USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	if username == "" {
		username = os.Getenv("USERNAME")
	}
	if username == "" {
		username = "bonjou-user"
	}
	secret := randomHex(32)
	cfg := &Config{
		Username:           username,
		ListenPort:         46321,
		DiscoveryPort:      46320,
		BaseDir:            base,
		SaveDir:            filepath.Join(base, "received"),
		LogDir:             filepath.Join(base, "logs"),
		ReceivedFilesDir:   filepath.Join(base, "received", "files"),
		ReceivedFoldersDir: filepath.Join(base, "received", "folders"),
		Secret:             secret,
		LastUpdated:        time.Now().Unix(),
	}
	cfg.populateDerived()
	return cfg
}

// Save persists configuration to disk.
func (c *Config) Save() error {
	c.populateDerived()
	if err := os.MkdirAll(filepath.Dir(c.configPath), 0o755); err != nil {
		return err
	}
	c.LastUpdated = time.Now().Unix()
	data, err := json.MarshalIndent(struct {
		Username           string `json:"username"`
		ListenPort         int    `json:"listen_port"`
		DiscoveryPort      int    `json:"discovery_port"`
		BaseDir            string `json:"base_dir"`
		SaveDir            string `json:"save_dir"`
		LogDir             string `json:"log_dir"`
		ReceivedFilesDir   string `json:"received_files_dir"`
		ReceivedFoldersDir string `json:"received_folders_dir"`
		Secret             string `json:"secret"`
		LastUpdated        int64  `json:"last_updated"`
	}{
		Username:           c.Username,
		ListenPort:         c.ListenPort,
		DiscoveryPort:      c.DiscoveryPort,
		BaseDir:            c.BaseDir,
		SaveDir:            c.SaveDir,
		LogDir:             c.LogDir,
		ReceivedFilesDir:   c.ReceivedFilesDir,
		ReceivedFoldersDir: c.ReceivedFoldersDir,
		Secret:             c.Secret,
		LastUpdated:        c.LastUpdated,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.configPath, data, 0o600)
}

// EnsureDirectories prepares the filesystem layout required by Bonjou.
func (c *Config) EnsureDirectories() error {
	c.populateDerived()
	dirs := []string{c.BaseDir, c.SaveDir, c.LogDir, c.ReceivedFilesDir, c.ReceivedFoldersDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// ConfigDir exposes the directory holding configuration artifacts.
func (c *Config) ConfigDir() string {
	dir, _ := filepath.Split(c.configPath)
	if dir == "" {
		base, _ := defaultBaseDir()
		return base
	}
	return strings.TrimSuffix(dir, string(filepath.Separator))
}

func (c *Config) populateDerived() {
	if c.BaseDir == "" {
		base, _ := defaultBaseDir()
		c.BaseDir = base
	}
	if c.SaveDir == "" {
		c.SaveDir = filepath.Join(c.BaseDir, "received")
	}
	if c.LogDir == "" {
		c.LogDir = filepath.Join(c.BaseDir, "logs")
	}
	if c.ReceivedFilesDir == "" {
		c.ReceivedFilesDir = filepath.Join(c.BaseDir, "received", "files")
	}
	if c.ReceivedFoldersDir == "" {
		c.ReceivedFoldersDir = filepath.Join(c.BaseDir, "received", "folders")
	}
	if c.Secret == "" {
		c.Secret = randomHex(32)
	}
	if c.configPath == "" {
		base, _ := defaultBaseDir()
		c.configPath = filepath.Join(base, configFileName)
	}
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

func defaultBaseDir() (string, error) {
	if dir := os.Getenv("BONJOU_HOME"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".bonjou"), nil
}

// GetLocalIP tries to resolve a LAN-reachable IPv4 address.
func GetLocalIP() (string, error) {
	conn, err := net.Dial("udp", "198.51.100.1:80")
	if err != nil {
		return fallbackIP(), nil
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

func fallbackIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	if runtime.GOOS == "windows" {
		return "127.0.0.1"
	}
	return "127.0.0.1"
}
