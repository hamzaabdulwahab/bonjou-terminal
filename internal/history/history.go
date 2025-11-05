package history

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/hamzawahab/bonjou-terminal/internal/config"
)

type Manager struct {
	cfg *config.Config
	mu  sync.Mutex
}

func New(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg}
}

func (m *Manager) chatLogPath() string {
	return filepath.Join(m.cfg.LogDir, "chat.log")
}

func (m *Manager) transferLogPath() string {
	return filepath.Join(m.cfg.LogDir, "transfers.log")
}

func (m *Manager) AppendChat(from, to, message string) error {
	entry := time.Now().Format(time.RFC3339) + " | chat | " + from + " -> " + to + " | " + message + "\n"
	return m.append(m.chatLogPath(), entry)
}

func (m *Manager) AppendTransfer(from, to, path string, size int64, kind string) error {
	entry := time.Now().Format(time.RFC3339) + " | transfer | " + kind + " | " + from + " -> " + to + " | " + path + " | bytes=" + strconv.FormatInt(size, 10) + "\n"
	return m.append(m.transferLogPath(), entry)
}

func (m *Manager) append(path, entry string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(entry)
	return err
}

func (m *Manager) ReadAll() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	chats, err := readLines(m.chatLogPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	transfers, err := readLines(m.transferLogPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	out := append(chats, transfers...)
	return out, nil
}

func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	paths := []string{m.chatLogPath(), m.transferLogPath()}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
