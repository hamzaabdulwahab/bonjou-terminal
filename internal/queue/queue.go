package queue

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrQueueItemNotFound = errors.New("queue item not found")
)

const (
	snapshotFileName = "queue.json"
	pendingDirName   = "pending"
)

type PendingFile struct {
	ID        int       `json:"id"`
	RequestID string    `json:"request_id"`
	Sender    string    `json:"sender"`
	SenderIP  string    `json:"sender_ip"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Preview   string    `json:"preview,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type PendingFolder struct {
	ID        int       `json:"id"`
	RequestID string    `json:"request_id"`
	Sender    string    `json:"sender"`
	SenderIP  string    `json:"sender_ip"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Preview   string    `json:"preview,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type snapshot struct {
	NextID  int              `json:"next_id"`
	Files   []*PendingFile   `json:"files"`
	Folders []*PendingFolder `json:"folders"`
}

type Manager struct {
	mu      sync.RWMutex
	files   map[int]*PendingFile
	folders map[int]*PendingFolder
	nextID  int

	baseDir      string
	snapshotPath string
}

func NewManager(baseDir string) (*Manager, error) {
	root := filepath.Join(baseDir, pendingDirName)
	m := &Manager{
		files:        make(map[int]*PendingFile),
		folders:      make(map[int]*PendingFolder),
		nextID:       1,
		baseDir:      root,
		snapshotPath: filepath.Join(root, snapshotFileName),
	}
	if err := m.ensureDirs(); err != nil {
		return nil, err
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) AddFile(requestID, sender, senderIP, name string, size int64, preview string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := m.nextID
	m.nextID++

	item := &PendingFile{
		ID:        id,
		RequestID: strings.TrimSpace(requestID),
		Sender:    strings.TrimSpace(sender),
		SenderIP:  strings.TrimSpace(senderIP),
		Name:      filepath.Base(strings.TrimSpace(name)),
		Size:      size,
		Preview:   strings.TrimSpace(preview),
		Timestamp: time.Now(),
	}
	if item.Name == "" || item.Name == "." || item.Name == string(os.PathSeparator) {
		m.nextID--
		return 0, errors.New("invalid pending file name")
	}

	m.files[id] = item
	if err := m.saveLocked(); err != nil {
		delete(m.files, id)
		m.nextID--
		return 0, err
	}
	return id, nil
}

func (m *Manager) AddFolder(requestID, sender, senderIP, name string, size int64, preview string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := m.nextID
	m.nextID++

	item := &PendingFolder{
		ID:        id,
		RequestID: strings.TrimSpace(requestID),
		Sender:    strings.TrimSpace(sender),
		SenderIP:  strings.TrimSpace(senderIP),
		Name:      filepath.Base(strings.TrimSpace(name)),
		Size:      size,
		Preview:   strings.TrimSpace(preview),
		Timestamp: time.Now(),
	}
	if item.Name == "" || item.Name == "." || item.Name == string(os.PathSeparator) {
		m.nextID--
		return 0, errors.New("invalid pending folder name")
	}

	m.folders[id] = item
	if err := m.saveLocked(); err != nil {
		delete(m.folders, id)
		m.nextID--
		return 0, err
	}
	return id, nil
}

func (m *Manager) GetFile(id int) (*PendingFile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	file, exists := m.files[id]
	if !exists {
		return nil, ErrQueueItemNotFound
	}
	copy := *file
	return &copy, nil
}

func (m *Manager) GetFolder(id int) (*PendingFolder, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	folder, exists := m.folders[id]
	if !exists {
		return nil, ErrQueueItemNotFound
	}
	copy := *folder
	return &copy, nil
}

func (m *Manager) RemoveFile(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	file, exists := m.files[id]
	if !exists {
		return ErrQueueItemNotFound
	}

	delete(m.files, id)
	if err := m.saveLocked(); err != nil {
		m.files[id] = file
		return err
	}
	return nil
}

func (m *Manager) RemoveFolder(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	folder, exists := m.folders[id]
	if !exists {
		return ErrQueueItemNotFound
	}

	delete(m.folders, id)
	if err := m.saveLocked(); err != nil {
		m.folders[id] = folder
		return err
	}
	return nil
}

func (m *Manager) ListFiles() []*PendingFile {
	m.mu.RLock()
	defer m.mu.RUnlock()

	files := make([]*PendingFile, 0, len(m.files))
	for _, file := range m.files {
		copy := *file
		files = append(files, &copy)
	}
	return files
}

func (m *Manager) ListFolders() []*PendingFolder {
	m.mu.RLock()
	defer m.mu.RUnlock()

	folders := make([]*PendingFolder, 0, len(m.folders))
	for _, folder := range m.folders {
		copy := *folder
		folders = append(folders, &copy)
	}
	return folders
}

// Close persists metadata-only pending approvals without downloading payloads.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveLocked()
}

func (m *Manager) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Metadata-first approvals do not stage incoming payloads on disk.
	// Flushing clears only persisted queue metadata.
	m.files = make(map[int]*PendingFile)
	m.folders = make(map[int]*PendingFolder)
	m.nextID = 1
	return m.saveLocked()
}

func (m *Manager) ensureDirs() error {
	// The pending directory is metadata-only and currently stores queue.json.
	return os.MkdirAll(m.baseDir, 0o755)
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.snapshotPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return m.saveLocked()
		}
		return err
	}

	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		corruptPath := m.snapshotPath + ".corrupt"
		_ = os.Remove(corruptPath)
		if moveErr := os.Rename(m.snapshotPath, corruptPath); moveErr != nil {
			_ = os.Remove(m.snapshotPath)
		}
		m.files = make(map[int]*PendingFile)
		m.folders = make(map[int]*PendingFolder)
		m.nextID = 1
		return m.saveLocked()
	}

	m.files = make(map[int]*PendingFile)
	m.folders = make(map[int]*PendingFolder)

	maxID := 0

	for _, file := range snap.Files {
		if file == nil {
			continue
		}
		if strings.TrimSpace(file.Name) == "" {
			continue
		}
		copy := *file
		copy.Name = filepath.Base(strings.TrimSpace(copy.Name))
		copy.RequestID = strings.TrimSpace(copy.RequestID)
		copy.Sender = strings.TrimSpace(copy.Sender)
		copy.SenderIP = strings.TrimSpace(copy.SenderIP)
		copy.Preview = strings.TrimSpace(copy.Preview)
		m.files[copy.ID] = &copy
		if copy.ID > maxID {
			maxID = copy.ID
		}
	}

	for _, folder := range snap.Folders {
		if folder == nil {
			continue
		}
		if strings.TrimSpace(folder.Name) == "" {
			continue
		}
		copy := *folder
		copy.Name = filepath.Base(strings.TrimSpace(copy.Name))
		copy.RequestID = strings.TrimSpace(copy.RequestID)
		copy.Sender = strings.TrimSpace(copy.Sender)
		copy.SenderIP = strings.TrimSpace(copy.SenderIP)
		copy.Preview = strings.TrimSpace(copy.Preview)
		m.folders[copy.ID] = &copy
		if copy.ID > maxID {
			maxID = copy.ID
		}
	}

	if snap.NextID > maxID {
		m.nextID = snap.NextID
	} else {
		m.nextID = maxID + 1
	}
	if m.nextID <= 0 {
		m.nextID = 1
	}

	return m.saveLocked()
}

func (m *Manager) saveLocked() error {
	if err := m.ensureDirs(); err != nil {
		return err
	}

	files := make([]*PendingFile, 0, len(m.files))
	for _, file := range m.files {
		copy := *file
		files = append(files, &copy)
	}

	folders := make([]*PendingFolder, 0, len(m.folders))
	for _, folder := range m.folders {
		copy := *folder
		folders = append(folders, &copy)
	}

	data, err := json.MarshalIndent(snapshot{
		NextID:  m.nextID,
		Files:   files,
		Folders: folders,
	}, "", "  ")
	if err != nil {
		return err
	}

	tempPath := m.snapshotPath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		return err
	}
	if err := os.Remove(m.snapshotPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(tempPath)
		return err
	}
	if err := os.Rename(tempPath, m.snapshotPath); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return nil
}

func UniquePath(path string) string {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return path
	}

	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)

	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}
}

func MoveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	return errors.New("move not supported: pending storage is metadata-only")
}
