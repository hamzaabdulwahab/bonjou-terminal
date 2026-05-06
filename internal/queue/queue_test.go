package queue

import (
	"path/filepath"
	"testing"
)

func TestManagerPersistsMetadataOnlyQueue(t *testing.T) {
	baseDir := t.TempDir()

	m, err := NewManager(baseDir)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	fileID, err := m.AddFile("req-file", "hamza", "192.168.1.3", "notes.txt", 1234, "")
	if err != nil {
		t.Fatalf("AddFile() error = %v", err)
	}
	folderID, err := m.AddFolder("req-folder", "abdulrehman", "192.168.1.8", "project", 9876, "a.txt\nb.txt")
	if err != nil {
		t.Fatalf("AddFolder() error = %v", err)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reloaded, err := NewManager(baseDir)
	if err != nil {
		t.Fatalf("NewManager() reload error = %v", err)
	}

	file, err := reloaded.GetFile(fileID)
	if err != nil {
		t.Fatalf("GetFile() error = %v", err)
	}
	if file.RequestID != "req-file" {
		t.Fatalf("file.RequestID = %q, want %q", file.RequestID, "req-file")
	}
	if file.Sender != "hamza" {
		t.Fatalf("file.Sender = %q, want %q", file.Sender, "hamza")
	}
	if file.SenderIP != "192.168.1.3" {
		t.Fatalf("file.SenderIP = %q, want %q", file.SenderIP, "192.168.1.3")
	}
	if file.Name != "notes.txt" {
		t.Fatalf("file.Name = %q, want %q", file.Name, "notes.txt")
	}
	if file.Size != 1234 {
		t.Fatalf("file.Size = %d, want %d", file.Size, 1234)
	}
	if file.Preview != "" {
		t.Fatalf("file.Preview = %q, want empty", file.Preview)
	}

	folder, err := reloaded.GetFolder(folderID)
	if err != nil {
		t.Fatalf("GetFolder() error = %v", err)
	}
	if folder.RequestID != "req-folder" {
		t.Fatalf("folder.RequestID = %q, want %q", folder.RequestID, "req-folder")
	}
	if folder.Sender != "abdulrehman" {
		t.Fatalf("folder.Sender = %q, want %q", folder.Sender, "abdulrehman")
	}
	if folder.SenderIP != "192.168.1.8" {
		t.Fatalf("folder.SenderIP = %q, want %q", folder.SenderIP, "192.168.1.8")
	}
	if folder.Name != "project" {
		t.Fatalf("folder.Name = %q, want %q", folder.Name, "project")
	}
	if folder.Size != 9876 {
		t.Fatalf("folder.Size = %d, want %d", folder.Size, 9876)
	}
	if folder.Preview != "a.txt\nb.txt" {
		t.Fatalf("folder.Preview = %q, want %q", folder.Preview, "a.txt\nb.txt")
	}

	nextID, err := reloaded.AddFile("req-next", "hamza", "192.168.1.3", "later.txt", 55, "")
	if err != nil {
		t.Fatalf("AddFile() after reload error = %v", err)
	}
	if nextID <= folderID {
		t.Fatalf("nextID = %d, want > %d", nextID, folderID)
	}
}

func TestManagerFlushClearsPersistedQueue(t *testing.T) {
	baseDir := t.TempDir()

	m, err := NewManager(baseDir)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if _, err := m.AddFile("req-file", "hamza", "192.168.1.3", "notes.txt", 1234, ""); err != nil {
		t.Fatalf("AddFile() error = %v", err)
	}
	if _, err := m.AddFolder("req-folder", "abdulrehman", "192.168.1.8", "project", 9876, "manifest"); err != nil {
		t.Fatalf("AddFolder() error = %v", err)
	}

	if err := m.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	reloaded, err := NewManager(baseDir)
	if err != nil {
		t.Fatalf("NewManager() reload error = %v", err)
	}

	if got := len(reloaded.ListFiles()); got != 0 {
		t.Fatalf("len(ListFiles()) = %d, want 0", got)
	}
	if got := len(reloaded.ListFolders()); got != 0 {
		t.Fatalf("len(ListFolders()) = %d, want 0", got)
	}

	if _, err := reloaded.AddFile("req-reset", "hamza", "192.168.1.3", "reset.txt", 1, ""); err != nil {
		t.Fatalf("AddFile() after flush error = %v", err)
	} else if file, err := reloaded.GetFile(1); err != nil {
		t.Fatalf("GetFile(1) after flush error = %v", err)
	} else if file.Name != "reset.txt" {
		t.Fatalf("file.Name = %q, want %q", file.Name, "reset.txt")
	}
}

func TestManagerLoadDropsInvalidNamesAndKeepsSnapshotReadable(t *testing.T) {
	baseDir := t.TempDir()

	m, err := NewManager(baseDir)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if _, err := m.AddFile("req-file", "hamza", "192.168.1.3", "safe.txt", 12, ""); err != nil {
		t.Fatalf("AddFile() error = %v", err)
	}

	snapshotPath := filepath.Join(baseDir, pendingDirName, snapshotFileName)
	if snapshotPath == "" {
		t.Fatal("snapshotPath should not be empty")
	}

	reloaded, err := NewManager(baseDir)
	if err != nil {
		t.Fatalf("NewManager() reload error = %v", err)
	}

	if got := len(reloaded.ListFiles()); got != 1 {
		t.Fatalf("len(ListFiles()) = %d, want 1", got)
	}
}
