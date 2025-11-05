package events

import "time"

// Type enumerates high-level UI events.
type Type string

const (
	MessageReceived Type = "message_received"
	MessageSent     Type = "message_sent"
	FileReceived    Type = "file_received"
	FileSent        Type = "file_sent"
	FolderReceived  Type = "folder_received"
	FolderSent      Type = "folder_sent"
	Status          Type = "status"
	Error           Type = "error"
	Progress        Type = "progress"
)

// Event carries data between background services and the UI renderer.
type Event struct {
	Type      Type
	Title     string
	Message   string
	From      string
	To        string
	Path      string
	Size      int64
	Timestamp time.Time
	Progress  *ProgressState
	Level     string
}

// ProgressState models transfer progress updates.
type ProgressState struct {
	ID        string
	Current   int64
	Total     int64
	Label     string
	Done      bool
	Path      string
	Peer      string
	Direction string
	Kind      string
	StartedAt time.Time
	UpdatedAt time.Time
}
