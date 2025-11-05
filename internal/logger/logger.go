package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger wraps log.Logger with file persistence.
type Logger struct {
	mu   sync.Mutex
	file *os.File
	std  *log.Logger
}

// New creates a file-based logger rooted at dir.
func New(dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("bonjou-%s.log", time.Now().Format("20060102"))
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	lg := &Logger{file: file}
	lg.std = log.New(file, "", log.LstdFlags|log.Lmicroseconds)
	return lg, nil
}

// Close flushes and closes underlying file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

// Info logs informational messages.
func (l *Logger) Info(format string, args ...any) {
	l.output("INFO", format, args...)
}

// Error logs error messages.
func (l *Logger) Error(format string, args ...any) {
	l.output("ERROR", format, args...)
}

func (l *Logger) output(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.std == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	l.std.Printf("[%s] %s", level, msg)
}
