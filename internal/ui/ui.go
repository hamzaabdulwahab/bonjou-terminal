package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chzyer/readline"

	"github.com/hamzawahab/bonjou-terminal/internal/commands"
	"github.com/hamzawahab/bonjou-terminal/internal/events"
	"github.com/hamzawahab/bonjou-terminal/internal/session"
	"github.com/hamzawahab/bonjou-terminal/internal/version"
)

const (
	colorReset          = "\033[0m"
	colorPrimary        = "\033[36m"
	colorSuccess        = "\033[32m"
	colorError          = "\033[31m"
	colorMuted          = "\033[90m"
	minProgressStep     = 5.0
	minProgressInterval = 750 * time.Millisecond
	bannerWidth         = 80
)

var welcomeBanner = []string{
	` ____                      _               `,
	`| __ )  ___  _ __ ___  ___| |_ _   _ ___   `,
	`|  _ \ / _ \| '__/ _ \/ __| __| | | / __|  `,
	`| |_) | (_) | | |  __/\__ \ |_| |_| \__ \  `,
	`|____/ \___/|_|  \___||___/\__|\__,_|___/  `,
}

type progressSnapshot struct {
	percent   float64
	lastPrint time.Time
}

// UI drives the interactive terminal session.
type UI struct {
	session    *session.Session
	handler    *commands.Handler
	rl         *readline.Instance
	done       chan struct{}
	progress   map[string]progressSnapshot
	progressMu sync.Mutex
	printMu    sync.Mutex
}

func New(session *session.Session, handler *commands.Handler) (*UI, error) {
	cfg := &readline.Config{
		Prompt:                 colorMuted + "> " + colorReset,
		InterruptPrompt:        colorMuted + "^C" + colorReset + "\n",
		EOFPrompt:              "",
		HistorySearchFold:      true,
		DisableAutoSaveHistory: true,
		Stdin:                  os.Stdin,
		Stdout:                 os.Stdout,
		Stderr:                 os.Stderr,
	}
	rl, err := readline.NewEx(cfg)
	if err != nil {
		return nil, err
	}
	return &UI{
		session:  session,
		handler:  handler,
		rl:       rl,
		done:     make(chan struct{}),
		progress: make(map[string]progressSnapshot),
	}, nil
}

// Run starts the interactive Bonjou session.
func (u *UI) Run() {
	defer u.rl.Close()
	u.printWelcome()
	go u.consumeEvents()
	for {
		line, err := u.rl.Readline()
		if err == readline.ErrInterrupt {
			u.writeLine(colorMuted + "^C" + colorReset)
			continue
		}
		if err == io.EOF {
			u.shutdown()
			return
		}
		if err != nil {
			u.writeLine(colorError + "Error reading input: " + err.Error() + colorReset)
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_ = u.rl.SaveHistory(line)
		result, err := u.handler.Handle(line)
		if err != nil {
			u.writeLine(colorError + err.Error() + colorReset)
			continue
		}
		if result.Clear {
			u.clearScreen()
			continue
		}
		if result.Output != "" {
			u.writeLine(colorSuccess + result.Output + colorReset)
		}
		if result.Quit {
			u.shutdown()
			return
		}
	}
}

func (u *UI) consumeEvents() {
	for {
		select {
		case evt := <-u.session.Events:
			u.renderEvent(evt)
		case <-u.done:
			return
		}
	}
}

func (u *UI) renderEvent(evt events.Event) {
	ts := time.Now().Format("15:04:05")
	switch evt.Type {
	case events.MessageReceived:
		u.writeLine(fmt.Sprintf("%s[%s] %s ➜ You:%s %s", colorPrimary, ts, safe(evt.From), colorReset, evt.Message))
	case events.MessageSent:
		u.writeLine(fmt.Sprintf("%s[%s] You ➜ %s:%s %s", colorMuted, ts, safe(evt.To), colorReset, evt.Message))
	case events.FileReceived, events.FolderReceived:
		u.writeLine(fmt.Sprintf("%s[%s] Received %s from %s -> %s%s", colorPrimary, ts, safe(evt.Message), safe(evt.From), evt.Path, colorReset))
	case events.FileSent, events.FolderSent:
		u.writeLine(fmt.Sprintf("%s[%s] Sent %s to %s%s", colorMuted, ts, safe(evt.Message), safe(evt.To), colorReset))
	case events.Error:
		u.writeLine(fmt.Sprintf("%s[%s] %s%s", colorError, ts, safe(evt.Message), colorReset))
	case events.Status:
		u.writeLine(fmt.Sprintf("%s[%s] %s%s", colorMuted, ts, safe(evt.Message), colorReset))
	case events.Progress:
		u.renderProgress(evt, ts)
	}
}

func (u *UI) printWelcome() {
	for _, line := range welcomeBanner {
		u.writeLine(colorPrimary + centerLine(line, bannerWidth) + colorReset)
	}
	tagline := "Terminal LAN chat & transfers like a boss."
	repo := "https://github.com/hamzaabdulwahab/bonjou-terminal"
	credit := "[with <3 by @hamzaabdulwahab]"
	u.writeLine(colorSuccess + centerLine(tagline, bannerWidth) + colorReset)
	u.writeLine(colorMuted + centerLine(repo, bannerWidth) + colorReset)
	u.writeLine(colorMuted + centerLine(credit, bannerWidth) + colorReset)
	u.writeLine("")
	u.writeLine(fmt.Sprintf("%s🌐 Welcome to Bonjou v%s%s", colorPrimary, version.Version, colorReset))
	u.writeLine(fmt.Sprintf("%s👤 User:%s %s | IP: %s", colorMuted, colorReset, u.session.Config.Username, u.session.LocalIP))
	u.writeLine(fmt.Sprintf("%s📡 LAN:%s Connected", colorMuted, colorReset))
	u.writeLine("Type @help for commands.")
}

func (u *UI) clearScreen() {
	u.printMu.Lock()
	fmt.Fprint(u.rl.Stdout(), "\033[2J\033[H")
	u.rl.Refresh()
	u.printMu.Unlock()
	u.printWelcome()
}

func (u *UI) renderProgress(evt events.Event, ts string) {
	if evt.Progress == nil || evt.Progress.Total <= 0 {
		return
	}
	percent := float64(evt.Progress.Current) / float64(evt.Progress.Total) * 100
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	label := evt.Progress.Label
	if label == "" {
		label = evt.Progress.ID
	}
	now := time.Now()
	u.progressMu.Lock()
	state, seen := u.progress[evt.Progress.ID]
	shouldPrint := false
	if evt.Progress.Done {
		delete(u.progress, evt.Progress.ID)
		shouldPrint = true
	} else {
		if percent >= 100 {
			state.percent = percent
			state.lastPrint = now
			u.progress[evt.Progress.ID] = state
			u.progressMu.Unlock()
			return
		}
		if !seen {
			state = progressSnapshot{percent: percent}
			if percent >= minProgressStep {
				shouldPrint = true
				state.lastPrint = now
			}
			u.progress[evt.Progress.ID] = state
		} else {
			if percent-state.percent >= minProgressStep && (state.lastPrint.IsZero() || now.Sub(state.lastPrint) >= minProgressInterval) {
				shouldPrint = true
				state.percent = percent
				state.lastPrint = now
				u.progress[evt.Progress.ID] = state
			} else {
				state.percent = percent
				u.progress[evt.Progress.ID] = state
			}
		}
	}
	u.progressMu.Unlock()
	if !shouldPrint {
		return
	}
	marker := colorMuted
	message := fmt.Sprintf("%s[%s] %s %.1f%%%s", marker, ts, label, percent, colorReset)
	if evt.Progress.Done {
		marker = colorSuccess
		message = fmt.Sprintf("%s[%s] %s complete%s", marker, ts, label, colorReset)
	}
	u.writeLine(message)
}

func (u *UI) shutdown() {
	select {
	case <-u.done:
	default:
		close(u.done)
	}
	u.writeLine(colorMuted + "Ending Bonjou session. Goodbye!" + colorReset)
}

func (u *UI) writeLine(line string) {
	u.printMu.Lock()
	defer u.printMu.Unlock()
	if u.rl != nil {
		fmt.Fprintf(u.rl.Stdout(), "\r\033[K%s\n", line)
		u.rl.Refresh()
	} else {
		fmt.Println(line)
	}
}

func safe(in string) string {
	if strings.TrimSpace(in) == "" {
		return "(unknown)"
	}
	return in
}

func centerLine(line string, width int) string {
	trimmed := strings.TrimRight(line, "\n")
	if len(trimmed) >= width {
		return trimmed
	}
	pad := (width - len(trimmed)) / 2
	if pad < 0 {
		pad = 0
	}
	return strings.Repeat(" ", pad) + trimmed
}
