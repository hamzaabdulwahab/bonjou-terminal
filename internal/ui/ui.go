package ui

import (
	"fmt"
	"io"
	"math"
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
	` ____    ___    _   _       _     ___    _   _ `,
	`| __ )  / _ \  | \ | |     | |   / _ \  | | | |`,
	`|  _ \ | | | | |  \| |  _  | |  | | | | | | | |`,
	`| |_) || |_| | | |\  | | |_| | | |_| | | |_| |`,
	`|____/  \___/  |_| \_|  \___/   \___/   \___/ `,
}

type progressSnapshot struct {
	percent   float64
	lastPrint time.Time
	started   time.Time
	path      string
	peer      string
	direction string
	kind      string
	label     string
}

// UI drives the interactive terminal session.
type UI struct {
	session        *session.Session
	handler        *commands.Handler
	rl             *readline.Instance
	done           chan struct{}
	progress       map[string]progressSnapshot
	progressMu     sync.Mutex
	printMu        sync.Mutex
	homeDir        string
	lastProgressID string
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
	home, _ := os.UserHomeDir()
	return &UI{
		session:  session,
		handler:  handler,
		rl:       rl,
		done:     make(chan struct{}),
		progress: make(map[string]progressSnapshot),
		homeDir:  home,
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
	credit := "[with ❤️ by @hamzaabdulwahab]"
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
	ps := evt.Progress
	if ps == nil || ps.Total <= 0 {
		return
	}
	percent := float64(ps.Current) / float64(ps.Total) * 100
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	now := time.Now()

	u.progressMu.Lock()
	snapshot, seen := u.progress[ps.ID]
	shouldPrint := false
	if !seen {
		snapshot = progressSnapshot{}
		shouldPrint = true
	}
	if ps.Path != "" {
		snapshot.path = ps.Path
	}
	if ps.Peer != "" {
		snapshot.peer = ps.Peer
	}
	if ps.Direction != "" {
		snapshot.direction = ps.Direction
	}
	if ps.Kind != "" {
		snapshot.kind = ps.Kind
	}
	if ps.Label != "" {
		snapshot.label = ps.Label
	}
	if !ps.StartedAt.IsZero() {
		snapshot.started = ps.StartedAt
	} else if snapshot.started.IsZero() {
		snapshot.started = now
	}
	prevPercent := snapshot.percent
	snapshot.percent = percent

	if ps.Done {
		shouldPrint = true
		snapshot.lastPrint = now
		delete(u.progress, ps.ID)
	} else {
		delta := math.Abs(percent - prevPercent)
		if !seen || delta >= minProgressStep || now.Sub(snapshot.lastPrint) >= minProgressInterval {
			shouldPrint = true
			snapshot.lastPrint = now
		}
		u.progress[ps.ID] = snapshot
	}
	u.progressMu.Unlock()

	if !shouldPrint {
		return
	}

	line := u.formatProgressLine(ts, ps, snapshot, percent, ps.Done, now)
	u.printProgressLine(ps.ID, line, ps.Done)
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
	u.lastProgressID = ""
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

func (u *UI) formatProgressLine(ts string, ps *events.ProgressState, snapshot progressSnapshot, percent float64, done bool, now time.Time) string {
	path := snapshot.path
	if path == "" && ps != nil {
		if ps.Path != "" {
			path = ps.Path
		} else if ps.Label != "" {
			path = ps.Label
		} else {
			path = ps.ID
		}
	}
	if path == "" {
		path = "(unknown)"
	}
	pathSegment := u.colorizePath(path)
	icon := progressIcon(snapshot.direction, snapshot.kind)
	if icon != "" {
		pathSegment = icon + " " + pathSegment
	}
	circle := progressCircle(percent, done)
	percentSegment := formatPercent(percent, done)
	statusSegment := u.progressStatus(snapshot.started, percent, done, now)
	peerSegment := u.progressPeer(snapshot.direction, snapshot.peer)
	return fmt.Sprintf("%s[%s]%s %s %s %s%s%s", colorMuted, ts, colorReset, pathSegment, circle, percentSegment, statusSegment, peerSegment)
}

func (u *UI) printProgressLine(id, line string, done bool) {
	u.printMu.Lock()
	defer u.printMu.Unlock()
	if u.rl == nil {
		fmt.Println(line)
		return
	}
	out := u.rl.Stdout()
	if u.lastProgressID == id {
		fmt.Fprintf(out, "\033[1A\r\033[K%s\n", line)
	} else {
		fmt.Fprintf(out, "\r\033[K%s\n", line)
	}
	if done {
		u.lastProgressID = ""
	} else {
		u.lastProgressID = id
	}
	u.rl.Refresh()
}

func (u *UI) colorizePath(path string) string {
	clean := path
	if u.homeDir != "" && strings.HasPrefix(path, u.homeDir) {
		suffix := strings.TrimPrefix(path, u.homeDir)
		suffix = strings.TrimPrefix(suffix, string(os.PathSeparator))
		if suffix == "" {
			clean = "~"
		} else {
			clean = "~" + string(os.PathSeparator) + suffix
		}
	}
	return colorPrimary + clean + colorReset
}

func progressIcon(direction, kind string) string {
	switch kind {
	case "folder":
		if strings.EqualFold(direction, "receive") {
			return "🗃️"
		}
		return "🗂️"
	case "file":
		if strings.EqualFold(direction, "receive") {
			return "📥"
		}
		return "📤"
	default:
		if strings.EqualFold(direction, "receive") {
			return "⬇"
		}
		return "⬆"
	}
}

func progressCircle(percent float64, done bool) string {
	const segments = 10
	filled := int(math.Round(percent / 100 * segments))
	if filled < 0 {
		filled = 0
	}
	if filled > segments {
		filled = segments
	}
	var builder strings.Builder
	builder.WriteString("⟨")
	if filled > 0 {
		color := colorPrimary
		if done {
			color = colorSuccess
		}
		builder.WriteString(color)
		builder.WriteString(strings.Repeat("●", filled))
		builder.WriteString(colorReset)
	}
	if segments-filled > 0 {
		builder.WriteString(colorMuted)
		builder.WriteString(strings.Repeat("○", segments-filled))
		builder.WriteString(colorReset)
	}
	builder.WriteString("⟩")
	return builder.String()
}

func formatPercent(percent float64, done bool) string {
	color := colorPrimary
	if done {
		color = colorSuccess
	}
	return fmt.Sprintf("%s%5.1f%%%s", color, percent, colorReset)
}

func (u *UI) progressStatus(start time.Time, percent float64, done bool, now time.Time) string {
	if done {
		if start.IsZero() {
			return fmt.Sprintf(" %sCompleted%s", colorSuccess, colorReset)
		}
		return fmt.Sprintf(" %sCompleted%s in %s", colorSuccess, colorReset, formatDuration(now.Sub(start)))
	}
	eta := formatETA(start, now, percent)
	return fmt.Sprintf(" %sETA%s %s%s%s", colorMuted, colorReset, colorPrimary, eta, colorReset)
}

func (u *UI) progressPeer(direction, peer string) string {
	if strings.TrimSpace(peer) == "" {
		return ""
	}
	arrow := "➜"
	if strings.EqualFold(direction, "receive") {
		arrow = "⬅"
	}
	return fmt.Sprintf(" %s%s%s %s%s%s", colorMuted, arrow, colorReset, colorPrimary, peer, colorReset)
}

func formatETA(start time.Time, now time.Time, percent float64) string {
	progress := percent / 100
	if progress <= 0 || start.IsZero() {
		return "--:--"
	}
	elapsed := now.Sub(start)
	if elapsed <= 0 {
		return "--:--"
	}
	remaining := time.Duration(float64(elapsed) * (1 - progress) / progress)
	if remaining < 0 {
		remaining = 0
	}
	return formatDuration(remaining)
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d >= 24*time.Hour {
		days := int(d / (24 * time.Hour))
		return fmt.Sprintf("%dd", days)
	}
	hours := int(d / time.Hour)
	minutes := int(d/time.Minute) % 60
	seconds := int(d/time.Second) % 60
	if hours > 0 {
		return fmt.Sprintf("%d:%02d:%02d", hours, minutes, seconds)
	}
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}
