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
	"golang.org/x/term"

	"github.com/hamzawahab/bonjou-terminal/internal/commands"
	"github.com/hamzawahab/bonjou-terminal/internal/events"
	"github.com/hamzawahab/bonjou-terminal/internal/session"
	"github.com/hamzawahab/bonjou-terminal/internal/version"
)

const (
	colorReset   = "\033[0m"
	colorPrimary = "\033[36m"
	colorSuccess = "\033[32m"
	colorError   = "\033[31m"
	colorMuted   = "\033[90m"
	bannerWidth  = 80
)

var welcomeBanner = []string{
	` ____    ___    _   _       _     ___    _   _ `,
	`| __ )  / _ \  | \ | |     | |   / _ \  | | | |`,
	`|  _ \ | | | | |  \| |  _  | |  | | | | | | | |`,
	`| |_) || |_| | | |\  | | |_| | | |_| | | |_| |`,
	`|____/  \___/  |_| \_|  \___/   \___/   \___/ `,
}

type UI struct {
	session *session.Session
	handler *commands.Handler
	rl      *readline.Instance
	done    chan struct{}

	printMu    sync.Mutex
	progressMu sync.Mutex
	homeDir    string

	progressActive bool
	progressID     string
	progressLine   string
}

func New(session *session.Session, handler *commands.Handler) (*UI, error) {
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
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
	configureReadline(cfg)
	enableANSI()
	rl, err := readline.NewEx(cfg)
	if err != nil {
		return nil, err
	}
	if !interactive {
		fmt.Fprintln(os.Stderr, colorMuted+"(Limited terminal detected; line editing shortcuts may be unavailable.)"+colorReset)
	}
	home, _ := os.UserHomeDir()
	return &UI{
		session: session,
		handler: handler,
		rl:      rl,
		done:    make(chan struct{}),
		homeDir: home,
	}, nil
}

func configureReadline(cfg *readline.Config) {
	cfg.HistoryLimit = 1024
	cfg.FuncIsTerminal = func() bool {
		return term.IsTerminal(int(os.Stdin.Fd()))
	}
	cfg.FuncGetWidth = func() int {
		width, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil || width <= 0 {
			return bannerWidth
		}
		return width
	}
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
	if u.rl == nil {
		fmt.Print("\033[2J\033[H")
	} else {
		u.printMu.Lock()
		fmt.Fprint(u.rl.Stdout(), "\033[2J\033[H")
		u.printMu.Unlock()
		u.rl.Refresh()
	}
	u.progressMu.Lock()
	u.progressActive = false
	u.progressLine = ""
	u.progressID = ""
	u.progressMu.Unlock()
	u.printWelcome()
}

func (u *UI) renderProgress(evt events.Event, ts string) {
	ps := evt.Progress
	if ps == nil || ps.Total <= 0 {
		return
	}
	if strings.EqualFold(ps.Direction, "receive") {
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
	line := u.formatProgressLine(ts, ps, percent, ps.Done, now)
	if ps.Done {
		u.finishProgressLine(ps.ID, line)
		return
	}
	u.updateProgressLine(ps.ID, line)
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
	u.progressMu.Lock()
	active := u.progressActive
	progressLine := u.progressLine
	u.progressMu.Unlock()

	if u.rl == nil {
		fmt.Printf("\r\033[K%s\n", line)
		if active {
			fmt.Printf("%s", progressLine)
		}
		return
	}

	u.printMu.Lock()
	fmt.Fprintf(u.rl.Stdout(), "\r\033[K%s\n", line)
	if active {
		fmt.Fprintf(u.rl.Stdout(), "%s", progressLine)
	}
	u.printMu.Unlock()
	u.rl.Refresh()
}

func (u *UI) updateProgressLine(id, line string) {
	u.progressMu.Lock()
	u.progressActive = true
	u.progressID = id
	u.progressLine = line
	u.progressMu.Unlock()

	if u.rl == nil {
		fmt.Printf("\r\033[K%s", line)
		return
	}

	u.printMu.Lock()
	fmt.Fprintf(u.rl.Stdout(), "\r\033[K%s", line)
	u.printMu.Unlock()
	u.rl.Refresh()
}

func (u *UI) finishProgressLine(id, line string) {
	var resume bool
	var resumeID string
	var resumeLine string

	u.progressMu.Lock()
	if u.progressActive && u.progressID != id {
		resume = true
		resumeID = u.progressID
		resumeLine = u.progressLine
	}
	if u.progressID == id {
		u.progressActive = false
		u.progressLine = ""
		u.progressID = ""
	}
	u.progressMu.Unlock()

	if u.rl == nil {
		fmt.Printf("\r\033[K%s\n", line)
	} else {
		u.printMu.Lock()
		fmt.Fprintf(u.rl.Stdout(), "\r\033[K%s\n", line)
		u.printMu.Unlock()
		u.rl.Refresh()
	}

	if resume {
		u.updateProgressLine(resumeID, resumeLine)
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

func (u *UI) formatProgressLine(ts string, ps *events.ProgressState, percent float64, done bool, now time.Time) string {
	path := strings.TrimSpace(ps.Path)
	if path == "" {
		path = strings.TrimSpace(ps.Label)
	}
	if path == "" {
		path = ps.ID
	}
	if path == "" {
		path = "(unknown)"
	}
	pathSegment := u.colorizePath(path)
	icon := progressIcon(ps.Direction, ps.Kind)
	if icon != "" {
		pathSegment = icon + " " + pathSegment
	}
	circle := progressCircle(percent, done)
	percentSegment := formatPercent(percent, done)
	statusSegment := u.progressStatus(ps.StartedAt, percent, done, now)
	peerSegment := u.progressPeer(ps.Direction, ps.Peer)
	return fmt.Sprintf("%s[%s]%s %s %s %s%s%s", colorMuted, ts, colorReset, pathSegment, circle, percentSegment, statusSegment, peerSegment)
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
