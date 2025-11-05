package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hamzawahab/bonjou-terminal/internal/commands"
	"github.com/hamzawahab/bonjou-terminal/internal/events"
	"github.com/hamzawahab/bonjou-terminal/internal/session"
)

const (
	colorReset   = "\033[0m"
	colorPrimary = "\033[36m"
	colorSuccess = "\033[32m"
	colorError   = "\033[31m"
	colorMuted   = "\033[90m"
)

// UI drives the interactive terminal session.
type UI struct {
	session *session.Session
	handler *commands.Handler
	reader  *bufio.Reader
	done    chan struct{}
}

func New(session *session.Session, handler *commands.Handler) *UI {
	return &UI{
		session: session,
		handler: handler,
		reader:  bufio.NewReader(os.Stdin),
		done:    make(chan struct{}),
	}
}

// Run starts the interactive Bonjou session.
func (u *UI) Run() {
	u.printWelcome()
	go u.consumeEvents()
	for {
		u.printPrompt()
		line, err := u.reader.ReadString('\n')
		if err != nil {
			fmt.Println(colorError + "Error reading input: " + err.Error() + colorReset)
			continue
		}
		result, err := u.handler.Handle(line)
		if err != nil {
			fmt.Println(colorError + err.Error() + colorReset)
			continue
		}
		if result.Clear {
			u.clearScreen()
			continue
		}
		if result.Output != "" {
			fmt.Println(colorSuccess + result.Output + colorReset)
		}
		if result.Quit {
			close(u.done)
			fmt.Println(colorMuted + "Ending Bonjou session. Goodbye!" + colorReset)
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
		fmt.Printf("\n%s[%s] %s ➜ You:%s %s\n", colorPrimary, ts, safe(evt.From), colorReset, evt.Message)
	case events.MessageSent:
		fmt.Printf("\n%s[%s] You ➜ %s:%s %s\n", colorMuted, ts, safe(evt.To), colorReset, evt.Message)
	case events.FileReceived, events.FolderReceived:
		fmt.Printf("\n%s[%s] Received %s from %s -> %s%s\n", colorPrimary, ts, safe(evt.Message), safe(evt.From), evt.Path, colorReset)
	case events.FileSent, events.FolderSent:
		fmt.Printf("\n%s[%s] Sent %s to %s%s\n", colorMuted, ts, safe(evt.Message), safe(evt.To), colorReset)
	case events.Error:
		fmt.Printf("\n%s[%s] %s%s\n", colorError, ts, safe(evt.Message), colorReset)
	case events.Status:
		fmt.Printf("\n%s[%s] %s%s\n", colorMuted, ts, safe(evt.Message), colorReset)
	case events.Progress:
		if evt.Progress != nil && evt.Progress.Total > 0 {
			percent := float64(evt.Progress.Current) / float64(evt.Progress.Total) * 100
			marker := colorMuted
			if evt.Progress.Done {
				marker = colorSuccess
			}
			label := evt.Progress.Label
			if label == "" {
				label = evt.Progress.ID
			}
			fmt.Printf("\n%s[%s] %s %.1f%%%s\n", marker, ts, label, percent, colorReset)
		}
	}
	u.printPrompt()
}

func (u *UI) printWelcome() {
	header := fmt.Sprintf("%s🌐 Welcome to Bonjou v1.0%s", colorPrimary, colorReset)
	user := fmt.Sprintf("%s👤 User:%s %s | IP: %s", colorMuted, colorReset, u.session.Config.Username, u.session.LocalIP)
	lan := fmt.Sprintf("%s📡 LAN:%s Connected", colorMuted, colorReset)
	fmt.Println(header)
	fmt.Println(user)
	fmt.Println(lan)
	fmt.Println("Type @help for commands.")
}

func (u *UI) clearScreen() {
	fmt.Print("\033[2J\033[H")
	u.printWelcome()
}

func (u *UI) printPrompt() {
	fmt.Print(colorMuted + "> " + colorReset)
}

func safe(in string) string {
	if strings.TrimSpace(in) == "" {
		return "(unknown)"
	}
	return in
}
