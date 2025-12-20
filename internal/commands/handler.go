package commands

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/hamzawahab/bonjou-terminal/internal/history"
	"github.com/hamzawahab/bonjou-terminal/internal/network"
	"github.com/hamzawahab/bonjou-terminal/internal/session"
)

var ErrUnknownCommand = errors.New("unknown command")

// Result carries command execution outcome back to the UI.
type Result struct {
	Output string
	Clear  bool
	Quit   bool
}

type Handler struct {
	session *session.Session
}

func New(session *session.Session) *Handler {
	return &Handler{session: session}
}

// Handle parses command input and executes matching action.
func (h *Handler) Handle(input string) (Result, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return Result{}, nil
	}
	if !strings.HasPrefix(trimmed, "@") {
		return Result{Output: "Commands must start with @. Type @help for options."}, nil
	}
	parts := strings.Fields(trimmed)
	cmd := strings.TrimPrefix(parts[0], "@")
	args := strings.TrimSpace(strings.TrimPrefix(trimmed, parts[0]))

	switch cmd {
	case "help":
		return Result{Output: helpText()}, nil
	case "whoami":
		return h.cmdWhoAmI()
	case "users":
		return h.cmdUsers()
	case "send":
		return h.cmdSend(parts, args)
	case "file":
		return h.cmdFile(parts, args)
	case "folder":
		return h.cmdFolder(parts, args)
	case "multi":
		return h.cmdMulti(parts, args)
	case "broadcast":
		return h.cmdBroadcast(args)
	case "history":
		return h.cmdHistory()
	case "setpath":
		return h.cmdSetPath(args)
	case "setname":
		return h.cmdSetName(args)
	case "status":
		return h.cmdStatus()
	case "update":
		return h.cmdUpdate()
	case "clear":
		return h.cmdClear(args)
	case "exit":
		return Result{Quit: true}, nil
	default:
		return Result{}, ErrUnknownCommand
	}
}

func (h *Handler) cmdWhoAmI() (Result, error) {
	cfg := h.session.Config
	msg := fmt.Sprintf("Username: %s\nIP: %s\nListen port: %d", cfg.Username, h.session.LocalIP(), cfg.ListenPort)
	return Result{Output: msg}, nil
}

func (h *Handler) cmdUsers() (Result, error) {
	peers := h.session.Discovery.ListPeers()
	if h.session.Discovery != nil {
		go h.session.Discovery.ForceAnnounce()
	}
	if len(peers) == 0 {
		return Result{Output: "No active users discovered."}, nil
	}
	var lines []string
	for _, peer := range peers {
		seen := seenLabel(peer.LastSeen)
		lines = append(lines, fmt.Sprintf("%s (%s) • %s", safePeerLabel(peer.Username), peer.IP, seen))
	}
	return Result{Output: strings.Join(lines, "\n")}, nil
}

func (h *Handler) cmdSend(parts []string, args string) (Result, error) {
	if len(parts) < 2 {
		return Result{Output: "Usage: @send <user/ip> <message>"}, nil
	}
	target := parts[1]
	message := strings.TrimSpace(strings.TrimPrefix(args, target))
	if message == "" {
		return Result{Output: "Message cannot be empty."}, nil
	}
	peer, err := h.resolvePeer(target)
	if err != nil {
		return Result{}, err
	}
	if err := h.session.Transfer.SendMessage(peer, message); err != nil {
		return Result{}, err
	}
	return Result{Output: fmt.Sprintf("Sent message to %s", peerLabel(peer))}, nil
}

func (h *Handler) cmdFile(parts []string, args string) (Result, error) {
	if len(parts) < 3 {
		return Result{Output: "Usage: @file <user/ip> <path>"}, nil
	}
	target := parts[1]
	rawPath := strings.TrimSpace(strings.TrimPrefix(args, target))
	path, err := normalizePathArg(rawPath)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return Result{}, err
	}
	if info.IsDir() {
		return Result{Output: "Path is a directory. Use @folder instead."}, nil
	}
	peer, err := h.resolvePeer(target)
	if err != nil {
		return Result{}, err
	}
	if err := h.session.Transfer.SendFile(peer, path); err != nil {
		return Result{}, err
	}
	return Result{}, nil
}

func (h *Handler) cmdFolder(parts []string, args string) (Result, error) {
	if len(parts) < 3 {
		return Result{Output: "Usage: @folder <user/ip> <dir>"}, nil
	}
	target := parts[1]
	rawPath := strings.TrimSpace(strings.TrimPrefix(args, target))
	path, err := normalizePathArg(rawPath)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return Result{}, err
	}
	if !info.IsDir() {
		return Result{Output: "Path is not a directory."}, nil
	}
	peer, err := h.resolvePeer(target)
	if err != nil {
		return Result{}, err
	}
	if err := h.session.Transfer.SendFolder(peer, path); err != nil {
		return Result{}, err
	}
	return Result{}, nil
}

func (h *Handler) cmdMulti(parts []string, args string) (Result, error) {
	targetsPart, payload, ok := splitMultiArgs(args)
	if !ok {
		return Result{Output: "Usage: @multi <u1,u2,...> <message|file>"}, nil
	}
	payloadPath := ""
	payloadIsDir := false
	if pathCandidate, err := normalizePathArg(payload); err == nil {
		if info, statErr := os.Stat(pathCandidate); statErr == nil {
			payloadPath = pathCandidate
			payloadIsDir = info.IsDir()
		}
	}
	var errs []string
	var success int
	for _, target := range strings.Split(targetsPart, ",") {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		peer, err := h.resolvePeer(target)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", target, err))
			continue
		}
		if payloadPath != "" {
			if payloadIsDir {
				err = h.session.Transfer.SendFolder(peer, payloadPath)
			} else {
				err = h.session.Transfer.SendFile(peer, payloadPath)
			}
		} else {
			err = h.session.Transfer.SendMessage(peer, payload)
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", target, err))
			continue
		}
		success++
	}
	if len(errs) > 0 {
		return Result{Output: fmt.Sprintf("Completed %d transfers, %d errors:\n%s", success, len(errs), strings.Join(errs, "\n"))}, nil
	}

	return Result{Output: fmt.Sprintf("Completed %d transfers", success)}, nil
}

func (h *Handler) cmdBroadcast(message string) (Result, error) {
	message = strings.TrimSpace(message)
	if message == "" {
		return Result{Output: "Usage: @broadcast <message>"}, nil
	}
	peers := h.session.Discovery.ListPeers()
	if len(peers) == 0 {
		return Result{Output: "No peers to broadcast to."}, nil
	}
	var errs []string
	for _, peer := range peers {
		resolved, err := h.session.Discovery.Resolve(peer.IP)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", peerLabel(&peer), err))
			continue
		}
		if err := h.session.Transfer.SendMessage(resolved, message); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", peerLabel(resolved), err))
		}
	}
	if len(errs) > 0 {
		return Result{Output: "Broadcast completed with errors:\n" + strings.Join(errs, "\n")}, nil
	}
	return Result{Output: fmt.Sprintf("Broadcast to %d peers", len(peers))}, nil
}

func (h *Handler) cmdHistory() (Result, error) {
	entries, err := h.session.History.ReadAll()
	if err != nil {
		return Result{}, err
	}
	if len(entries) == 0 {
		return Result{Output: "History is empty."}, nil
	}
	render := formatHistoryTable(entries, h.session.Config.Username)
	return Result{Output: render}, nil
}

func (h *Handler) cmdSetPath(arg string) (Result, error) {
	dir := strings.TrimSpace(arg)
	if dir == "" {
		return Result{Output: "Usage: @setpath <dir>"}, nil
	}
	dir, err := normalizePathArg(dir)
	if err != nil {
		return Result{}, err
	}
	cfg := h.session.Config
	cfg.SaveDir = dir
	cfg.ReceivedFilesDir = filepath.Join(dir, "files")
	cfg.ReceivedFoldersDir = filepath.Join(dir, "folders")
	if err := cfg.EnsureDirectories(); err != nil {
		return Result{}, err
	}
	if err := cfg.Save(); err != nil {
		return Result{}, err
	}
	return Result{Output: fmt.Sprintf("Receive directory set to %s", dir)}, nil
}

func (h *Handler) cmdSetName(arg string) (Result, error) {
	name := strings.TrimSpace(arg)
	if name == "" {
		return Result{Output: "Usage: @setname <username>"}, nil
	}
	if strings.ContainsAny(name, "\n\r") {
		return Result{Output: "Username cannot contain newlines."}, nil
	}
	sanitised, changed := sanitiseUsername(name)
	if sanitised == "" {
		return Result{Output: "Username cannot be blank."}, nil
	}
	if len(sanitised) > 64 {
		return Result{Output: "Username must be 64 characters or fewer."}, nil
	}
	cfg := h.session.Config
	if cfg == nil {
		return Result{}, errors.New("configuration not loaded")
	}
	if cfg.Username == sanitised {
		return Result{Output: fmt.Sprintf("Username already set to %s", sanitised)}, nil
	}
	if h.session.Discovery != nil {
		peers := h.session.Discovery.ListPeers()
		for _, peer := range peers {
			if strings.EqualFold(peer.Username, sanitised) {
				return Result{Output: fmt.Sprintf("Username %s is currently in use by %s (%s). Choose a different name.", sanitised, peer.Username, peer.IP)}, nil
			}
		}
	}
	old := cfg.Username
	cfg.Username = sanitised
	if err := cfg.Save(); err != nil {
		cfg.Username = old
		return Result{}, err
	}
	if h.session.Transfer != nil {
		h.session.Transfer.UpdateLocalUser(sanitised)
	}
	if h.session.Discovery != nil {
		h.session.Discovery.UpdateLocalUser(sanitised)
		h.session.Discovery.ForceAnnounce()
	}
	msg := fmt.Sprintf("Username updated to %s", sanitised)
	if changed {
		msg += " (spaces converted to '-')"
	}
	return Result{Output: msg}, nil
}

func (h *Handler) cmdStatus() (Result, error) {
	cfg := h.session.Config
	peers := h.session.Discovery.ListPeers()
	lines := []string{
		fmt.Sprintf("Username: %s", cfg.Username),
		fmt.Sprintf("Local IP: %s", h.session.LocalIP()),
		fmt.Sprintf("Listen port: %d", cfg.ListenPort),
		fmt.Sprintf("Discovery port: %d", cfg.DiscoveryPort),
		fmt.Sprintf("Discovered peers: %d", len(peers)),
		fmt.Sprintf("Receive path: %s", cfg.SaveDir),
	}
	return Result{Output: strings.Join(lines, "\n")}, nil
}

func (h *Handler) cmdClear(arg string) (Result, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return Result{Clear: true}, nil
	}
	if strings.EqualFold(arg, "history") {
		if err := h.session.History.Clear(); err != nil {
			return Result{}, err
		}
		return Result{Output: "History cleared."}, nil
	}
	return Result{Output: "Usage: @clear [history]"}, nil
}

func (h *Handler) cmdUpdate() (Result, error) {
	options := []string{}
	if path, err := exec.LookPath("bonjou-update"); err == nil {
		options = append(options, path)
	}
	options = append(options, filepath.Join(h.session.Config.ConfigDir(), "update.sh"))
	for _, candidate := range options {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		if err := runUpdateCandidate(candidate); err != nil {
			return Result{}, err
		}
		return Result{Output: fmt.Sprintf("Update script %s executed.", candidate)}, nil
	}
	return Result{Output: "No update source found. Install updates via packaging instructions."}, nil
}

func (h *Handler) resolvePeer(target string) (*network.Peer, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("empty target")
	}
	if ip := net.ParseIP(target); ip != nil {
		peer, err := h.session.Discovery.Resolve(ip.String())
		if err != nil {
			return nil, fmt.Errorf("peer %s not discovered", target)
		}
		return peer, nil
	}
	peer, err := h.session.Discovery.Resolve(target)
	if err != nil {
		return nil, err
	}
	return peer, nil
}

func peerLabel(peer *network.Peer) string {
	if peer.Username != "" {
		return fmt.Sprintf("%s@%s:%d", peer.Username, peer.IP, peer.Port)
	}
	return fmt.Sprintf("%s:%d", peer.IP, peer.Port)
}

func seenLabel(lastSeen time.Time) string {
	if lastSeen.IsZero() {
		return "seen recently"
	}
	diff := time.Since(lastSeen)
	if diff < 0 {
		diff = 0
	}
	switch {
	case diff < 1500*time.Millisecond:
		return "seen just now"
	case diff < time.Minute:
		secs := int(diff.Round(time.Second) / time.Second)
		if secs <= 1 {
			return "seen 1s ago"
		}
		return fmt.Sprintf("seen %ds ago", secs)
	case diff < time.Hour:
		mins := int(diff.Round(time.Minute) / time.Minute)
		if mins <= 1 {
			return "seen 1m ago"
		}
		return fmt.Sprintf("seen %dm ago", mins)
	case diff < 24*time.Hour:
		hours := int(diff.Round(time.Hour) / time.Hour)
		if hours <= 1 {
			return "seen 1h ago"
		}
		return fmt.Sprintf("seen %dh ago", hours)
	default:
		days := int(diff.Round(24*time.Hour) / (24 * time.Hour))
		if days <= 1 {
			return "seen 1d ago"
		}
		return fmt.Sprintf("seen %dd ago", days)
	}
}

func safePeerLabel(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "(unknown)"
	}
	return trimmed
}

func runUpdateCandidate(path string) error {
	cmd := exec.Command(path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func splitMultiArgs(input string) (string, string, bool) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", "", false
	}
	lastNonSpace := rune(0)
	for idx, r := range trimmed {
		if unicode.IsSpace(r) {
			if lastNonSpace != ',' {
				targets := strings.TrimSpace(trimmed[:idx])
				payload := strings.TrimSpace(trimmed[idx:])
				if targets == "" || payload == "" {
					return "", "", false
				}
				return targets, payload, true
			}
			continue
		}
		lastNonSpace = r
	}
	return "", "", false
}

func sanitiseUsername(input string) (string, bool) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", false
	}
	parts := strings.Fields(trimmed)
	if len(parts) == 0 {
		return "", false
	}
	joined := strings.Join(parts, "-")
	return joined, joined != trimmed
}

func normalizePathArg(input string) (string, error) {
	path := strings.TrimSpace(input)
	if path == "" {
		return "", errors.New("empty path")
	}
	if len(path) >= 2 {
		if (path[0] == '"' && path[len(path)-1] == '"') || (path[0] == '\'' && path[len(path)-1] == '\'') {
			path = strings.TrimSpace(path[1 : len(path)-1])
		}
	}
	if path == "" {
		return "", errors.New("empty path")
	}
	if strings.HasPrefix(path, "~") {
		if len(path) > 1 && path[1] != '/' && path[1] != '\\' {
			return "", fmt.Errorf("unsupported home expansion for %s", path)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			path = home
		} else {
			cleaned := strings.TrimPrefix(path, "~")
			cleaned = strings.TrimPrefix(cleaned, "/")
			cleaned = strings.TrimPrefix(cleaned, "\\")
			path = filepath.Join(home, cleaned)
		}
	}
	if !filepath.IsAbs(path) {
		cwd, _ := os.Getwd()
		path = filepath.Join(cwd, path)
	}
	return filepath.Clean(path), nil
}

func helpText() string {
	const (
		reset   = "\033[0m"
		heading = "\033[36m"
		accent  = "\033[96m"
		dim     = "\033[90m"
	)

	var b strings.Builder
	b.WriteString(reset)
	b.WriteString(heading + "Bonjou Command Guide" + reset + "\n")
	b.WriteString(dim + "Prefix every command with @. Quote paths that contain spaces." + reset + "\n\n")

	b.WriteString(heading + "Messaging" + reset + "\n")
	b.WriteString("  " + accent + "@send <user/ip> <message>" + reset + "\n")
	b.WriteString("    Direct message a peer by username, hostname, or IP." + "\n")
	b.WriteString("  " + accent + "@multi <user1,user2,...> <message|path>" + reset + "\n")
	b.WriteString("    Target a list of peers; send chat text, a file, or a folder." + "\n")
	b.WriteString("  " + accent + "@broadcast <message>" + reset + "\n")
	b.WriteString("    Push the same announcement to every discovered peer." + "\n\n")

	b.WriteString(heading + "File Transfer" + reset + "\n")
	b.WriteString("  " + accent + "@file <user/ip> <path>" + reset + "\n")
	b.WriteString("    Share a single file. ~ expansion and quoted paths supported." + "\n")
	b.WriteString("  " + accent + "@folder <user/ip> <dir>" + reset + "\n")
	b.WriteString("    Stream an entire directory; handy for project hand-offs." + "\n")
	b.WriteString("  " + accent + "@history" + reset + "\n")
	b.WriteString("    Review recent sends, receives, and system notices." + "\n\n")

	b.WriteString(heading + "Discovery & Status" + reset + "\n")
	b.WriteString("  " + accent + "@users" + reset + "\n")
	b.WriteString("    List online peers with last-seen timestamps." + "\n")
	b.WriteString("  " + accent + "@whoami" + reset + "\n")
	b.WriteString("    Show your username, LAN IP, and listening port." + "\n")
	b.WriteString("  " + accent + "@setname <username>" + reset + "\n")
	b.WriteString("    Update the username you broadcast to the LAN." + "\n")
	b.WriteString("  " + accent + "@status" + reset + "\n")
	b.WriteString("    Summarize discovery health and receive directories." + "\n\n")

	b.WriteString(heading + "Workspace & Maintenance" + reset + "\n")
	b.WriteString("  " + accent + "@setpath <dir>" + reset + "\n")
	b.WriteString("    Change where incoming files and folders are stored." + "\n")
	b.WriteString("  " + accent + "@clear [history]" + reset + "\n")
	b.WriteString("    Clear the screen, or include history to wipe saved logs." + "\n")
	b.WriteString("  " + accent + "@update" + reset + "\n")
	b.WriteString("    Execute a local updater script if one exists." + "\n")
	b.WriteString("  " + accent + "@help" + reset + "\n")
	b.WriteString("    View this guide again." + "\n")
	b.WriteString("  " + accent + "@exit" + reset + "\n")
	b.WriteString("    Quit Bonjou." + "\n")

	return strings.TrimRight(b.String(), "\n")
}

func formatHistoryTable(entries []history.Entry, localUser string) string {
	const (
		colTime      = 19
		colType      = 8
		colPeer      = 18
		colDirection = 10
		colDetails   = 40
		colSize      = 10
	)
	widths := []int{colTime, colType, colPeer, colDirection, colDetails, colSize}
	header := []string{"Time", "Type", "Peer", "Direction", "Details", "Size"}

	var rows [][]string
	for _, entry := range entries {
		peer, direction := describeHistoryDirection(entry, localUser)
		details := describeHistoryDetails(entry)
		size := describeHistorySize(entry)
		rows = append(rows, []string{
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			describeHistoryType(entry),
			peer,
			direction,
			details,
			size,
		})
	}

	topDivider := drawHistoryDivider(widths, '-')
	headerDivider := drawHistoryDivider(widths, '=')
	var buf strings.Builder
	buf.WriteString(topDivider)
	buf.WriteString("\n")
	buf.WriteString(drawHistoryRow(header, widths))
	buf.WriteString("\n")
	buf.WriteString(headerDivider)

	if len(rows) == 0 {
		empty := []string{"-", "-", "-", "-", "History is empty", "-"}
		buf.WriteString("\n")
		buf.WriteString(drawHistoryRow(empty, widths))
		buf.WriteString("\n")
		buf.WriteString(topDivider)
		return buf.String()
	}

	for _, row := range rows {
		buf.WriteString("\n")
		buf.WriteString(drawHistoryRow(row, widths))
		buf.WriteString("\n")
		buf.WriteString(topDivider)
	}
	return buf.String()
}

func drawHistoryDivider(widths []int, fill rune) string {
	var b strings.Builder
	b.WriteString("+")
	for _, width := range widths {
		b.WriteString(strings.Repeat(string(fill), width+2))
		b.WriteString("+")
	}
	return b.String()
}

func drawHistoryRow(cells []string, widths []int) string {
	wrapped := make([][]string, len(cells))
	maxLines := 0
	for idx, cell := range cells {
		width := widths[idx]
		lines := wrapCell(cell, width)
		wrapped[idx] = lines
		if len(lines) > maxLines {
			maxLines = len(lines)
		}
	}
	if maxLines == 0 {
		maxLines = 1
	}
	var b strings.Builder
	for line := 0; line < maxLines; line++ {
		if line > 0 {
			b.WriteString("\n")
		}
		b.WriteString("|")
		for idx, width := range widths {
			text := ""
			if line < len(wrapped[idx]) {
				text = wrapped[idx][line]
			}
			b.WriteString(" ")
			b.WriteString(padCell(text, width))
			b.WriteString(" |")
		}
	}
	return b.String()
}

func describeHistoryType(entry history.Entry) string {
	switch strings.ToLower(entry.Category) {
	case "chat":
		return "Message"
	case "transfer":
		switch strings.ToLower(entry.Kind) {
		case "folder":
			return "Folder"
		case "file":
			return "File"
		default:
			return "Transfer"
		}
	default:
		return titleCaseWord(entry.Category)
	}
}

func describeHistoryDirection(entry history.Entry, localUser string) (string, string) {
	from := strings.TrimSpace(entry.From)
	to := strings.TrimSpace(entry.To)
	local := strings.TrimSpace(localUser)
	switch {
	case local != "" && strings.EqualFold(from, local):
		peer := safePeerLabel(to)
		return peer, "Sent"
	case local != "" && strings.EqualFold(to, local):
		peer := safePeerLabel(from)
		return peer, "Received"
	default:
		peer := safePeerLabel(from)
		if peer == "(unknown)" {
			peer = safePeerLabel(to)
		}
		direction := strings.TrimSpace(from + " → " + to)
		if direction == "→" || direction == "" {
			direction = "-"
		}
		return peer, direction
	}
}

func describeHistoryDetails(entry history.Entry) string {
	switch strings.ToLower(entry.Category) {
	case "chat":
		message := strings.TrimSpace(entry.Message)
		if message == "" {
			message = "(empty message)"
		}
		message = strings.ReplaceAll(message, "\n", " ")
		return fmt.Sprintf("Message %q", message)
	case "transfer":
		label := strings.TrimSpace(entry.Path)
		if label == "" {
			label = "(unknown path)"
		}
		base := filepath.Base(label)
		if base == "." || base == string(os.PathSeparator) {
			base = label
		}
		prefix := "Transfer"
		switch strings.ToLower(entry.Kind) {
		case "file":
			prefix = "File"
		case "folder":
			prefix = "Folder"
		}
		return fmt.Sprintf("%s %s", prefix, base)
	default:
		return strings.TrimSpace(entry.Message)
	}
}

func describeHistorySize(entry history.Entry) string {
	if strings.ToLower(entry.Category) != "transfer" {
		return "-"
	}
	if entry.Size <= 0 {
		return "-"
	}
	return humanBytes(entry.Size)
}

func padCell(value string, width int) string {
	runes := []rune(value)
	if len(runes) >= width {
		return value
	}
	return value + strings.Repeat(" ", width-len(runes))
}

func wrapCell(value string, width int) []string {
	if width <= 0 {
		return []string{""}
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return []string{""}
	}
	runes := []rune(trimmed)
	var lines []string
	for len(runes) > 0 {
		if len(runes) <= width {
			lines = append(lines, strings.TrimSpace(string(runes)))
			break
		}
		split := width
		for i := width; i > 0; i-- {
			r := runes[i-1]
			if unicode.IsSpace(r) {
				split = i
				break
			}
		}
		lines = append(lines, strings.TrimSpace(string(runes[:split])))
		runes = trimLeadingSpaces(runes[split:])
	}
	if len(lines) == 0 {
		lines = append(lines, "")
	}
	return lines
}

func trimLeadingSpaces(runes []rune) []rune {
	idx := 0
	for idx < len(runes) && unicode.IsSpace(runes[idx]) {
		idx++
	}
	return runes[idx:]
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	value := float64(n)
	idx := 0
	for value >= 1024 && idx < len(units)-1 {
		value /= 1024
		idx++
	}
	if value >= 10 || idx == 0 {
		return fmt.Sprintf("%.0f %s", value, units[idx])
	}
	return fmt.Sprintf("%.1f %s", value, units[idx])
}

func titleCaseWord(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "-"
	}
	runes := []rune(strings.ToLower(trimmed))
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
