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
	msg := fmt.Sprintf("Username: %s\nIP: %s\nListen port: %d", cfg.Username, h.session.LocalIP, cfg.ListenPort)
	return Result{Output: msg}, nil
}

func (h *Handler) cmdUsers() (Result, error) {
	peers := h.session.Discovery.ListPeers()
	if len(peers) == 0 {
		return Result{Output: "No active users discovered."}, nil
	}
	var lines []string
	for _, peer := range peers {
		ago := time.Since(peer.LastSeen).Round(time.Second)
		lines = append(lines, fmt.Sprintf("%s (%s:%d) • seen %s ago", safePeerLabel(peer.Username), peer.IP, peer.Port, ago))
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
	lines, err := h.session.History.ReadAll()
	if err != nil {
		return Result{}, err
	}
	if len(lines) == 0 {
		return Result{Output: "History is empty."}, nil
	}
	return Result{Output: strings.Join(lines, "\n")}, nil
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
		fmt.Sprintf("Local IP: %s", h.session.LocalIP),
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

func safePeerLabel(name string) string {
	if name == "" {
		return "unknown"
	}
	return name
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
