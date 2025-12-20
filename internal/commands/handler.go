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
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return Result{Output: "File path required."}, nil
	}
	if !filepath.IsAbs(path) {
		cwd, _ := os.Getwd()
		path = filepath.Join(cwd, path)
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
	return Result{Output: fmt.Sprintf("Transferring file %s to %s", filepath.Base(path), peerLabel(peer))}, nil
}

func (h *Handler) cmdFolder(parts []string, args string) (Result, error) {
	if len(parts) < 3 {
		return Result{Output: "Usage: @folder <user/ip> <dir>"}, nil
	}
	target := parts[1]
	rawPath := strings.TrimSpace(strings.TrimPrefix(args, target))
	path := strings.TrimSpace(rawPath)
	if path == "" {
		return Result{Output: "Folder path required."}, nil
	}
	if !filepath.IsAbs(path) {
		cwd, _ := os.Getwd()
		path = filepath.Join(cwd, path)
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
	return Result{Output: fmt.Sprintf("Transferring folder %s to %s", filepath.Base(path), peerLabel(peer))}, nil
}

func (h *Handler) cmdMulti(parts []string, args string) (Result, error) {
	if len(parts) < 3 {
		return Result{Output: "Usage: @multi <u1,u2,...> <message|file>"}, nil
	}
	targetsPart := parts[1]
	payload := strings.TrimSpace(strings.TrimPrefix(args, targetsPart))
	if payload == "" {
		return Result{Output: "Message or file path required."}, nil
	}
	payloadPath := ""
	payloadIsDir := false
	if info, err := os.Stat(payload); err == nil {
		if !filepath.IsAbs(payload) {
			cwd, _ := os.Getwd()
			payload = filepath.Join(cwd, payload)
		}
		payloadPath = payload
		payloadIsDir = info.IsDir()
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
		if err := h.session.Transfer.SendMessage(&peer, message); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", peerLabel(&peer), err))
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
	if !filepath.IsAbs(dir) {
		cwd, _ := os.Getwd()
		dir = filepath.Join(cwd, dir)
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
		return &network.Peer{Username: target, IP: ip.String(), Port: h.session.Config.ListenPort, LastSeen: time.Now()}, nil
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

func helpText() string {
	return strings.TrimSpace(`Available commands:
@send <user/ip> <message>
@file <user/ip> <path>
@folder <user/ip> <dir>
@multi <u1,u2,...> <msg|path>
@broadcast <message>
@users
@whoami
@history
@setpath <dir>
@status
@help
@update
@clear
@exit`)
}
