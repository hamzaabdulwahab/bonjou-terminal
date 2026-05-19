package commands

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// This file groups the @send / @file / @folder / @multi / @broadcast
// command handlers — the surface area through which users initiate
// outbound transfers and chat. The actual wire work lives in
// internal/network; this layer only parses CLI arguments and calls into
// the session.

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

// multiResult records the outcome of one @multi send. Storing target/err
// structurally lets the retry phase compute "which targets failed" without
// round-tripping through formatted error strings (which broke for IPv6
// targets and "host:port" targets due to colon splits).
type multiResult struct {
	target string
	err    error
	retry  bool
}

func (h *Handler) cmdMulti(parts []string, args string) (Result, error) {
	// Check for --sequential flag (manual override)
	forceSequential := false
	argsToProcess := args
	if strings.HasPrefix(strings.TrimSpace(args), "--sequential ") || strings.HasPrefix(strings.TrimSpace(args), "--seq ") {
		forceSequential = true
		argsToProcess = strings.TrimPrefix(strings.TrimSpace(args), "--sequential ")
		argsToProcess = strings.TrimPrefix(strings.TrimSpace(argsToProcess), "--seq ")
	}

	targetsPart, payload, ok := splitMultiArgs(argsToProcess)
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

	// Parse + deduplicate targets so each peer is contacted at most once.
	seen := make(map[string]bool)
	var targets []string
	for _, target := range strings.Split(targetsPart, ",") {
		target = strings.TrimSpace(target)
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return Result{Output: "No valid targets specified"}, nil
	}

	sendOne := func(target string) error {
		peer, err := h.resolvePeer(target)
		if err != nil {
			return err
		}
		switch {
		case payloadPath != "" && payloadIsDir:
			return h.session.Transfer.SendFolder(peer, payloadPath)
		case payloadPath != "":
			return h.session.Transfer.SendFile(peer, payloadPath)
		default:
			return h.session.Transfer.SendMessage(peer, payload)
		}
	}

	var results []multiResult
	if forceSequential {
		for _, target := range targets {
			results = append(results, multiResult{target: target, err: sendOne(target)})
		}
	} else {
		// Phase 1: parallel attempt, bounded by maxMultiConcurrency so a
		// huge target list does not open hundreds of TCP connections at
		// once (and exhaust the local file-descriptor budget on macOS).
		const maxMultiConcurrency = 16
		results = make([]multiResult, len(targets))
		sem := make(chan struct{}, maxMultiConcurrency)
		var wg sync.WaitGroup
		for i, target := range targets {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int, t string) {
				defer wg.Done()
				defer func() { <-sem }()
				results[idx] = multiResult{target: t, err: sendOne(t)}
			}(i, target)
		}
		wg.Wait()

		// Phase 2: sequential retry of the failures, but only if at least
		// one target succeeded — if everything failed the issue is the
		// payload or our own network, not concurrency contention.
		failed := 0
		for _, r := range results {
			if r.err != nil {
				failed++
			}
		}
		if failed > 0 && failed < len(results) {
			for i, r := range results {
				if r.err == nil {
					continue
				}
				retryErr := sendOne(r.target)
				results[i] = multiResult{target: r.target, err: retryErr, retry: true}
			}
		}
	}

	var success int
	var errs []string
	for _, r := range results {
		if r.err == nil {
			success++
			continue
		}
		label := r.target
		if r.retry {
			label += " (sequential retry)"
		}
		errs = append(errs, fmt.Sprintf("%s: %v", label, r.err))
	}
	if len(errs) > 0 {
		return Result{Output: fmt.Sprintf("Completed %d transfers, %d errors:\n%s", success, len(errs), strings.Join(errs, "\n"))}, nil
	}
	return Result{Output: fmt.Sprintf("Completed %d transfers", success)}, nil
}

// extractFailedTargets is no longer used in production (cmdMulti tracks
// failures structurally now) but is kept so older test helpers and
// downstream callers can compile. New code should not depend on it.
func extractFailedTargets(errs []string, allTargets []string) []string {
	failedSet := make(map[string]bool)
	for _, errMsg := range errs {
		parts := strings.SplitN(errMsg, ":", 2)
		if len(parts) > 0 {
			target := strings.TrimSpace(parts[0])
			target = strings.TrimSuffix(target, " (sequential retry)")
			failedSet[target] = true
		}
	}
	var failed []string
	for _, target := range allTargets {
		if failedSet[target] {
			failed = append(failed, target)
		}
	}
	return failed
}

func (h *Handler) cmdBroadcast(message string) (Result, error) {
	message = strings.TrimSpace(message)
	if message == "" {
		return Result{Output: "Usage: @broadcast <message>"}, nil
	}
	peers := h.session.Discovery.ListPeers()
	if len(peers) == 0 {
		return Result{Output: "No active users discovered."}, nil
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
