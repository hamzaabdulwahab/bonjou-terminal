package network

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrUnknownPeer is returned by Forget when no entry exists for the username.
var ErrUnknownPeer = errors.New("no pinned key for that peer")

// KnownPeer is a username → public-key binding the local user has accepted.
// Once a peer's PublicKey is pinned, subsequent announcements claiming the
// same username but a different key are rejected as impersonation attempts.
type KnownPeer struct {
	Username    string `json:"username"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
}

// KnownPeers is the on-disk TOFU store.
//
// Entries are persisted to ~/.bonjou/known_peers.json (mode 0600). The set
// uses username as the primary key — the same identity choice peers see in
// chat and on the wire — so a single rename by a peer breaks the binding by
// design (the user has to re-confirm the new identity).
type KnownPeers struct {
	mu    sync.RWMutex
	path  string
	peers map[string]*KnownPeer
}

// NewKnownPeers loads (or initialises) the store at the given path.
func NewKnownPeers(path string) (*KnownPeers, error) {
	kp := &KnownPeers{
		path:  path,
		peers: make(map[string]*KnownPeer),
	}
	if err := kp.load(); err != nil {
		return nil, err
	}
	return kp, nil
}

func (k *KnownPeers) load() error {
	data, err := os.ReadFile(k.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var entries []*KnownPeer
	if err := json.Unmarshal(data, &entries); err != nil {
		// Corrupt store: rename and start fresh rather than fail to boot.
		_ = os.Rename(k.path, k.path+".corrupt")
		return nil
	}
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		entry.Username = strings.TrimSpace(entry.Username)
		entry.PublicKey = strings.TrimSpace(entry.PublicKey)
		if entry.Username == "" || entry.PublicKey == "" {
			continue
		}
		if entry.Fingerprint == "" {
			entry.Fingerprint = Fingerprint(entry.PublicKey)
		}
		k.peers[entry.Username] = entry
	}
	return nil
}

func (k *KnownPeers) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(k.path), 0o750); err != nil {
		return err
	}
	entries := make([]*KnownPeer, 0, len(k.peers))
	for _, entry := range k.peers {
		entry := *entry
		entries = append(entries, &entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Username < entries[j].Username })
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := k.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, k.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// PinOutcome describes what happened on a Pin attempt.
type PinOutcome int

const (
	PinAdded PinOutcome = iota
	PinMatches
	PinMismatch
)

// Pin records or verifies a username→pubkey binding. On first observation
// the entry is added (PinAdded). On a subsequent observation with the same
// key, LastSeen is updated (PinMatches). When the keys differ, no change is
// persisted and PinMismatch is returned so the caller can drop the message
// and emit a security event.
func (k *KnownPeers) Pin(username, pubkey string) (PinOutcome, *KnownPeer, error) {
	username = strings.TrimSpace(username)
	pubkey = strings.TrimSpace(pubkey)
	if username == "" || pubkey == "" {
		return PinMismatch, nil, errors.New("username and pubkey are required")
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	now := time.Now().Unix()
	if existing, ok := k.peers[username]; ok {
		if existing.PublicKey == pubkey {
			existing.LastSeen = now
			if err := k.saveLocked(); err != nil {
				return PinMatches, existing, err
			}
			entry := *existing
			return PinMatches, &entry, nil
		}
		entry := *existing
		return PinMismatch, &entry, nil
	}
	entry := &KnownPeer{
		Username:    username,
		PublicKey:   pubkey,
		Fingerprint: Fingerprint(pubkey),
		FirstSeen:   now,
		LastSeen:    now,
	}
	k.peers[username] = entry
	if err := k.saveLocked(); err != nil {
		delete(k.peers, username)
		return PinMismatch, nil, err
	}
	entryCopy := *entry
	return PinAdded, &entryCopy, nil
}

// Trust overwrites any existing binding. Used by `@trust <user> <fingerprint>`
// when the user has verified the new key out-of-band (e.g. peer changed
// devices). Caller is responsible for confirming intent.
func (k *KnownPeers) Trust(username, pubkey string) error {
	username = strings.TrimSpace(username)
	pubkey = strings.TrimSpace(pubkey)
	if username == "" || pubkey == "" {
		return errors.New("username and pubkey are required")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	now := time.Now().Unix()
	entry, ok := k.peers[username]
	if !ok {
		entry = &KnownPeer{Username: username, FirstSeen: now}
		k.peers[username] = entry
	}
	entry.PublicKey = pubkey
	entry.Fingerprint = Fingerprint(pubkey)
	entry.LastSeen = now
	return k.saveLocked()
}

// Forget removes the binding for username. Returns ErrUnknownPeer if absent.
func (k *KnownPeers) Forget(username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.peers[username]; !ok {
		return ErrUnknownPeer
	}
	delete(k.peers, username)
	return k.saveLocked()
}

// Find returns a copy of the pinned entry for username, or nil if absent.
func (k *KnownPeers) Find(username string) *KnownPeer {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	entry, ok := k.peers[username]
	if !ok {
		return nil
	}
	out := *entry
	return &out
}

// List returns all pinned entries (alphabetical by username).
func (k *KnownPeers) List() []*KnownPeer {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]*KnownPeer, 0, len(k.peers))
	for _, entry := range k.peers {
		copy := *entry
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// Fingerprint computes a short, human-readable digest of a hex-encoded
// public key. Truncated SHA-256 keeps it short enough to read aloud or
// compare on a sticker; eight bytes (16 hex chars) gives 64 bits of
// collision resistance — plenty for visual OOB verification.
func Fingerprint(hexPubkey string) string {
	raw, err := hex.DecodeString(strings.TrimSpace(hexPubkey))
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	short := digest[:8]
	parts := make([]string, len(short))
	for i, b := range short {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}
