package network

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// replayTTL is how long a nonce stays in the cache. After this window an
	// attacker replaying a captured frame is back to "first observation" and
	// will (rightly) be accepted by lower layers; the freshness check below
	// stops them sooner via env.Timestamp.
	replayTTL = 10 * time.Minute

	// replayCapPerPeer bounds memory per peer. With ~1 msg/sec sustained, a
	// 4096-entry cap is ~68 minutes — well past replayTTL, so the cap is
	// essentially a safety net rather than a normal-path eviction trigger.
	replayCapPerPeer = 4096

	// freshnessPast is how stale an env.Timestamp may be. Beyond this the
	// envelope is treated as a replay or relay attempt.
	freshnessPast = 10 * time.Minute

	// freshnessFuture tolerates a small amount of clock skew between peers.
	freshnessFuture = 1 * time.Minute
)

// replayCache stores per-peer-pubkey sets of recently observed wire nonces.
// Each observation records the wall-clock time so we can drop entries past
// replayTTL during the next observe() call (lazy eviction).
type replayCache struct {
	mu      sync.Mutex
	buckets map[string]map[string]time.Time
	now     func() time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{
		buckets: make(map[string]map[string]time.Time),
		now:     time.Now,
	}
}

// observe records (peerPub, nonce) and returns a non-nil error if the nonce
// was already seen for that peer within the TTL window. Callers MUST treat a
// non-nil error as a security event and drop the envelope.
func (c *replayCache) observe(peerPub string, nonce []byte) error {
	if c == nil {
		return nil
	}
	if peerPub == "" || len(nonce) == 0 {
		// Empty inputs cannot be reliably deduped; let the caller decide
		// whether to accept (in practice this only happens on malformed
		// frames that earlier checks already rejected).
		return nil
	}
	nonceHex := hex.EncodeToString(nonce)

	c.mu.Lock()
	defer c.mu.Unlock()

	bucket, ok := c.buckets[peerPub]
	if !ok {
		bucket = make(map[string]time.Time)
		c.buckets[peerPub] = bucket
	}

	now := c.now()
	cutoff := now.Add(-replayTTL)
	for n, ts := range bucket {
		if ts.Before(cutoff) {
			delete(bucket, n)
		}
	}

	if seenAt, exists := bucket[nonceHex]; exists {
		return fmt.Errorf("replay: nonce %s last seen %s ago", shortNonce(nonceHex), now.Sub(seenAt).Truncate(time.Second))
	}

	if len(bucket) >= replayCapPerPeer {
		// Evict the oldest entry to make room. This is O(n) but n is bounded
		// by replayCapPerPeer and only runs in the overflow case, which is
		// unreachable under normal usage given the TTL-based eviction above.
		var oldestKey string
		var oldestTime time.Time
		for n, ts := range bucket {
			if oldestKey == "" || ts.Before(oldestTime) {
				oldestKey = n
				oldestTime = ts
			}
		}
		delete(bucket, oldestKey)
	}

	bucket[nonceHex] = now
	return nil
}

func shortNonce(hexStr string) string {
	if len(hexStr) <= 8 {
		return hexStr
	}
	return hexStr[:8] + "…"
}

// checkTimestampFreshness rejects envelopes whose Timestamp is too far in the
// past (likely replay or relay) or in the future (clock manipulation).
func (t *TransferService) checkTimestampFreshness(env *envelope) error {
	if env == nil {
		return errors.New("nil envelope")
	}
	if env.Timestamp <= 0 {
		// Older messages may not carry a timestamp; accept them but do not
		// extend the same generosity to dated traffic.
		return nil
	}
	now := time.Now()
	envTime := time.Unix(env.Timestamp, 0)
	if envTime.Before(now.Add(-freshnessPast)) {
		return fmt.Errorf("stale envelope: timestamp %s is older than %s", envTime.UTC().Format(time.RFC3339), freshnessPast)
	}
	if envTime.After(now.Add(freshnessFuture)) {
		return fmt.Errorf("future envelope: timestamp %s is more than %s ahead of local clock", envTime.UTC().Format(time.RFC3339), freshnessFuture)
	}
	return nil
}
