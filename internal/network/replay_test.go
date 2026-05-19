package network

import (
	"testing"
	"time"
)

func TestReplayCacheAcceptsUnseenNonces(t *testing.T) {
	c := newReplayCache()
	if err := c.observe("peerA", []byte{1, 2, 3}); err != nil {
		t.Fatalf("first observation should succeed: %v", err)
	}
	if err := c.observe("peerA", []byte{4, 5, 6}); err != nil {
		t.Fatalf("second distinct observation should succeed: %v", err)
	}
}

func TestReplayCacheRejectsDuplicate(t *testing.T) {
	c := newReplayCache()
	if err := c.observe("peerA", []byte{1, 2, 3}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := c.observe("peerA", []byte{1, 2, 3}); err == nil {
		t.Fatalf("duplicate should be rejected")
	}
}

func TestReplayCachePartitionsByPeer(t *testing.T) {
	c := newReplayCache()
	if err := c.observe("peerA", []byte{1}); err != nil {
		t.Fatal(err)
	}
	// Same nonce from a different peer must not collide.
	if err := c.observe("peerB", []byte{1}); err != nil {
		t.Fatalf("nonce from a different peer should be accepted: %v", err)
	}
}

func TestReplayCacheEvictsAfterTTL(t *testing.T) {
	c := newReplayCache()
	frozen := time.Unix(1700000000, 0)
	c.now = func() time.Time { return frozen }
	if err := c.observe("peerA", []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return frozen.Add(replayTTL + time.Second) }
	if err := c.observe("peerA", []byte{1, 2, 3}); err != nil {
		t.Fatalf("after TTL expiry the same nonce should be accepted: %v", err)
	}
}

func TestReplayCacheHandlesEmptyInputs(t *testing.T) {
	c := newReplayCache()
	// Empty peer pubkey or empty nonce: function returns nil and skips
	// recording. We rely on earlier validation to reject these frames.
	if err := c.observe("", []byte{1, 2, 3}); err != nil {
		t.Fatalf("empty peer should not error: %v", err)
	}
	if err := c.observe("peerA", nil); err != nil {
		t.Fatalf("empty nonce should not error: %v", err)
	}
}

func TestFreshnessRejectsStaleAndFutureTimestamps(t *testing.T) {
	tr := &TransferService{}
	now := time.Now()

	if err := tr.checkTimestampFreshness(&envelope{Timestamp: now.Add(-freshnessPast - time.Minute).Unix()}); err == nil {
		t.Fatalf("stale envelope should be rejected")
	}
	if err := tr.checkTimestampFreshness(&envelope{Timestamp: now.Add(freshnessFuture + time.Minute).Unix()}); err == nil {
		t.Fatalf("future envelope should be rejected")
	}
	if err := tr.checkTimestampFreshness(&envelope{Timestamp: now.Unix()}); err != nil {
		t.Fatalf("fresh envelope should be accepted: %v", err)
	}
	// Envelopes with no timestamp (e.g. older protocol versions) are accepted.
	if err := tr.checkTimestampFreshness(&envelope{Timestamp: 0}); err != nil {
		t.Fatalf("no-timestamp envelope should be accepted for backwards compat: %v", err)
	}
}
