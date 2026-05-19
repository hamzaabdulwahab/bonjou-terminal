package network

import (
	"path/filepath"
	"testing"
)

func newTempStore(t *testing.T) (*KnownPeers, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_peers.json")
	kp, err := NewKnownPeers(path)
	if err != nil {
		t.Fatalf("NewKnownPeers: %v", err)
	}
	return kp, path
}

func TestPinFirstObservationAdds(t *testing.T) {
	kp, _ := newTempStore(t)
	outcome, entry, err := kp.Pin("alice", "deadbeef")
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if outcome != PinAdded {
		t.Fatalf("outcome = %v, want PinAdded", outcome)
	}
	if entry == nil || entry.PublicKey != "deadbeef" {
		t.Fatalf("entry not recorded correctly: %+v", entry)
	}
	if entry.Fingerprint == "" {
		t.Fatalf("fingerprint should be set")
	}
}

func TestPinSecondObservationSameKeyMatches(t *testing.T) {
	kp, _ := newTempStore(t)
	_, _, _ = kp.Pin("alice", "deadbeef")
	outcome, _, err := kp.Pin("alice", "deadbeef")
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if outcome != PinMatches {
		t.Fatalf("outcome = %v, want PinMatches", outcome)
	}
}

func TestPinSecondObservationDifferentKeyMismatches(t *testing.T) {
	kp, _ := newTempStore(t)
	_, _, _ = kp.Pin("alice", "deadbeef")
	outcome, entry, err := kp.Pin("alice", "cafebabe")
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if outcome != PinMismatch {
		t.Fatalf("outcome = %v, want PinMismatch", outcome)
	}
	// On mismatch, the existing entry is returned untouched.
	if entry == nil || entry.PublicKey != "deadbeef" {
		t.Fatalf("expected existing entry to be returned, got %+v", entry)
	}
	// Confirm the on-disk state did NOT change.
	stored := kp.Find("alice")
	if stored == nil || stored.PublicKey != "deadbeef" {
		t.Fatalf("mismatch should not overwrite: %+v", stored)
	}
}

func TestTrustOverwrites(t *testing.T) {
	kp, _ := newTempStore(t)
	_, _, _ = kp.Pin("alice", "deadbeef")
	if err := kp.Trust("alice", "cafebabe"); err != nil {
		t.Fatalf("Trust: %v", err)
	}
	stored := kp.Find("alice")
	if stored == nil || stored.PublicKey != "cafebabe" {
		t.Fatalf("Trust should overwrite: %+v", stored)
	}
}

func TestForget(t *testing.T) {
	kp, _ := newTempStore(t)
	_, _, _ = kp.Pin("alice", "deadbeef")
	if err := kp.Forget("alice"); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if kp.Find("alice") != nil {
		t.Fatalf("Forget should remove the entry")
	}
	if err := kp.Forget("alice"); err == nil {
		t.Fatalf("Forget on missing entry should error")
	}
}

func TestPersistsAcrossInstances(t *testing.T) {
	kp, path := newTempStore(t)
	_, _, _ = kp.Pin("alice", "deadbeef")

	kp2, err := NewKnownPeers(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	stored := kp2.Find("alice")
	if stored == nil || stored.PublicKey != "deadbeef" {
		t.Fatalf("entry should persist across reloads: %+v", stored)
	}
}

func TestFingerprintFormat(t *testing.T) {
	fp := Fingerprint("deadbeef")
	if fp == "" {
		t.Fatalf("Fingerprint should produce a non-empty string")
	}
	if len(fp) != 8*3-1 {
		// 8 bytes × ("xx:" repeated) minus trailing colon = 23 chars.
		t.Errorf("unexpected fingerprint length: %d (%q)", len(fp), fp)
	}
}
