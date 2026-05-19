package network

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// These tests exercise the security-critical paths end-to-end as a guard
// against regressions: replay rejection, wrong-key rejection, chunk-level
// tampering, and zip-slip extraction.

func TestEnvelopeWrongKeyRejected(t *testing.T) {
	correct := sha256.Sum256([]byte("correct shared secret"))
	wrong := sha256.Sum256([]byte("wrong shared secret"))

	in := &envelope{Kind: kindMessage, From: "alice", Message: "hello"}
	frame, err := sealEnvelope(in, correct[:])
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, _, err := openEnvelope(frame, wrong[:]); err == nil {
		t.Fatalf("opening with the wrong key must fail (no leak)")
	}
}

func TestReplayCacheBlocksReusedWireNonce(t *testing.T) {
	cache := newReplayCache()
	peer := "deadbeef"
	wireNonce := []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05}

	if err := cache.observe(peer, wireNonce); err != nil {
		t.Fatalf("first observation: %v", err)
	}
	if err := cache.observe(peer, wireNonce); err == nil {
		t.Fatalf("second observation of same nonce must be rejected")
	}
}

// TestStreamChunkTamperingDetectedEarly demonstrates that flipping a bit
// inside a chunk is detected by the AEAD reader before any plaintext is
// surfaced to the caller. Compare with the v1 design (CTR + final
// SHA-256), where tampering was only visible after the whole file had
// been written to disk.
func TestStreamChunkTamperingDetectedEarly(t *testing.T) {
	shared := sha256.Sum256([]byte("phase4 stream test"))
	streamKey, err := deriveStreamKey(shared[:], []byte("test-stream-id-bb"))
	if err != nil {
		t.Fatalf("deriveStreamKey: %v", err)
	}

	plaintext := bytes.Repeat([]byte{0xaa}, 1024*8)
	var wire bytes.Buffer
	w, err := newChunkedFrameWriter(&wire, streamKey)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Corrupt one byte inside the ciphertext (skip the 4-byte length).
	corrupted := wire.Bytes()
	corrupted[6] ^= 0x80

	r, err := newChunkedFrameReader(bytes.NewReader(corrupted), streamKey)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	out := make([]byte, 64)
	if _, err := r.Read(out); err == nil {
		t.Fatalf("corrupted chunk should fail authentication on first Read")
	}
}

// TestUnzipRejectsZipSlip writes a malicious zip whose member name points
// at "../escaped" and confirms unzip refuses to extract it. The default
// zip libraries in Go do *not* defend against this on their own.
func TestUnzipRejectsZipSlip(t *testing.T) {
	dir := t.TempDir()
	maliciousZip := filepath.Join(dir, "evil.zip")

	out, err := os.Create(maliciousZip)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)
	header := &zip.FileHeader{Name: "../escaped.txt", Method: zip.Deflate}
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "should not land outside dest"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "dest")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unzip(maliciousZip, dest); err == nil {
		t.Fatalf("zip-slip extraction must be refused")
	}
	// The escaped file must not exist beside dest.
	escaped := filepath.Join(dir, "escaped.txt")
	if _, err := os.Stat(escaped); err == nil {
		t.Fatalf("unzip wrote outside dest: %s exists", escaped)
	}
}

// TestKnownPeersPinThenMismatch demonstrates the discovery TOFU contract
// at the store level: a second observation with a different key is
// reported as PinMismatch and the originally pinned key remains on disk.
func TestKnownPeersPinThenMismatch(t *testing.T) {
	dir := t.TempDir()
	kp, err := NewKnownPeers(filepath.Join(dir, "known_peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := kp.Pin("alice", "aa"); err != nil || outcome != PinAdded {
		t.Fatalf("first pin: outcome=%v err=%v", outcome, err)
	}
	outcome, entry, err := kp.Pin("alice", "bb")
	if err != nil {
		t.Fatalf("second pin: %v", err)
	}
	if outcome != PinMismatch {
		t.Fatalf("expected PinMismatch, got %v", outcome)
	}
	if entry == nil || entry.PublicKey != "aa" {
		t.Fatalf("on mismatch, the original entry must be returned: %+v", entry)
	}
	stored := kp.Find("alice")
	if stored == nil || stored.PublicKey != "aa" {
		t.Fatalf("mismatch must not overwrite stored key: %+v", stored)
	}
}
