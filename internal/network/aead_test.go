package network

import (
	"bytes"
	"crypto/sha256"
	"io"
	"strings"
	"testing"
)

func envelopeKeyForTest(t *testing.T) []byte {
	t.Helper()
	// The shared key passed to seal/open is the raw 32-byte SHA-256 of
	// whatever the ECDH layer produced. For tests we use a deterministic
	// value so we can compare across runs.
	h := sha256.Sum256([]byte("phase2-test-shared-secret"))
	return h[:]
}

func TestEnvelopeRoundTripGCM(t *testing.T) {
	shared := envelopeKeyForTest(t)
	in := &envelope{
		Kind:      kindMessage,
		From:      "alice",
		To:        "bob",
		Message:   "hello bob, this is a v2 envelope test",
		Timestamp: 1700000000,
	}
	frame, err := sealEnvelope(in, shared)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	out, nonce, err := openEnvelope(frame, shared)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if out.Message != in.Message {
		t.Fatalf("message mismatch: got %q want %q", out.Message, in.Message)
	}
	if len(nonce) != 12 {
		t.Fatalf("expected 12-byte GCM nonce, got %d", len(nonce))
	}
}

func TestEnvelopeRejectsTampering(t *testing.T) {
	shared := envelopeKeyForTest(t)
	in := &envelope{Kind: kindMessage, From: "alice", Message: "hi"}
	frame, err := sealEnvelope(in, shared)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Flip a byte inside the JSON-encoded sealed envelope. Since the bit
	// flip lands somewhere in either nonce, ciphertext, or tag, AEAD must
	// detect it and refuse to open.
	for i := 10; i < len(frame); i++ {
		if frame[i] == '"' {
			continue
		}
		frame[i] ^= 0x01
		break
	}
	if _, _, err := openEnvelope(frame, shared); err == nil {
		t.Fatalf("tampered envelope should fail to open")
	}
}

func TestEnvelopeRejectsWrongVersion(t *testing.T) {
	shared := envelopeKeyForTest(t)
	in := &envelope{Kind: kindMessage, From: "alice", Message: "hi"}
	frame, err := sealEnvelope(in, shared)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Replace v=2 with v=1 in the JSON.
	tampered := bytes.Replace(frame, []byte(`"v":2`), []byte(`"v":1`), 1)
	if _, _, err := openEnvelope(tampered, shared); err == nil {
		t.Fatalf("v=1 envelope should be rejected")
	}
}

func TestChunkedStreamRoundTrip(t *testing.T) {
	streamKey, err := deriveStreamKey(envelopeKeyForTest(t), []byte("test-stream-id-0"))
	if err != nil {
		t.Fatalf("deriveStreamKey: %v", err)
	}

	var pipe bytes.Buffer
	w, err := newChunkedFrameWriter(&pipe, streamKey)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}

	// Write data larger than one chunk so we exercise multi-chunk encoding.
	plaintext := []byte(strings.Repeat("Bonjou stream payload ", streamChunkPlainBytes/20))
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}

	r, err := newChunkedFrameReader(&pipe, streamKey)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	out := make([]byte, len(plaintext))
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatalf("readfull: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestChunkedStreamRejectsCorruptChunk(t *testing.T) {
	streamKey, _ := deriveStreamKey(envelopeKeyForTest(t), []byte("test-stream-id-1"))
	var pipe bytes.Buffer
	w, _ := newChunkedFrameWriter(&pipe, streamKey)
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Flip a byte in the ciphertext (skip the 4-byte length prefix).
	buf := pipe.Bytes()
	buf[5] ^= 0x01
	r, _ := newChunkedFrameReader(bytes.NewReader(buf), streamKey)
	out := make([]byte, 16)
	if _, err := r.Read(out); err == nil {
		t.Fatalf("tampered chunk should fail authentication")
	}
}

func TestChunkedStreamRejectsWrongKey(t *testing.T) {
	keyA, _ := deriveStreamKey(envelopeKeyForTest(t), []byte("test-stream-id-a"))
	keyB, _ := deriveStreamKey(envelopeKeyForTest(t), []byte("test-stream-id-b"))
	var pipe bytes.Buffer
	w, _ := newChunkedFrameWriter(&pipe, keyA)
	if _, err := w.Write([]byte("hi")); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, _ := newChunkedFrameReader(&pipe, keyB)
	out := make([]byte, 16)
	if _, err := r.Read(out); err == nil {
		t.Fatalf("wrong-key reader should reject chunk")
	}
}

func TestEncodeMACFieldsDisambiguates(t *testing.T) {
	a := encodeMACFields([]byte("alic"), []byte("ebob"))
	b := encodeMACFields([]byte("alice"), []byte("bob"))
	if bytes.Equal(a, b) {
		t.Fatalf("length-prefixed concatenation must not collide for shifted boundaries")
	}
}
