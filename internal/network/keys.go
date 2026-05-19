package network

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// envelopeInfo, streamInfoPrefix, and macInfo are HKDF domain-separation
// labels. Different `info` strings yield independent keys from the same
// shared secret, so an attacker who recovers a stream key cannot derive the
// envelope key (and vice versa). The strings are versioned by including
// "v2" so a future protocol bump produces fresh keys even with the same
// shared secret.
const (
	envelopeInfo     = "bonjou/v2/envelope"
	streamInfoPrefix = "bonjou/v2/stream/"
	macInfo          = "bonjou/v2/mac"
	keyLen           = 32 // AES-256 key length in bytes
)

// deriveEnvelopeKey expands the shared secret into a dedicated key used for
// AES-256-GCM envelope encryption. The same `shared` always produces the
// same envelope key — fine because GCM uses a random per-message nonce.
func deriveEnvelopeKey(shared []byte) ([]byte, error) {
	return hkdfExpand(shared, envelopeInfo, keyLen)
}

// deriveMACKey expands the shared secret into a dedicated key for inline
// envelope HMACs. Kept separate from the AEAD key so each primitive uses
// its own keying material.
func deriveMACKey(shared []byte) ([]byte, error) {
	return hkdfExpand(shared, macInfo, keyLen)
}

// deriveStreamKey expands the shared secret + per-stream identifier into a
// dedicated AEAD key for one file/folder transfer. The streamID is a random
// value (16 bytes) sent in the kindFile/kindFolder envelope; binding the
// derived key to it makes nonce reuse across streams impossible.
func deriveStreamKey(shared, streamID []byte) ([]byte, error) {
	if len(streamID) == 0 {
		return nil, errors.New("streamID required")
	}
	info := streamInfoPrefix + string(streamID)
	return hkdfExpand(shared, info, keyLen)
}

func hkdfExpand(secret []byte, info string, length int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("empty secret")
	}
	if length <= 0 {
		return nil, fmt.Errorf("invalid length: %d", length)
	}
	// HKDF-Extract is skipped (salt nil) because the input already has
	// sufficient entropy (output of SHA-256(ECDH)). HKDF-Expand alone is
	// fine in that case per RFC 5869.
	reader := hkdf.Expand(sha256.New, secret, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, err
	}
	return out, nil
}

// chunkNonce builds the 12-byte AES-GCM nonce for a stream chunk:
//
//	[4-byte uint32 "Bonj"-ish magic][8-byte uint64 chunk counter]
//
// The magic prefix is fixed per direction; the counter increments per
// chunk. Because each stream uses its own AEAD key (deriveStreamKey), the
// counter resets safely at zero for every transfer.
func chunkNonce(direction streamDirection, counter uint64) []byte {
	var prefix uint32
	switch direction {
	case streamDirSend:
		prefix = 0x426F6E6A // "Bonj"
	case streamDirRecv:
		prefix = 0x4A6F6E62 // mirror
	}
	out := make([]byte, 12)
	binary.BigEndian.PutUint32(out[:4], prefix)
	binary.BigEndian.PutUint64(out[4:], counter)
	return out
}

type streamDirection int

const (
	streamDirSend streamDirection = iota
	streamDirRecv
)

// hmacLenPrefixedFields concatenates fields with a 4-byte big-endian length
// prefix per field so adjacent strings cannot be ambiguously concatenated
// (e.g. From="alic", To="ebob" no longer collides with From="alice", To="bob").
//
// Returns the input fed to HMAC, ready for mac.Write.
func encodeMACFields(fields ...[]byte) []byte {
	total := 0
	for _, f := range fields {
		total += 4 + len(f)
	}
	out := make([]byte, 0, total)
	var lenBuf [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(f)))
		out = append(out, lenBuf[:]...)
		out = append(out, f...)
	}
	return out
}

// newGCM constructs an AES-256-GCM AEAD from the given 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("aead key length = %d, want %d", len(key), keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
