package network

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// Wire format for chunked-AEAD streams (v2):
//
//	for each plaintext chunk (plaintext sized up to streamChunkPlainBytes):
//	  [4-byte big-endian uint32: len(ciphertext)+tag length]
//	  [ciphertext]
//	  [16-byte GCM tag]   ← appended by aead.Seal
//
// The nonce is *not* sent on the wire — it is derived deterministically
// from a per-stream subkey and a monotonic counter. Both sides reset the
// counter to zero at the start of each transfer. The per-stream subkey is
// derived from the shared secret + the streamID announced in the envelope,
// guaranteeing nonce uniqueness without per-chunk nonce bytes on the wire.
//
// Authentication is per chunk: any tampering with a chunk (or its length
// header) is detected immediately at aead.Open, before any plaintext is
// written to disk. End-of-stream is reached when the receiver has observed
// total plaintext bytes equal to envelope.Size.
const (
	// streamChunkPlainBytes caps the plaintext per AEAD chunk. 64 KiB
	// matches the legacy CTR chunk size, so existing buffer sizing is
	// preserved.
	streamChunkPlainBytes = 64 * 1024
	// streamMaxFrameBytes bounds memory a malicious sender can force us to
	// allocate per chunk: plaintext + tag (16 B) + slack.
	streamMaxFrameBytes = streamChunkPlainBytes + 1024
)

// chunkedFrameWriter encrypts and frames plaintext under AES-GCM into the
// wire format documented above.
type chunkedFrameWriter struct {
	inner   io.Writer
	aead    cipher.AEAD
	counter uint64
}

func newChunkedFrameWriter(inner io.Writer, streamKey []byte) (*chunkedFrameWriter, error) {
	aead, err := newGCM(streamKey)
	if err != nil {
		return nil, err
	}
	if aead.NonceSize() != 12 {
		return nil, fmt.Errorf("unexpected AEAD nonce size: %d", aead.NonceSize())
	}
	return &chunkedFrameWriter{inner: inner, aead: aead}, nil
}

// Write seals plaintext into one or more AEAD chunks. Plaintext longer than
// streamChunkPlainBytes is split into multiple chunks.
func (w *chunkedFrameWriter) Write(plaintext []byte) (int, error) {
	if len(plaintext) == 0 {
		return 0, nil
	}
	total := 0
	for total < len(plaintext) {
		end := total + streamChunkPlainBytes
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk := plaintext[total:end]
		nonce := chunkNonce(streamDirSend, w.counter)
		w.counter++
		sealed := w.aead.Seal(nil, nonce, chunk, nil)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(sealed)))
		if _, err := w.inner.Write(lenBuf[:]); err != nil {
			return total, err
		}
		if _, err := w.inner.Write(sealed); err != nil {
			return total, err
		}
		total = end
	}
	return total, nil
}

// chunkedFrameReader reads framed AEAD chunks and exposes the decrypted
// plaintext as a normal io.Reader.
type chunkedFrameReader struct {
	inner   io.Reader
	aead    cipher.AEAD
	counter uint64
	pending []byte
}

func newChunkedFrameReader(inner io.Reader, streamKey []byte) (*chunkedFrameReader, error) {
	aead, err := newGCM(streamKey)
	if err != nil {
		return nil, err
	}
	return &chunkedFrameReader{inner: inner, aead: aead}, nil
}

func (r *chunkedFrameReader) Read(out []byte) (int, error) {
	if len(out) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		if err := r.fillPending(); err != nil {
			return 0, err
		}
	}
	n := copy(out, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *chunkedFrameReader) fillPending() error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r.inner, lenBuf[:]); err != nil {
		return err
	}
	frameLen := binary.BigEndian.Uint32(lenBuf[:])
	if frameLen == 0 {
		return io.EOF
	}
	if frameLen > streamMaxFrameBytes {
		return fmt.Errorf("rejecting chunk: frame size %d exceeds max %d", frameLen, streamMaxFrameBytes)
	}
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(r.inner, frame); err != nil {
		return err
	}
	nonce := chunkNonce(streamDirSend, r.counter)
	r.counter++
	plain, err := r.aead.Open(nil, nonce, frame, nil)
	if err != nil {
		return fmt.Errorf("chunk authentication failed (chunk %d): %w", r.counter-1, err)
	}
	r.pending = plain
	return nil
}

// randomStreamID produces a 16-byte identifier used as part of the HKDF
// info string for a per-stream AEAD subkey. Returned as raw bytes; callers
// hex-encode when serializing into the envelope.
func randomStreamID() ([]byte, error) {
	out := make([]byte, 16)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}
