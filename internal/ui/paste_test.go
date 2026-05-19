package ui

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// readAll runs the filter over input until EOF and returns the filtered bytes.
func readAll(t *testing.T, input string) string {
	t.Helper()
	pf := newPasteFilterReader(io.NopCloser(strings.NewReader(input)))
	out, err := io.ReadAll(pf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(out)
}

func TestPasteFilterPassThrough(t *testing.T) {
	got := readAll(t, "hello\nworld")
	want := "hello\nworld"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPasteFilterStripsMarkersAndFlattensNewlines(t *testing.T) {
	input := "@send Alice " + bracketedPasteStart + "line one\nline two\r\nline three" + bracketedPasteEnd
	got := readAll(t, input)
	want := "@send Alice line one line two  line three"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPasteFilterPreservesNewlinesOutsidePaste(t *testing.T) {
	input := "first\n" + bracketedPasteStart + "pasted\nblock" + bracketedPasteEnd + "\nlast"
	got := readAll(t, input)
	want := "first\npasted block\nlast"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPasteFilterPassesThroughCSISequences(t *testing.T) {
	// ESC [ A is arrow-up; should not be mistaken for a paste marker.
	input := "abc\x1b[A\x1b[Bxyz"
	got := readAll(t, input)
	want := "abc\x1b[A\x1b[Bxyz"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPasteFilterHandlesSplitReads(t *testing.T) {
	// Feed the paste markers and content in many tiny chunks to exercise the
	// "wait for more bytes" path in process().
	full := "x" + bracketedPasteStart + "ab\ncd" + bracketedPasteEnd + "y"
	chunks := make([][]byte, 0, len(full))
	for i := 0; i < len(full); i++ {
		chunks = append(chunks, []byte{full[i]})
	}
	pf := newPasteFilterReader(io.NopCloser(&chunkReader{chunks: chunks}))
	var out bytes.Buffer
	buf := make([]byte, 8)
	for {
		n, err := pf.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	want := "xab cdy"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

// chunkReader yields its chunks one-at-a-time, returning io.EOF after the last.
// It mirrors how a terminal might deliver bytes in small reads.
type chunkReader struct {
	chunks [][]byte
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	chunk := c.chunks[0]
	n := copy(p, chunk)
	if n < len(chunk) {
		c.chunks[0] = chunk[n:]
	} else {
		c.chunks = c.chunks[1:]
	}
	return n, nil
}
