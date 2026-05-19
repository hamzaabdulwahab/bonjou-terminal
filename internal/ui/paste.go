package ui

import (
	"bytes"
	"io"
)

const (
	// Terminal escape sequences that mark a paste from the OS clipboard while
	// bracketed-paste mode is enabled. We strip them from the input stream and
	// flatten any embedded newlines so the underlying readline implementation
	// receives a single logical line.
	bracketedPasteStart = "\x1b[200~"
	bracketedPasteEnd   = "\x1b[201~"

	// Sequences to toggle bracketed-paste mode on the controlling terminal.
	enableBracketedPaste  = "\x1b[?2004h"
	disableBracketedPaste = "\x1b[?2004l"
)

// pasteFilterReader wraps an io.ReadCloser and rewrites bracketed-paste
// sequences so readline never sees an Enter while a paste is in progress.
//
// Without this, pasting a multi-line message into an `@send` command causes
// readline to submit each line as a separate command — the embedded newlines
// look identical to the user pressing Enter.
type pasteFilterReader struct {
	inner   io.ReadCloser
	pending []byte // bytes read from inner but not yet emitted
	out     []byte // bytes ready to deliver to caller
	pasting bool
}

func newPasteFilterReader(inner io.ReadCloser) *pasteFilterReader {
	return &pasteFilterReader{inner: inner}
}

func (p *pasteFilterReader) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	for len(p.out) == 0 {
		tmp := make([]byte, max(len(buf), 1024))
		n, err := p.inner.Read(tmp)
		if n > 0 {
			p.pending = append(p.pending, tmp[:n]...)
			p.process()
		}
		if err != nil {
			if len(p.out) > 0 {
				break
			}
			return 0, err
		}
	}
	n := copy(buf, p.out)
	p.out = p.out[n:]
	return n, nil
}

// Close is a no-op. We wrap os.Stdin which must outlive the readline session,
// and chzyer/readline only closes the FillableStdin layer it creates, not the
// reader passed in via Config.Stdin.
func (p *pasteFilterReader) Close() error { return nil }

// process consumes p.pending byte-by-byte and appends emitted bytes to p.out.
// Bracketed-paste markers are stripped; CR/LF inside a paste become spaces.
// If the buffer ends mid-escape-sequence we stop and wait for more input.
func (p *pasteFilterReader) process() {
	startBytes := []byte(bracketedPasteStart)
	endBytes := []byte(bracketedPasteEnd)
	markerLen := len(startBytes)
	for len(p.pending) > 0 {
		b := p.pending[0]
		if b != 0x1b {
			if p.pasting && (b == '\r' || b == '\n') {
				p.out = append(p.out, ' ')
			} else {
				p.out = append(p.out, b)
			}
			p.pending = p.pending[1:]
			continue
		}
		// ESC byte. We need at least the full marker length to decide.
		if len(p.pending) >= markerLen {
			if bytes.HasPrefix(p.pending, startBytes) {
				p.pasting = true
				p.pending = p.pending[markerLen:]
				continue
			}
			if bytes.HasPrefix(p.pending, endBytes) {
				p.pasting = false
				p.pending = p.pending[markerLen:]
				continue
			}
			// Some other ESC sequence (arrow keys, etc.) — emit the ESC and
			// continue processing from the next byte so readline's existing
			// escape handling still works.
			p.out = append(p.out, b)
			p.pending = p.pending[1:]
			continue
		}
		// Fewer than markerLen bytes available. If the buffered prefix could
		// still grow into a paste marker, wait for more input. Otherwise emit
		// the ESC and keep processing.
		if isMarkerPrefix(p.pending) {
			return
		}
		p.out = append(p.out, b)
		p.pending = p.pending[1:]
	}
}

// isMarkerPrefix reports whether b is a strict, non-empty prefix of either
// bracketed-paste marker. Used to decide whether to wait for more input.
func isMarkerPrefix(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	candidates := [][]byte{[]byte(bracketedPasteStart), []byte(bracketedPasteEnd)}
	for _, c := range candidates {
		if len(b) < len(c) && bytes.HasPrefix(c, b) {
			return true
		}
	}
	return false
}
