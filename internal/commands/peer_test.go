package commands

import "testing"

func TestSanitiseUsernameStripsControlAndZeroWidth(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		want       string
		wantChange bool
	}{
		{"plain", "alice", "alice", false},
		{"spaces", "alice cooper", "alice-cooper", true},
		// Leading/trailing trim alone is not reported as a "change" — the
		// caller only wants notification when an interior character was
		// translated or removed.
		{"leading-trailing-space", "  bob  ", "bob", false},
		{"control-chars", "ali\x00ce\x07", "alice", true},
		{"zero-width-joiner", "ali​ce", "alice", true},
		{"bidi-override", "ali‮ce", "alice", true},
	}
	for _, c := range cases {
		got, changed := sanitiseUsername(c.input)
		if got != c.want {
			t.Errorf("[%s] got=%q want=%q", c.name, got, c.want)
		}
		if changed != c.wantChange {
			t.Errorf("[%s] changed=%v want=%v", c.name, changed, c.wantChange)
		}
	}
}

func TestSanitiseUsernameRejectsEmptyAfterStripping(t *testing.T) {
	got, _ := sanitiseUsername("\x00\x00​")
	if got != "" {
		t.Fatalf("all-unsafe input should produce empty username, got %q", got)
	}
}
