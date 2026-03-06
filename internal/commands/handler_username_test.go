package commands

import (
	"testing"

	"github.com/hamzawahab/bonjou-cli/internal/network"
)

func TestResolveUniqueUsernameUnchangedWhenAvailable(t *testing.T) {
	peers := []network.Peer{{Username: "alex", IP: "192.168.1.10"}}
	name, changed := resolveUniqueUsername("hamza", "192.168.1.25", peers)
	if changed {
		t.Fatal("expected unchanged username")
	}
	if name != "hamza" {
		t.Fatalf("unexpected name: %s", name)
	}
}

func TestResolveUniqueUsernameAddsDeterministicSuffix(t *testing.T) {
	peers := []network.Peer{{Username: "hamza", IP: "192.168.1.10"}}
	name, changed := resolveUniqueUsername("hamza", "192.168.1.25", peers)
	if !changed {
		t.Fatal("expected collision adjustment")
	}
	if name != "hamza-1-25" {
		t.Fatalf("unexpected adjusted name: %s", name)
	}
}

func TestResolveUniqueUsernameIncrementsWhenSuffixTaken(t *testing.T) {
	peers := []network.Peer{
		{Username: "hamza", IP: "192.168.1.10"},
		{Username: "hamza-1-25", IP: "192.168.1.11"},
	}
	name, changed := resolveUniqueUsername("hamza", "192.168.1.25", peers)
	if !changed {
		t.Fatal("expected collision adjustment")
	}
	if name != "hamza-1-25-2" {
		t.Fatalf("unexpected adjusted name: %s", name)
	}
}

func TestAppendUsernameSuffixLimitsLength(t *testing.T) {
	base := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	name := appendUsernameSuffix(base, "123-456")
	if len(name) > 64 {
		t.Fatalf("name exceeds length limit: %d", len(name))
	}
}
