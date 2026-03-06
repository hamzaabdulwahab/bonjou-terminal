package network

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func randomSecretHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func TestLocalPublicKeyAndSharedKeyExchange(t *testing.T) {
	aliceSecret := randomSecretHex(t)
	bobSecret := randomSecretHex(t)

	alicePub, err := localPublicKeyFromSecret(aliceSecret)
	if err != nil {
		t.Fatalf("alice public key: %v", err)
	}
	bobPub, err := localPublicKeyFromSecret(bobSecret)
	if err != nil {
		t.Fatalf("bob public key: %v", err)
	}

	aliceShared, err := sharedKeyFromPeerPublic(aliceSecret, bobPub)
	if err != nil {
		t.Fatalf("alice shared key: %v", err)
	}
	bobShared, err := sharedKeyFromPeerPublic(bobSecret, alicePub)
	if err != nil {
		t.Fatalf("bob shared key: %v", err)
	}

	if hex.EncodeToString(aliceShared) != hex.EncodeToString(bobShared) {
		t.Fatal("shared keys do not match")
	}
}

func TestSharedKeyFromPeerPublicRejectsInvalidKey(t *testing.T) {
	_, err := sharedKeyFromPeerPublic(randomSecretHex(t), "not-hex")
	if err == nil {
		t.Fatal("expected invalid peer public key error")
	}
}
