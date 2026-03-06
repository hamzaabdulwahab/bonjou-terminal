package network

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func localPublicKeyFromSecret(secret string) (string, error) {
	priv, err := privateKeyFromSecret(secret)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(priv.PublicKey().Bytes()), nil
}

func sharedKeyFromPeerPublic(localSecret, peerPublicHex string) ([]byte, error) {
	priv, err := privateKeyFromSecret(localSecret)
	if err != nil {
		return nil, err
	}
	peerPublicHex = strings.TrimSpace(peerPublicHex)
	if peerPublicHex == "" {
		return nil, fmt.Errorf("missing peer public key")
	}
	publicBytes, err := hex.DecodeString(peerPublicHex)
	if err != nil {
		return nil, fmt.Errorf("decode peer public key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid peer public key: %w", err)
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh failed: %w", err)
	}
	sum := sha256.Sum256(secret)
	return sum[:], nil
}

func privateKeyFromSecret(secret string) (*ecdh.PrivateKey, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, fmt.Errorf("missing local secret")
	}
	seed := sha256.Sum256([]byte(secret))
	private := seed
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	return ecdh.X25519().NewPrivateKey(private[:])
}
