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
		return nil, fmt.Errorf("this peer has not shared their encryption key yet — wait for them to appear in @users and try again")
	}
	publicBytes, err := hex.DecodeString(peerPublicHex)
	if err != nil {
		return nil, fmt.Errorf("received an invalid encryption key from this peer — they may be running a different version of Bonjou")
	}
	pub, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return nil, fmt.Errorf("received an invalid encryption key from this peer — they may be running a different version of Bonjou")
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("could not establish a secure connection with this peer — they may be running a different version of Bonjou")
	}
	sum := sha256.Sum256(secret)
	return sum[:], nil
}

func privateKeyFromSecret(secret string) (*ecdh.PrivateKey, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, fmt.Errorf("your Bonjou configuration is incomplete — try deleting ~/.bonjou/config.json and restarting")
	}
	seed := sha256.Sum256([]byte(secret))
	private := seed
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	return ecdh.X25519().NewPrivateKey(private[:])
}
