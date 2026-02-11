package udp

import (
	"crypto/sha256"
)

type cipher struct {
	key []byte
}

func newCipher(key string) (*cipher, error) {
	h := sha256.Sum256([]byte(key))
	return &cipher{key: h[:]}, nil
}

func (c *cipher) encrypt(data []byte) []byte {
	// Simple XOR for demonstration/performance
	out := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		out[i] = data[i] ^ c.key[i%len(c.key)]
	}
	return out
}

func (c *cipher) decrypt(data []byte) []byte {
	return c.encrypt(data) // XOR is symmetric
}
