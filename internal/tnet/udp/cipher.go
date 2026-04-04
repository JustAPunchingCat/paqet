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
	keyLen := len(c.key)
	if keyLen == 0 || len(data) == 0 {
		return data
	}
	// In-place XOR for zero-allocation performance
	for i := range data {
		data[i] ^= c.key[i%keyLen]
	}
	return data
}

func (c *cipher) decrypt(data []byte) []byte {
	return c.encrypt(data) // XOR is symmetric
}
