package udp

import (
	"bytes"
	"testing"
)

func TestCipherRoundTrip(t *testing.T) {
	c, err := newCipher("my-secret-key")
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	original := []byte("hello world from paqet udp cipher")
	data := make([]byte, len(original))
	copy(data, original)

	// In-place encrypt
	encrypted := c.encrypt(data)

	// In-place decrypt
	decrypted := c.decrypt(encrypted)

	if !bytes.Equal(original, decrypted) {
		t.Errorf("decrypted data mismatch: got %s, want %s", decrypted, original)
	}
}

func TestCipherEmptyPayload(t *testing.T) {
	c, err := newCipher("key")
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	data := []byte{}
	encrypted := c.encrypt(data)
	if len(encrypted) != 0 {
		t.Errorf("expected empty encrypted payload, got len %d", len(encrypted))
	}
}
