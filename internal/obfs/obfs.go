package obfs

import (
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"paqet/internal/conf"
	"sync"
	"time"
)

var (
	ErrInvalidData    = errors.New("invalid obfuscated data")
	ErrBufferTooSmall = errors.New("buffer too small for obfuscation")
)

// Shared random state for all obfuscators in this package
var (
	noise   [4096]byte
	prng    = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	prngMu  sync.Mutex
	initOne sync.Once
)

func initNoise() {
	initOne.Do(func() {
		rand.Read(noise[:]) // Fill noise buffer once with crypto random
	})
}

// Obfuscator wraps/unwraps data with obfuscation layer to evade DPI detection
type Obfuscator interface {
	// Name returns the obfuscator identifier
	Name() string

	// Wrap adds obfuscation layer to plaintext data
	// Returns obfuscated data or error
	Wrap(data []byte) ([]byte, error)

	// Unwrap removes obfuscation layer from obfuscated data
	// Returns plaintext data or error
	Unwrap(data []byte) ([]byte, error)

	// Overhead returns maximum bytes added by obfuscation
	Overhead() int
}

// New creates an obfuscator based on configuration
func New(cfg *conf.Obfuscation, key []byte) (Obfuscator, error) {
	if cfg.UseTLS {
		return NewTLSRecordObfuscator(cfg, key)
	}
	if cfg.Padding.Enabled {
		return NewPaddingObfuscator(cfg, key)
	}
	return NewNoneObfuscator(key)
}
