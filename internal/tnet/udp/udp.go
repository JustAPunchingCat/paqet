package udp

import (
	"errors"
	"time"
)

var (
	ErrClosed  = errors.New("udp: connection closed")
	ErrTimeout = errors.New("udp: i/o timeout")
)

const (
	handshakeTimeout  = 10 * time.Second
	keepAliveInterval = 15 * time.Second
	connectionTimeout = 120 * time.Second
)

var (
	// Magic bytes to identify direction and filter loopback
	MagicClient = []byte{0xCA, 0xFE, 0xBA, 0xBE}
	MagicServer = []byte{0xDE, 0xAD, 0xBE, 0xEF}
)
