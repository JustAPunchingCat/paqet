package socks

import (
	"context"
	"paqet/internal/tnet"
	"sync"
)

var rPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4+1+255+2) // header + addr + port (max domain length 255)
		return &b
	},
}

type Client interface {
	TCPByIndex(serverIdx int, addr string) (tnet.Strm, error)
	UDPByIndex(serverIdx int, lAddr, tAddr string) (tnet.Strm, bool, uint64, error)
	CloseUDP(serverIdx int, key uint64) error
}

type Handler struct {
	client    Client
	ctx       context.Context
	ServerIdx int
}
