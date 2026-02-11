package forward

import (
	"context"
	"fmt"
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"sync"
)

type Client interface {
	TCPByIndex(serverIdx int, addr string) (tnet.Strm, error)
	UDPByIndex(serverIdx int, lAddr, tAddr string) (tnet.Strm, bool, uint64, error)
	CloseUDP(serverIdx int, key uint64) error
}

type Forward struct {
	client     Client
	listenAddr string
	targetAddr string
	wg         sync.WaitGroup
	ServerIdx  int
}

func New(client Client, listenAddr, targetAddr string, serverIdx int) (*Forward, error) {
	return &Forward{
		client:     client,
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		ServerIdx:  serverIdx,
	}, nil
}

func (f *Forward) Start(ctx context.Context, protocol string) error {
	flog.Debugf("starting %s forwarder: %s -> %s", protocol, f.listenAddr, f.targetAddr)
	switch protocol {
	case "tcp":
		return f.startTCP(ctx)
	case "udp":
		return f.startUDP(ctx)
	default:
		flog.Errorf("unsupported protocol: %s", protocol)
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (f *Forward) startTCP(ctx context.Context) error {
	f.wg.Go(func() {
		if err := f.listenTCP(ctx); err != nil {
			flog.Debugf("TCP forwarder stopped with: %v", err)
		}
	})
	return nil
}

func (f *Forward) startUDP(ctx context.Context) error {
	f.wg.Go(func() {
		f.listenUDP(ctx)
	})
	return nil
}
