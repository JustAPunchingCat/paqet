package client

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/forward"
	"paqet/internal/pkg/iterator"
	"paqet/internal/socks"
	"paqet/internal/tnet"
	"sync"
	"syscall"
)

type Client struct {
	cfg      *conf.Conf
	iters    []*iterator.Iterator[*timedConn]
	udpPools []*udpPool
	mu       sync.Mutex
}

func New(cfg *conf.Conf) (*Client, error) {
	c := &Client{
		cfg:      cfg,
		iters:    make([]*iterator.Iterator[*timedConn], len(cfg.Servers)),
		udpPools: make([]*udpPool, len(cfg.Servers)),
	}
	for i := range c.udpPools {
		c.udpPools[i] = &udpPool{strms: make(map[uint64]tnet.Strm)}
	}
	return c, nil
}

func (c *Client) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sig:
			flog.Infof("Shutdown signal received...")
			cancel()
		case <-ctx.Done():
		}
	}()

	totalConns := 0
	activeServers := 0
	for sIdx := range c.cfg.Servers {
		srv := &c.cfg.Servers[sIdx]
		if !*srv.Enabled {
			continue
		}
		activeServers++
		for i := 0; i < srv.Transport.Conn; i++ {
			tc, err := newTimedConn(ctx, c.cfg, srv)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating client connection: %v\n", err)
				flog.Errorf("failed to create connection to server %d (conn %d): %v", sIdx+1, i+1, err)
				return err
			}
			flog.Debugf("client connection %d created successfully", i+1)
			if c.iters[sIdx] == nil {
				c.iters[sIdx] = &iterator.Iterator[*timedConn]{}
			}
			c.iters[sIdx].Items = append(c.iters[sIdx].Items, tc)
			totalConns++
		}

		for _, s5cfg := range srv.SOCKS5 {
			s5, err := socks.New(c, sIdx)
			if err != nil {
				flog.Errorf("failed to create SOCKS5 server: %v", err)
				continue
			}
			if err := s5.Start(ctx, s5cfg); err != nil {
				flog.Errorf("failed to start SOCKS5 server: %v", err)
			}
		}

		for _, fwdCfg := range srv.Forward {
			fwd, err := forward.New(c, fwdCfg.Listen.String(), fwdCfg.Target.String(), sIdx)
			if err != nil {
				flog.Errorf("failed to create forwarder: %v", err)
				continue
			}
			if err := fwd.Start(ctx, fwdCfg.Protocol); err != nil {
				flog.Errorf("failed to start forwarder: %v", err)
			}
		}
	}
	go c.ticker(ctx)

	ipv4Addr := "<nil>"
	ipv6Addr := "<nil>"
	if c.cfg.Network.IPv4.Addr != nil {
		ipv4Addr = c.cfg.Network.IPv4.Addr.IP.String()
	}
	if c.cfg.Network.IPv6.Addr != nil {
		ipv6Addr = c.cfg.Network.IPv6.Addr.IP.String()
	}
	flog.Infof("Client started: IPv4:%s IPv6:%s -> %d upstream servers (%d total connections)", ipv4Addr, ipv6Addr, activeServers, totalConns)

	<-ctx.Done()
	for _, iter := range c.iters {
		for _, tc := range iter.Items {
			tc.close()
		}
	}
	flog.Infof("client shutdown complete")
	return nil
}
