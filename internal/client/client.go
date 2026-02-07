package client

import (
	"context"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/pkg/iterator"
	"paqet/internal/tnet"
	"sync"
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
	totalConns := 0
	for sIdx := range c.cfg.Servers {
		srv := &c.cfg.Servers[sIdx]
		for i := 0; i < srv.Transport.Conn; i++ {
			tc, err := newTimedConn(ctx, c.cfg, srv)
			if err != nil {
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
	}
	go c.ticker(ctx)

	go func() {
		<-ctx.Done()
		for _, iter := range c.iters {
			for _, tc := range iter.Items {
				tc.close()
			}
		}
		flog.Infof("client shutdown complete")
	}()

	ipv4Addr := "<nil>"
	ipv6Addr := "<nil>"
	if c.cfg.Network.IPv4.Addr != nil {
		ipv4Addr = c.cfg.Network.IPv4.Addr.IP.String()
	}
	if c.cfg.Network.IPv6.Addr != nil {
		ipv6Addr = c.cfg.Network.IPv6.Addr.IP.String()
	}
	flog.Infof("Client started: IPv4:%s IPv6:%s -> %d upstream servers (%d total connections)", ipv4Addr, ipv6Addr, len(c.cfg.Servers), totalConns)
	return nil
}
