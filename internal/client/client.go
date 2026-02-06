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
	cfg     *conf.Conf
	iter    *iterator.Iterator[*timedConn]
	udpPool *udpPool
	mu      sync.Mutex
}

func New(cfg *conf.Conf) (*Client, error) {
	c := &Client{
		cfg:     cfg,
		iter:    &iterator.Iterator[*timedConn]{},
		udpPool: &udpPool{strms: make(map[uint64]tnet.Strm)},
	}
	return c, nil
}

func (c *Client) Start(ctx context.Context) error {
	for sIdx := range c.cfg.Servers {
		srv := &c.cfg.Servers[sIdx]
		for i := 0; i < srv.Transport.Conn; i++ {
			tc, err := newTimedConn(ctx, c.cfg, srv)
			if err != nil {
				flog.Errorf("failed to establish connection to server %d (conn %d): %v", sIdx+1, i+1, err)
				return err
			}
			c.iter.Items = append(c.iter.Items, tc)
		}
	}
	go c.ticker(ctx)

	go func() {
		<-ctx.Done()
		for _, tc := range c.iter.Items {
			tc.close()
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
	flog.Infof("Client started: IPv4:%s IPv6:%s -> %d upstream servers (%d total connections)", ipv4Addr, ipv6Addr, len(c.cfg.Servers), len(c.iter.Items))
	return nil
}
