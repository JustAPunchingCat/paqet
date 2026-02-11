package client

import (
	"context"
	"fmt"
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
	flog.Infof("Client started: IPv4:%s IPv6:%s -> %d upstream servers (%d total connections)", ipv4Addr, ipv6Addr, activeServers, totalConns)
	return nil
}

func (c *Client) newStrm(serverIdx int) (tnet.Strm, error) {
	iter := c.iters[serverIdx]
	// Try all connections in round-robin
	for i := 0; i < len(iter.Items); i++ {
		tc := iter.Next()

		tc.mu.Lock()
		if tc.conn == nil {
			var err error
			tc.conn, err = tc.createConn()
			if err != nil {
				tc.mu.Unlock()
				flog.Debugf("failed to connect to server %d: %v", serverIdx+1, err)
				continue
			}
		}

		strm, err := tc.conn.OpenStrm()
		if err == nil {
			tc.mu.Unlock()
			return strm, nil
		}

		flog.Debugf("failed to open stream, reconnecting: %v", err)
		if tc.conn != nil {
			tc.conn.Close()
		}

		// Reconnect
		tc.conn, err = tc.createConn()
		if err != nil {
			flog.Debugf("reconnection failed: %v", err)
			tc.conn = nil
			tc.mu.Unlock()
			continue
		}

		// Retry opening stream on new connection
		strm, err = tc.conn.OpenStrm()
		if err == nil {
			flog.Infof("reconnected to server %d", serverIdx+1)
			tc.mu.Unlock()
			return strm, nil
		}

		flog.Debugf("failed to open stream after reconnect: %v", err)
		tc.conn.Close()
		tc.conn = nil
		tc.mu.Unlock()
	}
	return nil, fmt.Errorf("no healthy connections available for server %d", serverIdx+1)
}
