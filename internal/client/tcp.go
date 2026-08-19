package client

import (
	"fmt"
	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
)

func (c *Client) TCP(addr string) (tnet.Strm, error) {
	return c.TCPByIndex(0, addr)
}

func (c *Client) TCPByIndex(serverIdx int, addr string) (tnet.Strm, error) {
	tAddr, err := tnet.NewAddr(addr)
	if err != nil {
		flog.Debugf("invalid TCP address %s: %v", addr, err)
		return nil, err
	}

	p := protocol.Proto{Type: protocol.PTCP, Addr: tAddr}

	iter := c.iters[serverIdx]
	maxAttempts := len(iter.Items)
	if maxAttempts == 0 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		tc := iter.Next()
		strm, err := tc.openAndSendProto(&p)
		if err == nil {
			flog.Debugf("TCP stream %d created for %s", strm.SID(), addr)
			return strm, nil
		}
		flog.Debugf("failed to establish TCP stream on connection (attempt %d/%d): %v", attempt+1, maxAttempts, err)
		lastErr = err
	}

	return nil, fmt.Errorf("failed to create stream for TCP %s: %v", addr, lastErr)
}
