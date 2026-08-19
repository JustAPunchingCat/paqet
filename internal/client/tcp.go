package client

import (
	"fmt"
	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"time"
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

	iter := c.iters[serverIdx]
	maxAttempts := len(iter.Items)
	if maxAttempts == 0 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		strm, tc, err := c.newStrm(serverIdx)
		if err != nil {
			lastErr = err
			continue
		}

		p := protocol.Proto{Type: protocol.PTCP, Addr: tAddr}
		strm.SetWriteDeadline(time.Now().Add(2 * time.Second))
		err = p.Write(strm)
		strm.SetWriteDeadline(time.Time{})
		if err != nil {
			flog.Debugf("failed to write TCP protocol header for %s on stream %d (attempt %d/%d): %v", addr, strm.SID(), attempt+1, maxAttempts, err)
			strm.Close()
			if tc != nil {
				tc.markDead()
			}
			lastErr = err
			continue
		}

		flog.Debugf("TCP stream %d created for %s", strm.SID(), addr)
		return strm, nil
	}

	return nil, fmt.Errorf("failed to create stream for TCP %s: %v", addr, lastErr)
}
