package client

import (
	"paqet/internal/flog"
	"paqet/internal/pkg/hash"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
)

func (c *Client) UDP(srcAddr, dstAddr string) (tnet.Strm, bool, uint64, error) {
	return c.UDPByIndex(0, srcAddr, dstAddr)
}

func (c *Client) UDPByIndex(serverIdx int, lAddr, tAddr string) (tnet.Strm, bool, uint64, error) {
	key := hash.AddrPair(lAddr, tAddr)
	pool := c.udpPools[serverIdx]
	pool.mu.RLock()
	if strm, exists := pool.strms[key]; exists {
		pool.mu.RUnlock()
		flog.Debugf("reusing UDP stream %d for %s -> %s", strm.SID(), lAddr, tAddr)
		return strm, false, key, nil
	}
	pool.mu.RUnlock()

	strm, err := c.newStrm(serverIdx)
	if err != nil {
		flog.Debugf("failed to create stream for UDP %s -> %s: %v", lAddr, tAddr, err)
		return nil, false, 0, err
	}

	taddr, err := tnet.NewAddr(tAddr)
	if err != nil {
		flog.Debugf("invalid UDP address %s: %v", tAddr, err)
		strm.Close()
		return nil, false, 0, err
	}
	p := protocol.Proto{Type: protocol.PUDP, Addr: taddr}
	err = p.Write(strm)
	if err != nil {
		flog.Debugf("failed to write UDP protocol header for %s -> %s on stream %d: %v", lAddr, tAddr, strm.SID(), err)
		strm.Close()
		return nil, false, 0, err
	}

	pool.mu.Lock()
	pool.strms[key] = strm
	pool.mu.Unlock()

	flog.Debugf("established UDP stream %d for %s -> %s", strm.SID(), lAddr, tAddr)
	return strm, true, key, nil
}

func (c *Client) CloseUDP(serverIdx int, key uint64) error {
	return c.udpPools[serverIdx].delete(key)
}
