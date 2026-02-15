package client

import (
	"context"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/hash"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"paqet/internal/tnet/udp"
	"sync/atomic"
	"time"
)

// udpStreamCounter generates unique keys for uncached UDP streams
var udpStreamCounter uint64

func (c *Client) UDP(srcAddr, dstAddr string) (tnet.Strm, bool, uint64, error) {
	return c.UDPByIndex(0, srcAddr, dstAddr)
}

func (c *Client) UDPByIndex(serverIdx int, lAddr, tAddr string) (tnet.Strm, bool, uint64, error) {
	key := hash.AddrPair(lAddr, tAddr)
	pool := c.udpPools[serverIdx]

	// Check cache
	pool.mu.RLock()
	if strm, exists := pool.strms[key]; exists {
		pool.mu.RUnlock()
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
	// Double-check if created concurrently
	if existing, exists := pool.strms[key]; exists {
		pool.mu.Unlock()
		strm.Close()
		return existing, false, key, nil
	}
	pool.strms[key] = strm
	pool.mu.Unlock()

	flog.Debugf("established UDP stream %d for %s -> %s", strm.SID(), lAddr, tAddr)
	return strm, true, key, nil
}

// UDPNew creates a new UDP stream without caching.
// Used by forward mode for parallel streams to the same target.
func (c *Client) UDPNew(serverIdx int, tAddr string) (tnet.Strm, uint64, error) {
	strm, err := c.newStrm(serverIdx)
	if err != nil {
		flog.Debugf("failed to create stream for UDP -> %s: %v", tAddr, err)
		return nil, 0, err
	}

	taddr, err := tnet.NewAddr(tAddr)
	if err != nil {
		flog.Debugf("invalid UDP address %s: %v", tAddr, err)
		strm.Close()
		return nil, 0, err
	}
	p := protocol.Proto{Type: protocol.PUDP, Addr: taddr}
	err = p.Write(strm)
	if err != nil {
		flog.Debugf("failed to write UDP protocol header for -> %s on stream %d: %v", tAddr, strm.SID(), err)
		strm.Close()
		return nil, 0, err
	}

	// Generate unique key for tracking (not stored in pool)
	key := atomic.AddUint64(&udpStreamCounter, 1)

	flog.Debugf("established UDP stream %d for -> %s", strm.SID(), tAddr)
	return strm, key, nil
}

// CloseUDPStream closes a stream directly (for UDPNew streams).
func (c *Client) CloseUDPStream(strm tnet.Strm) {
	if strm != nil {
		strm.Close()
	}
}

func (c *Client) CloseUDP(serverIdx int, key uint64) error {
	return c.udpPools[serverIdx].delete(key)
}

// UDPDatagramByIndex gets an existing datagram session or creates a new one.
func (c *Client) UDPDatagramByIndex(serverIdx int, lAddr, tAddr string) (*UDPDatagramSession, bool, uint64, error) {
	// Use a prefix to avoid collision with standard UDP streams in the same pool
	key := hash.AddrPair(lAddr, "dgm:"+tAddr)
	pool := c.udpPools[serverIdx]

	// Check cache
	pool.mu.RLock()
	if strm, exists := pool.strms[key]; exists {
		pool.mu.RUnlock()
		if sess, ok := strm.(*UDPDatagramSession); ok {
			return sess, false, key, nil
		}
		// Should not happen if keys are distinct, but safe fallback
	}
	pool.mu.RUnlock()

	// Create new session
	// Use background context because the session outlives this single packet request
	sess, err := c.UDPDatagramNew(context.Background(), serverIdx, tAddr)
	if err != nil {
		return nil, false, 0, err
	}

	pool.mu.Lock()
	// Double-check
	if existing, exists := pool.strms[key]; exists {
		pool.mu.Unlock()
		sess.Close()
		if sess, ok := existing.(*UDPDatagramSession); ok {
			return sess, false, key, nil
		}
	}
	pool.strms[key] = sess
	pool.mu.Unlock()

	return sess, true, key, nil
}

// UDPDatagramNew creates a new datagram-based UDP session if the transport supports it.
// Returns nil if datagrams are not supported (caller should fall back to streams).
func (c *Client) UDPDatagramNew(ctx context.Context, serverIdx int, tAddr string) (*UDPDatagramSession, error) {
	// Get a connection and check if it supports datagrams
	iter := c.iters[serverIdx]
	if iter == nil {
		return nil, nil
	}
	// Get a connection (reuse existing logic)
	tc := iter.Next()
	if tc == nil || tc.conn == nil {
		return nil, nil
	}

	// Open a control stream to register the datagram session
	strm, err := tc.conn.OpenStrm()
	if err != nil {
		return nil, err
	}

	// Enable unordered mode on the client side too
	if udpStrm, ok := strm.(*udp.Strm); ok {
		udpStrm.SetUnordered(true)
	}

	taddr, err := tnet.NewAddr(tAddr)
	if err != nil {
		strm.Close()
		return nil, err
	}

	// Send PUDPDGM protocol header to register datagram mode
	p := protocol.Proto{Type: protocol.PUDPDGM, Addr: taddr}
	if err := p.Write(strm); err != nil {
		strm.Close()
		return nil, err
	}
	// Do NOT close the stream. We use this stream for the datagrams.

	sessCtx, cancel := context.WithCancel(ctx)
	flog.Infof("established UDP datagram session for -> %s", tAddr)

	return &UDPDatagramSession{
		strm:   strm,
		ctx:    sessCtx,
		cancel: cancel,
	}, nil
}

type UDPDatagramSession struct {
	strm   tnet.Strm
	ctx    context.Context
	cancel context.CancelFunc
}

// Send sends a UDP packet via QUIC datagram.
func (s *UDPDatagramSession) Send(data []byte) error {
	_, err := s.strm.Write(data)
	return err
}

// Close closes the datagram session.
func (s *UDPDatagramSession) Close() error {
	s.cancel()
	return s.strm.Close()
}

// Implement tnet.Strm interface for UDPDatagramSession so it can be stored in udpPool
func (s *UDPDatagramSession) Read(b []byte) (int, error)         { return s.strm.Read(b) }
func (s *UDPDatagramSession) Write(b []byte) (int, error)        { return s.strm.Write(b) }
func (s *UDPDatagramSession) LocalAddr() net.Addr                { return s.strm.LocalAddr() }
func (s *UDPDatagramSession) RemoteAddr() net.Addr               { return s.strm.RemoteAddr() }
func (s *UDPDatagramSession) SetDeadline(t time.Time) error      { return s.strm.SetDeadline(t) }
func (s *UDPDatagramSession) SetReadDeadline(t time.Time) error  { return s.strm.SetReadDeadline(t) }
func (s *UDPDatagramSession) SetWriteDeadline(t time.Time) error { return s.strm.SetWriteDeadline(t) }
func (s *UDPDatagramSession) SID() int                           { return s.strm.SID() }
