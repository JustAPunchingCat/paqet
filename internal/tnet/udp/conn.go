package udp

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net"
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"sync"
	"sync/atomic"
	"time"
)

// Conn implements tnet.Conn using a simple packet muxer over UDP.
// Format: [StreamID (4 bytes)][Seq (4 bytes)][CRC32 (4 bytes)][Flags (1 byte)][Data]
type Conn struct {
	conn         net.Conn
	streams      map[uint32]*muxStream
	mu           sync.RWMutex
	acceptCh     chan *muxStream
	datagramCh   chan []byte // Channel for received datagrams (Stream ID 0)
	closed       chan struct{}
	nextID       uint32
	isServer     bool
	readLoopWg   sync.WaitGroup
	lastRemoteID uint32 // Track last accepted ID to ignore late/replayed streams
	unordered    bool   // Default mode for new streams
	mtu          int    // Max fragment size
	lastActivity int64
}

const (
	flagMoreFrags = 0x01 // Flag indicating more fragments follow
	flagStart     = 0x02 // Flag indicating start of a message
	flagKeepAlive = 0x04 // Flag for keepalive packets
)

var packetPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

func newConn(adapter net.Conn, isServer bool, unordered bool, mtu int) *Conn {
	if mtu <= 0 {
		mtu = 1350
	}
	c := &Conn{
		conn:         adapter,
		streams:      make(map[uint32]*muxStream),
		acceptCh:     make(chan *muxStream, 1024),
		datagramCh:   make(chan []byte, 65536),
		closed:       make(chan struct{}),
		isServer:     isServer,
		nextID:       1,
		unordered:    unordered,
		mtu:          mtu,
		lastActivity: time.Now().UnixNano(),
	}
	if isServer {
		c.nextID = 2
	}
	c.readLoopWg.Add(1)
	go c.readLoop()
	go c.keepAliveLoop()
	return c
}

func (c *Conn) OpenStrm() (tnet.Strm, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.closed:
		return nil, net.ErrClosed
	default:
	}

	id := c.nextID
	c.nextID += 2

	strm := newMuxStream(c, id)
	strm.SetUnordered(c.unordered)
	c.streams[id] = strm
	return &Strm{stream: strm, conn: c}, nil
}

func (c *Conn) AcceptStrm() (tnet.Strm, error) {
	select {
	case s := <-c.acceptCh:
		return &Strm{stream: s, conn: c}, nil
	case <-c.closed:
		return nil, net.ErrClosed
	}
}

func (c *Conn) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
		c.conn.Close()
		c.mu.Lock()
		var streamsToClose []*muxStream
		for _, s := range c.streams {
			streamsToClose = append(streamsToClose, s)
		}
		c.streams = make(map[uint32]*muxStream)
		c.mu.Unlock()
		for _, s := range streamsToClose {
			s.closeInternal()
		}
	}
	return nil
}

func (c *Conn) SetMtu(mtu int) bool {
	c.mu.Lock()
	c.mtu = mtu
	c.mu.Unlock()
	return true
}

func (c *Conn) readLoop() {
	defer c.readLoopWg.Done()
	buf := make([]byte, 65536)

	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			c.Close()
			return
		}

		atomic.StoreInt64(&c.lastActivity, time.Now().UnixNano())

		if n < 13 {
			flog.Debugf("UDP Conn: packet too short: %d", n)
			continue
		}

		sid := binary.BigEndian.Uint32(buf[:4])
		seq := binary.BigEndian.Uint32(buf[4:8])
		sum := binary.BigEndian.Uint32(buf[8:12])
		flags := buf[12]

		// Handle KeepAlive
		if flags&flagKeepAlive != 0 {
			continue
		}

		// Use pooled buffer for active streams to avoid continuous heap allocations.
		var payload []byte
		var bp *[]byte
		if sid != 0 {
			bp = packetPool.Get().(*[]byte)
			pkt := *bp
			if cap(pkt) < n-13 {
				pkt = make([]byte, n-13)
				*bp = pkt
			}
			payload = pkt[:n-13]
			copy(payload, buf[13:n])
		} else {
			payload = make([]byte, n-13)
			copy(payload, buf[13:n])
		}

		// Verify CRC32
		if crc32.ChecksumIEEE(payload) != sum {
			flog.Debugf("UDP packet dropped: CRC mismatch (len=%d)", len(payload))
			if bp != nil {
				packetPool.Put(bp)
			}
			continue // Drop corrupted packet
		}

		// Stream ID 0 is reserved for unreliable datagrams
		if sid == 0 {
			select {
			case c.datagramCh <- payload:
			default: // Drop if buffer full
			}
			continue
		}

		c.mu.RLock()
		strm, exists := c.streams[sid]
		c.mu.RUnlock()

		if exists {
			atomic.StoreInt64(&strm.lastActivity, time.Now().UnixNano())
			select {
			case strm.rx <- fragment{seq: seq, data: payload, more: flags&flagMoreFrags != 0, flags: flags, bp: bp}:
			default:
				flog.Debugf("UDP Conn: stream %d buffer full, dropping packet", sid)
				if bp != nil {
					packetPool.Put(bp)
				}
			}
		} else if !c.isServer || (sid%2 != 1) {
			// flog.Debugf("UDP Conn: ignoring unknown stream %d", sid)
			if bp != nil {
				packetPool.Put(bp)
			}
			continue
		} else {
			// Check if this is an old ID from a closed stream
			// Allow a window of 1024 for out-of-order stream creation packets
			c.mu.RLock()
			if c.lastRemoteID > 1024 && sid <= c.lastRemoteID-1024 {
				c.mu.RUnlock()
				if bp != nil {
					packetPool.Put(bp)
				}
				continue
			}
			c.mu.RUnlock()

			c.mu.Lock()
			if _, exists := c.streams[sid]; exists {
				c.mu.Unlock()
				if bp != nil {
					packetPool.Put(bp)
				}
				continue
			}
			// Only create a new stream if it contains the start flag
			if flags&flagStart == 0 {
				c.mu.Unlock()
				if bp != nil {
					packetPool.Put(bp)
				}
				continue
			}
			strm := newMuxStream(c, sid)
			// Always start accepted streams in Ordered mode to ensure the handshake (gob)
			// is received correctly. The handler can switch to Unordered mode later.
			strm.SetUnordered(false)
			c.streams[sid] = strm
			if sid > c.lastRemoteID {
				c.lastRemoteID = sid
			}
			c.mu.Unlock()

			select {
			case strm.rx <- fragment{seq: seq, data: payload, more: flags&flagMoreFrags != 0, flags: flags, bp: bp}:
			default:
				if bp != nil {
					packetPool.Put(bp)
				}
			}

			select {
			case c.acceptCh <- strm:
			default:
				strm.closeInternal()
			}
		}
	}
}

func (c *Conn) closeStream(id uint32) {
	c.mu.Lock()
	delete(c.streams, id)
	c.mu.Unlock()
}

func (c *Conn) keepAliveLoop() {
	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			idle := time.Since(time.Unix(0, atomic.LoadInt64(&c.lastActivity)))

			if idle > connectionTimeout {
				flog.Debugf("UDP Conn timed out after %v idle", idle)
				c.Close()
				return
			}

			// Send KeepAlive packet (SID=0, Seq=0, Flags=KeepAlive, Empty Data)
			c.writePacket(0, 0, nil, flagKeepAlive)

			c.mu.Lock()
			now := time.Now()
			var idleStreams []*muxStream
			for _, s := range c.streams {
				idle := now.Sub(time.Unix(0, atomic.LoadInt64(&s.lastActivity)))
				if idle > connectionTimeout {
					idleStreams = append(idleStreams, s)
				}
			}
			c.mu.Unlock()

			for _, s := range idleStreams {
				s.closeInternal()
			}
		}
	}
}

func (c *Conn) writePacket(id, seq uint32, data []byte, flags byte) error {
	// Use pool to reduce GC pressure
	bufp := packetPool.Get().(*[]byte)
	pkt := *bufp

	if cap(pkt) < 13+len(data) {
		pkt = make([]byte, 13+len(data))
	}
	pkt = pkt[:13+len(data)]

	binary.BigEndian.PutUint32(pkt[:4], id)
	binary.BigEndian.PutUint32(pkt[4:8], seq)
	sum := crc32.ChecksumIEEE(data)
	binary.BigEndian.PutUint32(pkt[8:12], sum)
	pkt[12] = flags
	copy(pkt[13:], data)

	// flog.Debugf("Writing UDP packet: id=%d len=%d crc=%x", id, len(data), sum)
	_, err := c.conn.Write(pkt)

	*bufp = pkt
	packetPool.Put(bufp)

	return err
}

func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }
func (c *Conn) Ping(wait bool) error               { return nil } // UDP is connectionless
func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case data := <-c.datagramCh:
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, net.ErrClosed
	}
}
func (c *Conn) SendDatagram(data []byte) error {
	return c.writePacket(0, 0, data, 0)
}
func (c *Conn) SupportsDatagrams() bool { return true }

var _ tnet.DatagramConn = (*Conn)(nil)

type fragment struct {
	seq   uint32
	data  []byte
	more  bool
	flags byte
	bp    *[]byte // Backing buffer from sync.Pool to be returned after reading
}

// muxStream implements tnet.Strm for the custom packet muxer.
type muxStream struct {
	conn            *Conn
	id              uint32
	rx              chan fragment
	buf             []byte
	pendingPoolBuf  *[]byte             // Backing buffer for s.buf if it was pooled
	reassembly      []byte              // Buffer for reassembling fragments
	reassemblyPools []*[]byte           // Pooled buffers that were appended to reassembly
	nextReadSeq     uint32              // Next expected sequence number for reading
	nextWriteSeq    uint32              // Next sequence number for writing
	reorderBuf      map[uint32]fragment // Buffer for out-of-order packets
	dead            chan struct{}
	unordered       bool // If true, disable reordering logic
	highestRxSeq    uint32
	writeMu         sync.Mutex
	lastActivity    int64
}

func newMuxStream(conn *Conn, id uint32) *muxStream {
	return &muxStream{
		conn:         conn,
		id:           id,
		rx:           make(chan fragment, 4096),
		reorderBuf:   make(map[uint32]fragment),
		dead:         make(chan struct{}),
		lastActivity: time.Now().UnixNano(),
	}
}

func (s *muxStream) SetUnordered(b bool) {
	s.unordered = b
}

func (s *muxStream) Read(b []byte) (n int, err error) {
	if len(s.buf) > 0 {
		n = copy(b, s.buf)
		s.buf = s.buf[n:]
		if len(s.buf) == 0 {
			s.buf = nil // Explicitly free reference
			if s.pendingPoolBuf != nil {
				packetPool.Put(s.pendingPoolBuf)
				s.pendingPoolBuf = nil
			}
		}
		return n, nil
	}

	// Fast path for unordered streams (Datagram mode)
	if s.unordered {
		for {
			select {
			case frag := <-s.rx:
				// Update highest sequence (handle wrap-around safely)
				if diff := int32(frag.seq - s.highestRxSeq); diff > 0 {
					s.highestRxSeq = frag.seq
				}

				// Buffer the fragment
				s.reorderBuf[frag.seq] = frag

				// Search backwards to find the start of this message
				startSeq := frag.seq
				foundStart := false
				for {
					if f, ok := s.reorderBuf[startSeq]; ok {
						if f.flags&flagStart != 0 {
							foundStart = true
							break // Found the start!
						}
						startSeq--
					} else {
						// Missing a preceding fragment, so the message is not complete yet
						break
					}
				}

				if foundStart {
					if msg, pools, isSingle, ok := s.tryReassembleUnordered(startSeq); ok {
						n = copy(b, msg)
						if n < len(msg) {
							if isSingle && len(pools) == 1 {
								s.buf = msg[n:]
								s.pendingPoolBuf = pools[0]
							} else {
								s.buf = make([]byte, len(msg)-n)
								copy(s.buf, msg[n:])
								for _, bp := range pools {
									packetPool.Put(bp)
								}
							}
						} else {
							for _, bp := range pools {
								packetPool.Put(bp)
							}
						}
						return n, nil
					}
				}

				// Prune buffer if too large (simple protection)
				if len(s.reorderBuf) > 4096 {
					for k := range s.reorderBuf {
						// Delete fragments that are more than 2048 sequences behind the highest seen
						if diff := int32(s.highestRxSeq - k); diff > 2048 {
							if f, ok := s.reorderBuf[k]; ok && f.bp != nil {
								packetPool.Put(f.bp)
							}
							delete(s.reorderBuf, k)
						}
					}
					if len(s.reorderBuf) > 4096 {
						// Fast clear using Go's optimized map clearing (no new map allocation)
						for k, f := range s.reorderBuf {
							if f.bp != nil {
								packetPool.Put(f.bp)
							}
							delete(s.reorderBuf, k)
						}
					}
				}

			case <-s.dead:
				return 0, io.EOF
			case <-s.conn.closed:
				return 0, io.ErrClosedPipe
			}
		}
	}

	for {
		// 1. Check reorder buffer for the next expected fragment
		if frag, ok := s.reorderBuf[s.nextReadSeq]; ok {
			delete(s.reorderBuf, s.nextReadSeq)
			s.nextReadSeq++
			
			// If it's a single fragment and we haven't started reassembly yet:
			if !frag.more && len(s.reassembly) == 0 {
				n = copy(b, frag.data)
				if n < len(frag.data) {
					s.buf = frag.data[n:]
					s.pendingPoolBuf = frag.bp
				} else {
					if frag.bp != nil {
						packetPool.Put(frag.bp)
					}
				}
				return n, nil
			}

			s.reassembly = append(s.reassembly, frag.data...)
			if frag.bp != nil {
				s.reassemblyPools = append(s.reassemblyPools, frag.bp)
			}

			if frag.more {
				continue // Loop to check for next fragment in reorderBuf or wait for it
			}

			// Packet complete
			data := s.reassembly
			s.reassembly = nil // Abandon to GC instantly

			n = copy(b, data)
			if n < len(data) {
				s.buf = make([]byte, len(data)-n)
				copy(s.buf, data[n:])
			}
			for _, bp := range s.reassemblyPools {
				packetPool.Put(bp)
			}
			s.reassemblyPools = nil
			return n, nil
		}

		// 2. Wait for next fragment from network
		select {
		case frag := <-s.rx:
			// int32 cast ensures safe math when sequence wraps from 4.2 Billion to 0
			diff := int32(frag.seq - s.nextReadSeq)
			if diff < 0 {
				if frag.bp != nil {
					packetPool.Put(frag.bp)
				}
				continue // Duplicate/old
			}
			if diff > 0 {
				s.reorderBuf[frag.seq] = frag

				// Prevent infinite memory leak in ordered mode if a packet is permanently lost
				if len(s.reorderBuf) > 1024 {
					flog.Errorf("UDP stream %d ordered buffer overflow, stream irreparably broken due to lost packet, closing", s.id)
					s.closeInternal()
					return 0, io.ErrClosedPipe
				}
				continue // Buffered
			}

			// Found expected fragment
			s.nextReadSeq++
			
			// If it's a single fragment and we haven't started reassembly yet:
			if !frag.more && len(s.reassembly) == 0 {
				n = copy(b, frag.data)
				if n < len(frag.data) {
					s.buf = frag.data[n:]
					s.pendingPoolBuf = frag.bp
				} else {
					if frag.bp != nil {
						packetPool.Put(frag.bp)
					}
				}
				return n, nil
			}

			s.reassembly = append(s.reassembly, frag.data...)
			if frag.bp != nil {
				s.reassemblyPools = append(s.reassemblyPools, frag.bp)
			}

			if frag.more {
				continue // Loop back to check reorderBuf for next part
			}

			// Packet complete
			data := s.reassembly
			s.reassembly = nil // Abandon to GC instantly

			n = copy(b, data)
			if n < len(data) {
				s.buf = make([]byte, len(data)-n)
				copy(s.buf, data[n:])
			}
			for _, bp := range s.reassemblyPools {
				packetPool.Put(bp)
			}
			s.reassemblyPools = nil
			return n, nil

		case <-s.dead:
			return 0, io.EOF
		case <-s.conn.closed:
			return 0, io.ErrClosedPipe
		}
	}
}

// tryReassembleUnordered attempts to build a message starting at startSeq
func (s *muxStream) tryReassembleUnordered(startSeq uint32) (msg []byte, pools []*[]byte, isSingle bool, ok bool) {
	// Fast path: single-fragment message (zero allocation)
	if frag, ok := s.reorderBuf[startSeq]; ok && frag.flags&flagMoreFrags == 0 {
		delete(s.reorderBuf, startSeq)
		var pools []*[]byte
		if frag.bp != nil {
			pools = []*[]byte{frag.bp}
		}
		return frag.data, pools, true, true
	}

	var msgBuf []byte
	var poolsBuf []*[]byte
	curr := startSeq

	for {
		frag, ok := s.reorderBuf[curr]
		if !ok {
			return nil, nil, false, false // Missing fragment
		}

		msgBuf = append(msgBuf, frag.data...)
		if frag.bp != nil {
			poolsBuf = append(poolsBuf, frag.bp)
		}
		if frag.flags&flagMoreFrags == 0 {
			// End of message found
			// Cleanup used fragments (safe against sequence wrap-around)
			for i := startSeq; ; i++ {
				delete(s.reorderBuf, i)
				if i == curr {
					break
				}
			}
			return msgBuf, poolsBuf, false, true
		}
		curr++
	}
}

func (s *muxStream) Write(b []byte) (n int, err error) {
	select {
	case <-s.dead:
		return 0, io.ErrClosedPipe
	default:
	}

	s.writeMu.Lock()
	atomic.StoreInt64(&s.lastActivity, time.Now().UnixNano())
	defer s.writeMu.Unlock()

	// Fragment large writes into MTU-sized packets
	written := 0
	for len(b) > 0 {
		chunkSize := len(b)
		var flags byte = 0
		if written == 0 {
			flags |= flagStart
		}
		if chunkSize > s.conn.mtu {
			chunkSize = s.conn.mtu
			flags |= flagMoreFrags
		}
		chunk := b[:chunkSize]
		if err := s.conn.writePacket(s.id, s.nextWriteSeq, chunk, flags); err != nil {
			return written, err
		}
		s.nextWriteSeq++
		written += chunkSize
		b = b[chunkSize:]
	}
	return written, nil
}
func (s *muxStream) Close() error { s.closeInternal(); return nil }
func (s *muxStream) activity() int64 {
	return atomic.LoadInt64(&s.lastActivity)
}
func (s *muxStream) closeInternal() {
	select {
	case <-s.dead:
	default:
		close(s.dead)
		s.conn.closeStream(s.id)

		// Drain rx channel to recycle any buffered packets without closing it
		for {
			select {
			case frag := <-s.rx:
				if frag.bp != nil {
					packetPool.Put(frag.bp)
				}
			default:
				goto rxDrained
			}
		}
	rxDrained:

		// Recycle all buffers in reorderBuf
		for _, frag := range s.reorderBuf {
			if frag.bp != nil {
				packetPool.Put(frag.bp)
			}
		}
		s.reorderBuf = nil

		// Recycle reassembly pools
		for _, bp := range s.reassemblyPools {
			packetPool.Put(bp)
		}
		s.reassemblyPools = nil

		// Recycle pendingPoolBuf
		if s.pendingPoolBuf != nil {
			packetPool.Put(s.pendingPoolBuf)
			s.pendingPoolBuf = nil
		}
	}
}
func (s *muxStream) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *muxStream) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *muxStream) SetDeadline(t time.Time) error      { return nil }
func (s *muxStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *muxStream) SetWriteDeadline(t time.Time) error { return nil }
func (s *muxStream) SID() int                           { return int(s.id) }
