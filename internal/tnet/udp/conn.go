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
	lastActivity time.Time
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
		mtu = 1200
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
		lastActivity: time.Now(),
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

		c.mu.Lock()
		c.lastActivity = time.Now()
		c.mu.Unlock()

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

		// Must copy data because buf is reused in the next iteration
		payload := make([]byte, n-13)
		copy(payload, buf[13:n])

		// Verify CRC32
		if crc32.ChecksumIEEE(payload) != sum {
			flog.Debugf("UDP packet dropped: CRC mismatch (len=%d)", len(payload))
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
			strm.writeMu.Lock()
			strm.lastActivity = time.Now()
			strm.writeMu.Unlock()
			select {
			case strm.rx <- fragment{seq: seq, data: payload, more: flags&flagMoreFrags != 0, flags: flags}:
			default:
				flog.Debugf("UDP Conn: stream %d buffer full, dropping packet", sid)
			}
		} else if !c.isServer || (sid%2 != 1) {
			// flog.Debugf("UDP Conn: ignoring unknown stream %d", sid)
			continue
		} else {
			// Check if this is an old ID from a closed stream
			// Allow a window of 1024 for out-of-order stream creation packets
			c.mu.RLock()
			if c.lastRemoteID > 1024 && sid <= c.lastRemoteID-1024 {
				c.mu.RUnlock()
				continue
			}
			c.mu.RUnlock()

			c.mu.Lock()
			if _, exists := c.streams[sid]; exists {
				c.mu.Unlock()
				continue
			}
			// Only create a new stream if it contains the start flag
			if flags&flagStart == 0 {
				c.mu.Unlock()
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
			case strm.rx <- fragment{seq: seq, data: payload, more: flags&flagMoreFrags != 0, flags: flags}:
			default:
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
			c.mu.RLock()
			idle := time.Since(c.lastActivity)
			c.mu.RUnlock()

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
				s.writeMu.Lock()
				idle := now.Sub(s.lastActivity)
				s.writeMu.Unlock()
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
}

// muxStream implements tnet.Strm for the custom packet muxer.
type muxStream struct {
	conn         *Conn
	id           uint32
	rx           chan fragment
	buf          []byte
	reassembly   []byte              // Buffer for reassembling fragments
	nextReadSeq  uint32              // Next expected sequence number for reading
	nextWriteSeq uint32              // Next sequence number for writing
	reorderBuf   map[uint32]fragment // Buffer for out-of-order packets
	dead         chan struct{}
	unordered    bool // If true, disable reordering logic
	highestRxSeq uint32
	writeMu      sync.Mutex
	lastActivity time.Time
}

func newMuxStream(conn *Conn, id uint32) *muxStream {
	return &muxStream{
		conn:         conn,
		id:           id,
		rx:           make(chan fragment, 65536),
		reorderBuf:   make(map[uint32]fragment),
		dead:         make(chan struct{}),
		lastActivity: time.Now(),
	}
}

func (s *muxStream) SetUnordered(b bool) {
	s.unordered = b
}

func (s *muxStream) Read(b []byte) (n int, err error) {
	if len(s.buf) > 0 {
		n = copy(b, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}

	for {
		// Fast path for unordered streams (Datagram mode)
		if s.unordered {
			// Check if we have any complete messages in the buffer
			// Iterate over all buffered fragments to find Start fragments
			for seq, frag := range s.reorderBuf {
				// Check for Start flag
				// Note: We need to store flags in fragment struct to do this
				// Let's update fragment struct first (see below)
				if frag.flags&flagStart != 0 {
					// Attempt to reassemble from this start fragment
					if data, ok := s.tryReassemble(seq); ok {
						n = copy(b, data)
						if n < len(data) {
							s.buf = data[n:]
						}
						return n, nil
					}
				}
			}

			select {
			case frag := <-s.rx:
				// Update highest sequence (handle wrap-around safely)
				if frag.seq-s.highestRxSeq < 0x7FFFFFFF {
					s.highestRxSeq = frag.seq
				}

				// Buffer the fragment
				s.reorderBuf[frag.seq] = frag

				// Check if this fragment completes ANY pending message
				// We iterate the map to find any start fragments that might now be complete
				for seq, f := range s.reorderBuf {
					if f.flags&flagStart != 0 {
						if data, ok := s.tryReassemble(seq); ok {
							n = copy(b, data)
							if n < len(data) {
								s.buf = data[n:]
							}
							return n, nil
						}
					}
				}

				// Prune buffer if too large (simple protection)
				if len(s.reorderBuf) > 1024 {
					for k := range s.reorderBuf {
						// Delete fragments that are more than 512 sequences behind the highest seen
						if s.highestRxSeq-k > 512 && s.highestRxSeq-k < 0x7FFFFFFF {
							delete(s.reorderBuf, k)
						}
					}
					if len(s.reorderBuf) > 1024 {
						s.reorderBuf = make(map[uint32]fragment) // Emergency reset
					}
				}

			case <-s.dead:
				return 0, io.EOF
			case <-s.conn.closed:
				return 0, io.ErrClosedPipe
			}

			continue
		}

		// 1. Check reorder buffer for the next expected fragment
		if frag, ok := s.reorderBuf[s.nextReadSeq]; ok {
			delete(s.reorderBuf, s.nextReadSeq)
			s.nextReadSeq++
			s.reassembly = append(s.reassembly, frag.data...)

			if frag.more {
				continue // Loop to check for next fragment in reorderBuf or wait for it
			}

			// Packet complete
			data := s.reassembly
			s.reassembly = nil

			n = copy(b, data)
			if n < len(data) {
				s.buf = data[n:]
			}
			return n, nil
		}

		// 2. Wait for next fragment from network
		select {
		case frag := <-s.rx:
			if frag.seq < s.nextReadSeq {
				continue // Duplicate/old
			}
			if frag.seq > s.nextReadSeq {
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
			s.reassembly = append(s.reassembly, frag.data...)

			if frag.more {
				continue // Loop back to check reorderBuf for next part
			}

			// Packet complete
			data := s.reassembly
			s.reassembly = nil

			n = copy(b, data)
			if n < len(data) {
				s.buf = data[n:]
			}
			return n, nil

		case <-s.dead:
			return 0, io.EOF
		case <-s.conn.closed:
			return 0, io.ErrClosedPipe
		}
	}
}

// tryReassemble attempts to build a message starting at startSeq
func (s *muxStream) tryReassemble(startSeq uint32) ([]byte, bool) {
	var msg []byte
	curr := startSeq

	for {
		frag, ok := s.reorderBuf[curr]
		if !ok {
			return nil, false // Missing fragment
		}

		msg = append(msg, frag.data...)
		if frag.flags&flagMoreFrags == 0 {
			// End of message found
			// Cleanup used fragments
			for i := startSeq; i <= curr; i++ {
				delete(s.reorderBuf, i)
			}
			return msg, true
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
	s.lastActivity = time.Now()
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
func (s *muxStream) closeInternal() {
	select {
	case <-s.dead:
	default:
		close(s.dead)
		s.conn.closeStream(s.id)
	}
}
func (s *muxStream) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *muxStream) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *muxStream) SetDeadline(t time.Time) error      { return nil }
func (s *muxStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *muxStream) SetWriteDeadline(t time.Time) error { return nil }
func (s *muxStream) SID() int                           { return int(s.id) }
