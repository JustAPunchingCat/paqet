package udp

import (
	"bytes"
	"net"
	"paqet/internal/pkg/hash"
	"sync"
	"time"
)

const clientChanSize = 4096

// clientConn holds a per-client channel of received packets.
type clientConn struct {
	ch     chan packet
	addr   net.Addr
	cipher *cipher
}

type packet struct {
	data []byte
	n    int // valid bytes in data
	pool *sync.Pool
	bp   *[]byte // Original pointer from pool
}

// putBack returns the packet buffer to the pool.
func (p *packet) putBack() {
	if p.pool != nil && p.bp != nil {
		p.pool.Put(p.bp)
	}
}

var packetBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1500)
		return &b
	},
}

var largeBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536)
		return &b
	},
}

func getPacketBuf(n int) (*sync.Pool, *[]byte, []byte) {
	if n <= 1500 {
		bp := packetBufPool.Get().(*[]byte)
		return &packetBufPool, bp, (*bp)[:n]
	}
	bp := largeBufPool.Get().(*[]byte)
	return &largeBufPool, bp, (*bp)[:n]
}

// Demux reads from a single PacketConn and routes packets to per-client channels by source address.
type Demux struct {
	pConn   net.PacketConn
	cipher  *cipher
	clients sync.Map // uint64 -> *clientConn
	newConn chan *clientConn
	done    chan struct{}
}

// NewDemux creates a new packet demultiplexer.
func NewDemux(pConn net.PacketConn, cipher *cipher) *Demux {
	d := &Demux{
		pConn:   pConn,
		cipher:  cipher,
		newConn: make(chan *clientConn, 64),
		done:    make(chan struct{}),
	}
	go d.readLoop()
	return d
}

func (d *Demux) readLoop() {
	defer close(d.done)
	buf := make([]byte, 65536)
	for {
		n, addr, err := d.pConn.ReadFrom(buf)
		if err != nil {
			return
		}

		// Ignore packets from ourselves.
		// d.pConn.LocalAddr() returns the bind address (e.g. 0.0.0.0:9999), so we can't compare IP directly if it's wildcard.
		// But we can check if the source port matches our listening port, which implies it's a loopback of our own transmission.
		if udpAddr, ok := addr.(*net.UDPAddr); ok && udpAddr.Port == d.pConn.LocalAddr().(*net.UDPAddr).Port {
			continue
		}

		pool, bp, data := getPacketBuf(n)
		copy(data, buf[:n])

		// Decrypt if cipher is set
		if d.cipher != nil {
			plain := d.cipher.decrypt(data)
			// If decrypt returned a different slice, return the original
			if &plain[0] != &data[0] {
				// Fix: Use a separate variable for Put to avoid overwriting the pooled slice header
				pool.Put(bp)
				pool = nil // decrypted data is not pooled
			}
			data = plain
		}

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			if pool != nil {
				pool.Put(bp)
			}
			continue
		}

		key := hash.IPAddr(udpAddr.IP, uint16(udpAddr.Port))

		pkt := packet{data: data, n: len(data), pool: pool, bp: bp}
		if cc, ok := d.clients.Load(key); ok {
			select {
			case cc.(*clientConn).ch <- pkt:
			default: // drop if channel full
				pkt.putBack()
			}
		} else {
			// New client
			cc := &clientConn{
				ch:     make(chan packet, clientChanSize),
				addr:   addr,
				cipher: d.cipher,
			}
			cc.ch <- pkt
			d.clients.Store(key, cc)
			select {
			case d.newConn <- cc:
			default:
			}
		}
	}
}

// Accept waits for a new client connection.
func (d *Demux) Accept() (*clientConn, error) {
	cc, ok := <-d.newConn
	if !ok {
		return nil, net.ErrClosed
	}
	return cc, nil
}

// Close shuts down the demuxer.
func (d *Demux) Close() {
	d.pConn.Close()
	close(d.newConn)
}

// clientConnReader wraps a clientConn into an io.Reader-compatible net.Conn for smux.
type clientConnReader struct {
	cc         *clientConn
	pConn      net.PacketConn
	cipher     *cipher
	buf        []byte // leftover from previous read
	curPkt     packet // current packet for putBack (stored by value)
	readMagic  []byte
	writeMagic []byte
}

func newClientConnReader(cc *clientConn, pConn net.PacketConn, cipher *cipher, readMagic, writeMagic []byte) *clientConnReader {
	return &clientConnReader{cc: cc, pConn: pConn, cipher: cipher, readMagic: readMagic, writeMagic: writeMagic}
}

func (r *clientConnReader) Read(b []byte) (int, error) {
	if len(r.buf) > 0 {
		n := copy(b, r.buf)
		r.buf = r.buf[n:]
		if len(r.buf) == 0 && r.curPkt.pool != nil {
			r.curPkt.putBack()
			r.curPkt = packet{} // Clear
		}
		return n, nil
	}

	for {
		pkt, ok := <-r.cc.ch
		if !ok {
			return 0, net.ErrClosed
		}

		// Verify and strip magic
		if len(pkt.data) < pkt.n || len(pkt.data) < len(r.readMagic) || !bytes.Equal(pkt.data[:len(r.readMagic)], r.readMagic) {
			pkt.putBack()
			continue // Drop invalid packet, try next
		}
		// Adjust packet data to skip magic
		pkt.data = pkt.data[len(r.readMagic):]
		pkt.n -= len(r.readMagic)

		n := copy(b, pkt.data[:pkt.n])
		if n < pkt.n {
			r.buf = pkt.data[n:pkt.n]
			r.curPkt = pkt // Store by value
		} else {
			pkt.putBack()
		}
		return n, nil
	}
}

func (r *clientConnReader) Write(b []byte) (int, error) {
	// Prepend magic
	payload := append([]byte(nil), r.writeMagic...)
	payload = append(payload, b...)
	data := payload
	if r.cipher != nil {
		data = r.cipher.encrypt(payload)
	}
	return r.pConn.WriteTo(data, r.cc.addr)
}

func (r *clientConnReader) Close() error                       { return nil }
func (r *clientConnReader) LocalAddr() net.Addr                { return r.pConn.LocalAddr() }
func (r *clientConnReader) RemoteAddr() net.Addr               { return r.cc.addr }
func (r *clientConnReader) SetDeadline(_ time.Time) error      { return nil }
func (r *clientConnReader) SetReadDeadline(_ time.Time) error  { return nil }
func (r *clientConnReader) SetWriteDeadline(_ time.Time) error { return nil }
