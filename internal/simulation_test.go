package internal_test

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"paqet/internal/conf"
	"paqet/internal/transport"
)

// SimulatedPacketConn implements net.PacketConn over in-memory channels.
type SimulatedPacketConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	readCh     chan []byte
	writeCh    chan<- []byte
	closed     uint32
	mu         sync.Mutex

	Latency    time.Duration
	PacketLoss float64 // 0.0 to 1.0
	IsServer   bool
}

func NewSimulatedLink(latency time.Duration, loss float64) (*SimulatedPacketConn, *SimulatedPacketConn) {
	c2s := make(chan []byte, 1024)
	s2c := make(chan []byte, 1024)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20000}

	client := &SimulatedPacketConn{
		localAddr:  clientAddr,
		remoteAddr: serverAddr,
		readCh:     s2c,
		writeCh:    c2s,
		Latency:    latency,
		PacketLoss: loss,
		IsServer:   false,
	}

	server := &SimulatedPacketConn{
		localAddr:  serverAddr,
		remoteAddr: clientAddr,
		readCh:     c2s,
		writeCh:    s2c,
		Latency:    latency,
		PacketLoss: loss,
		IsServer:   true,
	}

	return client, server
}

func (c *SimulatedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if atomic.LoadUint32(&c.closed) == 1 {
		return 0, nil, net.ErrClosed
	}

	select {
	case data, ok := <-c.readCh:
		if !ok {
			return 0, nil, io.EOF
		}
		n = copy(p, data)
		return n, c.remoteAddr, nil
	}
}

func (c *SimulatedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if atomic.LoadUint32(&c.closed) == 1 {
		return 0, net.ErrClosed
	}

	buf := make([]byte, len(p))
	copy(buf, p)

	if c.Latency > 0 {
		go func() {
			time.Sleep(c.Latency)
			c.writeCh <- buf
		}()
	} else {
		c.writeCh <- buf
	}

	return len(p), nil
}

func (c *SimulatedPacketConn) Close() error {
	if atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		// handle close logic if needed
	}
	return nil
}

func (c *SimulatedPacketConn) LocalAddr() net.Addr { return c.localAddr }
func (c *SimulatedPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *SimulatedPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *SimulatedPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestSimulation_BasicKCPConnection(t *testing.T) {
	clientNet, serverNet := NewSimulatedLink(5*time.Millisecond, 0.0)

	cfg := &conf.Transport{
		Protocol: "auto",
		KCP: &conf.KCP{
			MTU:          1350,
			Sndwnd:       128,
			Rcvwnd:       128,
			NoDelay:      1,
			Interval:     10,
			Resend:       2,
			NoCongestion: 1,
			Smuxbuf:      4194304,
			Streambuf:    2097152,
		},
	}

	serverLn, err := transport.Listen(cfg, serverNet)
	if err != nil {
		t.Fatalf("Server Listen failed: %v", err)
	}

	serverReady := make(chan struct{})
	go func() {
		conn, err := serverLn.Accept()
		if err != nil {
			return
		}
		strm, err := conn.AcceptStrm()
		if err != nil {
			return
		}
		close(serverReady)

		buf := make([]byte, 1024)
		for {
			n, err := strm.Read(buf)
			if err != nil {
				return
			}
			strm.Write(buf[:n])
		}
	}()

	clientConn, err := transport.DialProto("kcp", serverNet.localAddr.(*net.UDPAddr), cfg, clientNet)
	if err != nil {
		t.Fatalf("Client Dial failed: %v", err)
	}

	strm, err := clientConn.OpenStrm()
	if err != nil {
		t.Fatalf("Client OpenStrm failed: %v", err)
	}

	msg := []byte("Hello, Simulated World!")
	if _, err = strm.Write(msg); err != nil {
		t.Fatalf("Client Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	strm.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := strm.Read(buf)
	if err != nil {
		t.Fatalf("Client Read failed: %v", err)
	}

	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("Expected %q, got %q", msg, buf[:n])
	}
}
