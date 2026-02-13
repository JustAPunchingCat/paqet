package udp

import (
	"bytes"
	"net"
	"paqet/internal/flog"
	"time"
)

// connAdapter adapts a PacketConn + RemoteAddr into a net.Conn (io.ReadWriteCloser)
// for use with smux. It handles encryption/decryption transparently.
type connAdapter struct {
	pConn      net.PacketConn
	remoteAddr net.Addr
	cipher     *cipher
	readCh     chan []byte
	closeCh    chan struct{}
	buf        []byte // Buffer for partial reads
	readMagic  []byte // Expected magic on read
	writeMagic []byte // Magic to prepend on write
}

func newConnAdapter(pConn net.PacketConn, remoteAddr net.Addr, cipher *cipher, readMagic, writeMagic []byte) *connAdapter {
	return &connAdapter{
		pConn:      pConn,
		remoteAddr: remoteAddr,
		cipher:     cipher,
		readCh:     make(chan []byte, 4096),
		closeCh:    make(chan struct{}),
		readMagic:  readMagic,
		writeMagic: writeMagic,
	}
}

func (c *connAdapter) Read(b []byte) (n int, err error) {
	if len(c.buf) > 0 {
		n = copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	for {
		select {
		case data := <-c.readCh:
			// Verify and strip magic
			if len(data) < len(c.readMagic) || !bytes.Equal(data[:len(c.readMagic)], c.readMagic) {
				flog.Debugf("UDP Adapter: dropped packet with invalid magic/len: %d", len(data))
				continue // Drop invalid packet (loopback or garbage) and wait for next
			}
			data = data[len(c.readMagic):]
			if len(data) == 0 {
				continue
			}

			n = copy(b, data)
			if n < len(data) {
				c.buf = data[n:]
			}
			return n, nil
		case <-c.closeCh:
			return 0, net.ErrClosed
		}
	}
}

func (c *connAdapter) Write(b []byte) (n int, err error) {
	// Encrypt and write
	// Prepend magic
	payload := append([]byte(nil), c.writeMagic...)
	payload = append(payload, b...)
	enc := c.cipher.encrypt(payload)
	_, err = c.pConn.WriteTo(enc, c.remoteAddr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *connAdapter) Close() error {
	select {
	case <-c.closeCh:
		return nil
	default:
		close(c.closeCh)
	}
	return c.pConn.Close()
}

func (c *connAdapter) LocalAddr() net.Addr                { return c.pConn.LocalAddr() }
func (c *connAdapter) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *connAdapter) SetDeadline(t time.Time) error      { return c.pConn.SetDeadline(t) }
func (c *connAdapter) SetReadDeadline(t time.Time) error  { return c.pConn.SetReadDeadline(t) }
func (c *connAdapter) SetWriteDeadline(t time.Time) error { return c.pConn.SetWriteDeadline(t) }

// pushInput pushes a decrypted packet payload into the read buffer
func (c *connAdapter) pushInput(data []byte) {
	select {
	case c.readCh <- data:
	default:
		// Drop if buffer full
	}
}
