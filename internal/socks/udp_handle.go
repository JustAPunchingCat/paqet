package socks

import (
	"encoding/binary"
	"io"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"time"

	"github.com/txthinking/socks5"
)

func (h *Handler) UDPHandle(server *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	strm, new, k, err := h.client.UDPByIndex(h.ServerIdx, addr.String(), d.Address())
	if err != nil {
		flog.Errorf("SOCKS5 failed to establish UDP stream for %s -> %s: %v", addr, d.Address(), err)
		return err
	}
	strm.SetWriteDeadline(time.Now().Add(30 * time.Second))

	// Write length prefix (2 bytes) + Data to preserve packet boundaries in the stream
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(d.Data)))
	strm.Write(lenBuf)
	_, err = strm.Write(d.Data)
	strm.SetWriteDeadline(time.Time{})
	if err != nil {
		flog.Errorf("SOCKS5 failed to forward %d bytes from %s -> %s: %v", len(d.Data), addr, d.Address(), err)
		h.client.CloseUDP(h.ServerIdx, k)
		return err
	}

	if new {
		flog.Infof("SOCKS5 accepted UDP connection %s -> %s via %s", addr, d.Address(), strm.RemoteAddr())

		// Capture needed fields to avoid accessing d in goroutine (safety against reuse)
		dAddr := d.Address()
		atyp := d.Atyp
		dstAddr := append([]byte(nil), d.DstAddr...)
		dstPort := append([]byte(nil), d.DstPort...)

		go func() {
			bufp := buffer.UPool.Get().(*[]byte)
			defer buffer.UPool.Put(bufp)
			buf := *bufp

			defer func() {
				flog.Debugf("SOCKS5 UDP stream %d closed for %s -> %s", strm.SID(), addr, dAddr)
				h.client.CloseUDP(h.ServerIdx, k)
			}()

			// Pre-calculate header length: RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT(2)
			headerLen := 4 + len(dstAddr) + len(dstPort)

			// Pre-fill header in buffer (constant for this stream)
			if len(buf) > headerLen {
				buf[0], buf[1], buf[2] = 0, 0, 0 // RSV, FRAG
				buf[3] = atyp
				copy(buf[4:], dstAddr)
				copy(buf[4+len(dstAddr):], dstPort)
			}

			for {
				select {
				case <-h.ctx.Done():
					return
				default:
					strm.SetDeadline(time.Now().Add(30 * time.Second))

					// Read length prefix (2 bytes)
					lenBuf := make([]byte, 2)
					if _, err := io.ReadFull(strm, lenBuf); err != nil {
						flog.Debugf("SOCKS5 UDP stream %d read error for %s -> %s: %v", strm.SID(), addr, dAddr, err)
						return
					}
					payloadLen := int(binary.BigEndian.Uint16(lenBuf))

					// Read payload
					if headerLen+payloadLen > len(buf) {
						flog.Errorf("SOCKS5 UDP packet too large: %d", payloadLen)
						return
					}
					_, err := io.ReadFull(strm, buf[headerLen:headerLen+payloadLen])
					strm.SetDeadline(time.Time{})
					if err != nil {
						return
					}
					_, err = server.UDPConn.WriteToUDP(buf[:headerLen+payloadLen], addr)
					if err != nil {
						flog.Errorf("SOCKS5 failed to write UDP response %d bytes to %s: %v", headerLen+payloadLen, addr, err)
						return
					}
				}
			}
		}()
	}
	return nil
}

func (h *Handler) handleUDPAssociate(conn *net.TCPConn) error {
	addr := conn.LocalAddr().(*net.TCPAddr)

	bufp := rPool.Get().(*[]byte)
	defer rPool.Put(bufp)
	buf := *bufp
	buf = append(buf, socks5.Ver)
	buf = append(buf, socks5.RepSuccess)
	buf = append(buf, 0x00) // reserved
	if ip4 := addr.IP.To4(); ip4 != nil {
		// IPv4
		buf = append(buf, socks5.ATYPIPv4)
		buf = append(buf, ip4...)
	} else if ip6 := addr.IP.To16(); ip6 != nil {
		// IPv6
		buf = append(buf, socks5.ATYPIPv6)
		buf = append(buf, ip6...)
	} else {
		// Domain name
		host := addr.IP.String()
		buf = append(buf, socks5.ATYPDomain)
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(addr.Port>>8), byte(addr.Port&0xff))

	if _, err := conn.Write(buf); err != nil {
		return err
	}
	flog.Debugf("SOCKS5 accepted UDP_ASSOCIATE from %s, waiting for TCP connection to close", conn.RemoteAddr())

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, conn)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil && h.ctx.Err() == nil {
			flog.Errorf("SOCKS5 TCP connection for UDP associate closed with: %v", err)
		}
	case <-h.ctx.Done():
		conn.Close() // Force close the connection to unblock io.Copy
		<-done       // Wait for the goroutine to finish
		flog.Debugf("SOCKS5 UDP_ASSOCIATE connection %s closed due to shutdown", conn.RemoteAddr())
	}

	flog.Debugf("SOCKS5 UDP_ASSOCIATE TCP connection %s closed", conn.RemoteAddr())
	return nil
}
