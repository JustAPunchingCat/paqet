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

func (h *Handler) UDPHandle(addr *net.UDPAddr, reqDst string, reqData []byte, atyp byte, dstAddrRaw, dstPortRaw []byte) error {
	// Try Datagram Mode first (Best for UDP transports like QUIC/Hysteria)
	sess, newDgm, kDgm, errDgm := h.client.UDPDatagramByIndex(h.ServerIdx, addr.String(), reqDst)
	if errDgm == nil && sess != nil {
		sess.SetWriteDeadline(time.Now().Add(5 * time.Second))
		err := sess.Send(reqData)
		sess.SetWriteDeadline(time.Time{})
		if err != nil {
			flog.Errorf("SOCKS5 failed to forward %d bytes from %s -> %s: %v", len(reqData), addr, reqDst, err)
			h.client.CloseUDP(h.ServerIdx, kDgm)
			return err
		}

		if newDgm {
			flog.Infof("SOCKS5 accepted UDP datagram connection %s -> %s via %s", addr, reqDst, sess.RemoteAddr())

			// Capture needed fields to avoid accessing d in goroutine (safety against reuse)
			dAddr := reqDst
			dstAddr := append([]byte(nil), dstAddrRaw...)
			dstPort := append([]byte(nil), dstPortRaw...)

			go func() {
				bufp, buf := buffer.GetU()
				defer buffer.PutU(bufp)

				defer func() {
					flog.Debugf("SOCKS5 UDP datagram stream %d closed for %s -> %s", sess.SID(), addr, dAddr)
					h.client.CloseUDP(h.ServerIdx, kDgm)
					go sess.Close() // Prevents smux FIN deadlock
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
						sess.SetReadDeadline(time.Now().Add(30 * time.Second))
						n, err := sess.Read(buf[headerLen:])
						if err != nil {
							flog.Debugf("SOCKS5 UDP datagram stream %d read error for %s -> %s: %v", sess.SID(), addr, dAddr, err)
							return
						}
						_, err = h.udpConn.WriteToUDP(buf[:headerLen+n], addr)
						if err != nil {
							flog.Errorf("SOCKS5 failed to write UDP response %d bytes to %s: %v", headerLen+n, addr, err)
							return
						}
					}
				}
			}()
		}
		return nil
	}

	// Fallback to Stream Mode with Length Prefixes (Required if using KCP transport)
	strm, newStrm, kStrm, errStrm := h.client.UDPByIndex(h.ServerIdx, addr.String(), reqDst)
	if errStrm != nil {
		flog.Errorf("SOCKS5 failed to establish UDP stream for %s -> %s: %v", addr, reqDst, errStrm)
		return errStrm
	}

	bufp, payload := buffer.GetU()
	defer buffer.PutU(bufp)
	if cap(payload) < 2+len(reqData) {
		payload = make([]byte, 2+len(reqData))
	}
	binary.BigEndian.PutUint16(payload[:2], uint16(len(reqData)))
	copy(payload[2:], reqData)
	strm.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := strm.Write(payload[:2+len(reqData)])
	strm.SetWriteDeadline(time.Time{})
	if err != nil {
		flog.Errorf("SOCKS5 failed to forward %d bytes from %s -> %s: %v", len(reqData), addr, reqDst, err)
		h.client.CloseUDP(h.ServerIdx, kStrm)
		return err
	}

	if newStrm {
		flog.Infof("SOCKS5 accepted UDP connection %s -> %s via %s", addr, reqDst, strm.RemoteAddr())

		// Capture needed fields to avoid accessing d in goroutine (safety against reuse)
		dAddr := reqDst
		dstAddr := append([]byte(nil), dstAddrRaw...)
		dstPort := append([]byte(nil), dstPortRaw...)

		go func() {
			bufp, buf := buffer.GetU()
			defer buffer.PutU(bufp)

			defer func() {
				flog.Debugf("SOCKS5 UDP stream %d closed for %s -> %s", strm.SID(), addr, dAddr)
				h.client.CloseUDP(h.ServerIdx, kStrm)
				go strm.Close() // Prevents smux FIN deadlock
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

			lenBuf := make([]byte, 2)
			for {
				select {
				case <-h.ctx.Done():
					return
				default:
					strm.SetReadDeadline(time.Now().Add(30 * time.Second))
					// Read length prefix (2 bytes)
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
					if err != nil {
						return
					}
					_, err = h.udpConn.WriteToUDP(buf[:headerLen+payloadLen], addr)
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
	buf := (*bufp)[:0]
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
