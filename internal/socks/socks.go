package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"paqet/internal/client"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"strconv"
	"time"

	"github.com/txthinking/socks5"
)

type SOCKS5 struct {
	handle *Handler
}

func New(client *client.Client, serverIdx int) (*SOCKS5, error) {
	return &SOCKS5{
		handle: &Handler{
			client:    client,
			ServerIdx: serverIdx,
			udpSem:    make(chan struct{}, 4096),
		},
	}, nil
}

func (s *SOCKS5) Start(ctx context.Context, cfg conf.SOCKS5) error {
	s.handle.ctx = ctx
	go s.listen(ctx, cfg)
	return nil
}

func (s *SOCKS5) listen(ctx context.Context, cfg conf.SOCKS5) error {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", cfg.Listen.String())
	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		flog.Fatalf("SOCKS5 TCP listen failed on %s: %v", tcpAddr.String(), err)
	}

	udpAddr, _ := net.ResolveUDPAddr("udp", cfg.Listen.String())
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		flog.Fatalf("SOCKS5 UDP listen failed on %s: %v", udpAddr.String(), err)
	}
	udpConn.SetReadBuffer(cfg.SockBuf)
	udpConn.SetWriteBuffer(cfg.SockBuf)

	s.handle.udpConn = udpConn

	flog.Infof("SOCKS5 server listening on %s", cfg.Listen.String())

	go s.serveUDP(ctx, udpConn)
	go func() {
		<-ctx.Done()
		tcpListener.Close()
		udpConn.Close()
	}()

	for {
		conn, err := tcpListener.AcceptTCP()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				flog.Errorf("SOCKS5 accept error: %v", err)
				continue
			}
		}

		go func() {
			defer conn.Close()
			// Set 15-second deadline for negotiation and request to prevent hung goroutines
			conn.SetDeadline(time.Now().Add(15 * time.Second))
			if err := s.negotiate(conn, cfg); err != nil {
				return
			}
			req, err := socks5.NewRequestFrom(conn)
			if err != nil {
				return
			}
			// Clear deadline for active data transfer
			conn.SetDeadline(time.Time{})
			if err := s.handle.TCPHandle(conn, req); err != nil {
				// handled
			}
		}()
	}
}

func (s *SOCKS5) negotiate(conn *net.TCPConn, cfg conf.SOCKS5) error {
	req, err := socks5.NewNegotiationRequestFrom(conn)
	if err != nil {
		return err
	}
	var method byte = socks5.MethodNone
	if cfg.Username != "" && cfg.Password != "" {
		method = socks5.MethodUsernamePassword
	}
	valid := false
	for _, m := range req.Methods {
		if m == method {
			valid = true
			break
		}
	}
	if !valid {
		socks5.NewNegotiationReply(socks5.MethodUnsupportAll).WriteTo(conn)
		return err
	}
	if _, err := socks5.NewNegotiationReply(method).WriteTo(conn); err != nil {
		return err
	}
	if method == socks5.MethodUsernamePassword {
		upReq, err := socks5.NewUserPassNegotiationRequestFrom(conn)
		if err != nil {
			return err
		}
		if string(upReq.Uname) != cfg.Username || string(upReq.Passwd) != cfg.Password {
			socks5.NewUserPassNegotiationReply(socks5.UserPassStatusFailure).WriteTo(conn)
			return err
		}
		if _, err := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusSuccess).WriteTo(conn); err != nil {
			return err
		}
	}
	return nil
}

func parseSocks5UDP(b []byte) (reqDst string, data []byte, atyp byte, dstAddr, dstPort []byte, err error) {
	if len(b) < 10 {
		return "", nil, 0, nil, nil, errors.New("packet too short")
	}
	if b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return "", nil, 0, nil, nil, errors.New("invalid header or fragmentation")
	}
	atyp = b[3]
	var addrLen int
	switch atyp {
	case socks5.ATYPIPv4:
		addrLen = 4
	case socks5.ATYPIPv6:
		addrLen = 16
	case socks5.ATYPDomain:
		addrLen = int(b[4]) + 1
	default:
		return "", nil, 0, nil, nil, errors.New("invalid ATYP")
	}
	if len(b) < 4+addrLen+2 {
		return "", nil, 0, nil, nil, errors.New("packet too short")
	}
	dstAddr = b[4 : 4+addrLen]
	dstPort = b[4+addrLen : 4+addrLen+2]
	data = b[4+addrLen+2:]

	var host string
	if atyp == socks5.ATYPIPv4 || atyp == socks5.ATYPIPv6 {
		host = net.IP(dstAddr).String()
	} else if atyp == socks5.ATYPDomain {
		host = string(dstAddr[1:])
	}
	port := binary.BigEndian.Uint16(dstPort)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), data, atyp, dstAddr, dstPort, nil
}

func (s *SOCKS5) serveUDP(ctx context.Context, udpConn *net.UDPConn) {
	for {
		bufp, buf := buffer.GetU()

		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			buffer.PutU(bufp)
			select {
			case <-ctx.Done():
				return
			default:
				flog.Errorf("SOCKS5 UDP read error: %v", err)
				continue
			}
		}

		reqDst, data, atyp, dstAddr, dstPort, err := parseSocks5UDP(buf[:n])
		if err != nil {
			buffer.PutU(bufp)
			continue
		}

		select {
		case s.handle.udpSem <- struct{}{}:
			go func(bufp *[]byte, addr *net.UDPAddr, reqDst string, data []byte, atyp byte, dstAddr, dstPort []byte) {
				defer func() {
					buffer.PutU(bufp)
					<-s.handle.udpSem
				}()
				if err := s.handle.UDPHandle(addr, reqDst, data, atyp, dstAddr, dstPort); err != nil {
					if ctx.Err() == nil {
						flog.Errorf("SOCKS5 UDP handle error: %v", err)
					}
				}
			}(bufp, addr, reqDst, data, atyp, dstAddr, dstPort)
		default:
			buffer.PutU(bufp)
		}
	}
}
