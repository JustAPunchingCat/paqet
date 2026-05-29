package socks

import (
	"context"
	"net"
	"paqet/internal/client"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"

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
			if err := s.negotiate(conn, cfg); err != nil {
				return
			}
			req, err := socks5.NewRequestFrom(conn)
			if err != nil {
				return
			}
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

func (s *SOCKS5) serveUDP(ctx context.Context, udpConn *net.UDPConn) {
	for {
		bufp := buffer.UPool.Get().(*[]byte)
		buf := *bufp

		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			buffer.UPool.Put(bufp)
			select {
			case <-ctx.Done():
				return
			default:
				flog.Errorf("SOCKS5 UDP read error: %v", err)
				continue
			}
		}

		d, err := socks5.NewDatagramFromBytes(buf[:n])
		if err != nil {
			buffer.UPool.Put(bufp)
			continue
		}

		select {
		case s.handle.udpSem <- struct{}{}:
			go func(bufp *[]byte, addr *net.UDPAddr, d *socks5.Datagram) {
				defer func() {
					buffer.UPool.Put(bufp)
					<-s.handle.udpSem
				}()
				if err := s.handle.UDPHandle(addr, d); err != nil {
					if ctx.Err() == nil {
						flog.Errorf("SOCKS5 UDP handle error: %v", err)
					}
				}
			}(bufp, addr, d)
		default:
			buffer.UPool.Put(bufp)
		}
	}
}
