package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
)

type Server struct {
	cfg   *conf.Conf
	pConn *socket.PacketConn
	wg    sync.WaitGroup
}

func New(cfg *conf.Conf) (*Server, error) {
	s := &Server{
		cfg: cfg,
	}

	return s, nil
}

func (s *Server) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		flog.Infof("Shutdown signal received, initiating graceful shutdown...")
		cancel()
	}()

	pConn, err := socket.NewWithHopping(ctx, &s.cfg.Network, &s.cfg.Hopping, false, &s.cfg.Obfuscation)
	if err != nil {
		return fmt.Errorf("could not create raw packet conn: %w", err)
	}
	s.pConn = pConn

	// Adjust MTU to account for obfuscation overhead
	kcpCfg := *s.cfg.Transport.KCP
	obfsCfg := s.cfg.Obfuscation
	overhead := 0
	if obfsCfg.UseTLS {
		overhead = 5 + 2 + obfsCfg.Padding.Max
	} else if obfsCfg.Padding.Enabled {
		overhead = 2 + obfsCfg.Padding.Max
	}
	if overhead > 0 {
		if kcpCfg.MTU == 0 {
			kcpCfg.MTU = 1350
		}
		kcpCfg.MTU -= overhead
		flog.Debugf("Adjusted Server KCP MTU to %d (overhead: %d)", kcpCfg.MTU, overhead)
	}

	listener, err := kcp.Listen(&kcpCfg, pConn)
	if err != nil {
		return fmt.Errorf("could not start KCP listener: %w", err)
	}
	defer listener.Close()
	listenInfo := fmt.Sprintf(":%d", s.cfg.Listen.Addr.Port)
	if s.cfg.Hopping.Enabled {
		ranges, err := s.cfg.Hopping.GetRanges()
		if err == nil && len(ranges) > 0 {
			var parts []string
			for _, r := range ranges {
				parts = append(parts, fmt.Sprintf("%d-%d", r.Min, r.Max))
			}
			listenInfo = fmt.Sprintf("ranges [%s]", strings.Join(parts, ", "))
		}
	}
	flog.Infof("Server started - listening for packets on %s", listenInfo)

	s.wg.Go(func() {
		s.listen(ctx, listener)
	})

	s.wg.Wait()
	flog.Infof("Server shutdown completed")
	return nil
}

func (s *Server) listen(ctx context.Context, listener tnet.Listener) {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			flog.Errorf("failed to accept connection: %v", err)
			continue
		}

		localInfo := conn.LocalAddr().String()
		if s.pConn != nil {
			if actualPort := s.pConn.GetClientPort(conn.RemoteAddr()); actualPort > 0 {
				localInfo = fmt.Sprintf("%s (via :%d)", conn.LocalAddr(), actualPort)
			}
		}

		flog.Infof("accepted new connection from %s (local: %s)", conn.RemoteAddr(), localInfo)

		s.wg.Go(func() {
			defer conn.Close()
			s.handleConn(ctx, conn)
		})
	}
}
