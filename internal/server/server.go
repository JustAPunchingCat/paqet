package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/transport"
)

type Server struct {
	cfg   *conf.Conf
	pConn *socket.PacketConn
	wg    sync.WaitGroup
	conns sync.Map
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
	pConn.OnRST = s.handleRST
	s.pConn = pConn

	var listener tnet.Listener

	// Calculate obfuscation overhead
	obfsCfg := s.cfg.Obfuscation
	overhead := 0
	if obfsCfg.UseTLS {
		overhead = 5 + 2 + obfsCfg.Padding.Max
	} else if obfsCfg.Padding.Enabled {
		overhead = 2 + obfsCfg.Padding.Max
	}

	if overhead > 0 {
		// Adjust KCP MTU
		if s.cfg.Transport.KCP != nil {
			if s.cfg.Transport.KCP.MTU == 0 {
				s.cfg.Transport.KCP.MTU = 1280
			}
			s.cfg.Transport.KCP.MTU -= overhead
			flog.Debugf("Adjusted Server KCP MTU to %d (overhead: %d)", s.cfg.Transport.KCP.MTU, overhead)
		}
		// Adjust UDP MTU
		if s.cfg.Transport.UDP != nil {
			if s.cfg.Transport.UDP.MTU == 0 {
				s.cfg.Transport.UDP.MTU = 1280
			}
			s.cfg.Transport.UDP.MTU -= overhead
			flog.Debugf("Adjusted Server UDP MTU to %d (overhead: %d)", s.cfg.Transport.UDP.MTU, overhead)
		}
	}

	listener, err = transport.Listen(&s.cfg.Transport, pConn)
	if err != nil {
		return fmt.Errorf("could not start KCP listener: %w", err)
	}
	defer listener.Close()
	listenInfo := fmt.Sprintf(":%d", s.cfg.Listen.Addr.Port)
	if s.cfg.Hopping.IsEnabled() {
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

	// Reap stale sessions. If a client vanishes without sending a goodbye
	// FIN (crash, power loss, or a FIN that got dropped because it rode an
	// un-primed hopped port), the server-side session would otherwise live
	// forever: smux's keepalive only closes sessions that still have frames
	// buffered in the recv bucket (bucket > 0), so a silently dead peer with
	// an empty bucket is never reaped, and the KCP session keeps
	// retransmitting forever — the stale-tunnel noise.
	deadlink := 120
	if s.cfg.Transport.KCP != nil && s.cfg.Transport.KCP.DeadLink != 0 {
		deadlink = s.cfg.Transport.KCP.DeadLink
	}
	if deadlink > 0 {
		s.wg.Go(func() {
			s.reapStale(ctx, time.Duration(deadlink)*time.Second)
		})
	}

	s.wg.Wait()
	flog.Infof("Server shutdown completed")
	return nil
}

// reapStale periodically closes sessions whose client has not sent any
// packet for longer than the deadlink timeout. This is the server-side
// backstop for dead-peer detection: it guarantees a vanished client cannot
// keep a session alive to retransmit indefinitely.
func (s *Server) reapStale(ctx context.Context, deadlink time.Duration) {
	ticker := time.NewTicker(deadlink / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.pConn == nil {
				continue
			}
			cutoff := time.Now().Add(-deadlink)
			s.conns.Range(func(key, value interface{}) bool {
				conn, ok := value.(tnet.Conn)
				if !ok {
					return true
				}
				last := s.pConn.GetClientLastSeen(conn.RemoteAddr())
				if last.IsZero() {
					return true
				}
				if last.Before(cutoff) {
					flog.Warnf("Client %s silent for %s, closing stale session", conn.RemoteAddr(), deadlink)
					conn.Close()
					s.conns.Delete(key)
				}
				return true
			})
		}
	}
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
			if ctx.Err() != nil {
				return
			}
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

		s.conns.Store(conn.RemoteAddr().String(), conn)
		s.wg.Go(func() {
			defer func() {
				s.conns.Delete(conn.RemoteAddr().String())
				conn.Close()
			}()
			stopCh := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					conn.Close()
				case <-stopCh:
				}
			}()
			s.handleConn(ctx, conn)
			close(stopCh)
		})
	}
}

func (s *Server) handleRST(addr net.Addr) {
	if addr == nil {
		return
	}
	// Sessions are keyed per client ip:port. A goodbye arriving on a given
	// client port can ONLY refer to the session on that same port — the
	// migrated session lives on a different port and is a different conns
	// entry. So honor the goodbye immediately: this is how the client tells
	// us its old-port session is orphaned by a local-port rotation (without
	// it, the orphan retransmits for the whole reaper timeout — field-proven
	// wire spam).
	if v, ok := s.conns.Load(addr.String()); ok {
		if conn, ok := v.(tnet.Conn); ok {
			flog.Debugf("Received RST from client %s, forcibly closing KCP session", addr)
			conn.Close()
			s.conns.Delete(addr.String())
		}
	}
}
