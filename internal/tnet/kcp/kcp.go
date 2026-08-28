package kcp

import (
	"paqet/internal/conf"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

func aplConf(conn *kcp.UDPSession, cfg *conf.KCP) {
	var noDelay, interval, resend, noCongestion int
	var wDelay, ackNoDelay bool
	switch cfg.Mode {
	case "normal":
		noDelay, interval, resend, noCongestion = 0, 40, 2, 1
		wDelay, ackNoDelay = true, false
	case "fast":
		noDelay, interval, resend, noCongestion = 1, 20, 2, 1
		wDelay, ackNoDelay = false, true
	case "fast2":
		noDelay, interval, resend, noCongestion = 1, 10, 2, 1
		wDelay, ackNoDelay = false, true
	case "fast3":
		noDelay, interval, resend, noCongestion = 1, 10, 2, 1
		wDelay, ackNoDelay = false, true
	case "manual":
		noDelay, interval, resend, noCongestion = cfg.NoDelay, cfg.Interval, cfg.Resend, cfg.NoCongestion
		wDelay, ackNoDelay = cfg.WDelay, cfg.AckNoDelay
	default:
		noDelay, interval, resend, noCongestion = 1, 10, 2, 1
		wDelay, ackNoDelay = false, true
	}

	conn.SetNoDelay(noDelay, interval, resend, noCongestion)
	conn.SetWindowSize(cfg.Sndwnd, cfg.Rcvwnd)
	if cfg.MTU > 0 {
		conn.SetMtu(cfg.MTU)
	}
	conn.SetWriteDelay(wDelay)
	conn.SetACKNoDelay(ackNoDelay)
	conn.SetDSCP(46)
}

func smuxConf(cfg *conf.KCP, isServer bool) *smux.Config {
	var sconf = smux.DefaultConfig()

	// Dead-peer detection. kcp-go v5 dropped its old deadlink timer, so we use
	// smux's one-way NOP keepalive as the liveness backstop: a peer is declared
	// dead after `deadlink` seconds of silence and the session is closed.
	// deadlink > 0 enables the keepalive with that timeout; deadlink -1 disables
	// it entirely (no false kills on lossy links, at the cost of no dead-peer
	// backstop — goodbye-RST still covers clean shutdowns). KeepAliveInterval is
	// a fraction of the timeout so live peers keep each other refreshed (and
	// satisfies smux's interval < timeout invariant).
	if cfg != nil && cfg.DeadLink > 0 {
		sconf.KeepAliveDisabled = false
		sconf.KeepAliveTimeout = time.Duration(cfg.DeadLink) * time.Second
		sconf.KeepAliveInterval = sconf.KeepAliveTimeout / 3
		if sconf.KeepAliveInterval < time.Second {
			sconf.KeepAliveInterval = time.Second
		}
	} else {
		// deadlink == -1 (or otherwise non-positive): keepalive disabled — no
		// idle traffic, but no dead-peer detection either.
		sconf.KeepAliveDisabled = true
		sconf.KeepAliveInterval = 0
		sconf.KeepAliveTimeout = 0
	}

	if cfg != nil && cfg.Smuxbuf > 0 {
		sconf.MaxReceiveBuffer = cfg.Smuxbuf
	}
	if cfg != nil && cfg.Streambuf > 0 {
		sconf.MaxStreamBuffer = cfg.Streambuf
	}
	return sconf
}
