package kcp

import (
	"paqet/internal/conf"

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
	// Disable smux synthetic keepalives completely on both client and server.
	// KCP is an ACK-based reliable protocol that handles user data on demand.
	// Disabling keepalives eliminates idle packet traffic and prevents false "closed pipe" disconnects.
	sconf.KeepAliveDisabled = true
	sconf.KeepAliveInterval = 0
	sconf.KeepAliveTimeout = 0

	if cfg != nil && cfg.Smuxbuf > 0 {
		sconf.MaxReceiveBuffer = cfg.Smuxbuf
	}
	if cfg != nil && cfg.Streambuf > 0 {
		sconf.MaxStreamBuffer = cfg.Streambuf
	}
	return sconf
}
