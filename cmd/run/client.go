package run

import (
	"context"
	"os"
	"os/signal"
	"paqet/internal/client"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/forward"
	"paqet/internal/socks"
	"syscall"
)

func startClient(cfg *conf.Conf) {
	flog.Infof("Starting client...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	c, err := client.New(cfg)
	if err != nil {
		flog.Errorf("Client init failed: %v", err)
		return
	}
	if err := c.Start(ctx); err != nil {
		flog.Errorf("Client start error: %v", err)
		return
	}

	for i, srvCfg := range cfg.Servers {
		for _, ss := range srvCfg.SOCKS5 {
			go func(ss conf.SOCKS5, idx int) {
				s, _ := socks.New(c, idx)
				if err := s.Start(ctx, ss); err != nil {
					flog.Errorf("SOCKS5 error %v: %v", ss.Listen, err)
				}
			}(ss, i)
		}
		for _, ff := range srvCfg.Forward {
			go func(ff conf.Forward, idx int) {
				f, _ := forward.New(c, ff.Listen.String(), ff.Target.String(), idx)
				if err := f.Start(ctx, ff.Protocol); err != nil {
					flog.Errorf("Forward error %v: %v", ff.Listen, err)
				}
			}(ff, i)
		}
	}

	<-sig
	flog.Infof("Shutdown signal received, initiating graceful shutdown...")
	cancel()
	flog.Infof("Shutdown complete.")
}
