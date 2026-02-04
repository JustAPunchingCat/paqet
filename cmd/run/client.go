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
	"sync"
	"syscall"
)

func startClient(cfg *conf.Conf) {
	flog.Infof("Starting client...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	for _, srvCfg := range cfg.Servers {
		wg.Add(1)
		go func(srvCfg conf.ServerConfig) {
			defer wg.Done()

			// Create a sub-configuration for this specific server connection
			subCfg := *cfg
			subCfg.Server = srvCfg.Server
			subCfg.SOCKS5 = srvCfg.SOCKS5
			subCfg.Forward = srvCfg.Forward
			subCfg.Transport = srvCfg.Transport

			client, err := client.New(&subCfg)
			if err != nil {
				flog.Errorf("Failed to initialize client for %s: %v", srvCfg.Server.Addr, err)
				return
			}
			if err := client.Start(ctx); err != nil {
				flog.Infof("Client for %s encountered an error: %v", srvCfg.Server.Addr, err)
			}

			for _, ss := range subCfg.SOCKS5 {
				s, err := socks.New(client)
				if err != nil {
					flog.Errorf("Failed to initialize SOCKS5: %v", err)
					continue
				}
				go func(ss conf.SOCKS5) {
					if err := s.Start(ctx, ss); err != nil {
						flog.Errorf("SOCKS5 encountered an error on %v: %v", ss.Listen, err)
					}
				}(ss)
			}
			for _, ff := range subCfg.Forward {
				f, err := forward.New(client, ff.Listen.String(), ff.Target.String())
				if err != nil {
					flog.Errorf("Failed to initialize Forward: %v", err)
					continue
				}
				go func(ff conf.Forward) {
					if err := f.Start(ctx, ff.Protocol); err != nil {
						flog.Errorf("Forward encountered an error on %v: %v", ff.Listen, err)
					}
				}(ff)
			}

			// Wait for context cancellation
			<-ctx.Done()
			// Perform any specific cleanup here if necessary (e.g., client.Close())
		}(srvCfg)
	}

	<-sig
	flog.Infof("Shutdown signal received, initiating graceful shutdown...")
	cancel()
	wg.Wait()
	flog.Infof("Shutdown complete.")
}
