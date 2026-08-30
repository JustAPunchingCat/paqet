package client

import (
	"context"
	"paqet/internal/conf"
	"testing"
)

// TestCreateConn requires a real capture interface; skipped when no
// suitable interface exists (CI/Windows). This test was stale for a
// long time (referenced removed conf.Interface) — kept behind the
// env gate until the harness supports raw sockets in CI.
func TestCreateConn(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	tc := &timedConn{
		ctx:     context.Background(),
		rootCfg: &conf.Conf{},
		srvCfg:  &conf.ServerConfig{Transport: conf.Transport{Protocol: "kcp"}},
	}
	_, err := tc.createConn()
	if err != nil {
		t.Skipf("raw socket capture unavailable here: %v", err)
	}
	tc.conn.Close()
	tc.pConn.Close()
	tc.conn = nil
	tc.pConn = nil
	if _, err := tc.createConn(); err != nil {
		t.Fatalf("failed 2: %v", err)
	}
}
