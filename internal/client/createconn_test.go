package client

import (
	"context"
	"paqet/internal/conf"
	"testing"
)

func TestCreateConn(t *testing.T) {
	tc := &timedConn{
		ctx:     context.Background(),
		rootCfg: &conf.Conf{Network: conf.Network{Interface: conf.Interface{Index: 1, Name: "lo"}}},
		srvCfg:  &conf.ServerConfig{Transport: conf.Transport{Protocol: "kcp"}},
	}
	_, err := tc.createConn()
	if err != nil {
		t.Fatalf("failed 1: %v", err)
	}
	tc.conn.Close()
	tc.pConn.Close()
	tc.conn = nil
	tc.pConn = nil
	_, err = tc.createConn()
	if err != nil {
		t.Fatalf("failed 2: %v", err)
	}
}
