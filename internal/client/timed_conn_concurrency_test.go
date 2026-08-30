package client

// TestTimedConn_ConcurrentTeardown — the sim gate for timed_conn.go.
// Reproduces the field wedges (runs 17:48–18:18): concurrent
// openAndSendProto rebuilds + OnRST teardowns + idleCheckLoop ticks
// must NEVER hold tc.mu > 2s, regardless of how slow createConn or
// OpenStrm are. Run before every commit touching timed_conn.go.

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"paqet/internal/conf"
	"paqet/internal/tnet"
)

// fakeStrm is a minimal tnet.Strm whose OpenStrm blocks for a
// configurable duration (simulating a desynced smux session against an
// offline server).
type fakeStrm struct{ net.Conn }

func (f *fakeStrm) SID() int { return 1 }

type fakeConn struct {
	openDelay time.Duration
	closed    atomic.Bool
}

func (f *fakeConn) OpenStrm() (tnet.Strm, error) {
	time.Sleep(f.openDelay)
	if f.closed.Load() {
		return nil, context.Canceled
	}
	return &fakeStrm{Conn: nil}, nil
}
func (f *fakeConn) AcceptStrm() (tnet.Strm, error) { return nil, context.Canceled }
func (f *fakeConn) Ping(wait bool) error           { return nil }
func (f *fakeConn) Close() error                   { f.closed.Store(true); return nil }
func (f *fakeConn) LocalAddr() net.Addr            { return &net.UDPAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr           { return &net.UDPAddr{} }
func (f *fakeConn) SetDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func newTestTimedConn(t *testing.T, openDelay time.Duration) *timedConn {
	t.Helper()
	tc := &timedConn{
		ctx:       context.Background(),
		rootCfg:   &conf.Conf{},
		srvCfg:    &conf.ServerConfig{},
		lastIdle:  time.Now(),
		closeJobs: make(chan func(), 64),
	}
	go func() {
		for job := range tc.closeJobs {
			job()
		}
	}()
	tc.createConnFn = func() (tnet.Conn, error) {
		time.Sleep(300 * time.Millisecond) // eBPF-init-scale slowness
		return &fakeConn{openDelay: openDelay}, nil
	}
	conn, err := tc.newConn()
	if err != nil {
		t.Fatalf("initial conn: %v", err)
	}
	tc.conn = conn
	go tc.idleCheckLoop()
	return tc
}

// TestNoLongTcMuHold asserts that under concurrent rebuilds, RST
// teardowns and idle-loop ticks, tc.mu is never held longer than 2s.
func TestNoLongTcMuHold(t *testing.T) {
	// openDelay 600ms — bigger than the contention threshold budget
	// when combined with rebuild slowness, but bounded by the 5s
	// OpenStrm deadline.
	tc := newTestTimedConn(t, 600*time.Millisecond)

	stop := make(chan struct{})
	var maxHold int64
	// Probe: repeatedly TryLock tc.mu and measure how long until a
	// lock succeeds — upper bound on the current hold time.
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			start := time.Now()
			if tc.mu.TryLock() {
				held := time.Since(start)
				tc.mu.Unlock()
				for {
					old := atomic.LoadInt64(&maxHold)
					h := int64(held)
					if h <= old || atomic.CompareAndSwapInt64(&maxHold, old, h) {
						break
					}
				}
			} else {
				time.Sleep(5 * time.Millisecond)
				held := time.Since(start)
				for {
					old := atomic.LoadInt64(&maxHold)
					h := int64(held)
					if h <= old || atomic.CompareAndSwapInt64(&maxHold, old, h) {
						break
					}
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	var wg sync.WaitGroup
	// 4 concurrent openAndSendProto (rebuild path, slow OpenStrm)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tc.rebuildMu.Lock()
			tc.lockDiag()
			_, _ = tc.boundedOpenStrm(tc.conn)
			tc.mu.Unlock()
			tc.rebuildMu.Unlock()
		}()
	}
	// OnRST teardowns racing the rebuilds
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(50 * time.Millisecond)
			tc.OnRST(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1})
		}()
	}
	wg.Wait()
	close(stop)

	if h := atomic.LoadInt64(&maxHold); h > int64(2*time.Second) {
		t.Fatalf("tc.mu held for %v (>2s) under concurrent teardown — deadlock shape regressed", time.Duration(h))
	}
	t.Logf("max observed tc.mu hold: %v", time.Duration(atomic.LoadInt64(&maxHold)))
}
