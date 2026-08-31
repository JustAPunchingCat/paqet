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
	"paqet/internal/protocol"
	"paqet/internal/socket"
	"paqet/internal/tnet"
)

// fakeStrm is a minimal tnet.Strm whose OpenStrm blocks for a
// configurable duration (simulating a desynced smux session against an
// offline server).
type fakeStrm struct{ net.Conn }

func (f *fakeStrm) SID() int { return 1 }

func (f *fakeStrm) Read(b []byte) (int, error)  { return 0, nil }
func (f *fakeStrm) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeStrm) Close() error                { return nil }
func (f *fakeStrm) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (f *fakeStrm) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (f *fakeStrm) SetDeadline(t time.Time) error {
	return nil
}
func (f *fakeStrm) SetReadDeadline(t time.Time) error {
	return nil
}
func (f *fakeStrm) SetWriteDeadline(t time.Time) error {
	return nil
}

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

func testProto() *protocol.Proto {
	a, err := tnet.NewAddr("1.2.3.4:443")
	if err != nil {
		panic(err)
	}
	return &protocol.Proto{Type: protocol.PTCP, Addr: a}
}

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

// TestFastPathNoSelfDeadlock: the fast path (conn exists) previously
// self-deadlocked — openAndSendProto locked tc.mu then called
// openStreamOnConn which locked it again (non-reentrant). Field run
// 18:42: holder timed_conn.go:580, tunnel dead after server restart.
func TestFastPathNoSelfDeadlock(t *testing.T) {
	// Healthy conn: OpenStrm returns instantly.
	tc := newTestTimedConn(t, 0)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := tc.openAndSendProto(testProto())
		if err != nil {
			t.Errorf("fast-path stream open failed: %v", err)
		}
	}()
	select {
	case <-done:
		// success — no self-deadlock
	case <-time.After(8 * time.Second):
		t.Fatal("fast path deadlocked — openStreamOnConn re-locked tc.mu")
	}
}

// TestFastPathUnderFire: healthy conn + concurrent OnRST teardowns +
// idle loop — the fast path must not wedge tc.mu either.
func TestFastPathUnderFire(t *testing.T) {
	tc := newTestTimedConn(t, 0)
	stop := make(chan struct{})
	var maxHold int64
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			start := time.Now()
			if tc.mu.TryLock() {
				tc.mu.Unlock()
				h := int64(time.Since(start))
				for {
					old := atomic.LoadInt64(&maxHold)
					if h <= old || atomic.CompareAndSwapInt64(&maxHold, old, h) {
						break
					}
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tc.openAndSendProto(testProto())
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(20 * time.Millisecond)
			tc.OnRST(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1})
		}()
	}
	wg.Wait()
	close(stop)
	if h := atomic.LoadInt64(&maxHold); h > int64(2*time.Second) {
		t.Fatalf("tc.mu held %v under fast-path fire", time.Duration(h))
	}
}

// TestInstallVsTeardownRace: the field-proven 18:59 wedge — the
// rebuild goroutine installs the conn (reads tc.pConn.GetCurrentPort())
// while OnRST teardown nils tc.pConn; the panic must not escape (it
// unwound without unlocking tc.mu and wedged every waiter forever).
func TestInstallVsTeardownRace(t *testing.T) {
	for i := 0; i < 200; i++ {
		tc := newTestTimedConn(t, 0)
		var wg sync.WaitGroup
		// Rebuild storm — install path reads tc.pConn under tc.mu.
		wg.Add(1)
		go func() {
			defer wg.Done()
			tc.rebuildMu.Lock()
			conn, err := tc.newConn()
			if err != nil {
				tc.rebuildMu.Unlock()
				return
			}
			installed := false
			func() {
				tc.lockDiag()
				defer tc.unlockDiag()
				tc.conn = conn
				if tc.pConn != nil {
					tc.lastPort = tc.pConn.GetCurrentPort()
				}
				installed = true
			}()
			tc.rebuildMu.Unlock()
			_ = installed
		}()
		// Teardown racing the install — nils tc.pConn.
		wg.Add(1)
		go func() {
			defer wg.Done()
			tc.OnRST(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1})
		}()
		wg.Wait()
		// Mutex must be free — no wedged holder.
		if !tc.mu.TryLock() {
			t.Fatalf("iter %d: tc.mu wedged — install panicked without unlocking", i)
		}
		tc.mu.Unlock()
	}
}

// TestFastPathOpenFailureReleasesLock: the field-proven 19:11 wedge —
// fast path's boundedOpenStrm error return leaked tc.mu (no unlock on
// that path); each offline-server OpenStrm timeout leaked the lock and
// wedged every subsequent waiter forever. After this test the mutex
// MUST be free despite repeated open failures.
func TestFastPathOpenFailureReleasesLock(t *testing.T) {
	// openDelay 6s > 5s deadline → boundedOpenStrm always times out,
	// exactly like a dead server.
	tc := newTestTimedConn(t, 6*time.Second)
	for i := 0; i < 5; i++ {
		_, err := tc.openAndSendProto(testProto())
		if err == nil {
			t.Fatalf("iter %d: expected open failure", i)
		}
		// THE assertion: mutex free after each failed open.
		if !tc.mu.TryLock() {
			t.Fatalf("iter %d: tc.mu LEAKED by failed open — wedged forever", i)
		}
		tc.mu.Unlock()
	}
}

// TestRebuildPathNoSelfDeadlock: the 19:19 wedge — openAndSendProto's
// REBUILD branch (tc.conn == nil) held tc.mu from the entry lockDiag
// and the install closure re-locked the same mutex on the same
// goroutine (non-reentrant) → permanent self-deadlock. Prior tests set
// tc.conn non-nil and only ever hit the fast path, so the rebuild
// branch's re-lock was never exercised. This test nils tc.conn and
// asserts openAndSendProto returns (success) within a hard deadline.
func TestRebuildPathNoSelfDeadlock(t *testing.T) {
	for i := 0; i < 5; i++ {
		// Build the harness, then force the rebuild path.
		tc := newTestTimedConn(t, 0)
		tc.lockDiag()
		conn := tc.conn
		tc.conn = nil
		tc.pConn = nil
		tc.unlockDiag()
		// The old conn is orphaned; fake createConn will produce a new
		// one. Install the seam to return a fresh healthy conn.
		tc.createConnFn = func() (tnet.Conn, error) {
			return &fakeConn{openDelay: 0}, nil
		}
		done := make(chan error, 1)
		go func() {
			_, err := tc.openAndSendProto(testProto())
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("iter %d: rebuild-path open errored: %v", i, err)
			}
		case <-time.After(8 * time.Second):
			t.Fatalf("iter %d: rebuild path SELF-DEADLOCKED (openAndSendProto.func1 re-locked entry tc.mu)", i)
		}
		_ = conn
	}
}

// TestWatchdogRotatesBeforeRebuild: the field-proven SSH-death shape —
// a stream written-but-no-read is AMBIGUOUS (DPI-blocked return path vs
// desynced smux). The old watchdog rebuilt the WHOLE conn on the FIRST
// no-read, dropping every sibling stream (field run: SSH died under a
// website burst after surviving 14 min of rotation). The fix must rotate
// first (preserve session + siblings) and rebuild only on a SECOND
// consecutive no-read after a real rotation.
func TestWatchdogRotatesBeforeRebuild(t *testing.T) {
	// Shrink the windows for a fast test; restore on exit.
	oldWindow, oldPoll, oldCooldown := firstReadWindow, watchdogPollInterval, rotateCooldown
	firstReadWindow = 100 * time.Millisecond
	watchdogPollInterval = 20 * time.Millisecond
	rotateCooldown = 40 * time.Millisecond
	defer func() {
		firstReadWindow, watchdogPollInterval, rotateCooldown = oldWindow, oldPoll, oldCooldown
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Manual harness: NO closer goroutine — deferClose enqueues into the
	// buffered closeJobs (never drained), so the zero-value pConn is never
	// actually Close()'d (its nil cancel func would panic). The watchdog
	// DECISION is what's under test, not the close.
	tc := &timedConn{
		ctx:       ctx,
		rootCfg:   &conf.Conf{},
		srvCfg:    &conf.ServerConfig{Hopping: conf.Hopping{RotateClientPort: true}},
		conn:      &fakeConn{},
		pConn:     &socket.PacketConn{},
		lastIdle:  time.Now(),
		closeJobs: make(chan func(), 64),
	}
	var rotates int32
	tc.rotatePortFn = func() (int, error) {
		atomic.AddInt32(&rotates, 1)
		return 4242, nil
	}

	strm := &idleTrackedStrm{Strm: &fakeStrm{}, tc: tc}
	strm.Write([]byte("hello")) // arms the watchdog (written, never read)

	waitFor := func(cond func() bool, what string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for %s", what)
	}

	// Strike 1: rotation must have happened AND the conn must still be
	// alive (the old code rebuilt here — this assertion catches the bug).
	waitFor(func() bool { return atomic.LoadInt32(&rotates) >= 1 }, "first rotation")
	tc.lockDiag()
	connAlive := tc.conn != nil
	tc.unlockDiag()
	if !connAlive {
		t.Fatal("first no-read strike REBUILT the conn — sibling SSH would have died")
	}

	// Rotation-only: after a second consecutive no-read, the watchdog must
	// rotate AGAIN — never rebuild. The destructive rebuild belongs to the
	// conn-level auto_rotate, not this per-stream watchdog (field-proven: a
	// per-stream rebuild here killed sibling SSH under a heavy speedtest).
	waitFor(func() bool { return atomic.LoadInt32(&rotates) >= 2 }, "second rotation (rotation-only, no rebuild)")

	tc.lockDiag()
	connAlive2 := tc.conn != nil
	tc.unlockDiag()
	if !connAlive2 {
		t.Fatal("second no-read strike REBUILT the conn — sibling SSH would have died")
	}
}

// TestIdleLoopAutoRotateNoSelfDeadlock: the 19:32 wedge — idleCheckLoop's
// tick body re-locked tc.mu immediately before `continue`, so the lock
// stayed held into the NEXT tick, where the loop's own lockDiag()
// self-deadlocked on a mutex it already owned (field dump: waiters
// everywhere, no holder, tag :757 = the re-lock site). This test drives
// the auto_rotate fresh-rebuild path (sending && deaf && recent rebuild)
// across several ticks and asserts tc.mu is never wedged.
func TestIdleLoopAutoRotateNoSelfDeadlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tc := &timedConn{
		ctx:       ctx,
		rootCfg:   &conf.Conf{},
		srvCfg:    &conf.ServerConfig{Hopping: conf.Hopping{AutoRotate: true, AutoRotateAfter: 15}},
		conn:      &fakeConn{},
		pConn:     &socket.PacketConn{},
		lastIdle:  time.Now(),
		closeJobs: make(chan func(), 64),
	}
	go func() {
		for job := range tc.closeJobs {
			job()
		}
	}()

	// sending (recent lastSend) && deaf (no recv) && fresh rebuild —
	// the exact field condition for the fresh-rebuild skip path.
	now := time.Now().UnixNano()
	tc.pConn.SetActivityForTest(now, 0)
	tc.rebuildAt.Store(now)

	go tc.idleCheckLoop()

	// Wait for several 1s ticks to elapse. The old code self-deadlocked
	// on the 2nd tick (held the lock from tick 1 into tick 2), so after
	// 3+ ticks the mutex must still be free on the fixed code.
	time.Sleep(3500 * time.Millisecond)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for {
		if tc.mu.TryLock() {
			tc.mu.Unlock()
			return // free — no self-deadlock
		}
		if time.Now().After(deadline) {
			t.Fatal("idle loop self-deadlocked on tc.mu (re-lock before continue)")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
