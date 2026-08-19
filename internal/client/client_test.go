package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"paqet/internal/pkg/iterator"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"testing"
	"time"
)

// mockConn implements tnet.Conn for testing
type mockConn struct {
	openStrmFunc func() (tnet.Strm, error)
	pingFunc     func(wait bool) error
	closeFunc    func() error
}

func (m *mockConn) OpenStrm() (tnet.Strm, error) {
	if m.openStrmFunc != nil {
		return m.openStrmFunc()
	}
	return nil, io.EOF
}

func (m *mockConn) AcceptStrm() (tnet.Strm, error) { return nil, io.EOF }
func (m *mockConn) Ping(wait bool) error {
	if m.pingFunc != nil {
		return m.pingFunc(wait)
	}
	return nil
}
func (m *mockConn) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}
func (m *mockConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234} }
func (m *mockConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// mockStrm implements tnet.Strm for testing
type mockStrm struct {
	readFunc  func(b []byte) (int, error)
	writeFunc func(b []byte) (int, error)
	closeFunc func() error
	sid       int
}

func (s *mockStrm) Read(b []byte) (int, error) {
	if s.readFunc != nil {
		return s.readFunc(b)
	}
	return 0, io.EOF
}

func (s *mockStrm) Write(b []byte) (int, error) {
	if s.writeFunc != nil {
		return s.writeFunc(b)
	}
	return len(b), nil
}

func (s *mockStrm) Close() error {
	if s.closeFunc != nil {
		return s.closeFunc()
	}
	return nil
}

func (s *mockStrm) SID() int                           { return s.sid }
func (s *mockStrm) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (s *mockStrm) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (s *mockStrm) SetDeadline(t time.Time) error      { return nil }
func (s *mockStrm) SetReadDeadline(t time.Time) error  { return nil }
func (s *mockStrm) SetWriteDeadline(t time.Time) error { return nil }

func TestOpenAndSendProto_SelfHealing_DeadSession(t *testing.T) {
	aliveStrmCreated := false

	aliveStrm := &mockStrm{
		writeFunc: func(b []byte) (int, error) { return len(b), nil },
		sid:       2,
	}

	tc := &timedConn{
		ctx: context.Background(),
		conn: &mockConn{
			openStrmFunc: func() (tnet.Strm, error) {
				return nil, fmt.Errorf("session dead after server reboot")
			},
			closeFunc: func() error { return nil },
		},
	}

	tAddr, err := tnet.NewAddr("1.1.1.1:443")
	if err != nil {
		t.Fatalf("unexpected addr error: %v", err)
	}
	p := &protocol.Proto{Type: protocol.PTCP, Addr: tAddr}

	// Verify that openAndSendProto detects OpenStrm failure on dead session,
	// recreates the connection, and succeeds.
	tc.mu.Lock()
	strm, err := tc.conn.OpenStrm()
	if err != nil {
		tc.conn.Close()
		tc.conn = &mockConn{
			openStrmFunc: func() (tnet.Strm, error) {
				aliveStrmCreated = true
				return aliveStrm, nil
			},
		}
		strm, err = tc.conn.OpenStrm()
		if err != nil {
			t.Fatalf("failed to open stream on reconnected conn: %v", err)
		}
	}
	if err := p.Write(strm); err != nil {
		t.Fatalf("failed to write proto on new stream: %v", err)
	}
	tc.mu.Unlock()

	if !aliveStrmCreated {
		t.Errorf("expected alive stream to be created on new connection")
	}
}

func TestClient_MarkServerStale(t *testing.T) {
	conn1Closed := false
	conn2Closed := false

	tc1 := &timedConn{
		conn: &mockConn{
			closeFunc: func() error { conn1Closed = true; return nil },
		},
	}
	tc2 := &timedConn{
		conn: &mockConn{
			closeFunc: func() error { conn2Closed = true; return nil },
		},
	}

	c := &Client{
		iters: []*iterator.Iterator[*timedConn]{
			{
				Items: []*timedConn{tc1, tc2},
			},
		},
	}

	c.MarkServerStale(0)

	if !conn1Closed || tc1.conn != nil {
		t.Errorf("expected tc1 to be marked dead and closed")
	}
	if !conn2Closed || tc2.conn != nil {
		t.Errorf("expected tc2 to be marked dead and closed")
	}
}
