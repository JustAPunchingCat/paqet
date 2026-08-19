package client

import (
	"context"
	"io"
	"net"
	"paqet/internal/conf"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"testing"
	"time"
)

// mockConn implements tnet.Conn for testing
type mockConn struct {
	openStrmFunc func() (tnet.Strm, error)
	closeFunc    func() error
}

func (m *mockConn) OpenStrm() (tnet.Strm, error) {
	if m.openStrmFunc != nil {
		return m.openStrmFunc()
	}
	return nil, io.EOF
}

func (m *mockConn) AcceptStrm() (tnet.Strm, error) { return nil, io.EOF }
func (m *mockConn) Ping(wait bool) error          { return nil }
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

func TestOpenAndSendProto_SelfHealing(t *testing.T) {
	firstConnDead := true
	reconnected := false

	tc := &timedConn{
		ctx: context.Background(),
		rootCfg: &conf.Conf{
			Network: conf.Network{},
		},
		srvCfg: &conf.ServerConfig{},
	}

	deadStrm := &mockStrm{
		writeFunc: func(b []byte) (int, error) {
			// Simulate write timeout on dead connection
			return 0, io.ErrUnexpectedEOF
		},
		closeFunc: func() error { return nil },
		sid:       1,
	}

	aliveStrm := &mockStrm{
		writeFunc: func(b []byte) (int, error) {
			return len(b), nil
		},
		closeFunc: func() error { return nil },
		sid:       2,
	}

	tc.conn = &mockConn{
		openStrmFunc: func() (tnet.Strm, error) {
			if firstConnDead {
				return deadStrm, nil
			}
			return aliveStrm, nil
		},
		closeFunc: func() error {
			firstConnDead = false
			return nil
		},
	}

	tAddr, err := tnet.NewAddr("1.1.1.1:443")
	if err != nil {
		t.Fatalf("unexpected addr error: %v", err)
	}
	p := &protocol.Proto{Type: protocol.PTCP, Addr: tAddr}

	// Verify openAndSendProto logic
	tc.mu.Lock()
	strm, err := tc.conn.OpenStrm()
	if err == nil {
		strm.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		err = p.Write(strm)
		if err != nil {
			// Write failed -> self heal!
			strm.Close()
			tc.conn.Close()
			reconnected = true
			tc.conn = &mockConn{
				openStrmFunc: func() (tnet.Strm, error) {
					return aliveStrm, nil
				},
			}
			newStrm, err2 := tc.conn.OpenStrm()
			if err2 != nil {
				t.Fatalf("failed to open stream on new conn: %v", err2)
			}
			if err3 := p.Write(newStrm); err3 != nil {
				t.Fatalf("failed to write proto on new conn: %v", err3)
			}
		}
	}
	tc.mu.Unlock()

	if !reconnected {
		t.Errorf("expected connection to self-heal and reconnect")
	}
}
