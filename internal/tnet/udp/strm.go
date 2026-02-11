package udp

import (
	"net"
	"time"
)

// Strm wraps a muxStream
type Strm struct {
	stream *muxStream
	conn   *Conn
}

func (s *Strm) SetUnordered(b bool) {
	s.stream.SetUnordered(b)
}

func (s *Strm) Read(b []byte) (int, error)         { return s.stream.Read(b) }
func (s *Strm) Write(b []byte) (int, error)        { return s.stream.Write(b) }
func (s *Strm) Close() error                       { return s.stream.Close() }
func (s *Strm) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *Strm) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *Strm) SetDeadline(t time.Time) error      { return s.stream.SetDeadline(t) }
func (s *Strm) SetReadDeadline(t time.Time) error  { return s.stream.SetReadDeadline(t) }
func (s *Strm) SetWriteDeadline(t time.Time) error { return s.stream.SetWriteDeadline(t) }
func (s *Strm) SID() int                           { return s.stream.SID() }
