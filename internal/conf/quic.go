package conf

import (
	"fmt"
	"time"
)

type QUIC struct {
	MaxStreams          int           `yaml:"max_streams"`
	IdleTimeout         time.Duration `yaml:"idle_timeout"`
	KeepAlive           time.Duration `yaml:"keep_alive"`
	InitialStreamWindow uint64        `yaml:"initial_stream_window"`
	MaxStreamWindow     uint64        `yaml:"max_stream_window"`
	InitialConnWindow   uint64        `yaml:"initial_conn_window"`
	MaxConnWindow       uint64        `yaml:"max_conn_window"`
	Key                 string        `yaml:"key"`
	CertFile            string        `yaml:"cert_file"`
	KeyFile             string        `yaml:"key_file"`
	ALPN                string        `yaml:"alpn"`
	MTU                 int           `yaml:"mtu"`
}

func (q *QUIC) setDefaults() {
	if q.MaxStreams == 0 {
		q.MaxStreams = 100
	}
	if q.IdleTimeout == 0 {
		q.IdleTimeout = 30 * time.Second
	}
	if q.KeepAlive == 0 {
		q.KeepAlive = 5 * time.Second // Aggressive keepalive for raw socket stability
	}
	if q.InitialStreamWindow == 0 {
		q.InitialStreamWindow = 1024 * 1024 // 1MB
	}
	if q.MaxStreamWindow == 0 {
		q.MaxStreamWindow = 16 * 1024 * 1024 // 16MB
	}
	if q.InitialConnWindow == 0 {
		q.InitialConnWindow = 1024 * 1024 // 1MB
	}
	if q.MaxConnWindow == 0 {
		q.MaxConnWindow = 32 * 1024 * 1024 // 32MB
	}
	if q.ALPN == "" {
		// Default to "h3" (HTTP/3) which is the standard ALPN for QUIC.
		// To support others (e.g. "h2"), ensure BOTH client and server configs match.
		q.ALPN = "h3"
	}
	if q.MTU == 0 {
		q.MTU = 1200 // Default safe MTU for QUIC
	}
}

func (q *QUIC) validate() []error {
	var errors []error
	if q.Key == "" {
		errors = append(errors, fmt.Errorf("QUIC key is required"))
	}
	if (q.CertFile != "" && q.KeyFile == "") || (q.CertFile == "" && q.KeyFile != "") {
		errors = append(errors, fmt.Errorf("both cert_file and key_file must be provided if one is set"))
	}
	if q.MTU < 1200 {
		errors = append(errors, fmt.Errorf("QUIC MTU must be at least 1200 bytes"))
	}
	return errors
}
