package conf

import (
	"fmt"
	"slices"
)

type Transport struct {
	Protocol string `yaml:"protocol"`
	Conn     int    `yaml:"conn"`
	TCPBuf   int    `yaml:"tcpbuf"`
	UDPBuf   int    `yaml:"udpbuf"`
	KCP      *KCP   `yaml:"kcp"`
	QUIC     *QUIC  `yaml:"quic"`
	UDP      *UDP   `yaml:"udp"`
}

func (t *Transport) setDefaults(role string) {
	if t.Conn == 0 {
		t.Conn = 1
	}

	if t.TCPBuf == 0 {
		t.TCPBuf = 64 * 1024
	}
	if t.TCPBuf < 4*1024 {
		t.TCPBuf = 4 * 1024
	}
	if t.UDPBuf == 0 {
		t.UDPBuf = 4 * 1024 * 1024
	}
	if t.UDPBuf < 2*1024 {
		t.UDPBuf = 2 * 1024
	}

	switch t.Protocol {
	case "kcp":
		t.KCP.setDefaults(role)
	case "quic":
		if t.QUIC == nil {
			t.QUIC = &QUIC{}
		}
		t.QUIC.setDefaults()
	case "udp":
		if t.UDP == nil {
			t.UDP = &UDP{}
		}
		t.UDP.setDefaults()
	case "auto":
		if t.KCP == nil {
			t.KCP = &KCP{}
		}
		t.KCP.setDefaults(role)
		if t.QUIC == nil {
			t.QUIC = &QUIC{}
		}
		t.QUIC.setDefaults()
		if t.UDP == nil {
			t.UDP = &UDP{}
		}
		t.UDP.setDefaults()
	}
}

func (t *Transport) validate() []error {
	var errors []error

	validProtocols := []string{"kcp", "quic", "udp", "auto"}
	if !slices.Contains(validProtocols, t.Protocol) {
		errors = append(errors, fmt.Errorf("transport protocol must be one of: %v", validProtocols))
	}

	if t.Conn < 1 || t.Conn > 256 {
		errors = append(errors, fmt.Errorf("KCP conn must be between 1-256 connections"))
	}

	switch t.Protocol {
	case "kcp":
		errors = append(errors, t.KCP.validate()...)
	case "quic":
		errors = append(errors, t.QUIC.validate()...)
	case "udp":
		errors = append(errors, t.UDP.validate()...)
	case "auto":
		errors = append(errors, t.KCP.validate()...)
		errors = append(errors, t.QUIC.validate()...)
		errors = append(errors, t.UDP.validate()...)
	}

	return errors
}
