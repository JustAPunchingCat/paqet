package conf

import (
	"net"
)

type SOCKS5 struct {
	Listen_  string       `yaml:"listen"`
	Username string       `yaml:"username"`
	Password string       `yaml:"password"`
	SockBuf  int          `yaml:"sockbuf"`
	Listen   *net.UDPAddr `yaml:"-"`
}

func (c *SOCKS5) setDefaults() {
	if c.SockBuf == 0 {
		c.SockBuf = 4194304 // 4MB default
	}
}
func (c *SOCKS5) validate() []error {
	var errors []error

	addr, err := validateAddr(c.Listen_, true)
	if err != nil {
		errors = append(errors, err)
	}
	c.Listen = addr
	return errors
}
