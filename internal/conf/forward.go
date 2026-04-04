package conf

import (
	"net"
	"paqet/internal/tnet"
)

type Forward struct {
	Listen_   string       `yaml:"listen"`
	Target_   string       `yaml:"target"`
	Protocol  string       `yaml:"protocol"`
	Unordered *bool        `yaml:"unordered"`
	Listen    *net.UDPAddr `yaml:"-"`
	Target    *tnet.Addr   `yaml:"-"`
}

func (c *Forward) setDefaults() {
	if c.Unordered == nil {
		t := true
		c.Unordered = &t
	}
}
func (c *Forward) validate() []error {
	var errors []error
	l, err := validateAddr(c.Listen_, true)
	if err != nil {
		errors = append(errors, err)
	}
	c.Listen = l

	t, err := tnet.NewAddr(c.Target_)
	if err != nil {
		errors = append(errors, err)
	}
	c.Target = t

	return errors
}
