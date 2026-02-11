package conf

import "time"

type PCAP struct {
	Snaplen int           `yaml:"snaplen"`
	Promisc bool          `yaml:"promisc"`
	Timeout time.Duration `yaml:"timeout"`
	Sockbuf int           `yaml:"sockbuf"`
}

func (p *PCAP) setDefaults(role string) {
	if p.Snaplen == 0 {
		p.Snaplen = 65535
	}
	if p.Timeout == 0 {
		p.Timeout = 30 * time.Second
	}
	if p.Sockbuf == 0 {
		if role == "server" {
			p.Sockbuf = 8 * 1024 * 1024 // 8MB
		} else {
			p.Sockbuf = 4 * 1024 * 1024 // 4MB
		}
	}
}

func (p *PCAP) validate() []error {
	return nil
}
