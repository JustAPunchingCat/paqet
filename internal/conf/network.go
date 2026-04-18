package conf

import (
	"fmt"
	"net"
	"runtime"
	"slices"
)

type Addr struct {
	Addr_      string           `yaml:"addr"`
	RouterMac_ string           `yaml:"router_mac"`
	Addr       *net.UDPAddr     `yaml:"-"`
	Router     net.HardwareAddr `yaml:"-"`
}

type Spoof struct {
	Enabled          bool                `yaml:"enabled"`
	Addrs            []string            `yaml:"addrs"`
	ClientMappings   map[string][]string `yaml:"client_mappings"`
	ServerMappings   map[string][]string `yaml:"server_mappings"`
	TargetSpoofAddrs map[string][]string `yaml:"target_spoof_addrs"`
	Clients          []SpoofClient       `yaml:"clients"`
	Servers          []SpoofServer       `yaml:"servers"`
}

type SpoofClient struct {
	Name              string   `yaml:"name"`
	RealClientIPs     []string `yaml:"real_client_ips"`
	SpoofedClientIPs  []string `yaml:"spoofed_client_ips"`
	SpoofingServerIPs []string `yaml:"spoofing_server_ips"`
}

type SpoofServer struct {
	Name              string   `yaml:"name"`
	RealServerIPs     []string `yaml:"real_server_ips"`
	SpoofedServerIPs  []string `yaml:"spoofed_server_ips"`
	SpoofingClientIPs []string `yaml:"spoofing_client_ips"`
}

type Network struct {
	Interface_  string         `yaml:"interface"`
	Driver      string         `yaml:"driver"`
	GUID        string         `yaml:"guid"`
	IPv4        Addr           `yaml:"ipv4"`
	IPv6        Addr           `yaml:"ipv6"`
	PCAP        PCAP           `yaml:"pcap"`
	TCP         TCP            `yaml:"tcp"`
	Interface   *net.Interface `yaml:"-"`
	Port        int            `yaml:"-"`
	Transport   *Transport     `yaml:"-"`
	Obfuscation *Obfuscation   `yaml:"-"`
	Spoof       *Spoof         `yaml:"spoof"`
	Role        string         `yaml:"-"`
}

func (n *Network) setDefaults(role string) {
	n.Role = role
	n.PCAP.setDefaults(role)
	n.TCP.setDefaults()
	if n.Driver == "" {
		n.Driver = "pcap"
	}
}

func (n *Network) validate() []error {
	var errors []error

	// Dynamically build the legacy maps from the clean list-based config
	if n.Spoof != nil {
		if n.Spoof.ClientMappings == nil {
			n.Spoof.ClientMappings = make(map[string][]string)
		}
		if n.Spoof.ServerMappings == nil {
			n.Spoof.ServerMappings = make(map[string][]string)
		}
		if n.Spoof.TargetSpoofAddrs == nil {
			n.Spoof.TargetSpoofAddrs = make(map[string][]string)
		}
		for _, c := range n.Spoof.Clients {
			if len(c.RealClientIPs) > 0 {
				for _, spoofed := range c.SpoofedClientIPs {
					if spoofed != "" {
						n.Spoof.ClientMappings[spoofed] = append(n.Spoof.ClientMappings[spoofed], c.RealClientIPs...)
					}
				}
				for _, realIP := range c.RealClientIPs {
					if len(c.SpoofingServerIPs) > 0 {
						n.Spoof.TargetSpoofAddrs[realIP] = append(n.Spoof.TargetSpoofAddrs[realIP], c.SpoofingServerIPs...)
					}
				}
			}
		}
		for _, srv := range n.Spoof.Servers {
			if len(srv.RealServerIPs) > 0 {
				for _, spoofed := range srv.SpoofedServerIPs {
					if spoofed != "" {
						n.Spoof.ServerMappings[spoofed] = append(n.Spoof.ServerMappings[spoofed], srv.RealServerIPs...)
					}
				}
				for _, realIP := range srv.RealServerIPs {
					if len(srv.SpoofingClientIPs) > 0 {
						n.Spoof.TargetSpoofAddrs[realIP] = append(n.Spoof.TargetSpoofAddrs[realIP], srv.SpoofingClientIPs...)
					}
				}
			}
		}
	}

	validDrivers := []string{"pcap", "ebpf", "afpacket", "ebpf-generic"}
	if !slices.Contains(validDrivers, n.Driver) {
		errors = append(errors, fmt.Errorf("driver must be one of: %v", validDrivers))
	}

	if n.Interface_ == "" {
		errors = append(errors, fmt.Errorf("network interface is required"))
	}
	if len(n.Interface_) > 15 {
		errors = append(errors, fmt.Errorf("network interface name too long (max 15 characters): '%s'", n.Interface_))
	}
	lIface, err := net.InterfaceByName(n.Interface_)
	if err != nil {
		errors = append(errors, fmt.Errorf("failed to find network interface %s: %v", n.Interface_, err))
	}
	n.Interface = lIface

	if runtime.GOOS == "windows" && n.GUID == "" {
		errors = append(errors, fmt.Errorf("guid is required on windows"))
	}

	ipv4Configured := n.IPv4.Addr_ != ""
	ipv6Configured := n.IPv6.Addr_ != ""
	if !ipv4Configured && !ipv6Configured {
		errors = append(errors, fmt.Errorf("at least one address family (IPv4 or IPv6) must be configured"))
		return errors
	}
	if ipv4Configured {
		errors = append(errors, n.IPv4.validate()...)
	}
	if ipv6Configured {
		errors = append(errors, n.IPv6.validate()...)
	}
	if ipv4Configured && ipv6Configured {
		if n.IPv4.Addr.Port != n.IPv6.Addr.Port {
			errors = append(errors, fmt.Errorf("IPv4 port (%d) and IPv6 port (%d) must match when both are configured", n.IPv4.Addr.Port, n.IPv6.Addr.Port))
		}
	}
	if n.IPv4.Addr != nil {
		n.Port = n.IPv4.Addr.Port
	}
	if n.IPv6.Addr != nil {
		n.Port = n.IPv6.Addr.Port
	}

	errors = append(errors, n.PCAP.validate()...)
	errors = append(errors, n.TCP.validate()...)

	return errors
}

func (n *Addr) validate() []error {
	var errors []error

	l, err := validateAddr(n.Addr_, false)
	if err != nil {
		errors = append(errors, err)
	}
	n.Addr = l

	if n.RouterMac_ == "" {
		errors = append(errors, fmt.Errorf("Router MAC address is required"))
	}

	hwAddr, err := net.ParseMAC(n.RouterMac_)
	if err != nil {
		errors = append(errors, fmt.Errorf("invalid Router MAC address '%s': %v", n.RouterMac_, err))
	}
	n.Router = hwAddr

	return errors
}
