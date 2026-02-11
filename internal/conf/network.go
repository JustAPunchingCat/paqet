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

type Network struct {
	Interface_  string         `yaml:"interface"`
	Driver      string         `yaml:"driver"`
	GUID        string         `yaml:"guid"`
	TUN         TUN            `yaml:"tun"`
	IPv4        Addr           `yaml:"ipv4"`
	IPv6        Addr           `yaml:"ipv6"`
	PCAP        PCAP           `yaml:"pcap"`
	TCP         TCP            `yaml:"tcp"`
	Interface   *net.Interface `yaml:"-"`
	Port        int            `yaml:"-"`
	Transport   *Transport     `yaml:"-"`
	Obfuscation *Obfuscation   `yaml:"-"`
}

func (n *Network) setDefaults(role string) {
	n.PCAP.setDefaults(role)
	n.TCP.setDefaults()
	n.TUN.setDefaults()
	if n.Driver == "" {
		if n.TUN.FD > 0 {
			n.Driver = "tun"
		} else {
			n.Driver = "pcap"
		}
	}
}

func (n *Network) validate() []error {
	var errors []error

	validDrivers := []string{"pcap", "ebpf", "tun"}
	if !slices.Contains(validDrivers, n.Driver) {
		errors = append(errors, fmt.Errorf("driver must be one of: %v", validDrivers))
	}

	if n.Driver != "tun" {
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
	} else {
		// For TUN driver, we don't need a physical interface.
		// Create a dummy interface struct for logging purposes.
		n.Interface = &net.Interface{
			Name: n.TUN.Name,
		}
	}

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
		errors = append(errors, n.IPv4.validate(n.Driver)...)
	}
	if ipv6Configured {
		errors = append(errors, n.IPv6.validate(n.Driver)...)
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

func (n *Addr) validate(driver string) []error {
	var errors []error

	l, err := validateAddr(n.Addr_, false)
	if err != nil {
		errors = append(errors, err)
	}
	n.Addr = l

	if n.RouterMac_ != "" {
		hwAddr, err := net.ParseMAC(n.RouterMac_)
		if err != nil {
			errors = append(errors, fmt.Errorf("invalid Router MAC address '%s': %v", n.RouterMac_, err))
		}
		n.Router = hwAddr
	} else if driver != "tun" {
		// Router MAC is required for pcap and ebpf (Layer 2), but not for tun (Layer 3)
		errors = append(errors, fmt.Errorf("router_mac is required (needed for raw packet injection)"))
	}

	return errors
}
