//go:build !nopcap

package socket

import (
	"fmt"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket/pcap"
)

func newHandle(cfg *conf.Network) (*pcap.Handle, error) {
	// On Windows, use the GUID field to construct the NPF device name
	// On other platforms, use the interface name directly
	ifaceName := cfg.Interface.Name
	if runtime.GOOS == "windows" {
		ifaceName = cfg.GUID
	}

	inactive, err := pcap.NewInactiveHandle(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create inactive pcap handle for %s: %v", cfg.Interface.Name, err)
	}
	defer inactive.CleanUp()

	// Set Buffer Size (if configured)
	if cfg.PCAP.Sockbuf > 0 {
		if err = inactive.SetBufferSize(cfg.PCAP.Sockbuf); err != nil {
			return nil, fmt.Errorf("failed to set pcap buffer size to %d: %v", cfg.PCAP.Sockbuf, err)
		}
	}

	// Set SnapLen
	snaplen := cfg.PCAP.Snaplen
	if snaplen == 0 {
		snaplen = 65536
	}
	if err = inactive.SetSnapLen(snaplen); err != nil {
		return nil, fmt.Errorf("failed to set pcap snap length: %v", err)
	}

	// Set Promiscuous Mode
	if err = inactive.SetPromisc(cfg.PCAP.Promisc); err != nil {
		return nil, fmt.Errorf("failed to enable promiscuous mode: %v", err)
	}

	// Set Timeout
	timeout := cfg.PCAP.Timeout
	if timeout <= 0 {
		timeout = pcap.BlockForever
	}
	if err = inactive.SetTimeout(timeout); err != nil {
		return nil, fmt.Errorf("failed to set pcap timeout: %v", err)
	}

	// Set Immediate Mode (Low Latency)
	if err = inactive.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("failed to enable immediate mode: %v", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("failed to activate pcap handle on %s: %v", cfg.Interface.Name, err)
	}

	return handle, nil
}
