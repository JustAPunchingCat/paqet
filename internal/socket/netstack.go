//go:build linux

package socket

import (
	"fmt"
	"net"
	"os"
	"paqet/internal/flog"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Netstack manages a userspace TCP/IP stack on top of a TUN device.
type Netstack struct {
	stack *stack.Stack
	nicID tcpip.NICID
}

func NewNetstack(ep stack.LinkEndpoint, localAddr net.IP) (*Netstack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("failed to create NIC: %v", err)
	}

	// Add the local address to the NIC
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(localAddr.To4()),
			PrefixLen: 32,
		},
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("failed to add protocol address: %v", err)
	}

	// Add a default route pointing to the TUN interface
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
	})

	return &Netstack{stack: s, nicID: nicID}, nil
}

// NewTunNetstack creates a Netstack backed by a TUN file descriptor
func NewTunNetstack(tunFile *os.File, localAddr net.IP) (*Netstack, error) {
	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:            []int{int(tunFile.Fd())},
		MTU:            1500,
		EthernetHeader: false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create fdbased endpoint: %v", err)
	}
	return NewNetstack(linkEP, localAddr)
}

// DialTCP creates a TCP connection using the userspace stack.
func (ns *Netstack) DialTCP(remoteAddr net.IP, remotePort int) (net.Conn, error) {
	fullAddr := fmt.Sprintf("%s:%d", remoteAddr.String(), remotePort)
	return gonet.DialTCP(ns.stack, tcpip.FullAddress{
		NIC:  ns.nicID,
		Addr: tcpip.AddrFromSlice(remoteAddr.To4()),
		Port: uint16(remotePort),
	}, ipv4.ProtocolNumber)
}

// ListenTCP creates a TCP listener using the userspace stack.
func (ns *Netstack) ListenTCP(localPort int) (net.Listener, error) {
	return gonet.ListenTCP(ns.stack, tcpip.FullAddress{
		NIC:  ns.nicID,
		Addr: tcpip.AddrFromSlice(net.IPv4zero.To4()),
		Port: uint16(localPort),
	}, ipv4.ProtocolNumber)
}

// NetstackInjector adapts a net.Conn to PacketInjector.
// It writes the payload directly to the stream.
type NetstackInjector struct {
	conn net.Conn
}

func (n *NetstackInjector) WritePacketData(data []byte) error {
	// NOTE: Since we are writing to a stream, we rely on the fact that
	// paqet's server (raw socket) reads packets. We must ensure 1:1 mapping.
	// Ideally, we should use framing (Length-Prefix), but the raw server
	// doesn't support it. We rely on PUSH flags and MTU.
	_, err := n.conn.Write(data)
	return err
}

func (n *NetstackInjector) Close() {
	n.conn.Close()
}

// NetstackSource adapts a net.Conn to PacketSource.
// It reads from the stream.
type NetstackSource struct {
	conn net.Conn
}

func (n *NetstackSource) ReadPacketData() ([]byte, error) {
	buf := make([]byte, 4096)
	num, err := n.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	// Return a copy of the data
	data := make([]byte, num)
	copy(data, buf[:num])
	return data, nil
}

func (n *NetstackSource) Close() {
	n.conn.Close()
}

// PaqetLinkEndpoint adapts PacketSource/PacketInjector to gVisor's LinkEndpoint
type PaqetLinkEndpoint struct {
	source     PacketSource
	injector   PacketInjector
	dispatcher stack.NetworkDispatcher
}

func NewPaqetLinkEndpoint(source PacketSource, injector PacketInjector) *PaqetLinkEndpoint {
	return &PaqetLinkEndpoint{
		source:   source,
		injector: injector,
	}
}

func (e *PaqetLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	go e.readLoop()
}

func (e *PaqetLinkEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *PaqetLinkEndpoint) Wait() {}

func (e *PaqetLinkEndpoint) MTU() uint32 {
	return 1500
}

func (e *PaqetLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (e *PaqetLinkEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *PaqetLinkEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *PaqetLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		// Serialize the packet buffer to bytes
		view := pkt.ToView()
		if err := e.injector.WritePacketData(view.AsSlice()); err != nil {
			// Log error but continue
			flog.Debugf("Netstack write error: %v", err)
		}
	}
	return pkts.Len(), nil
}

func (e *PaqetLinkEndpoint) readLoop() {
	for {
		data, err := e.source.ReadPacketData()
		if err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}

		// Wrap data in a PacketBuffer
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(data),
		})

		// Deliver to gVisor
		// Note: We assume IPv4 for simplicity, or check version byte
		proto := ipv4.ProtocolNumber
		e.dispatcher.DeliverNetworkPacket(proto, pkt)
		pkt.DecRef()
	}
}

func (e *PaqetLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *PaqetLinkEndpoint) AddHeader(pkt *stack.PacketBuffer) {}

func (e *PaqetLinkEndpoint) ParseHeader(pkt *stack.PacketBuffer) bool { return true }
