//go:build linux

package socket

import (
	"fmt"
	"io"
	"os"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
	TUNSETIFF = 0x400454ca
)

var (
	tunMu  sync.Mutex
	tunMap = make(map[string]*TunDevice)
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	_     [22]byte
}

type TunDevice struct {
	file     *os.File
	name     string
	subs     map[*TunSource]chan []byte
	mu       sync.RWMutex
	refCount int
}

func newTunDevice(cfg *conf.Network) (*TunDevice, error) {
	if cfg.TUN.FD > 0 {
		file := os.NewFile(uintptr(cfg.TUN.FD), cfg.TUN.Name)
		dev := &TunDevice{
			file:     file,
			name:     cfg.TUN.Name,
			subs:     make(map[*TunSource]chan []byte),
			refCount: 1,
		}
		return dev, nil
	}

	tunMu.Lock()
	defer tunMu.Unlock()

	if dev, ok := tunMap[cfg.TUN.Name]; ok {
		dev.refCount++
		return dev, nil
	}

	// Open the TUN device
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	// Create the interface
	var req ifReq
	copy(req.Name[:], cfg.TUN.Name)
	req.Flags = IFF_TUN | IFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

	// Force the interface to be UP
	if err := setInterfaceUp(cfg.TUN.Name); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to bring interface %s up: %w", cfg.TUN.Name, err)
	}

	dev := &TunDevice{
		file:     file,
		name:     cfg.TUN.Name,
		subs:     make(map[*TunSource]chan []byte),
		refCount: 1,
	}
	tunMap[cfg.TUN.Name] = dev

	return dev, nil
}

func (t *TunDevice) File() *os.File {
	return t.file
}

func setInterfaceUp(name string) error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %v", err)
	}
	defer syscall.Close(s)

	var ifr ifReq
	copy(ifr.Name[:], name)

	// Get current flags
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return fmt.Errorf("ioctl SIOCGIFFLAGS: %v", errno)
	}

	// Set IFF_UP
	ifr.Flags |= syscall.IFF_UP

	// Set new flags
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return fmt.Errorf("ioctl SIOCSIFFLAGS: %v", errno)
	}
	return nil
}

func (t *TunDevice) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, err := t.file.Read(buf)
		if err != nil {
			// Ignore errors caused by closing the file (shutdown/restart)
			if err == io.EOF || err == os.ErrClosed || strings.Contains(err.Error(), "file already closed") || strings.Contains(err.Error(), "not pollable") {
				flog.Debugf("TUN read loop stopped on %s: %v", t.name, err)
			} else {
				flog.Errorf("TUN read loop error on %s: %v", t.name, err)
			}

			// Remove from global map so new connections create a new device
			tunMu.Lock()
			if existing, ok := tunMap[t.name]; ok && existing == t {
				delete(tunMap, t.name)
			}
			tunMu.Unlock()

			// Close all subscribers to unblock RecvHandle
			t.mu.Lock()
			for _, ch := range t.subs {
				close(ch)
			}
			t.subs = make(map[*TunSource]chan []byte)
			t.mu.Unlock()

			t.file.Close()
			return
		}
		// Copy data for subscribers
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		t.mu.RLock()
		for _, ch := range t.subs {
			select {
			case ch <- pkt:
			default:
			}
		}
		t.mu.RUnlock()
	}
}

func (t *TunDevice) Subscribe() *TunSource {
	ch := make(chan []byte, 1024)
	ts := &TunSource{dev: t, ch: ch}
	t.mu.Lock()
	t.subs[ts] = ch
	t.mu.Unlock()
	return ts
}

func (t *TunDevice) Unsubscribe(ts *TunSource) {
	t.mu.Lock()
	if ch, ok := t.subs[ts]; ok {
		delete(t.subs, ts)
		close(ch)
	}
	t.mu.Unlock()
}

func (t *TunDevice) Release() {
	if t.name == "" {
		t.file.Close()
		return
	}

	tunMu.Lock()
	defer tunMu.Unlock()

	t.refCount--
	if t.refCount <= 0 {
		t.file.Close()
		if existing, ok := tunMap[t.name]; ok && existing == t {
			delete(tunMap, t.name)
		}
	}
}

type TunSource struct {
	dev *TunDevice
	ch  chan []byte
}

func (ts *TunSource) ReadPacketData() ([]byte, error) {
	data, ok := <-ts.ch
	if !ok {
		return nil, io.EOF
	}
	return data, nil
}

func (ts *TunSource) Close() {
	ts.dev.Unsubscribe(ts)
	ts.dev.Release()
}

type TunInjector struct {
	dev *TunDevice
}

func (ti *TunInjector) WritePacketData(data []byte) error {
	n, err := ti.dev.file.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func (ti *TunInjector) Close() {
	ti.dev.Release()
}

// Implement PacketSource interface
func newTunSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	dev, err := newTunDevice(cfg)
	if err != nil {
		return nil, err
	}
	go dev.readLoop()
	return dev.Subscribe(), nil
}

// Implement PacketInjector interface
func newTunInjector(cfg *conf.Network) (PacketInjector, error) {
	dev, err := newTunDevice(cfg)
	if err != nil {
		return nil, err
	}
	// Injector does not need to read, so we don't start the loop
	return &TunInjector{dev: dev}, nil
}
