//go:build linux

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"paqet/internal/conf"
	"syscall"
	"unsafe"

	"github.com/spf13/cobra"
)

const (
	IFF_TUN       = 0x0001
	IFF_NO_PI     = 0x1000
	TUNSETIFF     = 0x400454ca
	TUNSETPERSIST = 0x400454cb
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	_     [22]byte
}

var (
	confPath string
)

var Cmd = &cobra.Command{
	Use:   "tun",
	Short: "Manage TUN interface (Linux only)",
	Long:  "Create, configure, and delete persistent TUN interfaces for use with the 'tun' driver.",
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Create persistent TUN interface and configure IP/Up",
	Run:   runSetup,
}

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Delete persistent TUN interface",
	Run:   runCleanup,
}

func init() {
	Cmd.AddCommand(setupCmd)
	Cmd.AddCommand(cleanupCmd)
	setupCmd.Flags().StringVarP(&confPath, "config", "c", "config.yaml", "Path to the configuration file")
	cleanupCmd.Flags().StringVarP(&confPath, "config", "c", "config.yaml", "Path to the configuration file")
}

func runSetup(cmd *cobra.Command, args []string) {
	cfg, err := conf.LoadFromFile(confPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		return
	}

	if cfg.Network.Driver != "tun" {
		fmt.Println("Config is not set to use 'tun' driver. Skipping.")
		return
	}

	ifaceName := cfg.Network.Interface.Name
	fmt.Printf("Setting up persistent TUN interface: %s\n", ifaceName)

	// 1. Create persistent TUN device
	if err := setPersist(ifaceName, true); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create persistent TUN: %v\n", err)
		return
	}

	// 2. Set IP address
	if cfg.Network.IPv4.Addr != nil {
		ip := cfg.Network.IPv4.Addr.IP.String()
		fmt.Printf("Assigning IPv4: %s\n", ip)
		if err := runIPCmd("addr", "add", ip, "dev", ifaceName); err != nil {
			// Ignore error if IP already exists
			fmt.Printf("Warning: failed to add IP (might already exist): %v\n", err)
		}
	}

	// 3. Bring interface UP
	fmt.Println("Bringing interface UP...")
	if err := runIPCmd("link", "set", "dev", ifaceName, "up"); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to bring interface up: %v\n", err)
		return
	}

	fmt.Println("TUN interface setup complete.")
}

func runCleanup(cmd *cobra.Command, args []string) {
	cfg, err := conf.LoadFromFile(confPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		return
	}

	ifaceName := cfg.Network.Interface.Name
	fmt.Printf("Removing persistent TUN interface: %s\n", ifaceName)

	if err := setPersist(ifaceName, false); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove persistent TUN: %v\n", err)
		return
	}
	fmt.Println("TUN interface removed.")
}

func setPersist(name string, persist bool) error {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	var req ifReq
	copy(req.Name[:], name)
	req.Flags = IFF_TUN | IFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

	pval := 0
	if persist {
		pval = 1
	}
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETPERSIST), uintptr(pval))
	if errno != 0 {
		return fmt.Errorf("ioctl TUNSETPERSIST failed: %v", errno)
	}
	return nil
}

func runIPCmd(args ...string) error {
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}
