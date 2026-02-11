//go:build !linux

package tun

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	confPath string
)

var Cmd = &cobra.Command{
	Use:   "tun",
	Short: "Manage TUN interface",
	Long:  "Create, configure, and delete persistent TUN interfaces for use with the 'tun' driver.",
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Create persistent TUN interface and configure IP/Up",
	Run:   runStub,
}

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Delete persistent TUN interface",
	Run:   runStub,
}

func init() {
	Cmd.AddCommand(setupCmd)
	Cmd.AddCommand(cleanupCmd)
	setupCmd.Flags().StringVarP(&confPath, "config", "c", "config.yaml", "Path to the configuration file")
	cleanupCmd.Flags().StringVarP(&confPath, "config", "c", "config.yaml", "Path to the configuration file")
}

func runStub(cmd *cobra.Command, args []string) {
	fmt.Printf("tun command is not supported on %s\n", runtime.GOOS)
}
