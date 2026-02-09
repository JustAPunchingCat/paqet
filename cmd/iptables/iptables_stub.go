//go:build !linux

package iptables

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "iptables",
	Short: "Manage iptables rules for paqet",
	Long:  "Manage iptables rules to allow paqet to bypass kernel connection tracking and RST packets.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("iptables command is not supported on %s\n", runtime.GOOS)
	},
}
