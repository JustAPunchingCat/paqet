//go:build nopcap

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func addPcapCommands(root *cobra.Command) {
	root.AddCommand(&cobra.Command{
		Use:   "dump",
		Short: "Packet dump (disabled in nopcap build)",
		Run:   func(cmd *cobra.Command, args []string) { fmt.Println("dump command is disabled in nopcap build") },
	})
	root.AddCommand(&cobra.Command{
		Use:   "iface",
		Short: "Interface list (disabled in nopcap build)",
		Run:   func(cmd *cobra.Command, args []string) { fmt.Println("iface command is disabled in nopcap build") },
	})
}
