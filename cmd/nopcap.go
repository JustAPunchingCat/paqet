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
}
