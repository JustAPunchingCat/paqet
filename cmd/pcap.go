//go:build !nopcap

package main

import (
	"paqet/cmd/dump"
	"paqet/cmd/iface"

	"github.com/spf13/cobra"
)

func addPcapCommands(root *cobra.Command) {
	root.AddCommand(dump.Cmd)
	root.AddCommand(iface.Cmd)
}
