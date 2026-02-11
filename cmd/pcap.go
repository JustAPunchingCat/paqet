//go:build !nopcap

package main

import (
	"paqet/cmd/dump"

	"github.com/spf13/cobra"
)

func addPcapCommands(root *cobra.Command) {
	root.AddCommand(dump.Cmd)
}
