//go:build linux

package iptables

import (
	"fmt"
	"os"
	"os/exec"
	"paqet/internal/conf"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/spf13/cobra"
)

var (
	confPath string
)

var Cmd = &cobra.Command{
	Use:   "iptables",
	Short: "Manage iptables rules for paqet",
	Long:  "Manage iptables rules to allow paqet to bypass kernel connection tracking and RST packets.",
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List paqet related iptables rules",
	Run:   runList,
}

var removeCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove all paqet related iptables rules",
	Run:   runRemove,
}

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add iptables rules based on configuration",
	Run:   runAdd,
}

var persistCmd = &cobra.Command{
	Use:   "persist",
	Short: "Save iptables rules to persist across reboots",
	Run:   runPersist,
}

func init() {
	Cmd.AddCommand(listCmd)
	Cmd.AddCommand(removeCmd)
	Cmd.AddCommand(addCmd)
	Cmd.AddCommand(persistCmd)

	addCmd.Flags().StringVarP(&confPath, "config", "c", "config.yaml", "Path to the configuration file")
}

func getIPTables() (*iptables.IPTables, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize iptables: %v", err)
	}
	return ipt, nil
}

func runList(cmd *cobra.Command, args []string) {
	ipt, err := getIPTables()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	tables := []string{"raw", "mangle"}
	for _, table := range tables {
		chains, err := ipt.ListChains(table)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list chains in table %s: %v (check permissions?)\n", table, err)
			continue
		}
		for _, chain := range chains {
			rules, err := ipt.List(table, chain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to list rules in %s/%s: %v\n", table, chain, err)
				continue
			}
			for _, rule := range rules {
				if strings.Contains(rule, "paqet") {
					fmt.Printf("-t %s -A %s %s\n", table, chain, rule)
				}
			}
		}
	}
}

func runRemove(cmd *cobra.Command, args []string) {
	ipt, err := getIPTables()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	targets := []struct {
		table string
		chain string
	}{
		{"raw", "PREROUTING"},
		{"raw", "OUTPUT"},
		{"mangle", "OUTPUT"},
	}

	removedCount := 0
	for _, t := range targets {
		rules, err := ipt.List(t.table, t.chain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list rules in %s/%s: %v (check permissions?)\n", t.table, t.chain, err)
			continue
		}
		for _, rule := range rules {
			if strings.Contains(rule, "comment \"paqet\"") || strings.Contains(rule, "comment paqet") {
				// rule string from List (iptables -S) looks like: "-A PREROUTING ..."
				prefix := fmt.Sprintf("-A %s ", t.chain)
				if strings.HasPrefix(rule, prefix) {
					argsStr := strings.TrimPrefix(rule, prefix)
					// Split arguments correctly
					args := strings.Split(argsStr, " ")
					if err := ipt.Delete(t.table, t.chain, args...); err != nil {
						fmt.Fprintf(os.Stderr, "Failed to delete rule in %s/%s: %v\n", t.table, t.chain, err)
					} else {
						fmt.Printf("Removed rule: -t %s -A %s %s\n", t.table, t.chain, argsStr)
						removedCount++
					}
				}
			}
		}
	}
	if removedCount == 0 {
		fmt.Println("No paqet rules found to remove.")
	}
}

func runAdd(cmd *cobra.Command, args []string) {
	cfg, err := conf.LoadFromFile(confPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		return
	}

	ipt, err := getIPTables()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	ports := getPorts(cfg)
	if len(ports) == 0 {
		fmt.Println("No ports found in configuration to apply rules for.")
		return
	}

	for _, port := range ports {
		// Safety check: Do not apply rules to port 22 (SSH)
		if port == "22" {
			fmt.Fprintf(os.Stderr, "Skipping port 22 (SSH) for safety.\n")
			continue
		}
		if strings.Contains(port, ":") {
			parts := strings.Split(port, ":")
			if len(parts) == 2 {
				min, _ := strconv.Atoi(parts[0])
				max, _ := strconv.Atoi(parts[1])
				if min <= 22 && max >= 22 {
					fmt.Fprintf(os.Stderr, "Skipping port range %s containing 22 (SSH) for safety.\n", port)
					continue
				}
			}
		}

		// 1. raw PREROUTING
		err := ensureRule(ipt, "raw", "PREROUTING", "-p", "tcp", "--dport", port, "-m", "comment", "--comment", "paqet", "-j", "NOTRACK")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to add raw PREROUTING rule for %s: %v\n", port, err)
		}

		// 2. raw OUTPUT
		err = ensureRule(ipt, "raw", "OUTPUT", "-p", "tcp", "--sport", port, "-m", "comment", "--comment", "paqet", "-j", "NOTRACK")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to add raw OUTPUT rule for %s: %v\n", port, err)
		}

		// 3. mangle OUTPUT
		err = ensureRule(ipt, "mangle", "OUTPUT", "-p", "tcp", "--sport", port, "--tcp-flags", "RST", "RST", "-m", "comment", "--comment", "paqet", "-j", "DROP")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to add mangle OUTPUT rule for %s: %v\n", port, err)
		}
	}
	fmt.Printf("Iptables rules applied successfully for ports: %v\n", ports)
}

func ensureRule(ipt *iptables.IPTables, table, chain string, spec ...string) error {
	exists, err := ipt.Exists(table, chain, spec...)
	if err != nil {
		return err
	}
	if !exists {
		return ipt.Append(table, chain, spec...)
	}
	return nil
}

func getPorts(cfg *conf.Conf) []string {
	var ports []string

	add := func(p int) {
		if p > 0 {
			ports = append(ports, strconv.Itoa(p))
		}
	}
	addRange := func(min, max int) {
		if min > 0 && max > 0 {
			if min == max {
				add(min)
			} else {
				ports = append(ports, fmt.Sprintf("%d:%d", min, max))
			}
		}
	}

	if cfg.Role == "server" {
		if cfg.Listen.Addr != nil {
			add(cfg.Listen.Addr.Port)
		}
		if cfg.Hopping.Enabled {
			ranges, _ := cfg.Hopping.GetRanges()
			for _, r := range ranges {
				addRange(r.Min, r.Max)
			}
		}
	} else if cfg.Role == "client" {
		if cfg.Network.IPv4.Addr != nil {
			add(cfg.Network.IPv4.Addr.Port)
		}
	}

	return ports
}

func runPersist(cmd *cobra.Command, args []string) {
	if _, err := exec.LookPath("netfilter-persistent"); err == nil {
		out, err := exec.Command("netfilter-persistent", "save").CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "netfilter-persistent save failed: %v\n%s\n", err, out)
		} else {
			fmt.Println("Rules saved using netfilter-persistent")
			return
		}
	}

	// Fallback to iptables-save
	cmdSave := exec.Command("iptables-save")
	cmdSave.Stdout = os.Stdout
	if err := cmdSave.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "iptables-save failed: %v\n", err)
	} else {
		fmt.Println("Rules dumped to stdout. Please redirect to your rules file (e.g., > /etc/iptables/rules.v4)")
	}
}
