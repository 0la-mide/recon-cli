package cmd

import (
	"fmt"
	"os"

	"github.com/0la-mide/recon-cli/modules"
	"github.com/0la-mide/recon-cli/report"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "recon-cli",
	Short: "A recon automation CLI for bug bounty hunters",
	Long:  `ReconCLI — automated subdomain enum, port scan, HTTP probe, header analysis and tech detection.`,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run full recon pipeline against a target domain",
	Run:   runScan,
}

var (
	target     string
	outputFile string
	portMode   string
)

func init() {
	scanCmd.Flags().StringVarP(&target, "target", "t", "", "Target domain (required)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "report.json", "Output JSON file")
	scanCmd.Flags().StringVarP(&portMode, "ports", "p", "", "Port mode: top100 or top1000 (requires sudo)")
	scanCmd.MarkFlagRequired("target")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) {
	fmt.Printf("[*] Starting recon on %s\n", target)

	// Module 1 — Subdomain Enumeration
	subResult, err := modules.EnumerateSubdomains(target)
	if err != nil {
		fmt.Printf("[-] Subdomain enumeration failed: %v\n", err)
		return
	}

	// Module 2 — DNS Resolution
	dnsResult := modules.ResolveSubdomains(subResult.Subdomains)
	fmt.Printf("[+] Live hosts: %d\n", dnsResult.Count)

	// Module 3 — Port Scan (optional, requires sudo)
	portResult := modules.PortScanResult{Hosts: map[string][]int{}}
	if portMode != "" {
		fmt.Printf("[*] Port mode: %s (running with sudo)\n", portMode)
		portResult = modules.ScanPorts(dnsResult.LiveHosts, portMode)
	} else {
		fmt.Printf("[!] Skipping port scan (use --ports top100 or --ports top1000 with sudo)\n")
	}

	// Module 4 — HTTP Probe
	httpResult := modules.ProbeHTTP(dnsResult.LiveHosts)
	fmt.Printf("[+] HTTP hosts: %d\n", httpResult.Count)

	// Module 5 — Header Analysis
	headerResult := modules.AnalyzeHeaders(httpResult.Hosts)
	fmt.Printf("[+] Analysed headers on %d hosts\n", len(headerResult.Hosts))

	// Module 6 — Tech Detection
	techResult := modules.DetectTechnologies(httpResult.Hosts)
	fmt.Printf("[+] Tech detected on %d hosts\n", len(techResult.Hosts))

	// Write JSON report
	err = report.WriteJSON(target, subResult, dnsResult, portResult, httpResult, headerResult, techResult, outputFile)
	if err != nil {
		fmt.Printf("[-] Failed to write report: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[*] Recon complete.")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
