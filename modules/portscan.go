package modules

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type PortScanResult struct {
	Hosts map[string][]int `json:"hosts"`
	Total int              `json:"total_open_ports"`
}

func ScanPorts(liveHosts []LiveHost, portMode string) PortScanResult {
	fmt.Printf("[*] Scanning ports on %d live hosts...\n", len(liveHosts))

	// Write IPs to a temp file
	tmpFile, err := os.CreateTemp("", "recon-targets-*.txt")
	if err != nil {
		fmt.Printf("[-] Failed to create temp file: %v\n", err)
		return PortScanResult{Hosts: map[string][]int{}}
	}
	defer os.Remove(tmpFile.Name())

	// Map IP -> subdomain so we can label results properly
	ipToHost := make(map[string]string)
	seen := make(map[string]bool)

	for _, h := range liveHosts {
		for _, ip := range h.IPs {
			if !seen[ip] {
				tmpFile.WriteString(ip + "\n")
				ipToHost[ip] = h.Subdomain
				seen[ip] = true
			}
		}
	}
	tmpFile.Close()

	// Pick port range
	var portFlag string
	switch portMode {
	case "top1000":
		portFlag = "--top-ports=1000"
	default:
		portFlag = "--top-ports=100"
	}

	cmd := exec.Command("sudo", "naabu", portFlag, "-silent", "-list", tmpFile.Name())

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		fmt.Printf("[-] naabu error: %v\n", stderr.String())
		return PortScanResult{Hosts: map[string][]int{}}
	}

	result := PortScanResult{
		Hosts: make(map[string][]int),
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		ip := parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		// Label by subdomain if we can, otherwise use IP
		label := ip
		if host, ok := ipToHost[ip]; ok {
			label = host
		}
		result.Hosts[label] = append(result.Hosts[label], port)
		result.Total++
	}

	fmt.Printf("[+] Found %d open ports across %d hosts\n", result.Total, len(result.Hosts))
	return result
}
