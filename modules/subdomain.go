package modules

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type SubdomainResult struct {
	Target     string   `json:"target"`
	Subdomains []string `json:"subdomains"`
	Count      int      `json:"count"`
}

func EnumerateSubdomains(target string) (SubdomainResult, error) {
	fmt.Printf("[*] Enumerating subdomains for %s...\n", target)

	cmd := exec.Command("subfinder", "-d", target, "-silent")

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return SubdomainResult{}, fmt.Errorf("subfinder error: %v — %s", err, stderr.String())
	}

	raw := strings.TrimSpace(out.String())
	if raw == "" {
		return SubdomainResult{
			Target:     target,
			Subdomains: []string{},
			Count:      0,
		}, nil
	}

	subdomains := strings.Split(raw, "\n")

	result := SubdomainResult{
		Target:     target,
		Subdomains: subdomains,
		Count:      len(subdomains),
	}

	fmt.Printf("[+] Found %d subdomains\n", result.Count)
	return result, nil
}
