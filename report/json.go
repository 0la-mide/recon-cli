package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/0la-mide/recon-cli/modules"
)

type Report struct {
	Target     string                       `json:"target"`
	ScanDate   string                       `json:"scan_date"`
	Subdomains modules.SubdomainResult      `json:"subdomains"`
	LiveHosts  modules.DNSResult            `json:"live_hosts"`
	Ports      modules.PortScanResult       `json:"port_scan"`
	HTTP       modules.HTTPResult           `json:"http_probe"`
	Headers    modules.HeaderAnalysisResult `json:"security_headers"`
	Tech       modules.TechDetectResult     `json:"technologies"`
	Summary    Summary                      `json:"summary"`
}

type Summary struct {
	TotalSubdomains int `json:"total_subdomains"`
	LiveHosts       int `json:"live_hosts"`
	HTTPResponsive  int `json:"http_responsive"`
	HeadersAnalysed int `json:"headers_analysed"`
	TechDetected    int `json:"tech_detected"`
}

func WriteJSON(
	target string,
	subResult modules.SubdomainResult,
	dnsResult modules.DNSResult,
	portResult modules.PortScanResult,
	httpResult modules.HTTPResult,
	headerResult modules.HeaderAnalysisResult,
	techResult modules.TechDetectResult,
	outputFile string,
) error {
	r := Report{
		Target:     target,
		ScanDate:   time.Now().UTC().Format(time.RFC3339),
		Subdomains: subResult,
		LiveHosts:  dnsResult,
		Ports:      portResult,
		HTTP:       httpResult,
		Headers:    headerResult,
		Tech:       techResult,
		Summary: Summary{
			TotalSubdomains: subResult.Count,
			LiveHosts:       dnsResult.Count,
			HTTPResponsive:  httpResult.Count,
			HeadersAnalysed: len(headerResult.Hosts),
			TechDetected:    len(techResult.Hosts),
		},
	}

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %v", err)
	}

	err = os.WriteFile(outputFile, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write report: %v", err)
	}

	fmt.Printf("[+] Report saved to %s\n", outputFile)
	return nil
}
