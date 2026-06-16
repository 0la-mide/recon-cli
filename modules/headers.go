package modules

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type HeaderAnalysisResult struct {
	Hosts []HostHeaderReport `json:"hosts"`
}

type HostHeaderReport struct {
	Subdomain      string            `json:"subdomain"`
	URL            string            `json:"url"`
	PresentHeaders map[string]string `json:"present_headers"`
	MissingHeaders []string          `json:"missing_headers"`
	MissingCount   int               `json:"missing_count"`
}

var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
	"X-XSS-Protection",
}

func AnalyzeHeaders(httpHosts []HTTPHost) HeaderAnalysisResult {
	fmt.Printf("[*] Analyzing security headers on %d hosts...\n", len(httpHosts))

	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var reports []HostHeaderReport

	sem := make(chan struct{}, 30)

	for _, h := range httpHosts {
		wg.Add(1)
		go func(host HTTPHost) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp, err := client.Get(host.URL)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			report := HostHeaderReport{
				Subdomain:      host.Subdomain,
				URL:            host.URL,
				PresentHeaders: make(map[string]string),
			}

			for _, header := range securityHeaders {
				val := resp.Header.Get(header)
				if val != "" {
					report.PresentHeaders[header] = val
				} else {
					report.MissingHeaders = append(report.MissingHeaders, header)
				}
			}

			report.MissingCount = len(report.MissingHeaders)

			mu.Lock()
			reports = append(reports, report)
			mu.Unlock()
		}(h)
	}

	wg.Wait()

	fmt.Printf("[+] Header analysis complete\n")
	return HeaderAnalysisResult{Hosts: reports}
}
