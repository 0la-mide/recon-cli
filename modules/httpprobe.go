package modules

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type HTTPResult struct {
	Hosts []HTTPHost `json:"hosts"`
	Count int        `json:"count"`
}

type HTTPHost struct {
	Subdomain  string `json:"subdomain"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Server     string `json:"server"`
	Title      string `json:"title"`
	TLS        bool   `json:"tls"`
}

func ProbeHTTP(liveHosts []LiveHost) HTTPResult {
	fmt.Printf("[*] Probing HTTP/HTTPS on %d hosts...\n", len(liveHosts))

	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var results []HTTPHost

	sem := make(chan struct{}, 30)

	for _, h := range liveHosts {
		wg.Add(1)
		go func(host LiveHost) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Try HTTPS first, then HTTP
			for _, scheme := range []string{"https", "http"} {
				url := scheme + "://" + host.Subdomain
				resp, err := client.Get(url)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				result := HTTPHost{
					Subdomain:  host.Subdomain,
					URL:        url,
					StatusCode: resp.StatusCode,
					Server:     resp.Header.Get("Server"),
					TLS:        scheme == "https",
				}

				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				break
			}
		}(h)
	}

	wg.Wait()

	httpResult := HTTPResult{
		Hosts: results,
		Count: len(results),
	}

	fmt.Printf("[+] Got HTTP responses from %d hosts\n", httpResult.Count)
	return httpResult
}
