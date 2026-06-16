package modules

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type TechDetectResult struct {
	Hosts []HostTechReport `json:"hosts"`
}

type HostTechReport struct {
	Subdomain    string   `json:"subdomain"`
	URL          string   `json:"url"`
	Technologies []string `json:"technologies"`
}

var techSignatures = map[string][]string{
	"nginx":         {"Server:nginx"},
	"apache":        {"Server:Apache"},
	"cloudflare":    {"Server:cloudflare", "CF-RAY:"},
	"akamai":        {"Server:AkamaiGHost", "X-Check-Cacheable:"},
	"varnish":       {"X-Varnish:", "Via:varnish"},
	"aws":           {"Server:AmazonS3", "X-Amz-Request-Id:"},
	"fastly":        {"X-Served-By:", "Fastly-Debug-Digest:"},
	"wordpress":     {"X-Powered-By:W3 Total Cache", "link:wp-json"},
	"laravel":       {"Set-Cookie:laravel_session"},
	"php":           {"X-Powered-By:PHP"},
	"asp.net":       {"X-Powered-By:ASP.NET", "X-AspNet-Version:"},
	"django":        {"Set-Cookie:csrftoken"},
	"ruby on rails": {"X-Powered-By:Phusion Passenger"},
	"express":       {"X-Powered-By:Express"},
	"next.js":       {"X-Powered-By:Next.js"},
	"shopify":       {"X-ShopId:", "X-ShardId:"},
	"vercel":        {"X-Vercel-Id:"},
	"netlify":       {"X-Nf-Request-Id:"},
	"github pages":  {"Server:GitHub.com"},
	"iis":           {"Server:Microsoft-IIS"},
	"tomcat":        {"Server:Apache-Coyote"},
}

func DetectTechnologies(httpHosts []HTTPHost) TechDetectResult {
	fmt.Printf("[*] Detecting technologies on %d hosts...\n", len(httpHosts))

	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var reports []HostTechReport

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

			// Read a chunk of body for body-based signatures
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			body := string(bodyBytes)

			var detected []string

			for tech, signatures := range techSignatures {
				for _, sig := range signatures {
					parts := strings.SplitN(sig, ":", 2)
					if len(parts) == 2 {
						headerVal := resp.Header.Get(parts[0])
						if parts[1] == "" || strings.Contains(strings.ToLower(headerVal), strings.ToLower(parts[1])) {
							if headerVal != "" {
								detected = append(detected, tech)
								break
							}
						}
					} else {
						if strings.Contains(body, sig) {
							detected = append(detected, tech)
							break
						}
					}
				}
			}

			if len(detected) > 0 {
				mu.Lock()
				reports = append(reports, HostTechReport{
					Subdomain:    host.Subdomain,
					URL:          host.URL,
					Technologies: detected,
				})
				mu.Unlock()
			}
		}(h)
	}

	wg.Wait()

	fmt.Printf("[+] Detected technologies on %d hosts\n", len(reports))
	return TechDetectResult{Hosts: reports}
}
