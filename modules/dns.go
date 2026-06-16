package modules

import (
	"fmt"
	"net"
	"sync"
)

type DNSResult struct {
	LiveHosts []LiveHost `json:"live_hosts"`
	Count     int        `json:"count"`
}

type LiveHost struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
}

func ResolveSubdomains(subdomains []string) DNSResult {
	fmt.Printf("[*] Resolving %d subdomains...\n", len(subdomains))

	var mu sync.Mutex
	var wg sync.WaitGroup
	var liveHosts []LiveHost

	sem := make(chan struct{}, 50) // 50 concurrent goroutines

	for _, sub := range subdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ips, err := net.LookupHost(subdomain)
			if err != nil {
				return
			}

			mu.Lock()
			liveHosts = append(liveHosts, LiveHost{
				Subdomain: subdomain,
				IPs:       ips,
			})
			mu.Unlock()
		}(sub)
	}

	wg.Wait()

	result := DNSResult{
		LiveHosts: liveHosts,
		Count:     len(liveHosts),
	}

	fmt.Printf("[+] Resolved %d live hosts\n", result.Count)
	return result
}
