# ReconCLI

A fast, modular recon automation CLI for bug bounty hunters and security researchers. Written in Go.

## What it does

Takes a target domain and runs a full passive + active recon pipeline:

1. **Subdomain Enumeration** — discovers subdomains via subfinder
2. **DNS Resolution** — filters live hosts concurrently
3. **Port Scanning** — top 100/1000 ports via naabu (optional, requires sudo)
4. **HTTP Probe** — checks HTTP/HTTPS, status codes, server headers
5. **Security Header Analysis** — flags missing headers (HSTS, CSP, X-Frame-Options, etc.)
6. **Tech Detection** — fingerprints technologies from response headers (nginx, Cloudflare, Next.js, Django, WordPress, AWS, and more)

Outputs a structured JSON report you can pipe into other tools or visualize in a frontend.

## Installation

### Prerequisites

```bash
# Install Go 1.22+
brew install go

# Install subfinder and naabu
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Add Go binaries to PATH
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc
source ~/.zshrc
```

### Build

```bash
git clone https://github.com/0la-mide/recon-cli.git
cd recon-cli
go build -o recon-cli main.go
```

## Usage

```bash
# Basic scan (no port scanning)
./recon-cli scan --target example.com --output report.json

# Full scan with port scanning (requires sudo)
sudo ./recon-cli scan --target example.com --ports top100 --output report.json
sudo ./recon-cli scan --target example.com --ports top1000 --output report.json
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-t` | required | Target domain |
| `--output` | `-o` | `report.json` | Output file path |
| `--ports` | `-p` | disabled | Port mode: `top100` or `top1000` (requires sudo) |

## Output

```json
{
  "target": "example.com",
  "scan_date": "2026-06-15T14:04:20Z",
  "summary": {
    "total_subdomains": 658,
    "live_hosts": 200,
    "http_responsive": 112,
    "headers_analysed": 80,
    "tech_detected": 46
  },
  "subdomains": { ... },
  "live_hosts": { ... },
  "port_scan": { ... },
  "http_probe": { ... },
  "security_headers": { ... },
  "technologies": { ... }
}
```

## Example findings on tesla.com

