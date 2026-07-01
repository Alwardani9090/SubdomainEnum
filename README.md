# subdomainenum

A fast subdomain enumeration tool written in Go. It combines **passive** sources (certificate transparency, DNS aggregators, search engines, archives) with **active** techniques (DNS bruteforce and smart permutations) to build a validated list of live subdomains for a target.

```
   _____       __    ____                        _        ______
  / ___/__  __/ /_  / __ \____  ____ ___  ____ _(_)___   / ____/___  __  ______ ___
  \__ \/ / / / __ \/ / / / __ \/ __ `__ \/ __ `/ / __ \ / __/ / __ \/ / / / __ `__ \
 ___/ / /_/ / /_/ / /_/ / /_/ / / / / / / /_/ / / / / // /___ / / / / /_/ / / / / / /
/____/\__,_/_.___/_____/\____/_/ /_/ /_/\__,_/_/_/ /_/ /_____//_/ /_/\__,_/_/ /_/ /_/
```

## Features

- **Passive enumeration** from 25+ sources, run concurrently per target.
- **Active enumeration** (`-active`): DNS bruteforce with a built-in wordlist, plus a permutation engine (with optional [alterx](https://github.com/projectdiscovery/alterx) integration if it's installed on your system).
- **DNS validation**: every discovered host is resolved before being reported, with automatic **wildcard DNS detection** so you don't get flooded with false positives on wildcard-heavy domains.
- **Multi-domain input**: pass a single domain, a comma-separated list, or a file with one domain per line.
- **Pipe-friendly**: `-silent` mode prints just the subdomains, nothing else, so it drops straight into the rest of your recon pipeline.

## Install

```bash
git clone https://github.com/Alwardani9090/SubdomainEnum.git
cd subdomainenum
go build -o subdomainenum ./cmd/subdomainenum
```

Requires Go 1.22+. On first build, Go will fetch the two dependencies (`github.com/miekg/dns` and `gopkg.in/yaml.v3`) automatically — no manual steps needed as long as you have normal internet access.

## Usage

```bash
subdomainenum -d example.com
```

```bash
Usage of subdomainenum:
  -active
        Enable active enumeration (bruteforce + permutations)
  -c int
        Concurrency level for DNS probing (default 500)
  -d string
        Target domain(s) to enumerate subdomains for, comma-separated
  -dns-timeout int
        DNS timeout for validation queries (seconds) (default 3)
  -http-timeout int
        HTTP timeout for passive source requests (seconds) (default 20)
  -i string
        Input file: one domain per line
  -no-color
        Disable colored output
  -o string
        Output file for discovered subdomains
  -silent
        Silent mode: output only subdomains (for piping)
  -skip-final-validation
        Skip final DNS validation and defer resolution to a downstream dns stage
  -v    Verbose mode: show per-subdomain details and debug info
```

### Examples

```bash
# Passive only, single domain
subdomainenum -d example.com

# Passive + active (bruteforce + permutations)
subdomainenum -d example.com -active

# Multiple domains
subdomainenum -d example.com,another.com

# From a file, save output, pipe-friendly
subdomainenum -i domains.txt -o results.txt -silent

# Feed straight into httpx or another tool
subdomainenum -d example.com -silent | httpx
```

## Configuring API keys (optional)

Sources that need an API key are skipped automatically unless you configure them. Create `~/.config/subdomainenum/config.yaml` (the tool creates an empty one on first run) and add your keys:

```yaml
config:
  shodan:
    - "YOUR_SHODAN_KEY"
  virustotal:
    - "YOUR_VT_KEY"
  securitytrails:
    - "YOUR_ST_KEY"
  censys:
    - "YOUR_CENSYS_TOKEN"
```

Each source accepts a **list** of keys — if you provide more than one, the tool rotates between them to spread out rate limits.

**This file is never read from the repo and is never committed** — it lives in your home directory. `config.yaml` is also listed in `.gitignore` as an extra safety net in case a copy ever ends up inside the project folder.

### Passive sources (no key required)

crt.sh, CertSpotter, AlienVault OTX, Anubis, ThreatMiner, Google, HackerTarget, Wayback Machine, CommonCrawl, RapidDNS, DNS records (SPF/TXT parsing)

### Passive sources (API key required)

Censys, WhoisXMLAPI, SecurityTrails, PassiveTotal, Chaos (ProjectDiscovery), C99, Shodan, ZoomEye, FOFA, BinaryEdge, FullHunt, Netlas, URLScan, LeakIX, IntelX, DNSDB, VirusTotal, GitHub code search

## How it works

1. **Passive phase** — queries every enabled source concurrently for each target domain and collects raw hostnames.
2. **Active phase** *(optional, `-active`)* — generates a bruteforce wordlist and permutation candidates (common prefixes/patterns based on what was already found), resolving each candidate.
3. **Validation phase** — resolves every candidate, detects wildcard DNS (so `*.example.com` doesn't drown the real results), and outputs only confirmed, non-wildcard hosts.

## Legal / responsible use

This tool is intended for authorized security testing, bug bounty programs, and research on assets you own or have explicit permission to test. Running active enumeration against domains without authorization may violate terms of service or local law. Use responsibly.

## License

[MIT](LICENSE)
