package permutation

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	MaxInputSubdomains = 500

	MaxCandidates = 500000

	MaxPrefixParts = 4
)

var (
	wordlist = []string{
		"dev", "staging", "stage", "test", "qa", "uat", "prod", "production",
		"api", "app", "web", "admin", "portal", "dashboard", "panel",
		"internal", "external", "private", "public", "corp", "secure",
		"new", "old", "v1", "v2", "v3", "beta", "alpha", "canary", "preview",
		"backup", "bak", "dr", "mirror", "edge", "origin", "cdn",
		"mail", "smtp", "imap", "pop", "mx", "ns", "dns",
		"vpn", "remote", "proxy", "gateway", "lb", "cache",
		"db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
		"auth", "login", "sso", "id", "account", "accounts",
		"ci", "cd", "jenkins", "git", "gitlab", "jira", "wiki", "docs",
		"grafana", "monitor", "metrics", "logs", "status",
		"demo", "sandbox", "lab", "data", "analytics", "search",
		"shop", "store", "pay", "billing", "crm",
		"k8s", "docker", "cloud", "aws", "gcp", "azure",
		"us", "eu", "ap", "east", "west", "central",
		"primary", "secondary", "replica",
	}

	numRegex = regexp.MustCompile(`\d+`)
)

func Generate(subdomains []string, domain string) []string {
	type entry struct {
		sub    string
		prefix string
	}
	var entries []entry
	for _, sub := range subdomains {
		if sub == domain {
			continue
		}
		prefix := extractPrefix(sub, domain)
		if prefix == "" {
			continue
		}
		entries = append(entries, entry{sub, prefix})
	}
	sort.Slice(entries, func(i, j int) bool {
		return len(entries[i].prefix) < len(entries[j].prefix)
	})
	if len(entries) > MaxInputSubdomains {
		entries = entries[:MaxInputSubdomains]
	}

	seen := make(map[string]struct{})

	for _, e := range entries {
		if len(seen) >= MaxCandidates {
			break
		}

		prefix := e.prefix
		parts := splitLabels(prefix)

		if len(parts) <= MaxPrefixParts {
			for _, w := range wordlist {
				addCandidate(seen, w+"-"+prefix, domain)
				addCandidate(seen, prefix+"-"+w, domain)
				addCandidate(seen, w+"."+prefix, domain)
				for i, p := range parts {
					if p != w {
						replaced := make([]string, len(parts))
						copy(replaced, parts)
						replaced[i] = w
						addCandidate(seen, joinLabels(replaced), domain)
					}
				}
				if len(seen) >= MaxCandidates {
					break
				}
			}
		}

		locs := numRegex.FindAllStringIndex(prefix, -1)
		for _, loc := range locs {
			numStr := prefix[loc[0]:loc[1]]
			n, err := strconv.Atoi(numStr)
			if err != nil {
				continue
			}
			for _, delta := range []int{-1, 1, -2, 2, 10, -10} {
				newNum := n + delta
				if newNum < 0 {
					continue
				}
				candidate := prefix[:loc[0]] + strconv.Itoa(newNum) + prefix[loc[1]:]
				addCandidate(seen, candidate, domain)
			}
			width := len(numStr)
			for _, delta := range []int{-1, 1} {
				newNum := n + delta
				if newNum < 0 {
					continue
				}
				padded := fmt.Sprintf("%0*d", width, newNum)
				candidate := prefix[:loc[0]] + padded + prefix[loc[1]:]
				addCandidate(seen, candidate, domain)
			}
		}

		if strings.Contains(prefix, "-") {
			addCandidate(seen, strings.ReplaceAll(prefix, "-", ""), domain)
			addCandidate(seen, strings.ReplaceAll(prefix, "-", "."), domain)
		}
		if strings.Contains(prefix, ".") {
			addCandidate(seen, strings.ReplaceAll(prefix, ".", "-"), domain)
		}

		addCandidate(seen, prefix+"1", domain)
		addCandidate(seen, prefix+"2", domain)
		addCandidate(seen, prefix+"s", domain)
		addCandidate(seen, "m."+prefix, domain)
		addCandidate(seen, "www."+prefix, domain)
	}

	knownSet := make(map[string]struct{}, len(subdomains))
	for _, s := range subdomains {
		knownSet[s] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for candidate := range seen {
		if _, known := knownSet[candidate]; !known {
			out = append(out, candidate)
		}
	}
	return out
}

func extractPrefix(sub, domain string) string {
	suffix := "." + domain
	if !strings.HasSuffix(sub, suffix) {
		return ""
	}
	return strings.TrimSuffix(sub, suffix)
}

func splitLabels(prefix string) []string {
	var parts []string
	for _, label := range strings.Split(prefix, ".") {
		parts = append(parts, strings.Split(label, "-")...)
	}
	return parts
}

func joinLabels(parts []string) string {
	return strings.Join(parts, "-")
}

func addCandidate(seen map[string]struct{}, prefix, domain string) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	prefix = strings.Trim(prefix, "-.")
	if prefix == "" {
		return
	}
	fqdn := prefix + "." + domain
	seen[fqdn] = struct{}{}
}
