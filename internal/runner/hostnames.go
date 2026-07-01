package runner

import (
	"net"
	"sort"
	"strings"
	"unicode"
)

type normalizationStats struct {
	Duplicates int
	Invalid    int
}

func dedupeSubdomainCandidates(raws []string, roots []string) ([]string, normalizationStats) {
	seen := make(map[string]struct{}, len(raws))
	out := make([]string, 0, len(raws))
	stats := normalizationStats{}

	for _, raw := range raws {
		host := normalizeSubdomainCandidate(raw, roots)
		if host == "" {
			stats.Invalid++
			continue
		}
		if _, exists := seen[host]; exists {
			stats.Duplicates++
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}

	sort.Strings(out)
	return out, stats
}

type hostCollector struct {
	roots      []string
	seen       map[string]struct{}
	ordered    []string
	duplicates int
	invalid    int
}

func newHostCollector(roots []string) *hostCollector {
	normalizedRoots := append([]string(nil), roots...)
	sort.Slice(normalizedRoots, func(i, j int) bool {
		if len(normalizedRoots[i]) == len(normalizedRoots[j]) {
			return normalizedRoots[i] < normalizedRoots[j]
		}
		return len(normalizedRoots[i]) > len(normalizedRoots[j])
	})

	return &hostCollector{
		roots: normalizedRoots,
		seen:  make(map[string]struct{}),
	}
}

func (c *hostCollector) Add(raw string) string {
	host := normalizeSubdomainCandidate(raw, c.roots)
	if host == "" {
		c.invalid++
		return ""
	}
	if _, exists := c.seen[host]; exists {
		c.duplicates++
		return ""
	}
	c.seen[host] = struct{}{}
	c.ordered = append(c.ordered, host)
	return host
}

func (c *hostCollector) AddBatch(raws []string) []string {
	added := make([]string, 0, len(raws))
	for _, raw := range raws {
		if host := c.Add(raw); host != "" {
			added = append(added, host)
		}
	}
	sort.Strings(added)
	return added
}

func (c *hostCollector) List() []string {
	out := append([]string(nil), c.ordered...)
	sort.Strings(out)
	return out
}

func (c *hostCollector) Stats() normalizationStats {
	return normalizationStats{
		Duplicates: c.duplicates,
		Invalid:    c.invalid,
	}
}

func normalizeQueries(rawQueries []string) []string {
	seen := make(map[string]struct{}, len(rawQueries))
	out := make([]string, 0, len(rawQueries))

	for _, raw := range rawQueries {
		host := normalizeHostname(raw)
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}

	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) == len(out[j]) {
			return out[i] < out[j]
		}
		return len(out[i]) > len(out[j])
	})

	return out
}

func normalizeSubdomainCandidate(raw string, roots []string) string {
	host := normalizeHostname(raw)
	if host == "" {
		return ""
	}
	if len(roots) == 0 {
		return host
	}
	if matchRootDomain(host, roots) == "" {
		return ""
	}
	return host
}

func matchRootDomain(host string, roots []string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, root := range roots {
		if host == root || strings.HasSuffix(host, "."+root) {
			return root
		}
	}
	return ""
}

func normalizeHostname(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "\"'`<>")
	if raw == "" {
		return ""
	}

	raw = extractHost(raw)
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.Trim(raw, "[]")
	for strings.HasPrefix(raw, "*.") {
		raw = strings.TrimPrefix(raw, "*.")
	}
	raw = strings.TrimSuffix(raw, ".")

	if raw == "" || strings.ContainsAny(raw, " /\\") {
		return ""
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ""
	}

	labels := strings.Split(raw, ".")
	if len(labels) < 2 {
		return ""
	}

	for _, label := range labels {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}
		for _, r := range label {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
				continue
			}
			return ""
		}
	}

	return raw
}

func extractHost(raw string) string {
	candidate := strings.TrimSpace(raw)

	if idx := strings.Index(candidate, "://"); idx >= 0 {
		candidate = candidate[idx+3:]
	}
	if _, tail, ok := strings.Cut(candidate, "@"); ok {
		candidate = tail
	}
	if idx := strings.IndexAny(candidate, "/?#"); idx >= 0 {
		candidate = candidate[:idx]
	}

	if host, port, err := net.SplitHostPort(candidate); err == nil && port != "" {
		return host
	}

	if head, tail, ok := strings.Cut(candidate, ":"); ok && isNumericPort(tail) && !strings.Contains(head, ":") {
		return head
	}

	trimmed := strings.TrimSuffix(candidate, ".")
	if host, port, err := net.SplitHostPort(trimmed); err == nil && port != "" {
		return host
	}
	if head, tail, ok := strings.Cut(trimmed, ":"); ok && isNumericPort(tail) && !strings.Contains(head, ":") {
		return head
	}

	return candidate
}

func isNumericPort(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
