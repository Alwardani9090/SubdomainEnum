package hackertarget

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Source struct{}

func (s *Source) Name() string         { return "hackertarget" }
func (s *Source) RequiresAPIKey() bool { return false }

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	u := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s",
		url.QueryEscape(domain))

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackertarget http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	text := string(body)
	if strings.Contains(text, "error") || strings.Contains(text, "API count exceeded") {
		return []string{}, nil
	}

	seen := make(map[string]struct{})
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		hostname := strings.TrimSpace(parts[0])
		sub := normalize(hostname, domain)
		if sub != "" {
			seen[sub] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
}

func normalize(raw, target string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" || !strings.Contains(raw, ".") {
		return ""
	}
	if raw == target || strings.HasSuffix(raw, "."+target) {
		return raw
	}
	return ""
}
