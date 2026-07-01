package certspotter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Source struct{}

func (s *Source) Name() string         { return "certspotter" }
func (s *Source) RequiresAPIKey() bool { return false }

type issuance struct {
	DNSNames []string `json:"dns_names"`
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	u := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names",
		url.QueryEscape(domain))

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certspotter http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var issuances []issuance
	if err := json.Unmarshal(body, &issuances); err != nil {
		return nil, fmt.Errorf("certspotter parse error: %w", err)
	}

	seen := make(map[string]struct{})
	for _, iss := range issuances {
		for _, name := range iss.DNSNames {
			sub := normalize(name, domain)
			if sub == "" {
				continue
			}
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
