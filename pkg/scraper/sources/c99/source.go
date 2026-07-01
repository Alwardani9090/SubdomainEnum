package c99

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Source struct {
	apiKeys []string
}

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

func (s *Source) Name() string         { return "c99" }
func (s *Source) RequiresAPIKey() bool { return true }

type c99Response struct {
	Success    bool `json:"success"`
	Subdomains []struct {
		Subdomain string `json:"subdomain"`
		IP        string `json:"ip"`
	} `json:"subdomains"`
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("c99: no API keys provided")
	}
	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	u := fmt.Sprintf("https://api.c99.nl/subdomainfinder?key=%s&domain=%s&json",
		url.QueryEscape(apiKey), url.QueryEscape(domain))

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
		return nil, fmt.Errorf("c99 http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result c99Response
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("c99 parse error: %w", err)
	}

	if !result.Success {
		return []string{}, nil
	}

	seen := make(map[string]struct{})
	for _, entry := range result.Subdomains {
		sub := normalize(entry.Subdomain, domain)
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
