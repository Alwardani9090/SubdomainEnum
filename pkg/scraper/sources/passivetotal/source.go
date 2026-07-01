package passivetotal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Source struct {
	apiKeys []string
}

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

func (s *Source) Name() string         { return "passivetotal" }
func (s *Source) RequiresAPIKey() bool { return true }

type subdomainResponse struct {
	Subdomains []string `json:"subdomains"`
	QueryValue string   `json:"queryValue"`
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("passivetotal: no API keys provided")
	}
	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	parts := strings.SplitN(apiKey, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("passivetotal: key must be email:apikey format")
	}
	email, key := parts[0], parts[1]

	u := "https://api.riskiq.net/pt/v2/enrichment/subdomains?query=" + domain

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(email, key)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("passivetotal http %d: %.200s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result subdomainResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("passivetotal parse error: %w", err)
	}

	seen := make(map[string]struct{})
	for _, label := range result.Subdomains {
		label = strings.ToLower(strings.TrimSpace(label))
		if label == "" {
			continue
		}
		fullSub := label + "." + domain
		seen[fullSub] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
}
