package virustotal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

type Source struct {
	apiKeys []string
}

func (s *Source) Name() string {
	return "virustotal"
}

func (s *Source) RequiresAPIKey() bool {
	return true
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("no virustotal api key provided")
	}
	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	subdomainSet := make(map[string]struct{})

	if err := s.fetchSubdomains(client, apiKey, domain, subdomainSet); err != nil {
		_ = err
	}

	out := make([]string, 0, len(subdomainSet))
	for d := range subdomainSet {
		out = append(out, d)
	}
	return out, nil
}

type vtSubdomainsResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

func (s *Source) fetchSubdomains(client *http.Client, apiKey, domain string, set map[string]struct{}) error {
	cursor := ""
	for page := 0; page < 5; page++ {
		u := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)
		if cursor != "" {
			u += "&cursor=" + cursor
		}

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("x-apikey", apiKey)

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("virustotal http %d", resp.StatusCode)
		}

		var result vtSubdomainsResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}

		for _, d := range result.Data {
			addSubdomain(set, d.ID, domain)
		}

		if result.Links.Next == "" {
			break
		}
		parts := strings.Split(result.Links.Next, "cursor=")
		if len(parts) < 2 {
			break
		}
		cursor = parts[1]
	}
	return nil
}

func addSubdomain(set map[string]struct{}, raw, targetDomain string) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" || !strings.Contains(raw, ".") {
		return
	}
	if raw == targetDomain || strings.HasSuffix(raw, "."+targetDomain) {
		set[raw] = struct{}{}
	}
}
