package binaryedge

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

func (s *Source) Name() string         { return "binaryedge" }
func (s *Source) RequiresAPIKey() bool { return true }

type subdomainResponse struct {
	Total    int      `json:"total"`
	Page     int      `json:"page"`
	Pagesize int      `json:"pagesize"`
	Events   []string `json:"events"`
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("binaryedge: no API keys provided")
	}
	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	seen := make(map[string]struct{})
	const maxPages = 10

	for page := 1; page <= maxPages; page++ {
		u := fmt.Sprintf("https://api.binaryedge.io/v2/query/domains/subdomain/%s?page=%d",
			url.PathEscape(domain), page)

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Key", apiKey)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("binaryedge http %d: %.200s", resp.StatusCode, string(body))
		}

		var result subdomainResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("binaryedge parse error: %w", err)
		}

		for _, sub := range result.Events {
			n := normalize(sub, domain)
			if n != "" {
				seen[n] = struct{}{}
			}
		}

		if len(result.Events) < result.Pagesize || result.Pagesize == 0 {
			break
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
