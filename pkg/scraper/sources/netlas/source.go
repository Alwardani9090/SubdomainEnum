package netlas

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

func (s *Source) Name() string         { return "netlas" }
func (s *Source) RequiresAPIKey() bool { return true }

type netlasResponse struct {
	Items []struct {
		Data struct {
			Domain string `json:"domain"`
			Host   string `json:"host"`
		} `json:"data"`
	} `json:"items"`
	Count int `json:"count"`
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("netlas: no API keys provided")
	}
	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	seen := make(map[string]struct{})
	const maxPages = 5

	for page := 0; page < maxPages; page++ {
		query := fmt.Sprintf("domain:*.%s", domain)
		u := fmt.Sprintf("https://app.netlas.io/api/domains/?q=%s&start=%d&fields=domain,host",
			url.QueryEscape(query), page*20)

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-API-Key", apiKey)
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
			return nil, fmt.Errorf("netlas http %d: %.200s", resp.StatusCode, string(body))
		}

		var result netlasResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("netlas parse error: %w", err)
		}

		for _, item := range result.Items {
			for _, hostname := range []string{item.Data.Domain, item.Data.Host} {
				sub := normalize(hostname, domain)
				if sub != "" {
					seen[sub] = struct{}{}
				}
			}
		}

		if len(result.Items) < 20 {
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
