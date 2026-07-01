package leakix

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

func (s *Source) Name() string         { return "leakix" }
func (s *Source) RequiresAPIKey() bool { return true }

type leakixResult struct {
	Host     string `json:"host"`
	Hostname string `json:"hostname"`
	SSL      struct {
		Certificate struct {
			CNNames  []string `json:"cn_names"`
			AltNames []string `json:"alt_names"`
		} `json:"certificate"`
	} `json:"ssl"`
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("leakix: no API keys provided")
	}
	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	seen := make(map[string]struct{})

	queries := []string{
		fmt.Sprintf(`+hostname:"%s"`, domain),
		fmt.Sprintf(`+ssl.certificate.cn_names:"%s"`, domain),
	}

	for _, q := range queries {
		u := fmt.Sprintf("https://leakix.net/search?scope=service&q=%s",
			url.QueryEscape(q))

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("api-key", apiKey)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var results []leakixResult
		if err := json.Unmarshal(body, &results); err != nil {
			continue
		}

		for _, r := range results {
			addSubdomain(seen, r.Host, domain)
			addSubdomain(seen, r.Hostname, domain)
			for _, cn := range r.SSL.Certificate.CNNames {
				addSubdomain(seen, cn, domain)
			}
			for _, alt := range r.SSL.Certificate.AltNames {
				addSubdomain(seen, alt, domain)
			}
		}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
}

func addSubdomain(set map[string]struct{}, raw, target string) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" || !strings.Contains(raw, ".") {
		return
	}
	if raw == target || strings.HasSuffix(raw, "."+target) {
		set[raw] = struct{}{}
	}
}
