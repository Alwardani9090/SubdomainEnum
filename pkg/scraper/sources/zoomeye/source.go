package zoomeye

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

type Source struct {
	apiKeys []string
}

func (s *Source) Name() string {
	return "zoomeye"
}

func (s *Source) RequiresAPIKey() bool {
	return true
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("no zoomeye api key provided")
	}
	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	subdomainSet := make(map[string]struct{})

	dork := fmt.Sprintf(`hostname:"%s"`, domain)

	const maxPages = 5
	for page := 1; page <= maxPages; page++ {
		hits, err := s.fetchPage(client, apiKey, dork, page)
		if err != nil {
			return nil, err
		}
		if len(hits) == 0 {
			break
		}
		for _, d := range hits {
			addSubdomain(subdomainSet, d, domain)
		}
	}

	out := make([]string, 0, len(subdomainSet))
	for d := range subdomainSet {
		out = append(out, d)
	}
	return out, nil
}

type zoomEyeResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Total   int    `json:"total"`
	Data    []struct {
		Rdns      string   `json:"rdns"`
		Domain    string   `json:"domain"`
		SSLDomain []string `json:"ssl_domain"`
	} `json:"data"`
}

func (s *Source) fetchPage(client *http.Client, apiKey, dork string, page int) ([]string, error) {
	u, _ := url.Parse("https://api.zoomeye.ai/host/search")
	q := u.Query()
	q.Set("query", dork)
	q.Set("page", fmt.Sprintf("%d", page))
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("API-KEY", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zoomeye http %d", resp.StatusCode)
	}

	var result zoomEyeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Code != 0 && result.Code != 60000 {
		return nil, fmt.Errorf("zoomeye api error %d: %s", result.Code, result.Message)
	}

	var out []string
	for _, m := range result.Data {
		if m.Rdns != "" {
			out = append(out, m.Rdns)
		}
		if m.Domain != "" {
			out = append(out, m.Domain)
		}
		out = append(out, m.SSLDomain...)
	}
	return out, nil
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
