package fullhunt

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Source struct {
	apiKeys []string
}

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

func (s *Source) Name() string         { return "fullhunt" }
func (s *Source) RequiresAPIKey() bool { return true }

type subdomainResponse struct {
	Hosts   []string `json:"hosts"`
	Message string   `json:"message"`
	Status  int      `json:"status"`
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("fullhunt: no API keys provided")
	}
	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	u := fmt.Sprintf("https://fullhunt.io/api/v1/domain/%s/subdomains",
		url.PathEscape(domain))

	var body []byte
	var lastErr error

	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-API-KEY", apiKey)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * 3 * time.Second)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusOK {
			body = respBody
			lastErr = nil
			break
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("fullhunt http 429: %.200s", string(respBody))
			time.Sleep(time.Duration(attempt+1) * 15 * time.Second)
			continue
		}

		return nil, fmt.Errorf("fullhunt http %d: %.200s", resp.StatusCode, string(respBody))
	}

	if lastErr != nil {
		return nil, lastErr
	}

	var result subdomainResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("fullhunt parse error: %w", err)
	}

	seen := make(map[string]struct{})
	for _, host := range result.Hosts {
		sub := normalize(host, domain)
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
