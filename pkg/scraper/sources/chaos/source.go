package chaos

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Source struct {
	apiKeys []string
}

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

func (s *Source) Name() string         { return "chaos" }
func (s *Source) RequiresAPIKey() bool { return true }

type chaosResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Count      int      `json:"count"`
}

var validLabelRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$`)

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("chaos: no API keys provided")
	}
	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	u := fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s/subdomains",
		url.PathEscape(domain))

	var body []byte
	var lastErr error

	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", apiKey)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
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

		lastErr = fmt.Errorf("chaos http %d: %.200s", resp.StatusCode, string(respBody))

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusUnauthorized {
			time.Sleep(time.Duration(attempt+1) * 3 * time.Second)
			continue
		}

		return nil, lastErr
	}

	if lastErr != nil {
		return nil, lastErr
	}

	var result chaosResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("chaos parse error: %w", err)
	}

	seen := make(map[string]struct{})
	for _, label := range result.Subdomains {
		label = strings.ToLower(strings.TrimSpace(label))
		if label == "" {
			continue
		}
		parts := strings.Split(label, ".")
		clean := true
		for _, p := range parts {
			if !validLabelRegex.MatchString(p) {
				clean = false
				break
			}
		}
		if !clean {
			continue
		}
		var fullSub string
		if label == domain || strings.HasSuffix(label, "."+domain) {
			fullSub = label
		} else {
			fullSub = label + "." + domain
		}
		seen[fullSub] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
}
