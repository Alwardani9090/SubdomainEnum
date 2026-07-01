package whoisxmlapi

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
)

const apiURL = "https://subdomains.whoisxmlapi.com/api/v1"

type responseObj struct {
	Result struct {
		Count   int `json:"count"`
		Records []struct {
			Domain string `json:"domain"`
		} `json:"records"`
	} `json:"result"`
}

type Source struct {
	apiKeys []string
}

func New(apikeys []string) *Source {
	return &Source{
		apiKeys: apikeys,
	}
}

func (s *Source) Name() string {
	return "whoisxmlapi"
}

func (s *Source) RequiresAPIKey() bool {
	return true
}

func (s *Source) randomKey() string {
	return s.apiKeys[rand.Intn(len(s.apiKeys))]
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return []string{}, fmt.Errorf("no API keys provided for whoisxmlapi")
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	u, _ := url.Parse(apiURL)
	q := u.Query()
	q.Set("apiKey", s.randomKey())
	q.Set("domainName", domain)
	q.Set("outputFormat", "JSON")
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("api error: status=%d body=%s", resp.StatusCode, string(body))
	}

	var ro responseObj
	if err := json.Unmarshal(body, &ro); err != nil {
		return nil, err
	}

	var results []string
	seen := make(map[string]bool)
	for _, record := range ro.Result.Records {
		sub := normalizeSubdomain(record.Domain, domain)
		if sub == "" || seen[sub] {
			continue
		}
		seen[sub] = true
		results = append(results, sub)
	}

	return results, nil
}

func normalizeSubdomain(raw, targetDomain string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" || !strings.Contains(raw, ".") {
		return ""
	}
	if raw == targetDomain || strings.HasSuffix(raw, "."+targetDomain) {
		return raw
	}
	return ""
}
