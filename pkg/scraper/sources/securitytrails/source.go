package securitytrails

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	stAPIBase = "https://api.securitytrails.com/v1/domain"
)

type subdomainResponse struct {
	Subdomains     []string `json:"subdomains"`
	SubdomainCount int      `json:"subdomain_count"`
}

type Source struct {
	apiKeys []string
}

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

func (s *Source) Name() string {
	return "securitytrails"
}

func (s *Source) RequiresAPIKey() bool {
	return true
}

func (s *Source) randomKey() string {
	return s.apiKeys[rand.Intn(len(s.apiKeys))]
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("securitytrails: no API keys provided")
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	apiKey := s.randomKey()

	u := fmt.Sprintf("%s/%s/subdomains?children_only=false", stAPIBase, domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securitytrails http %d: %.300s", resp.StatusCode, string(body))
	}

	var result subdomainResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("securitytrails parse error: %w (body: %.200s)", err, string(body))
	}

	subdomainSet := make(map[string]struct{})
	for _, label := range result.Subdomains {
		label = strings.ToLower(strings.TrimSpace(label))
		if label == "" {
			continue
		}
		fullSub := label + "." + domain
		subdomainSet[fullSub] = struct{}{}
	}

	out := make([]string, 0, len(subdomainSet))
	for d := range subdomainSet {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}
