package censys

import (
	"bytes"
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
	platformAPIBase = "https://api.platform.censys.io/v3/global/search/query"
	legacyAPIBase   = "https://search.censys.io/api/v2/certificates/search"
	maxPages        = 5
	pageSize        = 100
)

type Source struct {
	apiKeys []string
}

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

func (s *Source) Name() string { return "censys" }

func (s *Source) RequiresAPIKey() bool { return true }

func (s *Source) randomKey() string {
	return s.apiKeys[rand.Intn(len(s.apiKeys))]
}

type platformRequest struct {
	Query    string `json:"query"`
	PageSize int    `json:"page_size"`
	Cursor   string `json:"cursor,omitempty"`
}

type platformResponse struct {
	Result struct {
		Documents  []platformDoc `json:"documents"`
		NextCursor string        `json:"next_cursor"`
	} `json:"result"`
	Code   int    `json:"code"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

type platformDoc struct {
	Cert struct {
		Parsed struct {
			Names   []string `json:"names"`
			Subject struct {
				CommonName string `json:"common_name"`
			} `json:"subject"`
		} `json:"parsed"`
	} `json:"cert"`
}

type legacyResponse struct {
	Result struct {
		Hits  []legacyHit `json:"hits"`
		Links struct {
			Next string `json:"next"`
		} `json:"links"`
	} `json:"result"`
}

type legacyHit struct {
	ParsedNames []string `json:"parsed.names"`
	Names       []string `json:"names"`
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("censys: no API keys provided")
	}
	apiKey := s.randomKey()
	if apiKey == "" {
		return nil, fmt.Errorf("censys: empty API key")
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if strings.Contains(apiKey, "|") {
		parts := strings.SplitN(apiKey, "|", 2)
		return s.searchPlatform(ctx, client, parts[0], parts[1], domain)
	}
	if strings.Contains(apiKey, ":") {
		return s.searchLegacy(ctx, client, apiKey, domain)
	}
	return s.searchPlatform(ctx, client, "", apiKey, domain)
}

func (s *Source) searchPlatform(ctx context.Context, client *http.Client, orgID, token, domain string) ([]string, error) {
	subdomainSet := make(map[string]struct{})
	cursor := ""

	for page := 1; page <= maxPages; page++ {
		reqBody := platformRequest{
			Query:    "cert.parsed.names: " + domain,
			PageSize: pageSize,
			Cursor:   cursor,
		}
		bodyBytes, _ := json.Marshal(reqBody)

		url := platformAPIBase
		if orgID != "" {
			url += "?organization_id=" + orgID
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", token)
		req.Header.Set("Content-Type", "application/json")
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
			return nil, fmt.Errorf("censys http %d: %.300s", resp.StatusCode, string(body))
		}

		var result platformResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("censys parse error: %w (body: %.200s)", err, string(body))
		}
		if len(result.Result.Documents) == 0 {
			break
		}
		for _, doc := range result.Result.Documents {
			for _, name := range doc.Cert.Parsed.Names {
				addSubdomain(subdomainSet, name, domain)
			}
			if cn := doc.Cert.Parsed.Subject.CommonName; cn != "" {
				addSubdomain(subdomainSet, cn, domain)
			}
		}
		cursor = result.Result.NextCursor
		if cursor == "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	return sortedSlice(subdomainSet), nil
}

func (s *Source) searchLegacy(ctx context.Context, client *http.Client, apiKey, domain string) ([]string, error) {
	subdomainSet := make(map[string]struct{})
	cursor := ""

	for page := 1; page <= maxPages; page++ {
		u := fmt.Sprintf("%s?q=parsed.names%%3A+%s&per_page=%d", legacyAPIBase, domain, pageSize)
		if cursor != "" {
			u += "&cursor=" + cursor
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		if parts := strings.SplitN(apiKey, ":", 2); len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		} else {
			req.SetBasicAuth(apiKey, "")
		}
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
			return nil, fmt.Errorf("censys http %d: %.300s", resp.StatusCode, string(body))
		}

		var result legacyResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("censys parse error: %w (body: %.200s)", err, string(body))
		}
		if len(result.Result.Hits) == 0 {
			break
		}
		for _, h := range result.Result.Hits {
			names := h.ParsedNames
			if len(names) == 0 {
				names = h.Names
			}
			for _, name := range names {
				addSubdomain(subdomainSet, name, domain)
			}
		}
		cursor = result.Result.Links.Next
		if cursor == "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	return sortedSlice(subdomainSet), nil
}

func addSubdomain(set map[string]struct{}, raw, targetDomain string) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || !strings.Contains(s, ".") {
		return
	}
	if s == targetDomain || strings.HasSuffix(s, "."+targetDomain) {
		set[s] = struct{}{}
	}
}

func sortedSlice(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
