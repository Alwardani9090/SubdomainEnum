package intelx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func (s *Source) Name() string         { return "intelx" }
func (s *Source) RequiresAPIKey() bool { return true }

type searchRequest struct {
	Term       string `json:"term"`
	MaxResults int    `json:"maxresults"`
	Media      int    `json:"media"`
	Target     int    `json:"target"`
	Timeout    int    `json:"timeout"`
}

type searchResponse struct {
	ID     string `json:"id"`
	Status int    `json:"status"`
}

type resultResponse struct {
	Records []struct {
		Name string `json:"name"`
	} `json:"records"`
	Selectors []struct {
		SelectValue string `json:"selectorvalue"`
	} `json:"selectors"`
	Status int `json:"status"`
}

var hostnameRegex = regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)`)

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("intelx: no API keys provided")
	}
	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	baseURLs := []string{
		"https://free.intelx.io",
		"https://2.intelx.io",
	}

	for _, baseURL := range baseURLs {
		results, err := s.searchWithBase(client, baseURL, apiKey, domain)
		if err == nil {
			return results, nil
		}
		if strings.Contains(err.Error(), "401") {
			continue
		}
		return nil, err
	}

	return nil, fmt.Errorf("intelx: all endpoints returned 401")
}

func (s *Source) searchWithBase(client *http.Client, baseURL, apiKey, domain string) ([]string, error) {
	reqBody := searchRequest{
		Term:       domain,
		MaxResults: 10000,
		Media:      0,
		Target:     1,
		Timeout:    20,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	endpoints := []string{"/phonebook/search", "/intelligent/search"}
	resultEndpoints := []string{"/phonebook/search/result", "/intelligent/search/result"}

	for idx, endpoint := range endpoints {
		req, err := http.NewRequest(http.MethodPost, baseURL+endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		req.Header.Set("x-key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("intelx http %d: %.200s", resp.StatusCode, string(body))
		}

		var searchResp searchResponse
		if err := json.Unmarshal(body, &searchResp); err != nil {
			continue
		}
		if searchResp.ID == "" {
			return []string{}, nil
		}

		return s.pollResults(client, baseURL+resultEndpoints[idx], apiKey, searchResp.ID, domain)
	}

	return nil, fmt.Errorf("intelx: 401")
}

func (s *Source) pollResults(client *http.Client, resultURL, apiKey, searchID, domain string) ([]string, error) {
	seen := make(map[string]struct{})

	time.Sleep(3 * time.Second)

	for attempt := 0; attempt < 5; attempt++ {
		u := fmt.Sprintf("%s?id=%s&limit=10000", resultURL, searchID)

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("x-key", apiKey)

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
			time.Sleep(2 * time.Second)
			continue
		}

		var result resultResponse
		if err := json.Unmarshal(body, &result); err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		for _, sel := range result.Selectors {
			addSubdomain(seen, sel.SelectValue, domain)
		}

		for _, rec := range result.Records {
			matches := hostnameRegex.FindAllString(rec.Name, -1)
			for _, m := range matches {
				addSubdomain(seen, m, domain)
			}
		}

		if result.Status == 1 || result.Status == 2 {
			break
		}

		time.Sleep(2 * time.Second)
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
