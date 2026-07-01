package commoncrawl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Source struct{}

func (s *Source) Name() string         { return "commoncrawl" }
func (s *Source) RequiresAPIKey() bool { return false }

type indexInfo struct {
	ID     string `json:"id"`
	CDXAPI string `json:"cdx-api"`
}

type cdxRecord struct {
	URL string `json:"url"`
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	cdxAPI, err := getLatestIndex(client)
	if err != nil {
		return nil, fmt.Errorf("commoncrawl index discovery: %w", err)
	}

	u := fmt.Sprintf("%s?url=*.%s&output=json&fl=url&limit=5000",
		cdxAPI, url.QueryEscape(domain))

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("commoncrawl http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec cdxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		host := extractHost(rec.URL)
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

func getLatestIndex(client *http.Client) (string, error) {
	resp, err := client.Get("https://index.commoncrawl.org/collinfo.json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var indexes []indexInfo
	if err := json.Unmarshal(body, &indexes); err != nil {
		return "", err
	}
	if len(indexes) == 0 {
		return "", fmt.Errorf("no indexes found")
	}

	return indexes[0].CDXAPI, nil
}

func extractHost(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
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
