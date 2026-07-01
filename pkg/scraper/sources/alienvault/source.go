package alienvault

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Source struct{}

func (s *Source) Name() string         { return "alienvault" }
func (s *Source) RequiresAPIKey() bool { return false }

type otxResponse struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
	HasNext bool `json:"has_next"`
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	seen := make(map[string]struct{})

	const maxPages = 10
	for page := 1; page <= maxPages; page++ {
		u := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns?page=%d",
			url.PathEscape(domain), page)

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			break
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			if len(seen) > 0 {
				break
			}
			return nil, fmt.Errorf("alienvault http %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			break
		}

		var result otxResponse
		if err := json.Unmarshal(body, &result); err != nil {
			break
		}

		for _, record := range result.PassiveDNS {
			sub := normalize(record.Hostname, domain)
			if sub != "" {
				seen[sub] = struct{}{}
			}
		}

		if !result.HasNext || len(result.PassiveDNS) == 0 {
			break
		}

		time.Sleep(500 * time.Millisecond)
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
