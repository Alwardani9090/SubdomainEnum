package wayback

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Source struct{}

func (s *Source) Name() string         { return "wayback" }
func (s *Source) RequiresAPIKey() bool { return false }

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	u := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey&limit=5000",
		url.QueryEscape(domain),
	)

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
		return nil, fmt.Errorf("wayback http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	text := strings.TrimSpace(string(body))
	if text == "" {
		return []string{}, nil
	}

	seen := make(map[string]struct{})

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err == nil {
		for i, row := range rows {
			if i == 0 || len(row) == 0 {
				continue
			}
			host := extractHost(row[0])
			sub := normalize(host, domain)
			if sub != "" {
				seen[sub] = struct{}{}
			}
		}
	} else {
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			host := extractHost(line)
			sub := normalize(host, domain)
			if sub != "" {
				seen[sub] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
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
	host := parsed.Hostname()
	return strings.ToLower(host)
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
