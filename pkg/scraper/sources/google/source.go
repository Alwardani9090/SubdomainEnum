package google

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Source struct{}

func (s *Source) Name() string         { return "google" }
func (s *Source) RequiresAPIKey() bool { return false }

var hostnameRegex = regexp.MustCompile(`(?i)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)`)

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	seen := make(map[string]struct{})

	dorks := []string{
		fmt.Sprintf("site:%s", domain),
		fmt.Sprintf("site:%s -www", domain),
		fmt.Sprintf("site:*.%s", domain),
	}

	for _, dork := range dorks {
		for start := 0; start < 50; start += 10 {
			u := fmt.Sprintf("https://www.google.com/search?q=%s&num=100&start=%d",
				url.QueryEscape(dork), start)

			req, err := http.NewRequest(http.MethodGet, u, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
				break
			}

			if resp.StatusCode != http.StatusOK {
				continue
			}

			html := string(body)
			matches := hostnameRegex.FindAllString(html, -1)
			for _, m := range matches {
				addSubdomain(seen, m, domain)
			}

			if !strings.Contains(html, "Next") && !strings.Contains(html, "navend") {
				break
			}

			time.Sleep(3 * time.Second)
		}
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
