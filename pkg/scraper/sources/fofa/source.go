package fofa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	fofaAPIBase = "https://fofa.info/api/v1/search/all"
	maxPages    = 5
	pageSize    = 100
)

type searchResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Mode    string     `json:"mode"`
	Page    int        `json:"page"`
	Size    int        `json:"size"`
	Query   string     `json:"query"`
	Results [][]string `json:"results"`
}

type Source struct {
	apiKeys []string
}

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

func (s *Source) Name() string {
	return "fofa"
}

func (s *Source) RequiresAPIKey() bool {
	return true
}

func (s *Source) randomKey() string {
	return s.apiKeys[rand.Intn(len(s.apiKeys))]
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("fofa: no API keys provided")
	}

	apiKey := s.randomKey()
	if apiKey == "" {
		return nil, fmt.Errorf("fofa: empty API key")
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	subdomainSet := make(map[string]struct{})

	fofaQueries := []string{
		fmt.Sprintf(`domain="%s"`, domain),
		fmt.Sprintf(`cert="%s"`, domain),
	}

	for _, fq := range fofaQueries {
		qb64 := base64.StdEncoding.EncodeToString([]byte(fq))

		for page := 1; page <= maxPages; page++ {
			resp, err := s.fetchPage(ctx, client, apiKey, qb64, page)
			if err != nil {
				return nil, err
			}

			if resp.Error {
				return nil, fmt.Errorf("fofa api error: %s", resp.ErrMsg)
			}

			if len(resp.Results) == 0 {
				break
			}

			for _, row := range resp.Results {
				for _, cell := range row {
					host := cell
					if idx := strings.LastIndex(host, ":"); idx != -1 {
						maybePort := host[idx+1:]
						if isNumeric(maybePort) {
							host = host[:idx]
						}
					}
					addSubdomain(subdomainSet, host, domain)
				}
			}

			if len(resp.Results) < pageSize {
				break
			}

			time.Sleep(1 * time.Second)
		}
	}

	out := make([]string, 0, len(subdomainSet))
	for d := range subdomainSet {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Source) fetchPage(
	ctx context.Context,
	client *http.Client,
	apiKey, queryB64 string,
	page int,
) (*searchResponse, error) {

	u, _ := url.Parse(fofaAPIBase)
	q := u.Query()
	q.Set("key", apiKey)
	q.Set("qbase64", queryB64)
	q.Set("fields", "host,domain")
	q.Set("page", fmt.Sprintf("%d", page))
	q.Set("size", fmt.Sprintf("%d", pageSize))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("fofa http %d: %.300s", resp.StatusCode, string(body))
	}

	var result searchResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("fofa parse error: %w (body: %.200s)", err, string(body))
	}

	return &result, nil
}

func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
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
