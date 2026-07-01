package github

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

type Source struct {
	apiKeys []string
}

func (s *Source) Name() string {
	return "github"
}

func (s *Source) RequiresAPIKey() bool {
	return true
}

var subdomainRegex = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)\b`)

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("no github api key provided")
	}
	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	subdomainSet := make(map[string]struct{})

	queries := []string{
		fmt.Sprintf(`"%s"`, domain),
		fmt.Sprintf(`"%s" extension:env OR extension:yaml OR extension:json OR extension:conf`, domain),
	}

	for _, q := range queries {
		items, err := s.fetchCodeSearch(client, apiKey, q)
		if err != nil {
			continue
		}
		for _, item := range items {
			content, err := s.fetchFileContent(client, apiKey, item)
			if err != nil {
				continue
			}
			extractSubdomains(content, domain, subdomainSet)
		}
	}

	out := make([]string, 0, len(subdomainSet))
	for d := range subdomainSet {
		out = append(out, d)
	}
	return out, nil
}

type githubSearchResponse struct {
	Items []struct {
		Path       string `json:"path"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		URL string `json:"url"`
	} `json:"items"`
}

func (s *Source) fetchCodeSearch(client *http.Client, apiKey, query string) ([]struct {
	Path string
	Repo string
	URL  string
}, error) {
	u, _ := url.Parse("https://api.github.com/search/code")
	q := u.Query()
	q.Set("q", query)
	q.Set("per_page", "30")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+apiKey)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github http %d", resp.StatusCode)
	}

	var result githubSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	out := make([]struct {
		Path string
		Repo string
		URL  string
	}, 0, len(result.Items))

	for _, item := range result.Items {
		out = append(out, struct {
			Path string
			Repo string
			URL  string
		}{item.Path, item.Repository.FullName, item.URL})
	}
	return out, nil
}

type githubFileResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

func (s *Source) fetchFileContent(client *http.Client, apiKey string, item struct {
	Path string
	Repo string
	URL  string
}) (string, error) {
	req, err := http.NewRequest(http.MethodGet, item.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "token "+apiKey)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github file http %d", resp.StatusCode)
	}

	var result githubFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.Encoding == "base64" {
		clean := strings.ReplaceAll(result.Content, "\n", "")
		decoded, err := decodeBase64(clean)
		if err != nil {
			return result.Content, nil
		}
		return decoded, nil
	}
	return result.Content, nil
}

func extractSubdomains(text, targetDomain string, set map[string]struct{}) {
	matches := subdomainRegex.FindAllString(text, -1)
	for _, m := range matches {
		addSubdomain(set, m, targetDomain)
	}
}

func addSubdomain(set map[string]struct{}, raw, targetDomain string) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" || !strings.Contains(raw, ".") {
		return
	}
	if raw == targetDomain || strings.HasSuffix(raw, "."+targetDomain) {
		set[raw] = struct{}{}
	}
}

func decodeBase64(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
