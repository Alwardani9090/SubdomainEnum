package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

type Source struct {
	apiKeys []string
}

func (s *Source) Name() string         { return "shodan" }
func (s *Source) RequiresAPIKey() bool { return true }

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("no shodan api key provided")
	}

	apiKey := s.apiKeys[0]
	domain = strings.ToLower(strings.TrimSpace(domain))

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	subdomainSet := make(map[string]struct{})
	var allErrs []error

	dnsdbErr := s.fetchDNSDB(ctx, client, apiKey, domain, subdomainSet)
	if dnsdbErr != nil {
		allErrs = append(allErrs, fmt.Errorf("dnsdb: %w", dnsdbErr))
	}

	time.Sleep(1500 * time.Millisecond)

	searchErr := s.fetchSearchDorks(ctx, client, apiKey, domain, subdomainSet)
	if searchErr != nil {
		allErrs = append(allErrs, searchErr)
	}

	if len(subdomainSet) == 0 && len(allErrs) > 0 {
		return nil, errors.Join(allErrs...)
	}

	out := make([]string, 0, len(subdomainSet))
	for d := range subdomainSet {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

type dnsDBResponse struct {
	Domain     string      `json:"domain"`
	Subdomains []string    `json:"subdomains"`
	Data       []dnsRecord `json:"data"`
	More       bool        `json:"more"`
}

type dnsRecord struct {
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
	Value     string `json:"value"`
}

func (s *Source) fetchDNSDB(ctx context.Context, client *http.Client, apiKey, domain string, set map[string]struct{}) error {
	const maxPages = 10

	for page := 1; page <= maxPages; page++ {
		u, _ := url.Parse(fmt.Sprintf("https://api.shodan.io/dns/domain/%s", url.PathEscape(domain)))
		q := u.Query()
		q.Set("key", apiKey)
		q.Set("page", fmt.Sprintf("%d", page))
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if err != nil {
			return err
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			break
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("shodan dns/domain http %d: %.300s", resp.StatusCode, string(body))
		}

		var result dnsDBResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("shodan dns/domain parse: %w", err)
		}

		for _, sub := range result.Subdomains {
			sub = strings.ToLower(strings.TrimSpace(sub))
			if sub == "" {
				continue
			}
			fqdn := sub + "." + domain
			addSubdomain(set, fqdn, domain)
		}

		for _, rec := range result.Data {
			sub := strings.ToLower(strings.TrimSpace(rec.Subdomain))
			if sub != "" {
				fqdn := sub + "." + domain
				addSubdomain(set, fqdn, domain)
			}
			addSubdomain(set, rec.Value, domain)
		}

		if !result.More {
			break
		}

		time.Sleep(1500 * time.Millisecond)
	}

	return nil
}

func (s *Source) fetchSearchDorks(ctx context.Context, client *http.Client, apiKey, domain string, set map[string]struct{}) error {
	const maxPages = 3
	var searchErrs []error

	dorks := buildDorks(domain)
	for di, dork := range dorks {
		if di > 0 {
			time.Sleep(1500 * time.Millisecond)
		}
		for page := 1; page <= maxPages; page++ {
			res, err := s.fetchSearchPage(ctx, client, apiKey, dork, page)
			if err != nil {
				searchErrs = append(searchErrs, fmt.Errorf("%s: %w", dork, err))
				break
			}
			if len(res.Matches) == 0 {
				break
			}

			for _, m := range res.Matches {
				for _, h := range m.Hostnames {
					addSubdomain(set, h, domain)
				}
				for _, d := range m.Domains {
					addSubdomain(set, d, domain)
				}
				if m.SSL != nil && m.SSL.Cert != nil {
					if cn, ok := m.SSL.Cert.Subject["CN"].(string); ok {
						addSubdomain(set, cn, domain)
					}
					for _, san := range extractSANDNSNames(m.SSL.Cert.Extensions) {
						addSubdomain(set, san, domain)
					}
				}
				if m.HTTP != nil {
					addSubdomain(set, m.HTTP.Host, domain)
					for _, r := range m.HTTP.Redirects {
						addSubdomain(set, r.Host, domain)
					}
				}
			}

			time.Sleep(1500 * time.Millisecond)
		}
	}

	if len(searchErrs) > 0 {
		return errors.Join(searchErrs...)
	}
	return nil
}

func buildDorks(domain string) []string {
	return []string{
		fmt.Sprintf(`hostname:".%s"`, domain),
		fmt.Sprintf(`ssl.cert.subject.CN:".%s"`, domain),
		fmt.Sprintf(`ssl:".%s"`, domain),
		fmt.Sprintf(`http.host:".%s"`, domain),
	}
}

type SearchResponse struct {
	Matches []Match `json:"matches"`
}

type Match struct {
	Hostnames []string `json:"hostnames"`
	Domains   []string `json:"domains"`
	SSL       *SSL     `json:"ssl"`
	HTTP      *HTTP    `json:"http"`
}

type HTTP struct {
	Host      string     `json:"host"`
	Redirects []Redirect `json:"redirects"`
}

type Redirect struct {
	Host string `json:"host"`
}

type SSL struct {
	Cert *Cert `json:"cert"`
}

type Cert struct {
	Subject    map[string]any  `json:"subject"`
	Extensions json.RawMessage `json:"extensions"`
}

func (s *Source) fetchSearchPage(
	ctx context.Context,
	client *http.Client,
	apiKey, query string,
	page int,
) (*SearchResponse, error) {
	u, _ := url.Parse("https://api.shodan.io/shodan/host/search")
	q := u.Query()
	q.Set("key", apiKey)
	q.Set("query", query)
	q.Set("page", fmt.Sprintf("%d", page))
	q.Set("minify", "true")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return &SearchResponse{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		var e map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return nil, fmt.Errorf("shodan http %d: %v", resp.StatusCode, e)
	}

	var out SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func normalizeHostname(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")

	if net.ParseIP(s) != nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	if !strings.Contains(s, ".") {
		return ""
	}
	return s
}

func addSubdomain(set map[string]struct{}, raw, targetDomain string) {
	h := normalizeHostname(raw)
	if h == "" {
		return
	}
	if h == targetDomain || strings.HasSuffix(h, "."+targetDomain) {
		set[h] = struct{}{}
	}
}

func extractSANDNSNames(extRaw json.RawMessage) []string {
	if len(extRaw) == 0 || string(extRaw) == "null" {
		return nil
	}

	var obj map[string]any
	if err := json.Unmarshal(extRaw, &obj); err != nil {
		return nil
	}

	san, ok := obj["subjectAltName"].(map[string]any)
	if !ok {
		return nil
	}

	dns, ok := san["dns_names"].([]any)
	if !ok {
		return nil
	}

	out := make([]string, 0, len(dns))
	for _, v := range dns {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}
