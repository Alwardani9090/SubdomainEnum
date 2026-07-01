package dnsdb

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	apiBase      = "https://api.dnsdb.info/dnsdb/v2"
	defaultLimit = 50000
)

type Source struct {
	apiKeys []string
}

func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

func (s *Source) Name() string         { return "dnsdb" }
func (s *Source) RequiresAPIKey() bool { return true }

func (s *Source) randomKey() string {
	return s.apiKeys[rand.Intn(len(s.apiKeys))]
}

type safRecord struct {
	Cond string `json:"cond,omitempty"`
	Msg  string `json:"msg,omitempty"`
	Obj  *struct {
		RRName string `json:"rrname"`
	} `json:"obj,omitempty"`
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	if len(s.apiKeys) == 0 {
		return nil, fmt.Errorf("dnsdb: no API keys provided")
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	u := fmt.Sprintf("%s/lookup/rrset/name/%s?limit=%d",
		apiBase, url.PathEscape("*."+domain), defaultLimit)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", s.randomKey())
	req.Header.Set("Accept", "application/x-ndjson")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dnsdb http %d", resp.StatusCode)
	}

	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var rec safRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}

		if rec.Cond == "failed" {
			return nil, fmt.Errorf("dnsdb failed: %s", rec.Msg)
		}
		if rec.Obj == nil {
			continue
		}

		sub := normalize(rec.Obj.RRName, domain)
		if sub != "" {
			seen[sub] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
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
