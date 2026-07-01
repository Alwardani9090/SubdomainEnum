package crtsh

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Source struct{}

const (
	maxAttempts       = 3
	retryDelay        = 1500 * time.Millisecond
	maxErrorBodyBytes = 200
)

type response struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

type temporaryHTTPError struct {
	statusCode int
	body       string
}

func (e *temporaryHTTPError) Error() string {
	return fmt.Sprintf("crtsh http %d: %s", e.statusCode, e.body)
}

func (s *Source) Name() string {
	return "crtsh"
}

func (s *Source) RequiresAPIKey() bool {
	return false
}

func (s *Source) Search(domain string, client *http.Client) ([]string, error) {
	results := []string{}
	domain = strings.ToLower(strings.TrimSpace(domain))

	fmtURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", url.QueryEscape(domain))

	body, err := fetchBodyWithRetry(client, fmtURL)
	if err != nil {
		var tempErr *temporaryHTTPError
		if errors.As(err, &tempErr) {
			return []string{}, nil
		}
		return []string{}, err
	}

	var r []*response
	if err := json.Unmarshal(body, &r); err != nil {
		return []string{}, fmt.Errorf("crtsh parse error: %w (body: %s)", err, string(body[:min(len(body), maxErrorBodyBytes)]))
	}

	seen := map[string]bool{}
	for _, entry := range r {
		for _, candidate := range extractCandidates(entry) {
			sub := normalizeSubdomain(candidate, domain)
			if sub == "" || seen[sub] {
				continue
			}
			seen[sub] = true
			results = append(results, sub)
		}
	}

	return results, nil
}

func fetchBodyWithRetry(client *http.Client, requestURL string) ([]byte, error) {
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		body, err := fetchBody(client, requestURL)
		if err == nil {
			return body, nil
		}

		lastErr = err
		if !isRetryable(err) || attempt == maxAttempts {
			break
		}

		time.Sleep(time.Duration(attempt) * retryDelay)
	}

	return nil, lastErr
}

func fetchBody(client *http.Client, requestURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "subenum/1.0 (+https://crt.sh)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("crtsh http %d: %s", resp.StatusCode, string(body[:min(len(body), maxErrorBodyBytes)]))
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
			return nil, &temporaryHTTPError{
				statusCode: resp.StatusCode,
				body:       string(body[:min(len(body), maxErrorBodyBytes)]),
			}
		}
		return nil, err
	}

	return body, nil
}

func isRetryable(err error) bool {
	var tempErr *temporaryHTTPError
	return errors.As(err, &tempErr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func extractCandidates(entry *response) []string {
	candidates := []string{entry.CommonName}
	if entry.NameValue != "" {
		candidates = append(candidates, strings.Split(entry.NameValue, "\n")...)
	}
	return candidates
}

func normalizeSubdomain(raw, targetDomain string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ToLower(raw)
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.TrimSuffix(raw, ".")

	if raw == "" || !strings.Contains(raw, ".") {
		return ""
	}

	if raw == targetDomain || strings.HasSuffix(raw, "."+targetDomain) {
		return raw
	}

	return ""
}
