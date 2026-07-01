// Package dnsclient is a minimal DNS resolution helper used by the active
// validation engine (wildcard detection, A/CNAME confirmation). It wraps
// github.com/miekg/dns with a small, dependency-free result type.
package dnsclient

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// DefaultResolvers is the pool of resolvers queries are load-balanced across.
var DefaultResolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

// Result is a normalized view of a single DNS answer.
type Result struct {
	RecordName string   // e.g. "A", "CNAME"
	DnsStatus  string   // e.g. "NOERROR"
	Values     []string // answer values (IPs for A, target names for CNAME)
}

// Query performs a single DNS lookup of the given type against resolver.
func Query(host string, timeoutSeconds int, recordType uint16, resolver string) (*Result, error) {
	if timeoutSeconds < 1 {
		timeoutSeconds = 3
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), recordType)
	msg.RecursionDesired = true

	client := &dns.Client{Timeout: time.Duration(timeoutSeconds) * time.Second}

	resp, _, err := client.Exchange(msg, resolver)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("dnsclient: empty response for %s", host)
	}

	result := &Result{
		RecordName: dns.TypeToString[recordType],
		DnsStatus:  dns.RcodeToString[resp.Rcode],
	}

	for _, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.A:
			result.Values = append(result.Values, record.A.String())
		case *dns.AAAA:
			result.Values = append(result.Values, record.AAAA.String())
		case *dns.CNAME:
			result.Values = append(result.Values, record.Target)
		}
	}

	return result, nil
}
