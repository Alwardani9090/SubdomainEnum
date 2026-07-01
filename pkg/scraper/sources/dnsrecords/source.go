package dnsrecords

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

var resolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

type Source struct{}

func (s *Source) Name() string         { return "dnsrecords" }
func (s *Source) RequiresAPIKey() bool { return false }

func (s *Source) Search(domain string, _ *http.Client) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	seen := make(map[string]struct{})

	for _, ns := range queryDNS(domain, dns.TypeNS) {
		addIfMatch(seen, ns, domain)
	}

	for _, mx := range queryDNS(domain, dns.TypeMX) {
		addIfMatch(seen, mx, domain)
	}

	for _, soa := range queryDNS(domain, dns.TypeSOA) {
		addIfMatch(seen, soa, domain)
	}

	for _, txt := range queryDNS(domain, dns.TypeTXT) {
		for _, hostname := range extractHostnames(txt) {
			addIfMatch(seen, hostname, domain)
		}
	}

	srvPrefixes := []string{
		"_sip._tcp", "_sip._udp", "_sips._tcp",
		"_xmpp-server._tcp", "_xmpp-client._tcp",
		"_ldap._tcp", "_kerberos._tcp", "_kerberos._udp",
		"_autodiscover._tcp", "_caldav._tcp", "_carddav._tcp",
		"_imaps._tcp", "_submission._tcp", "_pop3s._tcp",
	}
	for _, prefix := range srvPrefixes {
		fqdn := fmt.Sprintf("%s.%s", prefix, domain)
		for _, target := range queryDNS(fqdn, dns.TypeSRV) {
			addIfMatch(seen, target, domain)
		}
	}

	commonSubs := []string{
		"www", "mail", "webmail", "autodiscover", "lyncdiscover",
		"sip", "vpn", "remote", "owa", "exchange",
		"_dmarc", "selector1._domainkey", "selector2._domainkey",
	}
	for _, sub := range commonSubs {
		fqdn := fmt.Sprintf("%s.%s", sub, domain)
		for _, target := range queryDNS(fqdn, dns.TypeCNAME) {
			addIfMatch(seen, target, domain)
		}
		if aRecords := queryDNS(fqdn, dns.TypeA); len(aRecords) > 0 {
			addIfMatch(seen, fqdn, domain)
		}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
}

func queryDNS(name string, qtype uint16) []string {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	client := new(dns.Client)
	resolver := resolvers[rand.Intn(len(resolvers))]

	resp, _, err := client.Exchange(msg, resolver)
	if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
		return nil
	}

	var results []string
	for _, answer := range resp.Answer {
		switch rr := answer.(type) {
		case *dns.NS:
			results = append(results, strings.TrimSuffix(rr.Ns, "."))
		case *dns.MX:
			results = append(results, strings.TrimSuffix(rr.Mx, "."))
		case *dns.CNAME:
			results = append(results, strings.TrimSuffix(rr.Target, "."))
		case *dns.SRV:
			results = append(results, strings.TrimSuffix(rr.Target, "."))
		case *dns.SOA:
			results = append(results, strings.TrimSuffix(rr.Ns, "."))
			results = append(results, strings.TrimSuffix(rr.Mbox, "."))
		case *dns.TXT:
			results = append(results, strings.Join(rr.Txt, " "))
		case *dns.A:
			results = append(results, answer.Header().Name)
		}
	}
	return results
}

func extractHostnames(txt string) []string {
	var hosts []string
	for _, token := range strings.Fields(txt) {
		token = strings.ToLower(token)
		var host string
		switch {
		case strings.HasPrefix(token, "include:"):
			host = strings.TrimPrefix(token, "include:")
		case strings.HasPrefix(token, "redirect="):
			host = strings.TrimPrefix(token, "redirect=")
		case strings.HasPrefix(token, "a:"):
			host = strings.TrimPrefix(token, "a:")
		case strings.HasPrefix(token, "mx:"):
			host = strings.TrimPrefix(token, "mx:")
		case strings.HasPrefix(token, "ptr:"):
			host = strings.TrimPrefix(token, "ptr:")
		}
		if host != "" && strings.Contains(host, ".") {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func addIfMatch(seen map[string]struct{}, raw, target string) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.TrimSuffix(raw, ".")
	if raw == "" || !strings.Contains(raw, ".") {
		return
	}
	if raw == target || strings.HasSuffix(raw, "."+target) {
		seen[raw] = struct{}{}
	}
}
