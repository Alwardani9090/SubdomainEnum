package runner

import (
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	dnsclient "github.com/Alwardani9090/SubdomainEnum/internal/dnsclient"
	"github.com/miekg/dns"
)

const (
	maxDNSConcurrency = 500

	wildcardProbeCount = 5

	wildcardThreshold = 5

	defaultDNSTimeout = 3
)

var (
	dnsQuery    = dnsclient.Query
	randomLabel = generateRandomLabel
)

type wildcardBaseline struct {
	detected bool
	ips      map[string]struct{}
}

type dnsProbeData struct {
	resolved    bool
	ips         map[string]struct{}
	fingerprint string
	signatures  map[string]struct{}
}

type ipTracker struct {
	mu        sync.Mutex
	counts    map[string]int
	fpToHosts map[string][]string
}

func newIPTracker() *ipTracker {
	return &ipTracker{
		counts:    make(map[string]int),
		fpToHosts: make(map[string][]string),
	}
}

func (t *ipTracker) add(fingerprint, host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.counts[fingerprint]++
	t.fpToHosts[fingerprint] = append(t.fpToHosts[fingerprint], host)
}

func (t *ipTracker) overThreshold() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for fp, cnt := range t.counts {
		if cnt >= wildcardThreshold {
			out = append(out, fp)
		}
	}
	return out
}

func (t *ipTracker) anyHostForFP(fp string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if hosts := t.fpToHosts[fp]; len(hosts) > 0 {
		return hosts[0]
	}
	return ""
}

type validationEngine struct {
	roots       []string
	dnsTimeout  int
	concurrency int
	resolverSeq uint64

	wildcardMu sync.Mutex

	wildcards map[string]wildcardBaseline
}

type dnsValidationReport struct {
	Hosts           []string
	Skipped         bool
	UnresolvedCount int
	WildcardCount   int
}

func newValidationEngine(roots []string, concurrency, dnsTimeout int) *validationEngine {
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > maxDNSConcurrency {
		concurrency = maxDNSConcurrency
	}
	if dnsTimeout < 1 {
		dnsTimeout = defaultDNSTimeout
	}

	sortedRoots := append([]string(nil), roots...)
	sort.Slice(sortedRoots, func(i, j int) bool {
		if len(sortedRoots[i]) == len(sortedRoots[j]) {
			return sortedRoots[i] < sortedRoots[j]
		}
		return len(sortedRoots[i]) > len(sortedRoots[j])
	})

	return &validationEngine{
		roots:       sortedRoots,
		dnsTimeout:  dnsTimeout,
		concurrency: concurrency,
		wildcards:   make(map[string]wildcardBaseline),
	}
}

func (e *validationEngine) validateDNS(hosts []string) dnsValidationReport {
	if len(hosts) == 0 {
		return dnsValidationReport{}
	}

	type outcome struct {
		host        string
		resolved    bool
		wildcard    bool
		fingerprint string
	}

	jobs := make(chan string)
	results := make(chan outcome, len(hosts))
	tracker := newIPTracker()

	var wg sync.WaitGroup
	for i := 0; i < e.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				probe := e.probeDNS(host)
				if !probe.resolved {
					results <- outcome{host: host}
					continue
				}

				root := matchRootDomain(host, e.roots)
				if root != "" && host != root {
					if e.isWildcardHit(host, root, probe) {
						results <- outcome{host: host, wildcard: true}
						continue
					}
				}

				tracker.add(probe.fingerprint, host)

				results <- outcome{
					host:        host,
					resolved:    true,
					fingerprint: probe.fingerprint,
				}
			}
		}()
	}

	go func() {
		for _, host := range hosts {
			jobs <- host
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	type passOne struct {
		host        string
		resolved    bool
		wildcard    bool
		fingerprint string
	}
	var pass1 []passOne
	for r := range results {
		pass1 = append(pass1, passOne(r))
	}

	wildcardFPs := make(map[string]bool)
	for _, fp := range tracker.overThreshold() {
		if _, decided := wildcardFPs[fp]; decided {
			continue
		}
		root := e.rootForAnyHost(tracker.anyHostForFP(fp))
		confirmHost := randomLabel() + "." + root
		probe := e.probeDNS(confirmHost)
		wildcardFPs[fp] = probe.resolved && probe.fingerprint == fp
	}

	report := dnsValidationReport{
		Hosts: make([]string, 0, len(hosts)),
	}
	for _, r := range pass1 {
		switch {
		case r.wildcard:
			report.WildcardCount++
		case !r.resolved:
			report.UnresolvedCount++
		default:
			if isWild, checked := wildcardFPs[r.fingerprint]; checked && isWild {
				report.WildcardCount++
			} else {
				report.Hosts = append(report.Hosts, r.host)
			}
		}
	}

	sort.Strings(report.Hosts)
	return report
}

func (e *validationEngine) rootForAnyHost(host string) string {
	if root := matchRootDomain(host, e.roots); root != "" {
		return root
	}
	if len(e.roots) > 0 {
		return e.roots[0]
	}
	return "invalid"
}

func (e *validationEngine) isWildcardHit(host, root string, probe dnsProbeData) bool {
	for _, level := range wildcardLevels(host, root) {
		baseline := e.getWildcardBaseline(level)
		if baseline.detected && probeMatchesBaseline(probe, baseline) {
			return true
		}
	}
	return false
}

func wildcardLevels(host, root string) []string {
	var levels []string
	current := host
	for {
		dot := strings.Index(current, ".")
		if dot < 0 {
			break
		}
		current = current[dot+1:]
		levels = append(levels, current)
		if current == root {
			break
		}
	}
	return levels
}

func (e *validationEngine) getWildcardBaseline(level string) wildcardBaseline {
	e.wildcardMu.Lock()
	if b, ok := e.wildcards[level]; ok {
		e.wildcardMu.Unlock()
		return b
	}
	e.wildcardMu.Unlock()

	baseline := wildcardBaseline{ips: make(map[string]struct{})}

	for i := 0; i < wildcardProbeCount; i++ {
		probe := e.probeDNS(randomLabel() + "." + level)
		if !probe.resolved {
			continue
		}
		baseline.detected = true
		for ip := range probe.ips {
			baseline.ips[ip] = struct{}{}
		}
	}

	e.wildcardMu.Lock()
	if cached, ok := e.wildcards[level]; ok {
		e.wildcardMu.Unlock()
		return cached
	}
	e.wildcards[level] = baseline
	e.wildcardMu.Unlock()
	return baseline
}

func probeMatchesBaseline(probe dnsProbeData, baseline wildcardBaseline) bool {
	if !probe.resolved || !baseline.detected || len(probe.ips) == 0 {
		return false
	}
	for ip := range probe.ips {
		if _, ok := baseline.ips[ip]; !ok {
			return false
		}
	}
	return true
}

func (e *validationEngine) probeDNS(host string) dnsProbeData {
	if len(dnsclient.DefaultResolvers) == 0 {
		return dnsProbeData{}
	}

	resolver := e.nextResolver()

	if result, ok := e.queryDNSRecord(host, resolver, dns.TypeA); ok {
		ips := extractNormalisedValues(result)
		fp := joinSorted(ips)
		return dnsProbeData{
			resolved:    true,
			ips:         ips,
			fingerprint: fp,
			signatures:  map[string]struct{}{fp: {}},
		}
	}

	if result, ok := e.queryDNSRecord(host, resolver, dns.TypeCNAME); ok {
		ips := extractNormalisedValues(result)
		fp := joinSorted(ips)
		return dnsProbeData{
			resolved:    true,
			ips:         ips,
			fingerprint: fp,
			signatures:  map[string]struct{}{fp: {}},
		}
	}

	return dnsProbeData{}
}

func (e *validationEngine) nextResolver() string {
	if len(dnsclient.DefaultResolvers) == 1 {
		return dnsclient.DefaultResolvers[0]
	}
	idx := atomic.AddUint64(&e.resolverSeq, 1) - 1
	return dnsclient.DefaultResolvers[idx%uint64(len(dnsclient.DefaultResolvers))]
}

func (e *validationEngine) queryDNSRecord(host, resolver string, record uint16) (*dnsclient.Result, bool) {
	result, err := dnsQuery(host, e.dnsTimeout, record, resolver)
	if err != nil || !isUsableDNSResult(result) {
		return nil, false
	}
	return result, true
}

func extractNormalisedValues(result *dnsclient.Result) map[string]struct{} {
	out := make(map[string]struct{}, len(result.Values))
	for _, v := range result.Values {
		n := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(v, ".")))
		if n != "" {
			out[n] = struct{}{}
		}
	}
	return out
}

func joinSorted(m map[string]struct{}) string {
	items := make([]string, 0, len(m))
	for k := range m {
		items = append(items, k)
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

func isUsableDNSResult(result *dnsclient.Result) bool {
	return result != nil && result.DnsStatus == "NOERROR" && len(result.Values) > 0
}

func dnsResultSignature(result *dnsclient.Result) string {
	values := make([]string, 0, len(result.Values))
	for _, value := range result.Values {
		normalized := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
		if normalized != "" {
			values = append(values, normalized)
		}
	}
	sort.Strings(values)
	return strings.ToUpper(result.RecordName) + ":" + strings.Join(values, ",")
}

func dnsSignaturesFingerprint(signatures map[string]struct{}) string {
	items := make([]string, 0, len(signatures))
	for signature := range signatures {
		items = append(items, signature)
	}
	sort.Strings(items)
	return strings.Join(items, "|")
}

func generateRandomLabel() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, 20)
	for i := range buf {
		buf[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(buf)
}
