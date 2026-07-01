package runner

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/abdulrahmanalwardani/subdomainenum/internal/progress"
	"github.com/abdulrahmanalwardani/subdomainenum/internal/log"
	"github.com/abdulrahmanalwardani/subdomainenum/pkg/active/alterx"
	"github.com/abdulrahmanalwardani/subdomainenum/pkg/active/bruteforce"
	"github.com/abdulrahmanalwardani/subdomainenum/pkg/active/permutation"
	"github.com/abdulrahmanalwardani/subdomainenum/pkg/scraper"
	"github.com/abdulrahmanalwardani/subdomainenum/pkg/scraper/sources"
	"github.com/abdulrahmanalwardani/subdomainenum/pkg/utils"
)

type sourceResult struct {
	name       string
	subdomains []string
	duration   time.Duration
	err        error
}

func Run(opts *Options) error {
	opts.queries = normalizeQueries(utils.ExtractDomainsFromString(opts.Query))

	if opts.Query == "" && opts.InputFile == "" {
		log.Fatalf("No input specified: use -d <domain> or -i <file>")
	}

	if opts.InputFile != "" {
		var err error
		opts.queries, err = utils.ReadInputFromFile(opts.InputFile)
		if err != nil {
			log.Fatalf("Error reading input file %s: %s", opts.InputFile, err)
		}
		opts.queries = normalizeQueries(opts.queries)
	}

	if len(opts.queries) == 0 {
		log.Fatalf("No domains found in input")
	}

	apiKeys, err := scraper.ExtractALLAPIKeys()
	if err != nil {
		log.Fatalf("Error extracting API keys: %s", err)
	}
	baseSources := sources.GetAllSources(apiKeys)
	progressTotal := len(opts.queries) * len(baseSources)
	if opts.ActiveEnabled {
		progressTotal += 1 + len(opts.queries)
	}
	if !opts.SkipFinalValidation {
		progressTotal++
	}
	progressDone := 0
	progress.WriteToolProgress(os.Stderr, progressDone, progressTotal, "passive-sources")

	collector := newHostCollector(opts.queries)
	validator := newValidationEngine(opts.queries, opts.Concurrency, opts.DNSTimeout)
	filterStats := normalizationStats{}

	for _, domain := range opts.queries {
		log.Phase("PASSIVE ENUMERATION")
		log.Stat("Target domain", domain)

		client := scraper.NewSession(opts.HTTPTimeout)
		srcs := sources.GetAllSources(apiKeys)
		log.Stat("Sources loaded", len(srcs))

		resultsCh := make(chan sourceResult, len(srcs))
		var wg sync.WaitGroup
		var completed int64

		for _, src := range srcs {
			wg.Add(1)
			go func(s scraper.Source) {
				defer wg.Done()
				log.SourceStart(s.Name())
				start := time.Now()
				subdomains, err := s.Search(domain, client)
				resultsCh <- sourceResult{
					name:       s.Name(),
					subdomains: subdomains,
					duration:   time.Since(start),
					err:        err,
				}
			}(src)
		}

		go func() {
			wg.Wait()
			close(resultsCh)
		}()

		totalSources := len(srcs)
		for res := range resultsCh {
			done := int(atomic.AddInt64(&completed, 1))

			if res.err != nil {
				log.SourceDone(res.name, 0, res.duration, res.err)
			} else {
				filteredBatch, batchStats := dedupeSubdomainCandidates(res.subdomains, opts.queries)
				filterStats.Duplicates += batchStats.Duplicates
				filterStats.Invalid += batchStats.Invalid
				newSubs := collector.AddBatch(filteredBatch)
				log.SourceDone(res.name, len(newSubs), res.duration, nil)
				log.ListSubdomains(newSubs)
			}

			log.SourceProgress(done, totalSources)
			progressDone++
			progress.WriteToolProgress(os.Stderr, progressDone, progressTotal, "passive-sources")
		}

		log.Stat("Passive subtotal", len(collector.List()))
	}

	if opts.ActiveEnabled {
		log.Phase("ACTIVE ENUMERATION")

		prefixWordlist := bruteforce.GenerateWordlist(opts.queries)
		log.Stat("Bruteforce candidates", len(prefixWordlist))

		start := time.Now()
		bruteReport := validator.validateDNS(prefixWordlist)
		filteredBrute, batchStats := dedupeSubdomainCandidates(bruteReport.Hosts, opts.queries)
		filterStats.Duplicates += batchStats.Duplicates
		filterStats.Invalid += batchStats.Invalid
		newFromBrute := collector.AddBatch(filteredBrute)
		log.Infof("Bruteforce: %d new subdomain(s) in %s", len(newFromBrute), time.Since(start).Round(time.Millisecond))
		if bruteReport.WildcardCount > 0 {
			log.Stat("Bruteforce wildcard filtered", bruteReport.WildcardCount)
		}
		progressDone++
		progress.WriteToolProgress(os.Stderr, progressDone, progressTotal, "bruteforce")

		log.Phase("PERMUTATION ENGINE")

		for _, domain := range opts.queries {
			knownHosts := collector.List()
			var permCandidates []string

			if alterx.IsAvailable() {
				log.Infof("Running alterx permutation engine...")
				alterxInput := knownHosts
				if len(alterxInput) > 500 {
					alterxInput = alterxInput[:500]
				}
				start := time.Now()
				alterxResults, err := alterx.Generate(alterxInput, true)
				if err != nil {
					log.Errorf("alterx error: %s", err)
				} else {
					log.Infof("alterx: %d permutation(s) in %s", len(alterxResults), time.Since(start).Round(time.Millisecond))
					permCandidates = alterxResults
				}
			} else {
				log.Warnf("alterx not installed — using built-in engine only")
				log.Debugf("Install: go install github.com/projectdiscovery/alterx/cmd/alterx@latest")
			}

			start := time.Now()
			builtinPerms := permutation.Generate(knownHosts, domain)
			log.Infof("Built-in engine: %d candidate(s) in %s", len(builtinPerms), time.Since(start).Round(time.Millisecond))

			permSet := make(map[string]struct{})
			for _, candidate := range permCandidates {
				if normalized := normalizeSubdomainCandidate(candidate, opts.queries); normalized != "" {
					permSet[normalized] = struct{}{}
				}
			}
			for _, candidate := range builtinPerms {
				if normalized := normalizeSubdomainCandidate(candidate, opts.queries); normalized != "" {
					permSet[normalized] = struct{}{}
				}
			}

			permList := make([]string, 0, len(permSet))
			for candidate := range permSet {
				permList = append(permList, candidate)
			}

			if len(permList) == 0 {
				continue
			}

			filteredPerms, batchStats := dedupeSubdomainCandidates(permList, opts.queries)
			filterStats.Duplicates += batchStats.Duplicates
			filterStats.Invalid += batchStats.Invalid

			log.Stat("Permutation candidates", len(filteredPerms))
			start = time.Now()
			permReport := validator.validateDNS(filteredPerms)
			newFromPerm := collector.AddBatch(permReport.Hosts)
			log.Infof("Permutations: %d new subdomain(s) in %s", len(newFromPerm), time.Since(start).Round(time.Millisecond))
			if permReport.WildcardCount > 0 {
				log.Stat("Permutation wildcard filtered", permReport.WildcardCount)
			}
			progressDone++
			progress.WriteToolProgress(os.Stderr, progressDone, progressTotal, "permutations")
		}

		log.Stat("Total after active", len(collector.List()))
	}

	discoveredSubdomains := collector.List()
	dnsReport := resolveAliveSubdomains(opts, validator, discoveredSubdomains)
	if !opts.SkipFinalValidation {
		progressDone++
		progress.WriteToolProgress(os.Stderr, progressDone, progressTotal, "dns-validation")
	}

	for _, sub := range dnsReport.Hosts {
		log.Resultf("%s", sub)
	}

	if opts.OutputFile != "" {
		if err := utils.WriteOutputToFile(opts.OutputFile, dnsReport.Hosts); err != nil {
			log.Fatalf("Error writing output file: %s", err)
		}
		log.Infof("Results written to: %s", opts.OutputFile)
	}

	collectorStats := collector.Stats()
	log.PrintStats(log.Summary{
		DiscoveredHosts:     len(discoveredSubdomains),
		ResolvedHosts:       len(dnsReport.Hosts),
		DuplicateDiscarded:  filterStats.Duplicates + collectorStats.Duplicates,
		InvalidDiscarded:    filterStats.Invalid + collectorStats.Invalid,
		WildcardDiscarded:   dnsReport.WildcardCount,
		UnresolvedDiscarded: dnsReport.UnresolvedCount,
		ValidationSkipped:   dnsReport.Skipped,
	})

	return nil
}

func resolveAliveSubdomains(opts *Options, validator *validationEngine, uniqueSubdomains []string) dnsValidationReport {
	log.Phase("DNS VALIDATION")
	if opts.SkipFinalValidation {
		log.Warnf("Skipping final DNS validation; deferring resolution to downstream dns stage")
		log.Stat("Subdomains forwarded", len(uniqueSubdomains))
		return dnsValidationReport{
			Hosts:   append([]string(nil), uniqueSubdomains...),
			Skipped: true,
		}
	}

	log.Stat("Subdomains to validate", len(uniqueSubdomains))
	start := time.Now()
	report := validator.validateDNS(uniqueSubdomains)
	log.Infof("DNS validation: %d resolved / %d discovered in %s",
		len(report.Hosts), len(uniqueSubdomains), time.Since(start).Round(time.Millisecond))
	if report.WildcardCount > 0 {
		log.Stat("Wildcard filtered", report.WildcardCount)
	}
	if report.UnresolvedCount > 0 {
		log.Stat("Unresolved filtered", report.UnresolvedCount)
	}
	return report
}
