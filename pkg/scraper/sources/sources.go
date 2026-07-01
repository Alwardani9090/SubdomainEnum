package sources

import (
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/alienvault"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/anubis"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/binaryedge"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/c99"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/censys"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/certspotter"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/chaos"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/commoncrawl"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/crtsh"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/dnsdb"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/dnsrecords"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/fofa"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/fullhunt"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/github"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/google"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/hackertarget"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/intelx"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/leakix"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/netlas"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/passivetotal"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/rapiddns"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/securitytrails"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/shodan"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/threatminer"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/urlscan"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/virustotal"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/wayback"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/whoisxmlapi"
	"github.com/Alwardani9090/SubdomainEnum/pkg/scraper/sources/zoomeye"
)

var AllSources = [...]scraper.Source{
	&crtsh.Source{},
	&certspotter.Source{},

	&alienvault.Source{},
	&anubis.Source{},

	&threatminer.Source{},

	&google.Source{},
	&hackertarget.Source{},

	&wayback.Source{},
	&commoncrawl.Source{},

	&rapiddns.Source{},

	&dnsrecords.Source{},
}

func GetAllSources(apiKeys map[string][]string) []scraper.Source {
	var sources []scraper.Source

	for _, source := range AllSources {
		if !source.RequiresAPIKey() {
			sources = append(sources, source)
		}
	}

	keyedSources := map[string]func([]string) scraper.Source{
		"censys": func(k []string) scraper.Source { return censys.New(k) },

		"whoisxmlapi":    func(k []string) scraper.Source { return whoisxmlapi.New(k) },
		"securitytrails": func(k []string) scraper.Source { return securitytrails.New(k) },
		"passivetotal":   func(k []string) scraper.Source { return passivetotal.New(k) },
		"chaos":          func(k []string) scraper.Source { return chaos.New(k) },
		"c99":            func(k []string) scraper.Source { return c99.New(k) },

		"shodan":     func(k []string) scraper.Source { return shodan.New(k) },
		"zoomeye":    func(k []string) scraper.Source { return zoomeye.New(k) },
		"fofa":       func(k []string) scraper.Source { return fofa.New(k) },
		"binaryedge": func(k []string) scraper.Source { return binaryedge.New(k) },
		"fullhunt":   func(k []string) scraper.Source { return fullhunt.New(k) },
		"netlas":     func(k []string) scraper.Source { return netlas.New(k) },
		"urlscan":    func(k []string) scraper.Source { return urlscan.New(k) },
		"leakix":     func(k []string) scraper.Source { return leakix.New(k) },

		"intelx": func(k []string) scraper.Source { return intelx.New(k) },

		"dnsdb": func(k []string) scraper.Source { return dnsdb.New(k) },

		"virustotal": func(k []string) scraper.Source { return virustotal.New(k) },

		"github": func(k []string) scraper.Source { return github.New(k) },
	}

	for name, factory := range keyedSources {
		if keys, ok := apiKeys[name]; ok && len(keys) > 0 {
			sources = append(sources, factory(keys))
		}
	}

	return sources
}
