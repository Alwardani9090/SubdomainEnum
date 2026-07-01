package dnsprobe

import (
	"math/rand"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var resolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

func randomResolver() string {
	return resolvers[rand.Intn(len(resolvers))]
}

func CheckDomains(domains []string) []string {
	return CheckDomainsWithConcurrency(domains, 500)
}

func CheckDomainsWithConcurrency(domains []string, concurrency int) []string {
	if concurrency > 500 {
		concurrency = 500
	}
	if concurrency < 1 {
		concurrency = 1
	}
	results := []string{}
	resultsMutex := &sync.Mutex{}

	domainsChan := make(chan string, concurrency*2)

	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainsChan {
				if isAlive(domain) {
					resultsMutex.Lock()
					results = append(results, domain)
					resultsMutex.Unlock()
				}
			}
		}()
	}

	for _, domain := range domains {
		domainsChan <- domain
	}

	close(domainsChan)

	wg.Wait()

	return results
}

func isAlive(host string) bool {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)

	client := new(dns.Client)
	client.Timeout = 7 * time.Second

	resp, _, err := client.Exchange(msg, randomResolver())
	if err != nil || resp == nil {
		return false
	}

	if resp.Rcode != dns.RcodeSuccess {
		return false
	}

	return len(resp.Answer) > 0
}
