package main

import (
	"flag"

	"github.com/Alwardani9090/SubdomainEnum/internal/log"
	"github.com/Alwardani9090/SubdomainEnum/internal/runner"
)

var options = &runner.Options{}

func main() {
	flag.StringVar(&options.Query, "d", "", "Target domain(s) to enumerate subdomains for, comma-separated")
	flag.IntVar(&options.HTTPTimeout, "http-timeout", 20, "HTTP timeout for passive source requests (seconds)")
	flag.IntVar(&options.DNSTimeout, "dns-timeout", 3, "DNS timeout for validation queries (seconds)")
	flag.IntVar(&options.Concurrency, "c", 500, "Concurrency level for DNS probing")
	flag.StringVar(&options.InputFile, "i", "", "Input file: one domain per line")
	flag.StringVar(&options.OutputFile, "o", "", "Output file for discovered subdomains")
	flag.BoolVar(&options.ActiveEnabled, "active", false, "Enable active enumeration (bruteforce + permutations)")
	flag.BoolVar(&options.SkipFinalValidation, "skip-final-validation", false, "Skip final DNS validation and defer resolution to a downstream dns stage")
	flag.BoolVar(&options.Silent, "silent", false, "Silent mode: output only subdomains (for piping)")
	flag.BoolVar(&options.Verbose, "v", false, "Verbose mode: show per-subdomain details and debug info")

	var noColor bool
	flag.BoolVar(&noColor, "no-color", false, "Disable colored output")
	flag.Parse()

	level := log.LevelNormal
	if options.Silent {
		level = log.LevelSilent
	} else if options.Verbose {
		level = log.LevelVerbose
	}
	log.Init(level, noColor)

	log.Banner()

	if err := runner.Run(options); err != nil {
		log.Errorf("Error: %v", err)
	}
}
