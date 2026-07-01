package runner

type Options struct {
	Query               string
	queries             []string
	InputFile           string
	OutputFile          string
	Concurrency         int
	HTTPTimeout         int
	DNSTimeout          int
	Silent              bool
	Verbose             bool
	ActiveEnabled       bool
	SkipFinalValidation bool
}
