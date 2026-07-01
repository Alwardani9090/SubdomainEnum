package alterx

import (
	"bufio"
	"os/exec"
	"strings"
)

func IsAvailable() bool {
	_, err := exec.LookPath("alterx")
	return err == nil
}

func Generate(subdomains []string, enrich bool) ([]string, error) {
	args := []string{"-silent"}
	if enrich {
		args = append(args, "-enrich")
	}

	cmd := exec.Command("alterx", args...)
	cmd.Stdin = strings.NewReader(strings.Join(subdomains, "\n"))

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			seen[strings.ToLower(line)] = struct{}{}
		}
	}

	results := make([]string, 0, len(seen))
	for s := range seen {
		results = append(results, s)
	}
	return results, nil
}
