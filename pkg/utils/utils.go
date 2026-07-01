package utils

import (
	"bufio"
	"os"
	"strings"
)

func ReadInputFromFile(file string) ([]string, error) {

	fileData, err := os.ReadFile(file)
	if err != nil {
		return []string{}, err
	}
	return strings.Split(string(fileData), "\n"), nil
}

func WriteOutputToFile(file string, data []string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, line := range data {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func ExtractDomainsFromString(input string) []string {
	return strings.Split(input, ",")
}
