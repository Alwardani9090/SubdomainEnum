package scraper

import (
	"crypto/tls"
	"github.com/abdulrahmanalwardani/subdomainenum/internal/config"
	"net/http"
	"time"
)

type Source interface {
	Name() string
	Search(query string, client *http.Client) ([]string, error)
	RequiresAPIKey() bool
}

func NewSession(timeout int) *http.Client {

	return &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

}

func ExtractALLAPIKeys() (map[string][]string, error) {
	cfg, err := config.ReadConfig()
	if err != nil {
		return nil, err
	}

	return cfg.Format, nil
}
