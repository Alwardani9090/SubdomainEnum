package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var configFile string = filepath.Join(os.Getenv("HOME"), ".config", "subdomainenum", "config.yaml")

type Config struct {
	Format map[string][]string `yaml:"config"`
}

func ReadConfig() (*Config, error) {
	dir := filepath.Dir(configFile)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return nil, err
	}
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		defaultConfig := []byte("config: {}\n")
		if err := os.WriteFile(configFile, defaultConfig, os.ModePerm); err != nil {
			return nil, err
		}
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
