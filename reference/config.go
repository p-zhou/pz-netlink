package config

import (
	"os"

	"gopkg.in/yaml.v3"
	"ssh-proxy/pkg/types"
)

type Config struct {
	path string
	data *types.Config
}

func New(path string) *Config {
	return &Config{path: path}
}

func (c *Config) Load() (*types.Config, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, err
	}

	var cfg types.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	c.data = &cfg
	return &cfg, nil
}

func (c *Config) Save(cfg *types.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0644)
}

func (c *Config) Get() *types.Config {
	return c.data
}
