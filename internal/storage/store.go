package storage

import (
	"bytes"
	_ "embed"
	"os"
	"path/filepath"
	"sync"

	"github.com/BurntSushi/toml"
	"pz-netlink/pkg/types"
)

type legacyConfig struct {
	Server       types.ServerConfig    `toml:"server"`
	SSHServers   []types.SSHServer     `toml:"ssh_servers"`
	PortForwards []types.PortForward   `toml:"port_forwards"`
	HTTPProxy    types.HTTPProxyConfig `toml:"http_proxy"`
}

//go:embed config.toml
var defaultConfig []byte

type Store struct {
	path string
	mu   sync.RWMutex
	data *types.Config
}

func New(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Load() (*types.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := s.createFromTemplate(); err != nil {
				return nil, err
			}
			data = defaultConfig
		} else {
			return nil, err
		}
	}

	cfg := &types.Config{}
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	s.data = cfg
	return s.data, nil
}

func (s *Store) createFromTemplate() error {
	dir := filepath.Dir(s.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(s.path, defaultConfig, 0644)
}

func (s *Store) Save(cfg *types.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return err
	}

	return os.WriteFile(s.path, buf.Bytes(), 0644)
}

func (s *Store) Get() *types.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}

func (s *Store) LoadRaw() (*legacyConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}

	cfg := &legacyConfig{}
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
