package storage

import (
	"bytes"
	"os"
	"sync"

	"github.com/BurntSushi/toml"
	"pz-netlink/pkg/types"
)

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
			s.data = &types.Config{}
			return s.data, nil
		}
		return nil, err
	}

	cfg := &types.Config{}
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	s.data = cfg
	return s.data, nil
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
