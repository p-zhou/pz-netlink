package storage

import (
	"encoding/json"
	"os"
	"sync"

	"ssh-proxy/pkg/types"
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

	var cfg types.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	s.data = &cfg
	return s.data, nil
}

func (s *Store) Save(cfg *types.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.path, data, 0644)
}

func (s *Store) Get() *types.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}
