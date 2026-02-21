package storage

import (
	"bytes"
	_ "embed"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/BurntSushi/toml"
	"pz-netlink/pkg/types"
)

//go:embed config.toml
var defaultConfig []byte

var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

func expandEnvVars(data []byte) []byte {
	// 将 []byte 转换为 string，展开环境变量，再转回 []byte
	dataStr := string(data)
	expanded := envVarPattern.ReplaceAllStringFunc(dataStr, func(match string) string {
		// 提取变量名 ${VAR_NAME} 中的 VAR_NAME
		varName := match[2 : len(match)-1]
		envValue := os.Getenv(varName)
		if envValue == "" {
			// 环境变量未设置，返回原样
			return match
		}
		return envValue
	})
	return []byte(expanded)
}

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

	// 展开环境变量
	expandedData := expandEnvVars(data)

	cfg := &types.Config{}
	if err := toml.Unmarshal(expandedData, cfg); err != nil {
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
