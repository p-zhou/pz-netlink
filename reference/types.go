package types

import "time"

type Config struct {
	Server       ServerConfig    `yaml:"server"`
	SSHServers   []SSHServer     `yaml:"ssh_servers"`
	PortForwards []PortForward   `yaml:"port_forwards"`
	HTTPProxy    HTTPProxyConfig `yaml:"http_proxy"`
}

type ServerConfig struct {
	Port         string `yaml:"port"`
	StaticDir    string `yaml:"static_dir"`
	TemplatesDir string `yaml:"templates_dir"`
}

type SSHServer struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// AuthType: "password" or "key"
	AuthType string `yaml:"auth_type"`
	// PrivateKey path (for key auth)
	PrivateKey string `yaml:"private_key,omitempty"`
	// KeepAliveInterval seconds
	KeepAliveInterval int `yaml:"keep_alive_interval"`
}

type PortForward struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	SSHServerID string `yaml:"ssh_server_id"`
	ListenHost  string `yaml:"listen_host"`
	ListenPort  int    `yaml:"listen_port"`
	RemoteHost  string `yaml:"remote_host"`
	RemotePort  int    `yaml:"remote_port"`
	Enabled     bool   `yaml:"enabled"`
}

type HTTPProxyConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Listen      string `yaml:"listen"`
	SSHServerID string `yaml:"ssh_server_id"`
}

type ConnectionStatus struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"` // "port_forward" or "http_proxy"
	Name       string    `json:"name"`
	LocalAddr  string    `json:"local_addr"`
	RemoteAddr string    `json:"remote_addr"`
	Status     string    `json:"status"` // "connected", "disconnected", "error"
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	StartedAt  time.Time `json:"started_at"`
	LastError  string    `json:"last_error,omitempty"`
}

type LogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	Level        string    `json:"level"`
	Message      string    `json:"message"`
	ConnectionID string    `json:"connection_id,omitempty"`
}
