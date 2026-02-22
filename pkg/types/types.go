package types

import "time"

type Config struct {
	Server       ServerConfig    `yaml:"server" json:"server" toml:"server"`
	SSHServers   []SSHServer     `yaml:"ssh_servers" json:"ssh_servers" toml:"ssh_servers"`
	PortForwards []PortForward   `yaml:"port_forwards" json:"port_forwards" toml:"port_forwards"`
	HTTPProxy    HTTPProxyConfig `yaml:"http_proxy" json:"http_proxy" toml:"http_proxy"`
}

type ServerConfig struct {
	Port     string `yaml:"port" json:"port" toml:"port"`
	Username string `yaml:"username,omitempty" json:"username,omitempty" toml:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty" toml:"password,omitempty"`
}

type SSHServer struct {
	ID                string `yaml:"id" json:"id" toml:"id"`
	Name              string `yaml:"name" json:"name" toml:"name"`
	Host              string `yaml:"host" json:"host" toml:"host"`
	Port              int    `yaml:"port" json:"port" toml:"port"`
	Username          string `yaml:"username" json:"username" toml:"username"`
	Password          string `yaml:"password" json:"password" toml:"password"`
	AuthType          string `yaml:"auth_type" json:"auth_type" toml:"auth_type"`
	PrivateKey        string `yaml:"private_key,omitempty" json:"private_key,omitempty" toml:"private_key,omitempty"`
	KeepAliveInterval int    `yaml:"keep_alive_interval" json:"keep_alive_interval" toml:"keep_alive_interval"`
}

type PortForward struct {
	ID          string `yaml:"id" json:"id" toml:"id"`
	Name        string `yaml:"name" json:"name" toml:"name"`
	SSHServerID string `yaml:"ssh_server_id" json:"ssh_server_id" toml:"ssh_server_id"`
	ListenHost  string `yaml:"listen_host" json:"listen_host" toml:"listen_host"`
	ListenPort  int    `yaml:"listen_port" json:"listen_port" toml:"listen_port"`
	RemoteHost  string `yaml:"remote_host" json:"remote_host" toml:"remote_host"`
	RemotePort  int    `yaml:"remote_port" json:"remote_port" toml:"remote_port"`
	Enabled     bool   `yaml:"enabled" json:"enabled" toml:"enabled"`
}

type HTTPProxyConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled" toml:"enabled"`
	Listen      string `yaml:"listen" json:"listen" toml:"listen"`
	SSHServerID string `yaml:"ssh_server_id" json:"ssh_server_id" toml:"ssh_server_id"`
}

type ConnectionStatus struct {
	ID                string    `json:"id"`
	Type              string    `json:"type"`
	Name              string    `json:"name"`
	LocalAddr         string    `json:"local_addr"`
	RemoteAddr        string    `json:"remote_addr"`
	Status            string    `json:"status"`
	BytesIn           int64     `json:"bytes_in"`
	BytesOut          int64     `json:"bytes_out"`
	StartedAt         time.Time `json:"started_at"`
	LastError         string    `json:"last_error,omitempty"`
	ActiveConnections int       `json:"active_connections"`
}

type LogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	Level        string    `json:"level"`
	Message      string    `json:"message"`
	ConnectionID string    `json:"connection_id,omitempty"`
}
