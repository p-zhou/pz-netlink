package types

import "time"

// Config 表示应用程序的完整配置结构
// 该结构体包含了服务端配置、SSH服务器列表、端口转发规则和HTTP代理配置
// 支持从YAML/JSON/TOML格式的配置文件中加载
type Config struct {
	// Server 配置Web管理界面的服务端参数
	Server ServerConfig `yaml:"server" json:"server" toml:"server"`
	// SSHServers SSH服务器配置列表，定义所有可用的SSH服务器
	SSHServers []SSHServer `yaml:"ssh_servers" json:"ssh_servers" toml:"ssh_servers"`
	// PortForwards 端口转发规则列表，定义所有端口转发配置
	PortForwards []PortForward `yaml:"port_forwards" json:"port_forwards" toml:"port_forwards"`
	// HTTPProxies HTTP代理服务配置列表，支持多个代理实例
	HTTPProxies []HTTPProxy `yaml:"http_proxies" json:"http_proxies" toml:"http_proxies"`
}

// ServerConfig 配置Web管理界面的服务端参数
// 定义了管理界面的监听端口和可选的认证信息
type ServerConfig struct {
	// Port Web服务器监听端口，格式为":port"，例如":8080"
	// 也可以指定为"host:port"，例如"0.0.0.0:8080"监听所有网络接口
	Port string `yaml:"port" json:"port" toml:"port"`
	// Username 可选的HTTP认证用户名
	// 如果留空则不启用HTTP基础认证
	Username string `yaml:"username,omitempty" json:"username,omitempty" toml:"username,omitempty"`
	// Password 可选的HTTP认证密码
	// 与username配合使用，如果username留空则此字段无效
	Password string `yaml:"password,omitempty" json:"password,omitempty" toml:"password,omitempty"`
}

// SSHServer 定义SSH服务器的连接配置
// 包含了连接SSH服务器所需的所有参数，用于建立SSH会话
type SSHServer struct {
	// ID 服务器的唯一标识符
	// 自动生成或手动指定，用于在端口转发和HTTP代理中引用此服务器
	ID string `yaml:"id" json:"id" toml:"id"`
	// Name 服务器的显示名称
	// 用于在Web界面中显示，便于用户识别
	Name string `yaml:"name" json:"name" toml:"name"`
	// Host SSH服务器的主机名或IP地址
	Host string `yaml:"host" json:"host" toml:"host"`
	// Port SSH服务器的端口号，默认为22
	Port int `yaml:"port" json:"port" toml:"port"`
	// Username 登录SSH服务器的用户名
	Username string `yaml:"username" json:"username" toml:"username"`
	// Password 登录密码（当auth_type为"password"时使用）
	Password string `yaml:"password" json:"password" toml:"password"`
	// AuthType 认证方式，可选值为"password"或"key"
	// password: 使用密码认证
	// key: 使用私钥文件认证
	AuthType string `yaml:"auth_type" json:"auth_type" toml:"auth_type"`
	// PrivateKey 私钥文件路径（当auth_type为"key"时使用）
	// 例如："/home/user/.ssh/id_rsa"
	PrivateKey string `yaml:"private_key,omitempty" json:"private_key,omitempty" toml:"private_key,omitempty"`
	// KeepAliveInterval SSH连接的保活间隔时间（秒）
	// 设置为0表示禁用保活机制
	// 建议设置为30秒以防止长时间空闲连接被断开
	KeepAliveInterval int `yaml:"keep_alive_interval" json:"keep_alive_interval" toml:"keep_alive_interval"`
	// Valid SSH服务器是否有效
	// true: 服务器有效且可连接
	// false: 服务器无效或无法连接
	// 此字段不保存到配置文件，仅用于运行时状态
	Valid bool `yaml:"-" json:"valid" toml:"-"`
	// LastCheckedTime 最后一次有效性检查时间
	// 此字段不保存到配置文件，仅用于运行时状态
	LastCheckedTime time.Time `yaml:"-" json:"last_checked_time" toml:"-"`
	// LastValidationError 最后一次验证错误信息
	// 此字段不保存到配置文件，仅用于运行时状态
	LastValidationError string `yaml:"-" json:"last_validation_error" toml:"-"`
}

// PortForward 定义端口转发规则
// 实现本地端口到SSH服务器远程端口的转发，用于通过SSH隧道访问远程服务
type PortForward struct {
	// ID 转发规则的唯一标识符
	// 用于API操作中的引用
	ID string `yaml:"id" json:"id" toml:"id"`
	// Name 转发规则的显示名称
	Name string `yaml:"name" json:"name" toml:"name"`
	// SSHServerID 关联的SSH服务器ID
	// 必须是在SSHServers列表中存在的服务器ID
	SSHServerID string `yaml:"ssh_server_id" json:"ssh_server_id" toml:"ssh_server_id"`
	// ListenHost 本地监听地址
	// 通常为"127.0.0.1"（仅本机访问）或"0.0.0.0"（允许外部访问）
	ListenHost string `yaml:"listen_host" json:"listen_host" toml:"listen_host"`
	// ListenPort 本地监听端口
	// 连接到此端口的流量将被转发到远程主机
	ListenPort int `yaml:"listen_port" json:"listen_port" toml:"listen_port"`
	// RemoteHost 远程目标主机地址
	// 从SSH服务器端访问的目标主机
	RemoteHost string `yaml:"remote_host" json:"remote_host" toml:"remote_host"`
	// RemotePort 远程目标端口
	RemotePort int `yaml:"remote_port" json:"remote_port" toml:"remote_port"`
	// Enabled 是否启用此转发规则
	// true: 启用并在服务启动时建立转发
	// false: 禁用
	Enabled bool `yaml:"enabled" json:"enabled" toml:"enabled"`
}

// HTTPProxy 定义单个HTTP代理服务配置
// 提供标准的HTTP代理服务，通过SSH隧道转发HTTP/HTTPS流量
type HTTPProxy struct {
	// ID 代理的唯一标识符
	// 用于API操作中的引用
	ID string `yaml:"id" json:"id" toml:"id"`
	// Name 代理的显示名称
	// 用于在Web界面中显示，便于用户识别
	Name string `yaml:"name" json:"name" toml:"name"`
	// Enabled 是否启用HTTP代理服务
	Enabled bool `yaml:"enabled" json:"enabled" toml:"enabled"`
	// Listen 代理服务的监听地址和端口
	// 格式为"host:port"，例如"0.0.0.0:1080"或":1080"
	Listen string `yaml:"listen" json:"listen" toml:"listen"`
	// SSHServerID 关联的SSH服务器ID
	// 指定使用哪个SSH服务器进行代理转发
	// 如果留空，将自动使用第一个可用的SSH服务器
	SSHServerID string `yaml:"ssh_server_id" json:"ssh_server_id" toml:"ssh_server_id"`
}

// HTTPProxyConfig 旧的HTTP代理配置类型，用于向后兼容
// Deprecated: 请使用 HTTPProxy 类型
type HTTPProxyConfig = HTTPProxy

// PortForwardWithStatus 包含端口转发及其SSH服务器状态
type PortForwardWithStatus struct {
	PortForward
	SSHServerValid bool   `json:"ssh_server_valid"`
	SSHServerName  string `json:"ssh_server_name"`
}

// HTTPProxyWithStatus 包含HTTP代理及其SSH服务器状态
type HTTPProxyWithStatus struct {
	HTTPProxy
	SSHServerValid bool   `json:"ssh_server_valid"`
	SSHServerName  string `json:"ssh_server_name"`
}

// ConnectionStatus 表示活动连接的状态信息
// 用于在Web界面中展示当前所有活动连接的实时状态
type ConnectionStatus struct {
	// ID 连接的唯一标识符
	ID string `json:"id"`
	// Type 连接类型，例如"port_forward"或"http_proxy"
	Type string `json:"type"`
	// Name 连接的显示名称
	Name string `json:"name"`
	// LocalAddr 本地监听地址
	// 格式为"host:port"
	LocalAddr string `json:"local_addr"`
	// RemoteAddr 远程目标地址
	// 格式为"host:port"
	RemoteAddr string `json:"remote_addr"`
	// Status 连接状态
	// 常见值："running"（运行中）、"stopped"（已停止）、"error"（错误）
	Status string `json:"status"`
	// BytesIn 接收的字节数统计
	BytesIn int64 `json:"bytes_in"`
	// BytesOut 发送的字节数统计
	BytesOut int64 `json:"bytes_out"`
	// StartedAt 连接启动时间
	StartedAt time.Time `json:"started_at"`
	// LastError 最后一次错误信息（如果有）
	// 仅在Status为"error"时有值
	LastError string `json:"last_error,omitempty"`
	// ActiveConnections 当前活动的子连接数
	// 例如：端口转发时表示有多少客户端已连接到此转发
	ActiveConnections int `json:"active_connections"`
}

// LogEntry 表示一条系统日志记录
// 用于记录应用程序的运行日志，供Web界面查看和调试
type LogEntry struct {
	// Timestamp 日志记录的时间戳
	Timestamp time.Time `json:"timestamp"`
	// Level 日志级别
	// 常见值："INFO"（信息）、"WARN"（警告）、"ERROR"（错误）
	Level string `json:"level"`
	// Message 日志消息内容
	Message string `json:"message"`
	// ConnectionID 关联的连接ID（可选）
	// 如果此日志与特定连接相关，则包含该连接的ID
	ConnectionID string `json:"connection_id,omitempty"`
}
