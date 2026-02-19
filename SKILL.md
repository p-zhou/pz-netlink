# Skill: Go SSH 代理服务开发

## 概述
本技能用于开发和维护基于 SSH 的 HTTP 代理和端口转发服务，包含 Web 管理界面。

## 技术栈
- **语言**: Go 1.21+
- **HTTP 路由**: 标准库 net/http 或 gorilla/mux
- **SSH**: golang.org/x/crypto/ssh
- **配置**: YAML 格式 (gopkg.in/yaml.v3)
- **模板**: html/template
- **存储**: JSON 文件 (简单场景) 或 SQLite

## 项目结构
```
cmd/server/main.go          # 程序入口
internal/
  config/config.go          # 配置加载和管理
  ssh/client.go             # SSH 连接管理
  ssh/forward.go            # 端口转发逻辑
  proxy/http.go             # HTTP 代理逻辑
  web/
    handlers.go             # HTTP 处理器
    middleware.go           # 中间件
    templates.go            # 模板渲染
  storage/store.go          # 配置存储
pkg/types/types.go          # 类型定义
```

## 核心功能

### 1. SSH 连接管理
- 支持密码和密钥认证
- 连接池管理
- 心跳保活 (Keep-alive)
- 自动重连机制

### 2. 端口转发
- 本地端口 -> SSH -> 远程主机:端口
- 支持多个并发转发
- 流量统计和状态监控

### 3. HTTP 代理
- CONNECT 方法支持
- 代理认证 (可选)
- 流量统计

### 4. Web 管理界面
- 实时连接状态展示
- 日志查看
- 配置 CRUD 操作
- SSH 服务器配置管理

## 关键实现细节

### SSH 客户端配置
```go
config := &ssh.ClientConfig{
    User: username,
    Auth: []ssh.AuthMethod{
        ssh.Password(password),
        // 或 ssh.PublicKeys(key),
    },
    HostKeyCallback: ssh.InsecureIgnoreHostKey(),
}
```

### 端口转发实现
```go
// 本地监听
listener, err := net.Listen("tcp", "localhost:localPort")
// 转发到远程
for {
    conn, err := listener.Accept()
    go forward(conn, remoteHost, remotePort)
}
```

### HTTP 代理 CONNECT 处理
```go
// 劫持 CONNECT 请求，建立隧道
targetConn, err := sshDial(targetHost, targetPort)
// 替换为双向复制
go io.Copy(client, targetConn)
go io.Copy(targetConn, client)
```

## 开发流程
1. 定义配置结构 (Config, SSHServer, PortForward, HTTPProxy)
2. 实现 SSH 连接管理
3. 实现端口转发逻辑
4. 实现 HTTP 代理
5. 实现 Web API 和前端界面
6. 集成测试

## 测试
- 单元测试: go test ./...
- 手动测试: 启动服务，配置 SSH，测试代理和转发

## 部署
```bash
go build -o ssh-proxy cmd/server/main.go
./ssh-proxy -config config.yaml
```
