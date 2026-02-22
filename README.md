# pz-netlink
一个用于简单目的的 HTTP 代理及端口映射工具

## 概要设计

### 系统架构

pz-netlink 是一个基于 SSH 隧道的代理和端口转发工具，具有以下核心特性：

- **统一的 SSH 连接管理**：通过配置文件中定义的 SSH 服务器建立加密连接
- **端口映射服务**：将本地端口通过 SSH 通道转发到远程服务器端口
- **HTTP 代理服务**：支持标准 HTTP CONNECT 方法和自动 TLS 握手检测
- **实时监控**：Web 界面显示连接状态、流量统计和活动连接数

### 数据流向

整个系统的数据流架构如下：

```
┌─────────────────────────────────────────────────────────┐
│                        本地客户端                         │
│                        (浏览器/工具)                      │
└─────────────────────────────────────────────────────────┘
                          ↓
              ┌─────────────────────────┐
              │     本地监听服务          │
              │       - 端口映射         │
              │       - HTTP代理        │
              └─────────────────────────┘
                          ↓
              ┌─────────────────────────┐
              │       SSH 加密通道       │
              │  (配置文件中定义 SSH 服务) │
              └─────────────────────────┘
                          ↓
              ┌─────────────────────────┐
              │   远程目标服务器          │
              │    - 端口映射目标服务器    │
              │    - HTTP代理目标服务器   │
              └─────────────────────────┘
```

### 核心组件

#### 1. SSH 连接管理 (`internal/ssh/`)
- 建立和维护到远程 SSH 服务器的加密连接
- 支持密码和密钥两种认证方式
- 自动保活机制（可配置间隔）

#### 2. 端口转发 (`internal/forward/`)
- 监听本地端口（如 60080）
- 通过 SSH 通道将流量转发到远程服务器端口
- 实时流量统计和连接数监控
- 支持多个并发连接

#### 3. HTTP 代理 (`internal/proxy/`)
- 支持 HTTP 和 HTTPS 代理
  - **标准 CONNECT 方法**：浏览器等客户端使用
   - **自动 TLS 握手检测**：ab、curl 等工具直接发送 TLS 握手时自动建立隧道
  - 从 TLS SNI 中提取目标主机名
- 实时流量统计和连接数监控
- 双向数据转发

### 关键特性

#### 统一的 SSH 通道
- **共享连接**：端口映射和 HTTP 代理复用同一个 SSH 连接
- **加密传输**：所有流量都通过 SSH 加密通道传输
- **配置驱动**：通过配置文件 (默认为 `.conf/config.toml`) 定义 SSH 服务器

#### 实时统计
- **流量监控**：实时显示接收/发送字节数
- **连接统计**：显示当前活动的 TCP 连接数
- **连接时长**：记录服务启动时间和每个连接的持续时间
- **详细日志**：记录所有连接、断开、错误等事件

#### Web 管理
- **Web 界面**：http://localhost:8080 (默认通过 `.conf/config.toml` 文件配置)
- **实时监控**：每 5 秒自动刷新连接状态
- **配置管理**：通过 Web 界面添加/删除 SSH 服务器和端口转发规则
- **服务控制**：支持启动、停止、重启服务

### 配置文件

使用 TOML 格式的配置文件（`.conf/config.toml`），支持注释。程序首次运行时会自动创建配置文件，以下为配置示例：

```toml
# 示例配置：服务器配置
[server]
port = "8080"  # Web 服务监听端口

# 示例配置：SSH 服务器配置
[[ssh_servers]]
id = "ssh-server-1"
name = "测试服务器"
host = "your ssh server"
port = 22
username = "your ssh account"
password = "your ssh password"
keep_alive_interval = 30

# 示例配置：端口转发规则
[[port_forwards]]
id = "fw-60080"
name = "60080"
ssh_server_id = "ssh-server-1"
listen_host = "0.0.0.0"
listen_port = 60080
remote_host = "example.com"
remote_port = 80
enabled = true

# 示例配置：HTTP 代理
[http_proxy]
enabled = true
listen = "0.0.0.0:61080"
ssh_server_id = "ssh-server-1"
```

### 使用场景

1. **访问远程 Web 服务**
   ```bash
   # 通过端口映射访问示例
   curl http://localhost:60080/
   ```

2. **使用 HTTP/HTTPS 代理**
   ```bash
   # 标准代理方式（浏览器/工具）
   curl -x localhost:61080 https://example.com/
   
   # 并发测试示例
   parallel -j 10 curl -x localhost:61080 https://example.com/ ::: {1..10}
   ```

## 构建说明

### 前置要求
- Go 1.21 或更高版本

### 构建步骤

1. 克隆仓库并进入项目目录
```bash
git clone https://github.com/p-zhou/pz-netlink.git
cd pz-netlink
```

2. 安装依赖
```bash
go mod download

# 或者使用代理
GOPROXY=https://goproxy.cn go mod download
```

3. 编译项目
   ```bash
   go build -o pz-netlink ./cmd/server
   ```

4. 运行程序
   ```bash
   ./pz-netlink
   ```

   **使用环境变量运行**
   ```bash
   # 设置 SSH 连接信息（推荐）
   export SSH_HOST="your-ssh-server.com"
   export SSH_PORT="22"
   export SSH_USERNAME="your-username"
   export SSH_PASSWORD="your-password"
   
   # 或直接在命令行中设置
   SSH_HOST="your-ssh-server.com" SSH_USERNAME="your-username" \
   SSH_PASSWORD="your-password" ./pz-netlink
   ```
   
   **Docker 部署示例**
   ```dockerfile
   FROM golang:1.21-alpine
   WORKDIR /app
   COPY pz-netlink /app/
   ENV SSH_HOST="your-ssh-server.com"
   ENV SSH_PORT="22"
   ENV SSH_USERNAME="your-username"
   ENV SSH_PASSWORD="your-password"
   CMD ["./pz-netlink"]
   ```

### 配置

程序默认使用 `.conf/config.toml` 作为配置文件，程序首次运行时会自动创建配置文件，根据需要修改配置后重新运行。
