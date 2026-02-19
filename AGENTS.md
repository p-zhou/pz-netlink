# Go 网络服务开发指南

## 项目架构原则

### 1. 目录结构
```
project/
├── cmd/                    # 入口程序
│   └── server/
│       └── main.go
├── internal/               # 私有代码
│   ├── config/             # 配置管理
│   ├── proxy/              # 代理核心逻辑
│   ├── ssh/                # SSH 连接管理
│   ├── web/                # Web 服务器
│   │   ├── handlers/       # HTTP 处理器
│   │   ├── templates/      # HTML 模板
│   │   └── static/         # 静态资源
│   └── storage/            # 数据存储
├── pkg/                    # 公共库
├── go.mod
└── go.sum
```

### 2. 依赖原则
- **最小依赖**: 只引入必要的第三方库
- **优先标准库**: 优先使用 Go 标准库
- **小型应用推荐**:
  - `golang.org/x/crypto/ssh` - SSH 客户端
  - `github.com/gorilla/mux` 或标准库 `net/http` - HTTP 路由
  - `github.com/go-yaml/yaml` - YAML 配置
  - 无需 ORM，使用简单的 JSON 文件或 SQLite

### 3. 配置管理
- 使用 YAML/JSON 配置文件
- 支持环境变量覆盖
- 配置热加载能力
- 敏感信息不要硬编码

### 4. 日志记录
- 使用结构化日志 (zap 或 log/slog)
- 区分日志级别: DEBUG, INFO, WARN, ERROR
- 日志包含: 时间、级别、模块、消息、上下文

### 5. 错误处理
- 向上传播错误，保留上下文
- 使用 wrap 错误添加调用栈信息
- 避免 panic，用于不可恢复的错误

### 6. 并发处理
- 使用 context 控制超时和取消
- 使用 sync.WaitGroup 管理 goroutine
- 使用 channel 进行 goroutine 通信
- 注意资源泄露: 确保 goroutine 有退出机制

### 7. HTTP 服务开发
- 使用 net/http 标准库或轻量路由库
- 中间件模式: 日志、认证、限流
- Graceful shutdown 处理
- 合理的超时设置

### 8. SSH 代理开发
- 连接池管理 SSH 会话
- 心跳保活
- 自动重连机制
- 端口转发: 本地 -> SSH -> 远程
- HTTP 代理: 劫持 CONNECT 请求

### 9. Web UI
- 使用 Go 模板引擎 (html/template)
- 保持 HTML 简单，使用 JS 增强交互
- 避免引入大型前端框架
- API 使用 RESTful 风格
- 考虑安全性: 认证、会话管理

### 10. 测试
- 单元测试覆盖核心逻辑
- 集成测试验证组件交互
- 基准测试性能关键代码

### 11. 部署
- 静态编译，单二进制部署
- 支持命令行参数和配置文件
- 提供健康检查接口

### 12. 监控和运维
- /health 健康检查端点
- /metrics 指标端点 (可选)
- 配置变更可通过 Web UI 管理
