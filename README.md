# pz-netlink
一个用于简单目的的 HTTP 代理及端口映射工具

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

或者直接使用 `go run` 运行：
```bash
go run ./cmd/server
```

### 配置
程序使用 `config.json` 作为配置文件，根据需要修改配置后重新运行。
