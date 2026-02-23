package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"pz-netlink/internal/forward"
	"pz-netlink/internal/logger"
	"pz-netlink/internal/proxy"
	"pz-netlink/internal/ssh"
	"pz-netlink/internal/storage"
	"pz-netlink/internal/web"
	"pz-netlink/pkg/types"
)

type App struct {
	store       *storage.Store
	config      *types.Config
	mux         *http.ServeMux
	handler     *web.Handler
	httpHandler http.Handler
	httpServer  *http.Server
	forwarders  map[string]*forward.Forwarder
	httpProxies map[string]*proxy.Proxy
	sshClients  map[string]*ssh.Client
	logs        []*types.LogEntry
	logMu       sync.RWMutex
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	statusCheck *time.Ticker
}

func NewApp(configPath string) *App {
	ctx, cancel := context.WithCancel(context.Background())
	return &App{
		store:       storage.New(configPath),
		mux:         http.NewServeMux(),
		forwarders:  make(map[string]*forward.Forwarder),
		httpProxies: make(map[string]*proxy.Proxy),
		sshClients:  make(map[string]*ssh.Client),
		ctx:         ctx,
		cancel:      cancel,
		httpServer:  &http.Server{},
	}
}

func (a *App) LoadConfig() error {
	cfg, err := a.store.Load()
	if err != nil {
		return err
	}

	a.migrateHTTPProxyConfig(cfg)

	a.config = cfg
	a.resolveEnvVars()
	return nil
}

func (a *App) migrateHTTPProxyConfig(cfg *types.Config) {
	if len(cfg.HTTPProxies) > 0 {
		return
	}
	legacyCfg, err := a.store.LoadRaw()
	if err != nil {
		return
	}
	if legacyCfg == nil {
		return
	}
	if !legacyCfg.HTTPProxy.Enabled && legacyCfg.HTTPProxy.Listen == "" {
		return
	}
	proxyID := fmt.Sprintf("proxy-%d", time.Now().UnixNano())
	cfg.HTTPProxies = []types.HTTPProxy{
		{
			ID:          proxyID,
			Name:        "HTTP代理",
			Enabled:     legacyCfg.HTTPProxy.Enabled,
			Listen:      legacyCfg.HTTPProxy.Listen,
			SSHServerID: legacyCfg.HTTPProxy.SSHServerID,
		},
	}
	logger.Info("已迁移旧版HTTP代理配置到新版多代理格式", "listen", legacyCfg.HTTPProxy.Listen)
}

func (a *App) SaveConfig() error {
	return a.store.Save(a.config)
}

func (a *App) resolveEnvVars() {
	envVarPattern := regexp.MustCompile(`^\$\{([^}:]+)(?::-([^}]*))?\}$`)

	a.config.Server.Password = a.expandEnvVar(a.config.Server.Password, envVarPattern, "server.password", true)

	for i := range a.config.SSHServers {
		fieldName := fmt.Sprintf("ssh_servers[%s].password", a.config.SSHServers[i].ID)
		a.config.SSHServers[i].Password = a.expandEnvVar(a.config.SSHServers[i].Password, envVarPattern, fieldName, false)
	}
}

func (a *App) expandEnvVar(value string, pattern *regexp.Regexp, fieldName string, isServerPassword bool) string {
	if !pattern.MatchString(value) {
		return value
	}
	match := pattern.FindStringSubmatch(value)
	if len(match) < 2 {
		return value
	}
	varName := match[1]
	hasDefault := strings.Contains(value, ":-")
	isDebug := logger.IsDebug()

	envValue := os.Getenv(varName)
	if envValue != "" {
		if isDebug {
			logger.Debug(fmt.Sprintf("变量 '%s' 使用环境变量值: field=%s value=%s", varName, fieldName, envValue))
		} else {
			logger.Info(fmt.Sprintf("变量 '%s' 使用环境变量值: field=%s", varName, fieldName))
		}
		return envValue
	}

	if hasDefault {
		defaultValue := ""
		if len(match) >= 3 {
			defaultValue = match[2]
		}
		if isDebug {
			logger.Debug(fmt.Sprintf("变量 '%s' 使用默认值 field=%s default=%s", varName, fieldName, defaultValue))
		} else {
			logger.Info(fmt.Sprintf("变量 '%s' 使用默认值 field=%s", varName, fieldName))
		}
		return defaultValue
	}

	if isServerPassword {
		logger.Error(fmt.Sprintf("错误: 环境变量 '%s' 未设置且无默认值 (field=%s)", varName, fieldName))
		log.Fatalf("错误: 环境变量 '%s' 未设置且无默认值 (field=%s)", varName, fieldName)
		return value
	}

	randomUUID := generateRandomUUID()
	if isDebug {
		logger.Debug(fmt.Sprintf("变量 '%s' 未设置，使用随机UUID: field=%s value=%s", varName, fieldName, randomUUID))
	} else {
		logger.Warn(fmt.Sprintf("变量 '%s' 未设置，使用随机UUID: field=%s", varName, fieldName))
	}
	return randomUUID
}

func generateRandomUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("random-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (a *App) log(level, msg, connID string) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	a.logs = append(a.logs, &types.LogEntry{
		Timestamp:    time.Now(),
		Level:        level,
		Message:      msg,
		ConnectionID: connID,
	})
	if len(a.logs) > 1000 {
		a.logs = a.logs[len(a.logs)-500:]
	}
}

func (a *App) Start() error {
	// 重新创建 mux 和 context，清除之前的状态
	a.mux = http.NewServeMux()
	ctx, cancel := context.WithCancel(context.Background())
	a.ctx = ctx
	a.cancel = cancel

	a.log("INFO", "启动 NetLink 服务", "")

	if err := a.startSSHClients(); err != nil {
		return err
	}

	if err := a.startPortForwards(); err != nil {
		return err
	}

	if err := a.startHTTPProxy(); err != nil {
		return err
	}

	a.startStatusCheck()

	a.handler = web.NewHandler(a)
	a.handler.RegisterRoutes(a.mux)

	// 如果配置了用户名和密码，启用 Basic Auth
	a.httpHandler = http.Handler(a.mux)
	if a.config.Server.Username != "" && a.config.Server.Password != "" {
		a.httpHandler = a.basicAuthMiddleware(a.mux)
	}

	// 更新 httpServer 的 handler
	if a.httpServer != nil {
		a.httpServer.Handler = a.httpHandler
	}

	a.log("INFO", "服务启动成功", "")
	return nil
}

func (a *App) startSSHClients() error {
	for _, s := range a.config.SSHServers {
		client := ssh.NewClient(&s)
		if err := client.Connect(); err != nil {
			a.log("ERROR", fmt.Sprintf("连接SSH服务器失败: %s (%v)", s.Name, err), s.ID)
			continue
		}
		client.StartKeepAlive()
		a.sshClients[s.ID] = client
		a.log("INFO", fmt.Sprintf("已连接到SSH服务器: %s", s.Name), s.ID)
	}
	return nil
}

func (a *App) startPortForwards() error {
	for _, f := range a.config.PortForwards {
		if !f.Enabled {
			continue
		}
		client, ok := a.sshClients[f.SSHServerID]
		if !ok {
			logger.Error("SSH服务器未找到",
				"forward_name", f.Name,
				"forward_id", f.ID,
				"ssh_server_id", f.SSHServerID,
			)
			a.log("ERROR", fmt.Sprintf("未找到用于端口转发 %s 的SSH服务器", f.Name), f.ID)
			continue
		}
		f_copy := f
		fw := forward.NewForwarder(&f_copy, client)
		if err := fw.Start(); err != nil {
			logger.Error("端口转发启动失败",
				"forward_name", f.Name,
				"forward_id", f.ID,
				"error", err,
			)
			a.log("ERROR", fmt.Sprintf("启动端口转发失败: %s (%v)", f.Name, err), f.ID)
			continue
		}
		a.forwarders[f.ID] = fw
		logger.Info("端口转发启动成功",
			"forward_name", f.Name,
			"forward_id", f.ID,
		)
		a.log("INFO", fmt.Sprintf("端口转发已启动: %s", f.Name), f.ID)
	}
	return nil
}

func (a *App) startHTTPProxy() error {
	for _, p := range a.config.HTTPProxies {
		if !p.Enabled {
			continue
		}
		var client *ssh.Client
		if p.SSHServerID != "" {
			client = a.sshClients[p.SSHServerID]
		}
		if client == nil {
			if len(a.sshClients) == 0 {
				logger.Warn("无可用SSH服务器用于HTTP代理，跳过启动", "proxy_name", p.Name)
				a.log("WARN", fmt.Sprintf("无可用SSH服务器用于HTTP代理，跳过启动: %s", p.Name), p.ID)
				continue
			}
			for _, c := range a.sshClients {
				client = c
				break
			}
		}

		p_copy := p
		proxyInstance := proxy.NewProxy(p_copy.ID, p_copy.Name, &p_copy, client)
		if err := proxyInstance.Start(); err != nil {
			logger.Error("HTTP代理启动失败", "proxy_name", p.Name, "error", err)
			a.log("ERROR", fmt.Sprintf("启动HTTP代理失败: %s (%v)", p.Name, err), p.ID)
			continue
		}
		a.httpProxies[p.ID] = proxyInstance
		logger.Info("HTTP代理启动成功", "proxy_name", p.Name, "proxy_id", p.ID)
		a.log("INFO", fmt.Sprintf("HTTP代理已启动: %s", p.Name), p.ID)
	}
	return nil
}

func (a *App) startStatusCheck() {
	a.statusCheck = time.NewTicker(60 * time.Second)
	go func() {
		for {
			select {
			case <-a.statusCheck.C:
				a.checkStatus()
			case <-a.ctx.Done():
				return
			}
		}
	}()
}

func (a *App) checkStatus() {
	logger.Info("===== 状态检查 =====")

	a.mu.RLock()
	defer a.mu.RUnlock()

	for id, client := range a.sshClients {
		connected := client.IsConnected()
		logger.Info("SSH服务器状态",
			"server_id", id,
			"connected", connected,
		)
	}

	for id, fw := range a.forwarders {
		status := fw.GetStatus()
		connections := fw.GetActiveConnections()
		logger.Info("端口转发状态",
			"forward_id", id,
			"name", status.Name,
			"status", status.Status,
			"active_connections", len(connections),
			"bytes_in", status.BytesIn,
			"bytes_out", status.BytesOut,
		)
		for _, conn := range connections {
			logger.Debug("活动连接",
				"forward_id", id,
				"client_ip", conn["client_ip"],
				"duration", conn["duration"],
			)
		}
	}

	for id, px := range a.httpProxies {
		status := px.GetStatus()
		logger.Info("HTTP代理状态",
			"proxy_id", id,
			"name", status.Name,
			"status", status.Status,
			"bytes_in", status.BytesIn,
			"bytes_out", status.BytesOut,
		)
	}

	logger.Info("===== 状态检查结束 =====")
}

func (a *App) Stop() {
	logger.Info("停止NetLink 服务")
	a.log("INFO", "停止 NetLink 服务", "")

	if a.statusCheck != nil {
		a.statusCheck.Stop()
	}

	a.cancel()

	for _, fw := range a.forwarders {
		fw.Stop()
	}
	a.forwarders = make(map[string]*forward.Forwarder)

	for _, px := range a.httpProxies {
		px.Stop()
	}
	a.httpProxies = make(map[string]*proxy.Proxy)

	for _, client := range a.sshClients {
		client.Close()
	}
	a.sshClients = make(map[string]*ssh.Client)

	a.log("INFO", "服务已停止", "")
	logger.Info("服务已停止")
}

func (a *App) Restart() {
	a.Stop()
	time.Sleep(time.Second)
	a.LoadConfig()
	a.Start()
}

func (a *App) GetConnections() []*types.ConnectionStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var conns []*types.ConnectionStatus
	for _, fw := range a.forwarders {
		conns = append(conns, fw.GetStatus())
	}
	for _, px := range a.httpProxies {
		conns = append(conns, px.GetStatus())
	}
	return sortConnections(conns)
}

func sortConnections(conns []*types.ConnectionStatus) []*types.ConnectionStatus {
	var portForwards []*types.ConnectionStatus
	var httpProxies []*types.ConnectionStatus

	for _, conn := range conns {
		if conn.Type == "http_proxy" {
			httpProxies = append(httpProxies, conn)
		} else {
			portForwards = append(portForwards, conn)
		}
	}

	sort.Slice(portForwards, func(i, j int) bool {
		return portForwards[i].Name < portForwards[j].Name
	})

	sort.Slice(httpProxies, func(i, j int) bool {
		return httpProxies[i].Name < httpProxies[j].Name
	})

	result := portForwards
	result = append(result, httpProxies...)
	return result
}

func (a *App) GetLogs() []*types.LogEntry {
	a.logMu.RLock()
	defer a.logMu.RUnlock()
	logs := make([]*types.LogEntry, len(a.logs))
	copy(logs, a.logs)
	return logs
}

func (a *App) GetSSHServers() []*types.SSHServer {
	a.mu.RLock()
	defer a.mu.RUnlock()
	servers := make([]*types.SSHServer, len(a.config.SSHServers))
	for i := range a.config.SSHServers {
		servers[i] = &a.config.SSHServers[i]
	}
	return servers
}

func (a *App) AddSSHServer(s *types.SSHServer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s.ID = fmt.Sprintf("ssh-%d", time.Now().UnixNano())
	a.config.SSHServers = append(a.config.SSHServers, *s)
	a.store.Save(a.config)
	a.log("INFO", fmt.Sprintf("SSH服务器已添加: %s (%s@%s:%d)", s.Name, s.Username, s.Host, s.Port), s.ID)
	logger.Info("SSH服务器已添加", "name", s.Name, "id", s.ID, "host", s.Host, "port", s.Port)

	go func() {
		client := ssh.NewClient(s)
		if err := client.Connect(); err != nil {
			a.log("ERROR", fmt.Sprintf("连接失败: %v", err), s.ID)
			return
		}
		client.StartKeepAlive()
		a.sshClients[s.ID] = client
		a.log("INFO", fmt.Sprintf("SSH服务器已添加: %s", s.Name), s.ID)
	}()
}

func (a *App) UpdateSSHServer(s *types.SSHServer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, srv := range a.config.SSHServers {
		if srv.ID == s.ID {
			a.config.SSHServers[i] = *s
			break
		}
	}
	a.store.Save(a.config)
	a.log("INFO", fmt.Sprintf("SSH服务器已修改: %s (%s@%s:%d)", s.Name, s.Username, s.Host, s.Port), s.ID)
	logger.Info("SSH服务器已修改", "name", s.Name, "id", s.ID, "host", s.Host, "port", s.Port)
}

func (a *App) DeleteSSHServer(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var serverName string
	for _, s := range a.config.SSHServers {
		if s.ID == id {
			serverName = s.Name
			break
		}
	}

	if client, ok := a.sshClients[id]; ok {
		client.Close()
		delete(a.sshClients, id)
	}

	for i, s := range a.config.SSHServers {
		if s.ID == id {
			a.config.SSHServers = append(a.config.SSHServers[:i], a.config.SSHServers[i+1:]...)
			break
		}
	}
	a.store.Save(a.config)
	a.log("INFO", fmt.Sprintf("SSH服务器已删除: %s", serverName), id)
	logger.Info("SSH服务器已删除", "name", serverName, "id", id)
}

func (a *App) GetPortForwards() []*types.PortForward {
	a.mu.RLock()
	defer a.mu.RUnlock()
	forwards := make([]*types.PortForward, len(a.config.PortForwards))
	for i := range a.config.PortForwards {
		forwards[i] = &a.config.PortForwards[i]
	}
	sort.Slice(forwards, func(i, j int) bool {
		return forwards[i].Name < forwards[j].Name
	})
	return forwards
}

func (a *App) AddPortForward(p *types.PortForward) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p.ID = fmt.Sprintf("fw-%d", time.Now().UnixNano())
	a.config.PortForwards = append(a.config.PortForwards, *p)
	a.store.Save(a.config)
	a.log("INFO", fmt.Sprintf("端口转发已添加: %s (%s:%d -> %s:%d)", p.Name, p.ListenHost, p.ListenPort, p.RemoteHost, p.RemotePort), p.ID)
	logger.Info("端口转发已添加", "name", p.Name, "id", p.ID, "enabled", p.Enabled, "listen", fmt.Sprintf("%s:%d", p.ListenHost, p.ListenPort), "remote", fmt.Sprintf("%s:%d", p.RemoteHost, p.RemotePort))

	if p.Enabled {
		go a.startOnePortForward(p)
	}
}

func (a *App) startOnePortForward(p *types.PortForward) {
	client, ok := a.sshClients[p.SSHServerID]
	if !ok {
		a.log("ERROR", "未找到SSH服务器", p.ID)
		return
	}
	f_copy := *p
	fw := forward.NewForwarder(&f_copy, client)
	if err := fw.Start(); err != nil {
		a.log("ERROR", fmt.Sprintf("启动失败: %v", err), p.ID)
		return
	}
	a.mu.Lock()
	a.forwarders[p.ID] = fw
	a.mu.Unlock()
	a.log("INFO", fmt.Sprintf("端口转发已添加: %s", p.Name), p.ID)
}

func (a *App) UpdatePortForward(p *types.PortForward) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, f := range a.config.PortForwards {
		if f.ID == p.ID {
			oldEnabled := a.config.PortForwards[i].Enabled
			a.config.PortForwards[i] = *p

			if oldEnabled && !p.Enabled {
				if fw, ok := a.forwarders[p.ID]; ok {
					fw.Stop()
					delete(a.forwarders, p.ID)
				}
			} else if !oldEnabled && p.Enabled {
				go a.startOnePortForward(p)
			} else if p.Enabled {
				if fw, ok := a.forwarders[p.ID]; ok {
					fw.Stop()
				}
				go a.startOnePortForward(p)
			}
			break
		}
	}
	a.store.Save(a.config)
	a.log("INFO", fmt.Sprintf("端口转发已修改: %s (%s:%d -> %s:%d)", p.Name, p.ListenHost, p.ListenPort, p.RemoteHost, p.RemotePort), p.ID)
	logger.Info("端口转发已修改", "name", p.Name, "id", p.ID, "enabled", p.Enabled, "listen", fmt.Sprintf("%s:%d", p.ListenHost, p.ListenPort), "remote", fmt.Sprintf("%s:%d", p.RemoteHost, p.RemotePort))
}

func (a *App) DeletePortForward(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var forwardName string
	for _, f := range a.config.PortForwards {
		if f.ID == id {
			forwardName = f.Name
			break
		}
	}

	if fw, ok := a.forwarders[id]; ok {
		fw.Stop()
		delete(a.forwarders, id)
	}

	for i, f := range a.config.PortForwards {
		if f.ID == id {
			a.config.PortForwards = append(a.config.PortForwards[:i], a.config.PortForwards[i+1:]...)
			break
		}
	}
	a.store.Save(a.config)
	a.log("INFO", fmt.Sprintf("端口转发已删除: %s", forwardName), id)
	logger.Info("端口转发已删除", "name", forwardName, "id", id)
}

func (a *App) GetHTTPProxies() []*types.HTTPProxy {
	a.mu.RLock()
	defer a.mu.RUnlock()
	proxies := make([]*types.HTTPProxy, len(a.config.HTTPProxies))
	for i := range a.config.HTTPProxies {
		proxies[i] = &a.config.HTTPProxies[i]
	}
	sort.Slice(proxies, func(i, j int) bool {
		return proxies[i].Name < proxies[j].Name
	})
	return proxies
}

func (a *App) AddHTTPProxy(p *types.HTTPProxy) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p.ID = fmt.Sprintf("proxy-%d", time.Now().UnixNano())
	a.config.HTTPProxies = append(a.config.HTTPProxies, *p)
	a.store.Save(a.config)
	a.log("INFO", fmt.Sprintf("HTTP代理已添加: %s (%s)", p.Name, p.Listen), p.ID)
	logger.Info("HTTP代理已添加", "name", p.Name, "id", p.ID, "enabled", p.Enabled, "listen", p.Listen, "ssh_server_id", p.SSHServerID)

	if p.Enabled {
		go a.startOneHTTPProxy(p)
	}
}

func (a *App) startOneHTTPProxy(p *types.HTTPProxy) {
	var client *ssh.Client
	if p.SSHServerID != "" {
		client = a.sshClients[p.SSHServerID]
	}
	if client == nil {
		if len(a.sshClients) == 0 {
			a.log("ERROR", "无可用SSH服务器", p.ID)
			return
		}
		for _, c := range a.sshClients {
			client = c
			break
		}
	}
	p_copy := *p
	proxyInstance := proxy.NewProxy(p_copy.ID, p_copy.Name, &p_copy, client)
	if err := proxyInstance.Start(); err != nil {
		a.log("ERROR", fmt.Sprintf("启动失败: %v", err), p.ID)
		return
	}
	a.mu.Lock()
	a.httpProxies[p.ID] = proxyInstance
	a.mu.Unlock()
	a.log("INFO", fmt.Sprintf("HTTP代理已添加: %s", p.Name), p.ID)
}

func (a *App) UpdateHTTPProxy(p *types.HTTPProxy) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i, proxy := range a.config.HTTPProxies {
		if proxy.ID == p.ID {
			oldEnabled := a.config.HTTPProxies[i].Enabled
			a.config.HTTPProxies[i] = *p

			if oldEnabled && !p.Enabled {
				if px, ok := a.httpProxies[p.ID]; ok {
					px.Stop()
					delete(a.httpProxies, p.ID)
				}
			} else if !oldEnabled && p.Enabled {
				go a.startOneHTTPProxy(p)
			} else if p.Enabled {
				if px, ok := a.httpProxies[p.ID]; ok {
					px.Stop()
				}
				go a.startOneHTTPProxy(p)
			}
			break
		}
	}
	a.store.Save(a.config)
	a.log("INFO", fmt.Sprintf("HTTP代理已修改: %s (%s)", p.Name, p.Listen), p.ID)
	logger.Info("HTTP代理已修改", "name", p.Name, "id", p.ID, "enabled", p.Enabled, "listen", p.Listen, "ssh_server_id", p.SSHServerID)
}

func (a *App) DeleteHTTPProxy(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var proxyName string
	for _, p := range a.config.HTTPProxies {
		if p.ID == id {
			proxyName = p.Name
			break
		}
	}

	if px, ok := a.httpProxies[id]; ok {
		px.Stop()
		delete(a.httpProxies, id)
	}

	for i, p := range a.config.HTTPProxies {
		if p.ID == id {
			a.config.HTTPProxies = append(a.config.HTTPProxies[:i], a.config.HTTPProxies[i+1:]...)
			break
		}
	}
	a.store.Save(a.config)
	a.log("INFO", fmt.Sprintf("HTTP代理已删除: %s", proxyName), id)
	logger.Info("HTTP代理已删除", "name", proxyName, "id", id)
}

func (a *App) GetServerConfig() *types.ServerConfig {
	return &a.config.Server
}

func (a *App) basicAuthMiddleware(next http.Handler) http.Handler {
	expectedAuth := base64.StdEncoding.EncodeToString([]byte(a.config.Server.Username + ":" + a.config.Server.Password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(auth, "Basic ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		credentials := strings.TrimPrefix(auth, "Basic ")
		if credentials != expectedAuth {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	configPath := flag.String("config", ".conf/config.toml", "path to config file")
	port := flag.String("port", "8080", "web server port")
	logLevel := flag.String("log-level", "INFO", "log level: DEBUG, INFO, WARN, ERROR")
	flag.Parse()

	logger.Init(*logLevel)

	logger.Info("===== 服务启动 =====")
	logger.Info("加载配置文件", "config_path", *configPath)

	app := NewApp(*configPath)

	if err := app.LoadConfig(); err != nil {
		if os.IsNotExist(err) {
			logger.Warn("配置文件不存在，创建默认配置", "config_path", *configPath)
			cfg := &types.Config{
				Server: types.ServerConfig{
					Port: *port,
				},
				SSHServers:   []types.SSHServer{},
				PortForwards: []types.PortForward{},
				HTTPProxies:  []types.HTTPProxy{},
			}
			app.config = cfg
			app.store.Save(cfg)
		} else {
			logger.Error("加载配置文件失败", "error", err)
			log.Fatal(err)
		}
	}

	if err := app.Start(); err != nil {
		logger.Error("服务启动失败", "error", err)
		log.Fatal(err)
	}

	// 命令行参数优先于配置文件
	serverPort := *port
	// 检查用户是否显式指定了 -port 参数
	portExplicitlySet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			portExplicitlySet = true
		}
	})
	if !portExplicitlySet && app.config.Server.Port != "" {
		serverPort = app.config.Server.Port
	}
	addr := ":" + serverPort

	app.httpServer = &http.Server{
		Addr:    addr,
		Handler: app.httpHandler,
	}

	go func() {
		logger.Info("Web服务器启动", "addr", addr)
		log.Printf("Server starting on %s", addr)
		if err := app.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Web服务器错误", "error", err)
			log.Fatal(err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("收到停止信号")
	log.Println("Shutting down...")
	app.Stop()
	app.httpServer.Shutdown(context.Background())
	logger.Info("===== 服务停止 =====")
}

var _ web.Manager = (*App)(nil)
