package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	forwarders  map[string]*forward.Forwarder
	httpProxy   *proxy.Proxy
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
		store:      storage.New(configPath),
		mux:        http.NewServeMux(),
		forwarders: make(map[string]*forward.Forwarder),
		sshClients: make(map[string]*ssh.Client),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (a *App) LoadConfig() error {
	cfg, err := a.store.Load()
	if err != nil {
		return err
	}
	a.config = cfg
	return nil
}

func (a *App) SaveConfig() error {
	return a.store.Save(a.config)
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
	a.log("INFO", "Starting SSH Proxy Service", "")

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

	a.log("INFO", "Service started successfully", "")
	return nil
}

func (a *App) startSSHClients() error {
	for _, s := range a.config.SSHServers {
		client := ssh.NewClient(&s)
		if err := client.Connect(); err != nil {
			a.log("ERROR", fmt.Sprintf("Failed to connect to SSH server %s: %v", s.Name, err), s.ID)
			continue
		}
		client.StartKeepAlive()
		a.sshClients[s.ID] = client
		a.log("INFO", fmt.Sprintf("Connected to SSH server: %s", s.Name), s.ID)
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
			a.log("ERROR", fmt.Sprintf("SSH server not found for forward %s", f.Name), f.ID)
			continue
		}
		fw := forward.NewForwarder(&f, client)
		if err := fw.Start(); err != nil {
			logger.Error("端口转发启动失败",
				"forward_name", f.Name,
				"forward_id", f.ID,
				"error", err,
			)
			a.log("ERROR", fmt.Sprintf("Failed to start forward %s: %v", f.Name, err), f.ID)
			continue
		}
		a.forwarders[f.ID] = fw
		logger.Info("端口转发启动成功",
			"forward_name", f.Name,
			"forward_id", f.ID,
		)
		a.log("INFO", fmt.Sprintf("Started port forward: %s", f.Name), f.ID)
	}
	return nil
}

func (a *App) startHTTPProxy() error {
	if !a.config.HTTPProxy.Enabled {
		return nil
	}
	var client *ssh.Client
	if a.config.HTTPProxy.SSHServerID != "" {
		client = a.sshClients[a.config.HTTPProxy.SSHServerID]
	}
	if client == nil {
		if len(a.sshClients) == 0 {
			logger.Error("无可用SSH服务器用于HTTP代理")
			a.log("ERROR", "No SSH server available for HTTP proxy", "")
			return fmt.Errorf("no SSH server available")
		}
		for _, c := range a.sshClients {
			client = c
			break
		}
	}

	p := proxy.NewProxy(&a.config.HTTPProxy, client)
	if err := p.Start(); err != nil {
		logger.Error("HTTP代理启动失败", "error", err)
		a.log("ERROR", fmt.Sprintf("Failed to start HTTP proxy: %v", err), "")
		return err
	}
	a.httpProxy = p
	a.log("INFO", "HTTP proxy started", "")
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

	if a.httpProxy != nil {
		status := a.httpProxy.GetStatus()
		logger.Info("HTTP代理状态",
			"status", status.Status,
			"bytes_in", status.BytesIn,
			"bytes_out", status.BytesOut,
		)
	}

	logger.Info("===== 状态检查结束 =====")
}

func (a *App) Stop() {
	logger.Info("停止SSH代理服务")
	a.log("INFO", "Stopping SSH Proxy Service", "")

	if a.statusCheck != nil {
		a.statusCheck.Stop()
	}

	a.cancel()

	for _, fw := range a.forwarders {
		fw.Stop()
	}
	a.forwarders = make(map[string]*forward.Forwarder)

	if a.httpProxy != nil {
		a.httpProxy.Stop()
		a.httpProxy = nil
	}

	for _, client := range a.sshClients {
		client.Close()
	}
	a.sshClients = make(map[string]*ssh.Client)

	a.log("INFO", "Service stopped", "")
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
	if a.httpProxy != nil {
		conns = append(conns, a.httpProxy.GetStatus())
	}
	return conns
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
	for i, s := range a.config.SSHServers {
		servers[i] = &s
	}
	return servers
}

func (a *App) AddSSHServer(s *types.SSHServer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s.ID = fmt.Sprintf("ssh-%d", time.Now().UnixNano())
	a.config.SSHServers = append(a.config.SSHServers, *s)
	a.store.Save(a.config)

	go func() {
		client := ssh.NewClient(s)
		if err := client.Connect(); err != nil {
			a.log("ERROR", fmt.Sprintf("Failed to connect: %v", err), s.ID)
			return
		}
		client.StartKeepAlive()
		a.sshClients[s.ID] = client
		a.log("INFO", fmt.Sprintf("SSH server added: %s", s.Name), s.ID)
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
}

func (a *App) DeleteSSHServer(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()

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
	a.log("INFO", fmt.Sprintf("SSH server deleted: %s", id), id)
}

func (a *App) GetPortForwards() []*types.PortForward {
	a.mu.RLock()
	defer a.mu.RUnlock()
	forwards := make([]*types.PortForward, len(a.config.PortForwards))
	for i, f := range a.config.PortForwards {
		forwards[i] = &f
	}
	return forwards
}

func (a *App) AddPortForward(p *types.PortForward) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p.ID = fmt.Sprintf("fw-%d", time.Now().UnixNano())
	a.config.PortForwards = append(a.config.PortForwards, *p)
	a.store.Save(a.config)

	if p.Enabled {
		go a.startOnePortForward(p)
	}
}

func (a *App) startOnePortForward(p *types.PortForward) {
	client, ok := a.sshClients[p.SSHServerID]
	if !ok {
		a.log("ERROR", "SSH server not found", p.ID)
		return
	}
	fw := forward.NewForwarder(p, client)
	if err := fw.Start(); err != nil {
		a.log("ERROR", fmt.Sprintf("Failed to start: %v", err), p.ID)
		return
	}
	a.mu.Lock()
	a.forwarders[p.ID] = fw
	a.mu.Unlock()
	a.log("INFO", fmt.Sprintf("Port forward added: %s", p.Name), p.ID)
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
}

func (a *App) DeletePortForward(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()

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
	a.log("INFO", fmt.Sprintf("Port forward deleted: %s", id), id)
}

func (a *App) GetHTTPProxyConfig() *types.HTTPProxyConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return &a.config.HTTPProxy
}

func (a *App) UpdateHTTPProxyConfig(c *types.HTTPProxyConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()

	oldEnabled := a.config.HTTPProxy.Enabled
	a.config.HTTPProxy = *c

	if oldEnabled && !c.Enabled {
		if a.httpProxy != nil {
			a.httpProxy.Stop()
			a.httpProxy = nil
		}
	} else if !oldEnabled && c.Enabled {
		go a.startHTTPProxy()
	} else if c.Enabled {
		if a.httpProxy != nil {
			a.httpProxy.Stop()
		}
		go a.startHTTPProxy()
	}

	a.store.Save(a.config)
	a.log("INFO", "HTTP proxy config updated", "")
}

func (a *App) GetServerConfig() *types.ServerConfig {
	return &a.config.Server
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
				HTTPProxy:    types.HTTPProxyConfig{Enabled: false},
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

	addr := ":" + app.config.Server.Port
	if app.config.Server.Port == "" {
		addr = ":" + *port
	}

	server := &http.Server{
		Addr:    addr,
		Handler: app.mux,
	}

	go func() {
		logger.Info("Web服务器启动", "addr", addr)
		log.Printf("Server starting on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
	server.Shutdown(context.Background())
	logger.Info("===== 服务停止 =====")
}

var _ web.Manager = (*App)(nil)
