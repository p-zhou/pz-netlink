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
	"pz-netlink/internal/proxy"
	"pz-netlink/internal/ssh"
	"pz-netlink/internal/storage"
	"pz-netlink/internal/web"
	"pz-netlink/pkg/types"
)

type App struct {
	store      *storage.Store
	config     *types.Config
	mux        *http.ServeMux
	handler    *web.Handler
	forwarders map[string]*forward.Forwarder
	httpProxy  *proxy.Proxy
	sshClients map[string]*ssh.Client
	logs       []*types.LogEntry
	logMu      sync.RWMutex
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
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

	a.handler = web.NewHandler(a, "./web/templates")
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
			a.log("ERROR", fmt.Sprintf("SSH server not found for forward %s", f.Name), f.ID)
			continue
		}
		fw := forward.NewForwarder(&f, client)
		if err := fw.Start(); err != nil {
			a.log("ERROR", fmt.Sprintf("Failed to start forward %s: %v", f.Name, err), f.ID)
			continue
		}
		a.forwarders[f.ID] = fw
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
		a.log("ERROR", fmt.Sprintf("Failed to start HTTP proxy: %v", err), "")
		return err
	}
	a.httpProxy = p
	a.log("INFO", "HTTP proxy started", "")
	return nil
}

func (a *App) Stop() {
	a.log("INFO", "Stopping SSH Proxy Service", "")
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
	configPath := flag.String("config", "config.json", "path to config file")
	port := flag.String("port", "8080", "web server port")
	flag.Parse()

	app := NewApp(*configPath)

	if err := app.LoadConfig(); err != nil {
		if os.IsNotExist(err) {
			cfg := &types.Config{
				Server: types.ServerConfig{
					Port:         *port,
					TemplatesDir: "./web/templates",
				},
				SSHServers:   []types.SSHServer{},
				PortForwards: []types.PortForward{},
				HTTPProxy:    types.HTTPProxyConfig{Enabled: false},
			}
			app.config = cfg
			app.store.Save(cfg)
		} else {
			log.Fatal(err)
		}
	}

	if err := app.Start(); err != nil {
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
		log.Printf("Server starting on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	app.Stop()
	server.Shutdown(context.Background())
}

var _ web.Manager = (*App)(nil)
