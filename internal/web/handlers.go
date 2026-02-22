package web

import (
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"pz-netlink/pkg/types"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

type Handler struct {
	templates *template.Template
	manager   Manager
}

func NewHandler(manager Manager) *Handler {
	templatesFS, err := fs.Sub(templateFS, "templates")
	if err != nil {
		panic(err)
	}
	templates := template.Must(template.ParseFS(templatesFS, "*.html"))
	return &Handler{
		templates: templates,
		manager:   manager,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	mux.HandleFunc("/", h.index)
	mux.HandleFunc("/connections", h.connections)
	mux.HandleFunc("/logs", h.logs)
	mux.HandleFunc("/ssh-servers", h.sshServers)
	mux.HandleFunc("/port-forwards", h.portForwards)
	mux.HandleFunc("/http-proxy", h.httpProxy)

	mux.HandleFunc("/api/connections", h.apiConnections)
	mux.HandleFunc("/api/logs", h.apiLogs)
	mux.HandleFunc("/api/ssh-servers", h.apiSSHServers)
	mux.HandleFunc("/api/port-forwards", h.apiPortForwards)
	mux.HandleFunc("/api/http-proxy", h.apiHTTPProxy)
	mux.HandleFunc("/api/restart", h.apiRestart)
	mux.HandleFunc("/test", h.test)
}

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	h.templates.ExecuteTemplate(w, "index.html", nil)
}

func (h *Handler) connections(w http.ResponseWriter, r *http.Request) {
	h.templates.ExecuteTemplate(w, "connections.html", nil)
}

func (h *Handler) logs(w http.ResponseWriter, r *http.Request) {
	h.templates.ExecuteTemplate(w, "logs.html", nil)
}

func (h *Handler) sshServers(w http.ResponseWriter, r *http.Request) {
	h.templates.ExecuteTemplate(w, "ssh_servers.html", nil)
}

func (h *Handler) portForwards(w http.ResponseWriter, r *http.Request) {
	h.templates.ExecuteTemplate(w, "port_forwards.html", nil)
}

func (h *Handler) httpProxy(w http.ResponseWriter, r *http.Request) {
	h.templates.ExecuteTemplate(w, "http_proxy.html", nil)
}

func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	sleepMs := r.URL.Query().Get("sleep")
	if sleepMs != "" {
		ms, err := strconv.Atoi(sleepMs)
		if err == nil && ms > 0 {
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(time.Now().Format(time.RFC3339Nano)))
}

func (h *Handler) apiConnections(w http.ResponseWriter, r *http.Request) {
	conns := h.manager.GetConnections()
	json.NewEncoder(w).Encode(conns)
}

func (h *Handler) apiLogs(w http.ResponseWriter, r *http.Request) {
	logs := h.manager.GetLogs()
	json.NewEncoder(w).Encode(logs)
}

func (h *Handler) apiSSHServers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(h.manager.GetSSHServers())
	case http.MethodPost:
		var server types.SSHServer
		json.NewDecoder(r.Body).Decode(&server)
		h.manager.AddSSHServer(&server)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	case http.MethodPut:
		var server types.SSHServer
		json.NewDecoder(r.Body).Decode(&server)
		h.manager.UpdateSSHServer(&server)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		h.manager.DeleteSSHServer(id)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) apiPortForwards(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(h.manager.GetPortForwards())
	case http.MethodPost:
		var forward types.PortForward
		json.NewDecoder(r.Body).Decode(&forward)
		h.manager.AddPortForward(&forward)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	case http.MethodPut:
		var forward types.PortForward
		json.NewDecoder(r.Body).Decode(&forward)
		h.manager.UpdatePortForward(&forward)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		h.manager.DeletePortForward(id)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) apiHTTPProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(h.manager.GetHTTPProxyConfig())
		return
	}
	if r.Method == http.MethodPut {
		var cfg types.HTTPProxyConfig
		json.NewDecoder(r.Body).Decode(&cfg)
		h.manager.UpdateHTTPProxyConfig(&cfg)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *Handler) apiRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.manager.Restart()

		servers := h.manager.GetSSHServers()
		forwards := h.manager.GetPortForwards()
		proxyCfg := h.manager.GetHTTPProxyConfig()

		enabledForwards := 0
		for _, f := range forwards {
			if f.Enabled {
				enabledForwards++
			}
		}

		result := map[string]interface{}{
			"status": "success",
			"ssh_servers": map[string]interface{}{
				"total":   len(servers),
				"enabled": len(servers),
			},
			"port_forwards": map[string]interface{}{
				"total":   len(forwards),
				"enabled": enabledForwards,
			},
			"http_proxy": map[string]interface{}{
				"enabled": proxyCfg.Enabled,
			},
		}

		json.NewEncoder(w).Encode(result)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

type Manager interface {
	GetConnections() []*types.ConnectionStatus
	GetLogs() []*types.LogEntry
	GetSSHServers() []*types.SSHServer
	AddSSHServer(s *types.SSHServer)
	UpdateSSHServer(s *types.SSHServer)
	DeleteSSHServer(id string)
	GetPortForwards() []*types.PortForward
	AddPortForward(p *types.PortForward)
	UpdatePortForward(p *types.PortForward)
	DeletePortForward(id string)
	GetHTTPProxyConfig() *types.HTTPProxyConfig
	UpdateHTTPProxyConfig(c *types.HTTPProxyConfig)
	Restart()
}
