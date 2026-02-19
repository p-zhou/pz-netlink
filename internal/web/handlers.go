package web

import (
	"encoding/json"
	"html/template"
	"net/http"

	"pz-netlink/pkg/types"
)

type Handler struct {
	templates *template.Template
	manager   Manager
}

func NewHandler(manager Manager, templatesDir string) *Handler {
	templates := template.Must(template.ParseGlob(templatesDir + "/*.html"))
	return &Handler{
		templates: templates,
		manager:   manager,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
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
		go h.manager.Restart()
		json.NewEncoder(w).Encode(map[string]string{"status": "restarting"})
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
