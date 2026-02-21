package forward

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"pz-netlink/internal/logger"
	"pz-netlink/internal/ssh"
	"pz-netlink/pkg/types"
)

type Forwarder struct {
	config    *types.PortForward
	client    *ssh.Client
	listener  net.Listener
	conns     map[string]*connInfo
	mu        sync.RWMutex
	bytesIn   int64
	bytesOut  int64
	startedAt time.Time
	running   atomic.Bool
}

type connInfo struct {
	local    net.Conn
	remote   net.Conn
	startAt  time.Time
	clientIP string
}

func NewForwarder(cfg *types.PortForward, client *ssh.Client) *Forwarder {
	return &Forwarder{
		config: cfg,
		client: client,
		conns:  make(map[string]*connInfo),
	}
}

func (f *Forwarder) Start() error {
	addr := fmt.Sprintf("%s:%d", f.config.ListenHost, f.config.ListenPort)
	logger.Info("启动端口转发服务",
		"forward_name", f.config.Name,
		"forward_id", f.config.ID,
		"listen_addr", addr,
		"remote_addr", fmt.Sprintf("%s:%d", f.config.RemoteHost, f.config.RemotePort),
		"ssh_server_id", f.config.SSHServerID,
	)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("端口转发服务启动失败",
			"forward_name", f.config.Name,
			"forward_id", f.config.ID,
			"listen_addr", addr,
			"error", err,
		)
		return err
	}

	f.listener = listener
	f.startedAt = time.Now()
	f.running.Store(true)

	go f.acceptLoop()
	logger.Info("端口转发服务启动成功",
		"forward_name", f.config.Name,
		"forward_id", f.config.ID,
		"listen_addr", addr,
	)
	return nil
}

func (f *Forwarder) acceptLoop() {
	for f.running.Load() {
		conn, err := f.listener.Accept()
		if err != nil {
			if f.running.Load() {
				continue
			}
			break
		}
		go f.handleConn(conn)
	}
}

func (f *Forwarder) handleConn(local net.Conn) {
	clientIP := local.RemoteAddr().String()
	logger.Info("端口转发新连接",
		"forward_name", f.config.Name,
		"forward_id", f.config.ID,
		"client_ip", clientIP,
		"remote_addr", fmt.Sprintf("%s:%d", f.config.RemoteHost, f.config.RemotePort),
	)

	startTime := time.Now()
	remote, err := f.client.Dial("tcp", fmt.Sprintf("%s:%d", f.config.RemoteHost, f.config.RemotePort))
	if err != nil {
		logger.Error("端口转发远程连接失败",
			"forward_name", f.config.Name,
			"forward_id", f.config.ID,
			"client_ip", clientIP,
			"remote_addr", fmt.Sprintf("%s:%d", f.config.RemoteHost, f.config.RemotePort),
			"error", err,
		)
		local.Close()
		return
	}

	logger.Info("端口转发远程连接成功",
		"forward_name", f.config.Name,
		"forward_id", f.config.ID,
		"client_ip", clientIP,
		"remote_addr", fmt.Sprintf("%s:%d", f.config.RemoteHost, f.config.RemotePort),
		"duration", time.Since(startTime).String(),
	)

	connID := fmt.Sprintf("%s-%d", clientIP, time.Now().UnixNano())
	info := &connInfo{
		local:    local,
		remote:   remote,
		startAt:  time.Now(),
		clientIP: clientIP,
	}

	f.mu.Lock()
	f.conns[connID] = info
	f.mu.Unlock()

	go f.copyToRemote(local, remote)
	go f.copyFromRemote(remote, local)
}

func (f *Forwarder) copyToRemote(dst, src net.Conn) {
	n, err := io.Copy(dst, src)
	atomic.AddInt64(&f.bytesIn, n)
	dst.Close()
	src.Close()
	if err != nil {
		logger.Warn("端口转发数据传输错误(本地->远程)",
			"forward_name", f.config.Name,
			"forward_id", f.config.ID,
			"bytes", n,
			"error", err,
		)
	}
	f.removeConn(dst)
}

func (f *Forwarder) copyFromRemote(dst, src net.Conn) {
	n, err := io.Copy(dst, src)
	atomic.AddInt64(&f.bytesOut, n)
	dst.Close()
	src.Close()
	if err != nil {
		logger.Warn("端口转发数据传输错误(远程->本地)",
			"forward_name", f.config.Name,
			"forward_id", f.config.ID,
			"bytes", n,
			"error", err,
		)
	}
	f.removeConn(src)
}

func (f *Forwarder) removeConn(conn net.Conn) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, info := range f.conns {
		if info.local == conn || info.remote == conn {
			duration := time.Since(info.startAt)
			logger.Info("端口转发连接关闭",
				"forward_name", f.config.Name,
				"forward_id", f.config.ID,
				"client_ip", info.clientIP,
				"duration", duration.String(),
			)
			delete(f.conns, id)
			break
		}
	}
}

func (f *Forwarder) Stop() error {
	logger.Info("停止端口转发服务",
		"forward_name", f.config.Name,
		"forward_id", f.config.ID,
		"active_connections", len(f.conns),
	)
	f.running.Store(false)
	if f.listener != nil {
		f.listener.Close()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, info := range f.conns {
		info.local.Close()
		info.remote.Close()
	}
	f.conns = make(map[string]*connInfo)
	return nil
}

func (f *Forwarder) GetStatus() *types.ConnectionStatus {
	status := "disconnected"
	if f.running.Load() && f.listener != nil {
		status = "connected"
	}

	return &types.ConnectionStatus{
		ID:         f.config.ID,
		Type:       "port_forward",
		Name:       f.config.Name,
		LocalAddr:  fmt.Sprintf("%s:%d", f.config.ListenHost, f.config.ListenPort),
		RemoteAddr: fmt.Sprintf("%s:%d", f.config.RemoteHost, f.config.RemotePort),
		Status:     status,
		BytesIn:    atomic.LoadInt64(&f.bytesIn),
		BytesOut:   atomic.LoadInt64(&f.bytesOut),
		StartedAt:  f.startedAt,
	}
}

func (f *Forwarder) GetActiveConnections() []map[string]interface{} {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make([]map[string]interface{}, 0, len(f.conns))
	for id, info := range f.conns {
		result = append(result, map[string]interface{}{
			"id":         id,
			"client_ip":  info.clientIP,
			"started_at": info.startAt,
			"duration":   time.Since(info.startAt).String(),
		})
	}
	return result
}
