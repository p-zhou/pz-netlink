package forward

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ssh-proxy/internal/ssh"
	"ssh-proxy/pkg/types"
)

type Forwarder struct {
	config   *types.PortForward
	client   *ssh.Client
	listener net.Listener
	conns    map[string]*connInfo
	mu       sync.RWMutex
	bytesIn  int64
	bytesOut int64
	running  atomic.Bool
}

type connInfo struct {
	local   net.Conn
	remote  net.Conn
	startAt time.Time
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
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	f.listener = listener
	f.running.Store(true)

	go f.acceptLoop()
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
	remote, err := f.client.Dial("tcp", fmt.Sprintf("%s:%d", f.config.RemoteHost, f.config.RemotePort))
	if err != nil {
		local.Close()
		return
	}

	connID := fmt.Sprintf("%s-%d", local.RemoteAddr().String(), time.Now().UnixNano())
	info := &connInfo{local: local, remote: remote, startAt: time.Now()}

	f.mu.Lock()
	f.conns[connID] = info
	f.mu.Unlock()

	go f.copy(local, remote, "local->remote")
	go f.copy(remote, local, "remote->local")
}

func (f *Forwarder) copy(dst, src net.Conn, direction string) {
	n, _ := io.Copy(dst, src)
	atomic.AddInt64(&f.bytesIn, n)
	dst.Close()
	src.Close()

	f.mu.Lock()
	defer f.mu.Unlock()
	for id, info := range f.conns {
		if info.local == dst || info.remote == dst {
			delete(f.conns, id)
			break
		}
	}
}

func (f *Forwarder) Stop() error {
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
	f.mu.RLock()
	defer f.mu.RUnlock()

	status := "disconnected"
	if f.running.Load() && f.listener != nil {
		status = "connected"
	}

	return &types.ConnectionStatus{
		ID:          f.config.ID,
		Type:        "port_forward",
		Name:        f.config.Name,
		LocalAddr:   fmt.Sprintf("%s:%d", f.config.ListenHost, f.config.ListenPort),
		RemoteAddr:  fmt.Sprintf("%s:%d", f.config.RemoteHost, f.config.RemotePort),
		Status:      status,
		BytesIn:     atomic.LoadInt64(&f.bytesIn),
		BytesOut:    atomic.LoadInt64(&f.bytesOut),
		StartedAt:   time.Now(),
	}
}

func (f *Forwarder) GetConnections() []*connInfo {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make([]*connInfo, 0, len(f.conns))
	for _, info := range f.conns {
(result, info)
		result = append	}
	return result
}
