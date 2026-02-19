package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"ssh-proxy/pkg/types"
)

type Proxy struct {
	config    *types.HTTPProxyConfig
	sshDialer interface {
		Dial(network, addr string) (net.Conn, error)
	}
	listener  net.Listener
	running   atomic.Bool
	bytesIn   int64
	bytesOut  int64
	startTime time.Time
}

func NewProxy(cfg *types.HTTPProxyConfig, dialer interface {
	Dial(network, addr string) (net.Conn, error)
}) *Proxy {
	return &Proxy{
		config:    cfg,
		sshDialer: dialer,
	}
}

func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", p.config.Listen)
	if err != nil {
		return err
	}

	p.listener = listener
	p.running.Store(true)
	p.startTime = time.Now()

	go p.serveLoop()
	return nil
}

func (p *Proxy) serveLoop() {
	for p.running.Load() {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.running.Load() {
				continue
			}
			break
		}
		go p.handleConn(conn)
	}
}

func (p *Proxy) handleConn(client net.Conn) {
	defer client.Close()

	reader := bufio.NewReader(client)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(client, req)
	} else {
		p.handleHTTP(client, req)
	}
}

func (p *Proxy) handleConnect(client net.Conn, req *http.Request) {
	host := req.URL.Host
	if host == "" {
		host = req.URL.Path
	}

	remote, err := p.sshDialer.Dial("tcp", host)
	if err != nil {
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(remote, client)
		atomic.AddInt64(&p.bytesIn, n)
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, remote)
		atomic.AddInt64(&p.bytesOut, n)
	}()

	wg.Wait()
}

func (p *Proxy) handleHTTP(client net.Conn, req *http.Request) {
	host := req.URL.Host
	if host == "" {
		host = req.URL.Path
	}

	remote, err := p.sshDialer.Dial("tcp", host)
	if err != nil {
		return
	}
	defer remote.Close()

	req.Write(remote)
	io.Copy(client, remote)
}

func (p *Proxy) Stop() error {
	p.running.Store(false)
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

func (p *Proxy) GetStatus() *types.ConnectionStatus {
	status := "disconnected"
	if p.running.Load() && p.listener != nil {
		status = "connected"
	}

	return &types.ConnectionStatus{
		ID:        "http-proxy",
		Type:      "http_proxy",
		Name:      "HTTP Proxy",
		LocalAddr: p.config.Listen,
		Status:    status,
		BytesIn:   atomic.LoadInt64(&p.bytesIn),
		BytesOut:  atomic.LoadInt64(&p.bytesOut),
		StartedAt: p.startTime,
	}
}
