package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"pz-netlink/internal/logger"
	"pz-netlink/pkg/types"
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
	logger.Info("启动HTTP代理服务",
		"listen_addr", p.config.Listen,
		"ssh_server_id", p.config.SSHServerID,
	)
	listener, err := net.Listen("tcp", p.config.Listen)
	if err != nil {
		logger.Error("HTTP代理服务启动失败",
			"listen_addr", p.config.Listen,
			"error", err,
		)
		return err
	}

	p.listener = listener
	p.running.Store(true)
	p.startTime = time.Now()

	go p.serveLoop()
	logger.Info("HTTP代理服务启动成功",
		"listen_addr", p.config.Listen,
	)
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

	clientIP := client.RemoteAddr().String()
	logger.Debug("HTTP代理新连接",
		"client_ip", clientIP,
		"listen_addr", p.config.Listen,
	)

	reader := bufio.NewReader(client)
	req, err := http.ReadRequest(reader)
	if err != nil {
		logger.Warn("HTTP代理请求解析失败",
			"client_ip", clientIP,
			"error", err,
		)
		return
	}

	logger.Info("HTTP代理请求",
		"client_ip", clientIP,
		"method", req.Method,
		"host", req.Host,
		"url", req.URL.String(),
		"user_agent", req.UserAgent(),
	)

	if req.Method == http.MethodConnect {
		p.handleConnect(client, req, clientIP)
	} else {
		p.handleHTTP(client, req, clientIP)
	}
}

func (p *Proxy) handleConnect(client net.Conn, req *http.Request, clientIP string) {
	host := req.URL.Host
	if host == "" {
		host = req.URL.Path
	}

	logger.Info("HTTP代理CONNECT连接",
		"client_ip", clientIP,
		"target_host", host,
	)

	startTime := time.Now()
	remote, err := p.sshDialer.Dial("tcp", host)
	if err != nil {
		logger.Error("HTTP代理CONNECT连接失败",
			"client_ip", clientIP,
			"target_host", host,
			"error", err,
		)
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	logger.Info("HTTP代理CONNECT连接成功",
		"client_ip", clientIP,
		"target_host", host,
		"duration", time.Since(startTime).String(),
	)

	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	startTransfer := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(remote, client)
		atomic.AddInt64(&p.bytesIn, n)
		if err != nil {
			logger.Warn("HTTP代理数据传输错误(客户端->远程)",
				"client_ip", clientIP,
				"target_host", host,
				"bytes", n,
				"error", err,
			)
		}
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(client, remote)
		atomic.AddInt64(&p.bytesOut, n)
		if err != nil {
			logger.Warn("HTTP代理数据传输错误(远程->客户端)",
				"client_ip", clientIP,
				"target_host", host,
				"bytes", n,
				"error", err,
			)
		}
	}()

	wg.Wait()
	logger.Info("HTTP代理CONNECT连接关闭",
		"client_ip", clientIP,
		"target_host", host,
		"duration", time.Since(startTransfer).String(),
	)
}

func (p *Proxy) handleHTTP(client net.Conn, req *http.Request, clientIP string) {
	host := req.URL.Host
	if host == "" {
		host = req.URL.Path
	}

	startTime := time.Now()
	remote, err := p.sshDialer.Dial("tcp", host)
	if err != nil {
		logger.Error("HTTP代理HTTP连接失败",
			"client_ip", clientIP,
			"target_host", host,
			"error", err,
		)
		return
	}
	defer remote.Close()

	logger.Info("HTTP代理HTTP连接成功",
		"client_ip", clientIP,
		"target_host", host,
		"duration", time.Since(startTime).String(),
	)

	req.Write(remote)
	n, err := io.Copy(client, remote)
	logger.Debug("HTTP代理数据传输完成",
		"client_ip", clientIP,
		"target_host", host,
		"bytes", n,
	)
	if err != nil {
		logger.Warn("HTTP代理数据传输错误",
			"client_ip", clientIP,
			"target_host", host,
			"bytes", n,
			"error", err,
		)
	}
}

func (p *Proxy) Stop() error {
	logger.Info("停止HTTP代理服务",
		"listen_addr", p.config.Listen,
		"bytes_in", atomic.LoadInt64(&p.bytesIn),
		"bytes_out", atomic.LoadInt64(&p.bytesOut),
	)
	p.running.Store(false)
	if p.listener != nil {
		p.listener.Close()
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
