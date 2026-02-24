package proxy

import (
	"bufio"
	"bytes"
	"fmt"
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
	id        string
	name      string
	config    *types.HTTPProxy
	sshDialer interface {
		Dial(network, addr string) (net.Conn, error)
	}
	listener  net.Listener
	running   atomic.Bool
	bytesIn   int64
	bytesOut  int64
	startTime time.Time
	mu        sync.RWMutex
	conns     map[string]net.Conn
}

func NewProxy(id string, name string, cfg *types.HTTPProxy, dialer interface {
	Dial(network, addr string) (net.Conn, error)
}) *Proxy {
	return &Proxy{
		id:        id,
		name:      name,
		config:    cfg,
		sshDialer: dialer,
		conns:     make(map[string]net.Conn),
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

	// 读取前几个字节检测是否是 TLS 握手
	buf := make([]byte, 3)
	n, err := client.Read(buf)
	if err != nil {
		logger.Warn("HTTP代理读取数据失败",
			"client_ip", clientIP,
			"error", err,
		)
		return
	}

	// 检测 TLS ClientHello (0x16 = Handshake, 0x03 0x01 = TLS 1.0/1.1/1.2)
	isTLS := n >= 3 && buf[0] == 0x16 && buf[1] == 0x03 && (buf[2] == 0x01 || buf[2] == 0x02 || buf[2] == 0x03)

	if isTLS {
		// 这是 TLS 连接，需要自动建立 CONNECT 隧道
		// 由于已经读取了一些数据，我们需要重建一个包含已读取数据的 reader
		tlsReader := io.MultiReader(bytes.NewReader(buf[:n]), client)

		// 尝试从 TLS SNI 中提取目标主机
		host := p.extractSNI(tlsReader)
		if host == "" {
			logger.Warn("无法从 TLS SNI 提取目标主机",
				"client_ip", clientIP,
			)
			return
		}

		// 为 HTTPS 添加默认端口 443
		if !containsPort(host) {
			host += ":443"
		}

		logger.Info("检测到 TLS 连接，自动建立 CONNECT 隧道",
			"client_ip", clientIP,
			"target_host", host,
		)

		// 建立远程连接
		startTime := time.Now()
		remote, err := p.sshDialer.Dial("tcp", host)
		if err != nil {
			logger.Error("CONNECT连接失败",
				"client_ip", clientIP,
				"target_host", host,
				"error", err,
			)
			client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer remote.Close()

		connID := fmt.Sprintf("%s-%d", clientIP, time.Now().UnixNano())
		p.mu.Lock()
		p.conns[connID] = client
		p.mu.Unlock()

		logger.Info("CONNECT连接成功",
			"client_ip", clientIP,
			"target_host", host,
			"duration", time.Since(startTime).String(),
		)

		// 发送已读取的 TLS 数据到远程
		_, err = remote.Write(buf[:n])
		if err != nil {
			logger.Error("发送TLS数据失败",
				"client_ip", clientIP,
				"error", err,
			)
			return
		}

		// 双向转发数据
		startTransfer := time.Now()
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			n, err := io.Copy(remote, client)
			atomic.AddInt64(&p.bytesIn, n)
			if err != nil && err != io.EOF {
				logger.Warn("数据传输错误(客户端->远程)",
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
			if err != nil && err != io.EOF {
				logger.Warn("数据传输错误(远程->客户端)",
					"client_ip", clientIP,
					"target_host", host,
					"bytes", n,
					"error", err,
				)
			}
		}()

		wg.Wait()
		logger.Info("CONNECT连接关闭",
			"client_ip", clientIP,
			"target_host", host,
			"duration", time.Since(startTransfer).String(),
		)

		p.mu.Lock()
		delete(p.conns, connID)
		p.mu.Unlock()

		return
	}

	// 不是 TLS，按正常 HTTP 处理
	// 将已读取的数据放回 reader
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(buf[:n]), client))
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

func containsPort(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] == ':' {
			return true
		}
	}
	return false
}

func (p *Proxy) extractSNI(r io.Reader) string {
	buf := make([]byte, 512)
	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return ""
	}

	data := buf[:n]

	// TLS Record Header: 1 byte type, 2 bytes version, 2 bytes length
	if len(data) < 5 {
		return ""
	}

	// Verify it's a Handshake record (type 22)
	if data[0] != 0x16 {
		return ""
	}

	// Parse length (big-endian)
	length := int(data[3])<<8 | int(data[4])

	// Read more data if needed
	if len(data) < 5+length {
		// Need to read more, but for simplicity we just return what we can parse
	}

	// Handshake Header: 1 byte type, 3 bytes length
	if len(data) < 9 {
		return ""
	}

	// Verify it's ClientHello (type 1)
	if data[5] != 0x01 {
		return ""
	}

	// Try to find SNI extension
	// Format: https://datatracker.ietf.org/doc/html/rfc6066#section-3

	// Skip Handshake Header (4 bytes)
	offset := 9

	// Skip Protocol Version (2 bytes) + Random (32 bytes) = 34 bytes
	if len(data) < offset+34 {
		return ""
	}
	offset += 34

	// Skip Session ID (1 byte length + variable data)
	if len(data) < offset+1 {
		return ""
	}
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	// Skip Cipher Suites (2 bytes length + variable data)
	if len(data) < offset+2 {
		return ""
	}
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	// Skip Compression Methods (1 byte length + variable data)
	if len(data) < offset+1 {
		return ""
	}
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	// Extensions (2 bytes length + variable data)
	if len(data) < offset+2 {
		return ""
	}
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	if len(data) < offset+extensionsLen {
		return ""
	}

	extensionsEnd := offset + extensionsLen

	for offset < extensionsEnd {
		// Extension: 2 bytes type, 2 bytes length
		if len(data) < offset+4 {
			return ""
		}
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if len(data) < offset+extLen {
			return ""
		}

		// SNI extension type is 0 (server_name)
		if extType == 0 {
			// SNI format: 2 bytes list length + 2 bytes name type + 2 bytes name length + name
			if len(data) < offset+2 {
				return ""
			}
			listLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2

			if listLen == 0 || listLen > extLen {
				return ""
			}

			if len(data) < offset+2 {
				return ""
			}
			nameType := int(data[offset])<<8 | int(data[offset+1])
			offset += 2

			if nameType != 0 {
				return ""
			}

			if len(data) < offset+2 {
				return ""
			}
			nameLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2

			if len(data) < offset+nameLen {
				return ""
			}

			return string(data[offset : offset+nameLen])
		}

		offset += extLen
	}

	return ""
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

	connID := fmt.Sprintf("%s-%d", clientIP, time.Now().UnixNano())
	p.mu.Lock()
	p.conns[connID] = client
	p.mu.Unlock()

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
		if err != nil && err != io.EOF {
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
		if err != nil && err != io.EOF {
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

	p.mu.Lock()
	delete(p.conns, connID)
	p.mu.Unlock()
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

	connID := fmt.Sprintf("%s-%d", clientIP, time.Now().UnixNano())
	p.mu.Lock()
	p.conns[connID] = client
	p.mu.Unlock()

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
	if err != nil && err != io.EOF {
		logger.Warn("HTTP代理数据传输错误",
			"client_ip", clientIP,
			"target_host", host,
			"bytes", n,
			"error", err,
		)
	}

	p.mu.Lock()
	delete(p.conns, connID)
	p.mu.Unlock()
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
	status := types.ConnectionStatusDisconnected
	if p.running.Load() && p.listener != nil {
		status = types.ConnectionStatusConnected
	}

	p.mu.RLock()
	activeConns := len(p.conns)
	p.mu.RUnlock()

	return &types.ConnectionStatus{
		ID:                p.id,
		Type:              "http_proxy",
		Name:              p.name,
		LocalAddr:         p.config.Listen,
		Status:            status,
		BytesIn:           atomic.LoadInt64(&p.bytesIn),
		BytesOut:          atomic.LoadInt64(&p.bytesOut),
		StartedAt:         p.startTime,
		ActiveConnections: activeConns,
	}
}
