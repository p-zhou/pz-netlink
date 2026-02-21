package ssh

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"pz-netlink/internal/logger"
	"pz-netlink/pkg/types"
)

type Client struct {
	config *types.SSHServer
	client *ssh.Client
	mu     sync.RWMutex
}

func NewClient(cfg *types.SSHServer) *Client {
	return &Client{config: cfg}
}

func (c *Client) Connect() error {
	logger.Info("SSH连接开始",
		"server_name", c.config.Name,
		"server_id", c.config.ID,
		"host", c.config.Host,
		"port", c.config.Port,
		"auth_type", c.config.AuthType,
		"username", c.config.Username,
	)

	auth := []ssh.AuthMethod{}
	if c.config.AuthType == "password" {
		auth = append(auth, ssh.Password(c.config.Password))
	} else if c.config.AuthType == "key" && c.config.PrivateKey != "" {
		key, err := loadPrivateKey(c.config.PrivateKey)
		if err != nil {
			logger.Error("SSH密钥加载失败",
				"server_name", c.config.Name,
				"server_id", c.config.ID,
				"key_path", c.config.PrivateKey,
				"error", err,
			)
			return err
		}
		logger.Info("SSH密钥加载成功",
			"server_name", c.config.Name,
			"server_id", c.config.ID,
			"key_path", c.config.PrivateKey,
		)
		auth = append(auth, ssh.PublicKeys(key))
	}

	sshConfig := &ssh.ClientConfig{
		User:            c.config.Username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
	startTime := time.Now()
	conn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		logger.Error("SSH连接失败",
			"server_name", c.config.Name,
			"server_id", c.config.ID,
			"addr", addr,
			"error", err,
			"duration", time.Since(startTime).String(),
		)
		return err
	}

	c.client = conn
	logger.Info("SSH连接成功",
		"server_name", c.config.Name,
		"server_id", c.config.ID,
		"addr", addr,
		"duration", time.Since(startTime).String(),
	)
	return nil
}

func (c *Client) StartKeepAlive() {
	if c.config.KeepAliveInterval <= 0 {
		logger.Info("保活未启用",
			"server_name", c.config.Name,
			"server_id", c.config.ID,
		)
		return
	}
	logger.Info("启动SSH保活",
		"server_name", c.config.Name,
		"server_id", c.config.ID,
		"interval", c.config.KeepAliveInterval,
	)
	ticker := time.NewTicker(time.Duration(c.config.KeepAliveInterval) * time.Second)
	go func() {
		for range ticker.C {
			c.mu.RLock()
			if c.client != nil {
				_, err, _ := c.client.SendRequest("keepalive@golang.org", false, nil)
				if err != nil {
					logger.Warn("SSH保活失败",
						"server_name", c.config.Name,
						"server_id", c.config.ID,
						"error", err,
					)
				} else {
					logger.Debug("SSH保活成功",
						"server_name", c.config.Name,
						"server_id", c.config.ID,
					)
				}
			}
			c.mu.RUnlock()
		}
	}()
}

func (c *Client) Dial(network, addr string) (net.Conn, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.client == nil {
		return nil, fmt.Errorf("not connected")
	}
	return c.client.Dial(network, addr)
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		logger.Info("关闭SSH连接",
			"server_name", c.config.Name,
			"server_id", c.config.ID,
			"host", c.config.Host,
			"port", c.config.Port,
		)
		err := c.client.Close()
		c.client = nil
		return err
	}
	return nil
}

func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client != nil
}

func loadPrivateKey(path string) (ssh.Signer, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(keyData)
}
