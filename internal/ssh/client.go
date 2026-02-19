package ssh

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
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
	auth := []ssh.AuthMethod{}
	if c.config.AuthType == "password" {
		auth = append(auth, ssh.Password(c.config.Password))
	} else if c.config.AuthType == "key" && c.config.PrivateKey != "" {
		key, err := loadPrivateKey(c.config.PrivateKey)
		if err != nil {
			return err
		}
		auth = append(auth, ssh.PublicKeys(key))
	}

	sshConfig := &ssh.ClientConfig{
		User:            c.config.Username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
	conn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return err
	}

	c.client = conn
	return nil
}

func (c *Client) StartKeepAlive() {
	if c.config.KeepAliveInterval <= 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(c.config.KeepAliveInterval) * time.Second)
	go func() {
		for range ticker.C {
			c.mu.RLock()
			if c.client != nil {
				_, _, _ = c.client.SendRequest("keepalive@golang.org", false, nil)
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
