package forward

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pz-netlink/internal/logger"
	"pz-netlink/pkg/types"
)

type SSHCmdForwarder struct {
	config     *types.PortForward
	sshServer  *types.SSHServer
	cmd        *exec.Cmd
	startedAt  time.Time
	running    atomic.Bool
	sshCommand string
	mu         sync.RWMutex
}

func NewSSHCmdForwarder(cfg *types.PortForward, sshServer *types.SSHServer) *SSHCmdForwarder {
	return &SSHCmdForwarder{
		config:    cfg,
		sshServer: sshServer,
	}
}

func (f *SSHCmdForwarder) buildSSHArgs() []string {
	args := []string{
		"-N",
		"-T",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "TCPKeepAlive=yes",
	}

	if f.sshServer.AuthType == "password" {
		args = append(args, "-o", "PasswordAuthentication=yes")
		args = append(args, "-o", "BatchMode=no")
	} else if f.sshServer.AuthType == "key" {
		args = append(args, "-o", "PasswordAuthentication=no")
		if f.sshServer.PrivateKey != "" {
			args = append(args, "-i", f.sshServer.PrivateKey)
		}
		args = append(args, "-o", "BatchMode=yes")
	}

	localAddr := fmt.Sprintf("0.0.0.0:%d", f.config.ListenPort)
	remoteAddr := fmt.Sprintf("%s:%d", f.config.RemoteHost, f.config.RemotePort)
	args = append(args, "-L", fmt.Sprintf("%s:%s", localAddr, remoteAddr))

	if f.sshServer.Port != 22 {
		args = append(args, "-p", fmt.Sprintf("%d", f.sshServer.Port))
	}

	args = append(args, fmt.Sprintf("%s@%s", f.sshServer.Username, f.sshServer.Host))

	return args
}

func (f *SSHCmdForwarder) buildSSHCommand() string {
	args := f.buildSSHArgs()
	return fmt.Sprintf("ssh %s", strings.Join(args, " "))
}

func (f *SSHCmdForwarder) Start() error {
	f.sshCommand = f.buildSSHCommand()

	logger.Info("启动 SSH 命令转发服务",
		"forward_name", f.config.Name,
		"forward_id", f.config.ID,
		"listen_addr", fmt.Sprintf("0.0.0.0:%d", f.config.ListenPort),
		"remote_addr", fmt.Sprintf("%s:%d", f.config.RemoteHost, f.config.RemotePort),
		"ssh_server_id", f.config.SSHServerID,
		"ssh_command", f.sshCommand,
	)

	args := f.buildSSHArgs()
	f.cmd = exec.Command("ssh", args...)

	if f.sshServer.AuthType == "password" {
		stdinPipe, err := f.cmd.StdinPipe()
		if err != nil {
			logger.Error("SSH 命令转发启动失败",
				"forward_name", f.config.Name,
				"forward_id", f.config.ID,
				"error", err,
			)
			return fmt.Errorf("failed to create stdin pipe: %w", err)
		}

		go func() {
			defer stdinPipe.Close()
			stdinPipe.Write([]byte(f.sshServer.Password + "\n"))
		}()
	}

	f.cmd.Stdout = os.Stdout
	f.cmd.Stderr = os.Stderr

	if err := f.cmd.Start(); err != nil {
		logger.Error("SSH 命令转发启动失败",
			"forward_name", f.config.Name,
			"forward_id", f.config.ID,
			"error", err,
		)
		return fmt.Errorf("failed to start ssh command: %w", err)
	}

	f.startedAt = time.Now()
	f.running.Store(true)

	go func() {
		if err := f.cmd.Wait(); err != nil {
			if f.running.Load() {
				logger.Warn("SSH 命令转发进程退出",
					"forward_name", f.config.Name,
					"forward_id", f.config.ID,
					"error", err,
				)
			}
		}
	}()

	logger.Info("SSH 命令转发服务启动成功",
		"forward_name", f.config.Name,
		"forward_id", f.config.ID,
		"pid", f.cmd.Process.Pid,
	)

	return nil
}

func (f *SSHCmdForwarder) Stop() error {
	logger.Info("停止 SSH 命令转发服务",
		"forward_name", f.config.Name,
		"forward_id", f.config.ID,
	)

	f.running.Store(false)

	f.mu.RLock()
	cmd := f.cmd
	f.mu.RUnlock()

	if cmd != nil && cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil {
			logger.Error("终止 SSH 命令转发进程失败",
				"forward_name", f.config.Name,
				"forward_id", f.config.ID,
				"error", err,
			)
			return fmt.Errorf("failed to kill ssh process: %w", err)
		}
		logger.Info("SSH 命令转发服务已停止",
			"forward_name", f.config.Name,
			"forward_id", f.config.ID,
		)
	}

	return nil
}

func (f *SSHCmdForwarder) GetStatus() *types.ConnectionStatus {
	f.mu.RLock()
	defer f.mu.RUnlock()

	status := types.ConnectionStatusDisconnected
	if f.running.Load() && f.cmd != nil && f.cmd.Process != nil {
		status = types.ConnectionStatusConnected
	}

	return &types.ConnectionStatus{
		ID:                f.config.ID,
		Type:              "port_forward",
		Name:              f.config.Name,
		LocalAddr:         fmt.Sprintf("0.0.0.0:%d", f.config.ListenPort),
		RemoteAddr:        fmt.Sprintf("%s:%d", f.config.RemoteHost, f.config.RemotePort),
		Status:            status,
		BytesIn:           0,
		BytesOut:          0,
		StartedAt:         f.startedAt,
		ActiveConnections: 0,
		ForwardMode:       f.config.ForwardMode,
		SSHCommand:        f.sshCommand,
	}
}

func (f *SSHCmdForwarder) GetActiveConnections() []types.ActiveConnectionInfo {
	return []types.ActiveConnectionInfo{}
}
