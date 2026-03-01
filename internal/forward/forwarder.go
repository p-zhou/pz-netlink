package forward

import "pz-netlink/pkg/types"

// Forwarder 定义端口转发器的统一接口
// 无论是内建实现还是 SSH 命令实现，都需要实现此接口
type Forwarder interface {
	// Start 启动端口转发服务
	// 返回 nil 表示启动成功，否则返回错误信息
	Start() error

	// Stop 停止端口转发服务
	// 返回 nil 表示停止成功，否则返回错误信息
	Stop() error

	// GetStatus 获取连接状态信息
	// 返回当前转发器的运行状态、流量统计等信息
	GetStatus() *types.ConnectionStatus

	// GetActiveConnections 获取所有活动的子连接信息
	// 对于 SSH 命令模式，返回空切片（无法获取子连接信息）
	GetActiveConnections() []types.ActiveConnectionInfo
}
