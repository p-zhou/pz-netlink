let confirmResolve = null;

function initDialogs() {
    if (document.getElementById('confirmDialog') && document.getElementById('alertDialog') && document.getElementById('waitingOverlay')) {
        return;
    }

    document.body.insertAdjacentHTML('beforeend', `
        <dialog id="confirmDialog">
            <div class="dialog-content">
                <div class="dialog-body" id="confirmBody"></div>
                <div class="dialog-footer">
                    <button class="btn" style="background:#e2e8f0" onclick="closeConfirm(false)">取消</button>
                    <button class="btn btn-primary" onclick="closeConfirm(true)">确定</button>
                </div>
            </div>
        </dialog>

        <dialog id="alertDialog">
            <div class="dialog-content">
                <div class="dialog-body" id="alertBody"></div>
                <div class="dialog-footer">
                    <button class="btn btn-primary" onclick="closeAlert()">确定</button>
                </div>
            </div>
        </dialog>

        <div id="waitingOverlay" class="waiting-overlay">
            <div class="waiting-spinner"></div>
        </div>
    `);
}

function showConfirm(message) {
    initDialogs();
    return new Promise((resolve) => {
        document.getElementById('confirmBody').textContent = message;
        document.getElementById('confirmDialog').showModal();
        confirmResolve = resolve;
    });
}

function closeConfirm(result) {
    document.getElementById('confirmDialog').close();
    if (confirmResolve) {
        confirmResolve(result);
        confirmResolve = null;
    }
}

function showAlert(message) {
    initDialogs();
    document.getElementById('alertBody').textContent = message;
    document.getElementById('alertDialog').showModal();
}

function closeAlert() {
    document.getElementById('alertDialog').close();
}

function showWaiting() {
    initDialogs();
    document.getElementById('waitingOverlay').classList.add('active');
}

function hideWaiting() {
    const overlay = document.getElementById('waitingOverlay');
    if (overlay) {
        overlay.classList.remove('active');
    }
}

async function apiCall(url, options = {}) {
    showWaiting();
    try {
        if (options.body) {
            options.headers = {
                ...options.headers,
                'Content-Type': 'application/json'
            };
        }
        const response = await fetch(url, options);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } finally {
        hideWaiting();
    }
}

async function performRestart() {
    const res = await apiCall('/api/restart', { method: 'POST' });
    const sshTotal = res.ssh_servers.total;
    const sshEnabled = res.ssh_servers.enabled;
    const fwTotal = res.port_forwards.total;
    const fwEnabled = res.port_forwards.enabled;
    const proxyTotal = res.http_proxies.total;
    const proxyEnabled = res.http_proxies.enabled;
    showAlert(`重启完成\n\n应用启动时间：${res.app_start_time}\n最后重启时间：${res.last_restart_time}\n\nSSH服务器：共${sshTotal}个，启用${sshEnabled}个\n端口转发：共${fwTotal}个，启用${fwEnabled}个\nHTTP代理：共${proxyTotal}个，启用${proxyEnabled}个`);
}

document.addEventListener('DOMContentLoaded', initDialogs);
