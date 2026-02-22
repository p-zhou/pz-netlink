let confirmResolve = null;

function initDialogs() {
    if (document.getElementById('confirmDialog') && document.getElementById('alertDialog')) {
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

document.addEventListener('DOMContentLoaded', initDialogs);
