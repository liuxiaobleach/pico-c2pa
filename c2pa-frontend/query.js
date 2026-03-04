// API 配置
const API_BASE_URL = 'http://localhost:8080';

// DOM 元素
const taskIdInput = document.getElementById('taskIdInput');
const queryBtn = document.getElementById('queryBtn');
const resultCard = document.getElementById('resultCard');
const resultStatus = document.getElementById('resultStatus');
const resultContent = document.getElementById('resultContent');
const errorMessage = document.getElementById('errorMessage');

// 格式化文件大小
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 查询任务
async function queryTask() {
    const taskId = taskIdInput.value.trim();

    if (!taskId) {
        alert('请输入 Task ID');
        return;
    }

    queryBtn.disabled = true;
    queryBtn.textContent = '查询中...';

    try {
        const response = await fetch(`${API_BASE_URL}/api/v1/proof/${taskId}`);
        const data = await response.json();

        console.log('Query response:', data);

        displayResult(data);
    } catch (error) {
        console.error('Query error:', error);
        showError('查询失败: ' + error.message);
    } finally {
        queryBtn.disabled = false;
        queryBtn.textContent = '查询';
    }
}

// 显示结果
function displayResult(data) {
    resultCard.classList.add('show');
    errorMessage.style.display = 'none';

    // 更新状态
    resultStatus.className = 'result-status';

    if (data.status === 'completed') {
        resultStatus.classList.add('completed');
        resultStatus.querySelector('.status-text').textContent = '✓ 任务已完成';

        // 显示 Public Input 和 Public Values
        let html = '';

        // Public Input 部分
        if (data.publicInput) {
            html += `
                <div class="section-title">Public Input (ZK Proof 输入)</div>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Data Hash Prefix</span>
                        <span class="detail-value">${data.publicInput.dataHashPrefix}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Expected Hash Prefix</span>
                        <span class="detail-value">${data.publicInput.expectedHashPrefix}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Image Size</span>
                        <span class="detail-value">${formatFileSize(data.publicInput.imageSize)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Is Signed</span>
                        <span class="detail-value ${data.publicInput.isSigned ? 'success' : 'error'}">${data.publicInput.isSigned ? '是' : '否'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Action Count</span>
                        <span class="detail-value">${data.publicInput.actionCount}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Expected Actions Hash Prefix</span>
                        <span class="detail-value">${data.publicInput.expectedActionsHashPrefix}</span>
                    </div>
                </div>
            `;
        }

        // Public Values 部分
        if (data.proof && data.proof.publicValues) {
            const pv = data.proof.publicValues;
            html += `
                <div class="section-title">Public Values (ZK Proof 输出)</div>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Hash Valid</span>
                        <span class="detail-value ${pv.hashValid ? 'success' : 'error'}">${pv.hashValid ? '是' : '否'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Computed Hash Prefix</span>
                        <span class="detail-value">${pv.computedHashPrefix}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Is Signed</span>
                        <span class="detail-value ${pv.isSigned ? 'success' : 'error'}">${pv.isSigned ? '是' : '否'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Image Size</span>
                        <span class="detail-value">${formatFileSize(pv.imageSize)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Action Count</span>
                        <span class="detail-value">${pv.actionCount}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Actions Valid</span>
                        <span class="detail-value ${pv.actionsValid ? 'success' : 'error'}">${pv.actionsValid ? '是' : '否'}</span>
                    </div>
                </div>
            `;
        }

        // Proof 路径
        if (data.proof && data.proof.proofPath) {
            html += `
                <div class="section-title">Proof 文件</div>
                <div class="detail-grid">
                    <div class="detail-item" style="grid-column: span 2;">
                        <span class="detail-label">文件路径</span>
                        <span class="detail-value">${data.proof.proofPath}</span>
                    </div>
                </div>
            `;
        }

        // 操作按钮
        html += `
            <div style="display: flex; gap: 1rem; margin-top: 1.5rem;">
                <button class="btn btn-download" id="downloadBtn" style="flex: 1;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                        <polyline points="7 10 12 15 17 10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                    下载 Proof
                </button>
                <button class="btn btn-primary" id="verifyBtn" style="flex: 1;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                        <polyline points="22 4 12 14.01 9 11.01"></polyline>
                    </svg>
                    验证 Proof
                </button>
            </div>
            <div id="verifyResult" style="margin-top: 1rem; display: none;"></div>
        `;

        resultContent.innerHTML = html;

        // 添加下载事件
        document.getElementById('downloadBtn').addEventListener('click', () => {
            downloadProof(data.taskId);
        });

        // 添加验证事件
        document.getElementById('verifyBtn').addEventListener('click', () => {
            verifyProof(data.taskId);
        });

    } else if (data.status === 'processing') {
        resultStatus.classList.add('processing');
        resultStatus.querySelector('.status-text').textContent = '⏳ 任务处理中...';

        resultContent.innerHTML = `
            <p style="text-align: center; color: #666; margin-top: 1rem;">
                证明正在生成中，请稍后再查询...
            </p>
        `;

    } else if (data.status === 'failed') {
        resultStatus.classList.add('failed');
        resultStatus.querySelector('.status-text').textContent = '✗ 任务失败';

        let html = '';
        if (data.proof && data.proof.error) {
            html = `<div class="error-message">${data.proof.error}</div>`;
        } else if (data.error) {
            html = `<div class="error-message">${data.error}</div>`;
        }
        resultContent.innerHTML = html;

    } else if (data.error) {
        resultStatus.classList.add('notfound');
        resultStatus.querySelector('.status-text').textContent = '✗ 任务不存在';
        resultContent.innerHTML = '';
    }
}

// 显示错误
function showError(message) {
    resultCard.classList.add('show');
    resultStatus.className = 'result-status';
    resultStatus.classList.add('notfound');
    resultStatus.querySelector('.status-text').textContent = '✗ 查询失败';

    errorMessage.style.display = 'block';
    errorMessage.textContent = message;
    resultContent.innerHTML = '';
}

// 验证 Proof
function verifyProof(taskId) {
    const verifyBtn = document.getElementById('verifyBtn');
    const verifyResult = document.getElementById('verifyResult');

    verifyBtn.disabled = true;
    verifyBtn.textContent = '验证中...';

    fetch(`${API_BASE_URL}/api/v1/verify/${taskId}`)
        .then(response => response.json())
        .then(data => {
            verifyResult.style.display = 'block';
            if (data.valid) {
                verifyResult.innerHTML = `
                    <div style="padding: 1rem; background: #d1fae5; color: #065f46; border-radius: 8px;">
                        <strong>✓ 验证成功</strong><br>
                        ${data.message}
                    </div>
                `;
            } else {
                verifyResult.innerHTML = `
                    <div style="padding: 1rem; background: #fee2e2; color: #991b1b; border-radius: 8px;">
                        <strong>✗ 验证失败</strong><br>
                        ${data.message}
                    </div>
                `;
            }
        })
        .catch(error => {
            verifyResult.style.display = 'block';
            verifyResult.innerHTML = `
                <div style="padding: 1rem; background: #fee2e2; color: #991b1b; border-radius: 8px;">
                    <strong>✗ 验证失败</strong><br>
                    ${error.message}
                </div>
            `;
        })
        .finally(() => {
            verifyBtn.disabled = false;
            verifyBtn.textContent = '验证 Proof';
        });
}

// 下载 Proof 文件
function downloadProof(taskId) {
    // 从后端服务下载
    const downloadUrl = `${API_BASE_URL}/proofs/${taskId}.json`;

    fetch(downloadUrl)
        .then(response => {
            if (!response.ok) {
                throw new Error('Proof file not found');
            }
            return response.json();
        })
        .then(data => {
            // 将 JSON 转换为字符串并创建下载
            const jsonStr = JSON.stringify(data, null, 2);
            const blob = new Blob([jsonStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);

            const a = document.createElement('a');
            a.href = url;
            a.download = `proof_${taskId}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        })
        .catch(error => {
            alert('下载失败: ' + error.message);
        });
}

// 事件监听
queryBtn.addEventListener('click', queryTask);

taskIdInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        queryTask();
    }
});

// 页面加载后检查 URL 参数
window.addEventListener('load', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const taskId = urlParams.get('taskId');
    if (taskId) {
        taskIdInput.value = taskId;
        queryTask();
    }
});
