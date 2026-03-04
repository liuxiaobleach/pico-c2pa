// API 配置
const API_BASE_URL = 'http://localhost:8080';
const POLL_INTERVAL = 2000; // 2秒轮询一次

// DOM 元素
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const previewSection = document.getElementById('previewSection');
const imagePreview = document.getElementById('imagePreview');
const fileName = document.getElementById('fileName');
const clearBtn = document.getElementById('clearBtn');
const uploadBtn = document.getElementById('uploadBtn');
const resultSection = document.getElementById('resultSection');
const resultCard = document.getElementById('resultCard');
const resultStatus = document.getElementById('resultStatus');
const resultDetails = document.getElementById('resultDetails');
const resultError = document.getElementById('resultError');

// 选中的文件
let selectedFile = null;
let currentTaskId = null;
let pollIntervalId = null;

// 事件监听 - 点击上传
dropZone.addEventListener('click', () => fileInput.click());

// 事件监听 - 文件选择
fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
    }
});

// 事件监听 - 拖拽
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('drag-over');

    console.log('Drop event:', e.dataTransfer.files.length, 'files');

    if (e.dataTransfer.files.length > 0) {
        handleFileSelect(e.dataTransfer.files[0]);
    }
});

// 事件监听 - 清除按钮
clearBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    clearFile();
});

// 事件监听 - 上传按钮
uploadBtn.addEventListener('click', submitTask);

// 处理文件选择
function handleFileSelect(file) {
    // 验证文件类型 - 支持常见图片扩展名
    const allowedExtensions = ['jpg', 'jpeg', 'png', 'webp', 'gif', 'avif', 'heic', 'heif'];
    const fileName = file.name.toLowerCase();
    const extension = fileName.split('.').pop();

    // 检查 MIME 类型或扩展名
    const isImage = file.type.startsWith('image/') || allowedExtensions.includes(extension);

    if (!isImage) {
        alert('请选择图片文件 (JPEG, PNG, WebP, GIF, AVIF)');
        console.log('File rejected:', file.name, 'type:', file.type, 'ext:', extension);
        return;
    }

    console.log('File accepted:', file.name, 'type:', file.type, 'size:', file.size);

    selectedFile = file;

    // 显示预览
    const reader = new FileReader();
    reader.onload = (e) => {
        imagePreview.src = e.target.result;
        fileNameElement.textContent = `${file.name} (${formatFileSize(file.size)})`;
    };
    reader.readAsDataURL(file);

    // 切换显示
    dropZone.style.display = 'none';
    previewSection.style.display = 'block';
    uploadBtn.disabled = false;

    // 隐藏之前的结果
    resultSection.style.display = 'none';
}

// 清除文件
function clearFile() {
    selectedFile = null;
    currentTaskId = null;
    fileInput.value = '';
    dropZone.style.display = 'block';
    previewSection.style.display = 'none';
    uploadBtn.disabled = true;
    resultSection.style.display = 'none';

    // 停止轮询
    if (pollIntervalId) {
        clearInterval(pollIntervalId);
        pollIntervalId = null;
    }
}

// 格式化文件大小
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 提交任务
async function submitTask() {
    if (!selectedFile) return;

    // 显示加载状态
    setLoading(true);

    try {
        console.log('Submitting task to:', `${API_BASE_URL}/api/v1/proof`);

        const formData = new FormData();
        formData.append('image', selectedFile);

        const response = await fetch(`${API_BASE_URL}/api/v1/proof`, {
            method: 'POST',
            body: formData
        });

        console.log('Response status:', response.status);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log('Submit response:', data);

        if (data.taskId) {
            currentTaskId = data.taskId;
            showTaskId(data.taskId, data.publicInput);
            startPolling();
        } else {
            throw new Error('Failed to get task ID');
        }
    } catch (error) {
        console.error('Submit error:', error);
        displayError('提交任务失败: ' + error.message);
        setLoading(false);
    }
}

// 显示 Task ID 和 Public Input
function showTaskId(taskId, publicInput) {
    resultSection.style.display = 'block';
    resultStatus.className = 'result-status';
    resultStatus.classList.add('processing');
    resultStatus.querySelector('.status-icon').innerHTML = '';
    resultStatus.querySelector('.status-text').textContent = '任务已提交，请等待...';

    // 构建 Public Input 显示
    let publicInputHtml = '';
    if (publicInput) {
        publicInputHtml = `
            <h3>Public Input (ZK Proof 输入)</h3>
            <div class="detail-grid">
                <div class="detail-item">
                    <span class="detail-label">Data Hash Prefix</span>
                    <span class="detail-value">${publicInput.dataHashPrefix}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Expected Hash Prefix</span>
                    <span class="detail-value">${publicInput.expectedHashPrefix}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Image Size</span>
                    <span class="detail-value">${formatFileSize(publicInput.imageSize)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Is Signed</span>
                    <span class="detail-value ${publicInput.isSigned ? 'success' : 'error'}">${publicInput.isSigned ? '是' : '否'}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Action Count</span>
                    <span class="detail-value">${publicInput.actionCount}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Expected Actions Hash Prefix</span>
                    <span class="detail-value">${publicInput.expectedActionsHashPrefix}</span>
                </div>
            </div>
        `;
    }

    resultDetails.style.display = 'block';
    resultDetails.innerHTML = `
        <h3>任务信息</h3>
        <div class="detail-grid">
            <div class="detail-item">
                <span class="detail-label">Task ID</span>
                <span class="detail-value" id="taskIdValue">${taskId}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">状态</span>
                <span class="detail-value" id="taskStatus">处理中...</span>
            </div>
        </div>
        ${publicInputHtml}
        <p style="margin-top: 1rem; color: #666;">证明生成需要一些时间，请耐心等待...</p>
    `;
    resultError.style.display = 'none';

    // 滚动到结果区域
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// 开始轮询
function startPolling() {
    if (pollIntervalId) {
        clearInterval(pollIntervalId);
    }

    pollIntervalId = setInterval(async () => {
        if (!currentTaskId) return;

        try {
            const response = await fetch(`${API_BASE_URL}/api/v1/proof/${currentTaskId}`);
            const data = await response.json();

            console.log('Poll response:', data);

            if (data.status === 'completed' || data.status === 'failed') {
                // 停止轮询
                clearInterval(pollIntervalId);
                pollIntervalId = null;
                setLoading(false);

                if (data.status === 'completed' && data.proof) {
                    displayResult(data.proof);
                } else {
                    displayError(data.error || '任务处理失败');
                }
            } else if (data.status === 'processing') {
                // 更新状态显示
                const statusElement = document.getElementById('taskStatus');
                if (statusElement) {
                    statusElement.textContent = '处理中...';
                }
            }
        } catch (error) {
            console.error('Poll error:', error);
        }
    }, POLL_INTERVAL);
}

// 设置加载状态
function setLoading(loading) {
    const btnText = uploadBtn.querySelector('.btn-text');
    const btnLoading = uploadBtn.querySelector('.btn-loading');

    uploadBtn.disabled = loading;

    if (loading) {
        btnText.style.display = 'none';
        btnLoading.style.display = 'flex';
    } else {
        btnText.style.display = 'inline';
        btnLoading.style.display = 'none';
    }
}

// 显示结果
function displayResult(data) {
    resultSection.style.display = 'block';

    // 清除之前的类名
    resultStatus.className = 'result-status';

    if (data.success && data.proofGenerated) {
        // 成功状态
        resultStatus.classList.add('success');
        resultStatus.querySelector('.status-text').textContent = 'Proof 生成成功';

        // 显示详细信息
        resultDetails.style.display = 'block';
        resultError.style.display = 'none';

        if (data.publicValues) {
            const pv = data.publicValues;
            resultDetails.innerHTML = `
                <h3>Public Values</h3>
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
    } else {
        // 错误状态
        resultStatus.classList.add('error');
        resultStatus.querySelector('.status-text').textContent = 'Proof 生成失败';

        resultDetails.style.display = 'none';
        resultError.style.display = 'block';
        document.getElementById('errorMessage').textContent = data.error || '未知错误';
    }

    // 添加查询链接
    if (currentTaskId) {
        const queryLink = document.createElement('a');
        queryLink.href = `query.html?taskId=${currentTaskId}`;
        queryLink.className = 'btn btn-secondary';
        queryLink.style.display = 'inline-block';
        queryLink.style.marginTop = '1rem';
        queryLink.textContent = '查看详情 / 下载 Proof';
        resultCard.appendChild(queryLink);
    }

    // 滚动到结果区域
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// 显示错误
function displayError(message) {
    resultSection.style.display = 'block';
    resultStatus.className = 'result-status error';
    resultStatus.querySelector('.status-text').textContent = '请求失败';

    resultDetails.style.display = 'none';
    resultError.style.display = 'block';
    document.getElementById('errorMessage').textContent = message;

    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// 获取文件名的辅助函数（修复变量名冲突）
const fileNameElement = {
    get textContent() {
        return fileName.textContent;
    },
    set textContent(val) {
        fileName.textContent = val;
    }
};
