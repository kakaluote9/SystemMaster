// Scanning functionality JavaScript

/**
 * Initialize IP scan form
 */
function initIPScanForm() {
    const ipForm = document.getElementById('ip-scan-form');
    const advancedOptionsBtn = document.getElementById('advanced-options-btn');
    
    if (ipForm) {
        ipForm.addEventListener('submit', function(e) {
            const ipAddress = document.getElementById('ip_address').value;
            if (!isValidIP(ipAddress)) {
                e.preventDefault();
                showToast('请输入有效的IP地址', 'danger');
            }
        });
    }
    
    if (advancedOptionsBtn) {
        advancedOptionsBtn.addEventListener('click', function() {
            // Show advanced options modal or redirect to advanced options page
            window.location.href = '/ip-scan/advanced-options';
        });
    }
}

/**
 * Initialize Web scan form
 */
function initWebScanForm() {
    const webForm = document.getElementById('web-scan-form');
    
    if (webForm) {
        webForm.addEventListener('submit', function(e) {
            const url = document.getElementById('url').value;
            if (!isValidUrl(url)) {
                e.preventDefault();
                showToast('请输入有效的URL', 'danger');
            }
        });
    }
}

/**
 * Initialize Network scan form
 */
function initNetworkScanForm() {
    const networkForm = document.getElementById('network-scan-form');
    
    if (networkForm) {
        networkForm.addEventListener('submit', function(e) {
            const target = document.getElementById('target').value;
            if (target.trim() === '') {
                e.preventDefault();
                showToast('请输入有效的扫描目标', 'danger');
            }
        });
    }
}

/**
 * Validate IP address
 */
function isValidIP(ip) {
    // Simple regex for IPv4 address validation
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
}

/**
 * Validate URL
 */
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Handle stopping a scan
 */
function stopScan(taskId) {
    if (confirm('确定要停止此扫描任务吗？')) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = `/tasks/${taskId}/stop`;
        document.body.appendChild(form);
        form.submit();
    }
}

/**
 * Handle deleting a scan
 */
function deleteScan(taskId) {
    if (confirm('确定要删除此扫描任务吗？此操作无法撤销！')) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = `/tasks/${taskId}/delete`;
        document.body.appendChild(form);
        form.submit();
    }
}

/**
 * Show vulnerability verification form
 */
function showVerificationForm(vulnId) {
    const modal = new bootstrap.Modal(document.getElementById('verificationModal'));
    document.getElementById('vulnerability_id').value = vulnId;
    modal.show();
}

/**
 * Initialize data validation form
 */
function initDataValidationForm() {
    const form = document.getElementById('data-validation-form');
    const resultContainer = document.getElementById('validation-result');
    
    if (form) {
        form.addEventListener('submit', function(e) {
            const data = document.getElementById('data').value;
            if (data.trim() === '') {
                e.preventDefault();
                showToast('请输入需要验证的数据', 'danger');
            } else {
                // Show loading state
                const submitBtn = form.querySelector('[type="submit"]');
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 验证中...';
                }
                
                // Clear previous results
                if (resultContainer) {
                    resultContainer.innerHTML = '<div class="text-center"><div class="loader"></div><p>正在进行零知识证明验证，请稍候...</p></div>';
                }
            }
        });
    }
}

// Initialize all forms when the document is loaded
document.addEventListener('DOMContentLoaded', function() {
    initIPScanForm();
    initWebScanForm();
    initNetworkScanForm();
    initDataValidationForm();
});
