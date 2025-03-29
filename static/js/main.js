// Main JavaScript functionality

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Handle sidebar toggle
    const sidebarToggle = document.getElementById('sidebarToggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function() {
            document.body.classList.toggle('sidebar-collapsed');
            const sidebar = document.querySelector('.sidebar');
            const mainContent = document.querySelector('.main-content');
            
            if (document.body.classList.contains('sidebar-collapsed')) {
                sidebar.style.width = '0';
                mainContent.style.marginLeft = '0';
            } else {
                sidebar.style.width = '250px';
                mainContent.style.marginLeft = '250px';
            }
        });
    }

    // Add active class to current nav item
    const currentLocation = window.location.pathname;
    const navLinks = document.querySelectorAll('.sidebar .nav-link');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentLocation) {
            link.classList.add('active');
        }
    });

    // Task progress polling
    const taskProgressBars = document.querySelectorAll('[data-task-progress]');
    if (taskProgressBars.length > 0) {
        taskProgressBars.forEach(progressBar => {
            const taskId = progressBar.getAttribute('data-task-progress');
            const taskStatusElement = document.getElementById(`task-status-${taskId}`);
            
            if (taskStatusElement && taskStatusElement.textContent.trim() === 'running') {
                pollTaskProgress(taskId, progressBar, taskStatusElement);
            }
        });
    }

    // Handle form submission loading state
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = form.querySelector('[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 处理中...';
            }
        });
    });

    // Handle delete confirmation
    const deleteButtons = document.querySelectorAll('[data-confirm]');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm(this.getAttribute('data-confirm'))) {
                e.preventDefault();
            }
        });
    });
});

/**
 * Poll task progress API endpoint
 */
function pollTaskProgress(taskId, progressBar, statusElement) {
    const poll = setInterval(() => {
        fetch(`/api/task/${taskId}/progress`)
            .then(response => response.json())
            .then(data => {
                progressBar.style.width = `${data.progress}%`;
                progressBar.setAttribute('aria-valuenow', data.progress);
                
                if (statusElement) {
                    statusElement.textContent = data.status;
                    
                    // Add appropriate styling based on status
                    statusElement.className = 'badge';
                    switch (data.status) {
                        case 'pending':
                            statusElement.classList.add('bg-secondary');
                            break;
                        case 'running':
                            statusElement.classList.add('bg-primary');
                            break;
                        case 'completed':
                            statusElement.classList.add('bg-success');
                            break;
                        case 'failed':
                            statusElement.classList.add('bg-danger');
                            break;
                        case 'stopped':
                            statusElement.classList.add('bg-warning');
                            break;
                    }
                }
                
                // If task is complete or failed, stop polling
                if (data.status === 'completed' || data.status === 'failed' || data.status === 'stopped') {
                    clearInterval(poll);
                    
                    // Reload the page to show updated task data
                    if (data.status === 'completed') {
                        setTimeout(() => {
                            window.location.reload();
                        }, 1000);
                    }
                }
            })
            .catch(error => {
                console.error('Error fetching task progress:', error);
                clearInterval(poll);
            });
    }, 2000); // Poll every 2 seconds
}

/**
 * Initialize data tables
 */
function initDataTable(tableId, options = {}) {
    const defaultOptions = {
        pageLength: 10,
        language: {
            search: "搜索:",
            lengthMenu: "显示 _MENU_ 条记录",
            info: "显示第 _START_ 至 _END_ 条记录，共 _TOTAL_ 条",
            infoEmpty: "没有记录",
            infoFiltered: "(从 _MAX_ 条记录过滤)",
            paginate: {
                first: "首页",
                last: "末页",
                next: "下一页",
                previous: "上一页"
            }
        }
    };
    
    const mergedOptions = { ...defaultOptions, ...options };
    return new DataTable(document.getElementById(tableId), mergedOptions);
}

/**
 * Show a toast notification
 */
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'position-fixed bottom-0 end-0 p-3';
        container.style.zIndex = '5';
        document.body.appendChild(container);
    }
    
    const id = 'toast-' + Date.now();
    const html = `
        <div id="${id}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header bg-${type} text-white">
                <strong class="me-auto">系统通知</strong>
                <small>刚刚</small>
                <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    document.getElementById('toast-container').insertAdjacentHTML('beforeend', html);
    const toastElement = document.getElementById(id);
    const toast = new bootstrap.Toast(toastElement);
    toast.show();
    
    // Remove the toast from DOM after it's hidden
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

/**
 * Format date to local string
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}
