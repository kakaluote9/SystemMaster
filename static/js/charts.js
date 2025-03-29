// Charts for data visualization

/**
 * Create a vulnerability severity distribution chart
 */
function createSeverityChart(elementId, data) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    const colors = {
        critical: '#e74c3c',
        high: '#e67e22',
        medium: '#f39c12',
        low: '#3498db',
        info: '#1abc9c'
    };
    
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['严重', '高危', '中危', '低危', '信息'],
            datasets: [{
                data: [
                    data.critical || 0,
                    data.high || 0,
                    data.medium || 0,
                    data.low || 0,
                    data.info || 0
                ],
                backgroundColor: [
                    colors.critical,
                    colors.high,
                    colors.medium,
                    colors.low,
                    colors.info
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                }
            },
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });
}

/**
 * Create a vulnerability trend chart
 */
function createTrendChart(elementId, data) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    // Extract dates and counts from data
    const dates = data.map(item => item.date);
    const counts = data.map(item => item.count);
    
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [{
                label: '漏洞数量',
                data: counts,
                borderColor: '#3498db',
                backgroundColor: 'rgba(52, 152, 219, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            },
            plugins: {
                tooltip: {
                    mode: 'index',
                    intersect: false
                },
                legend: {
                    display: true,
                    position: 'top'
                }
            }
        }
    });
}

/**
 * Create a comparison chart for comparing vulnerabilities
 */
function createComparisonChart(elementId, currentData, previousData) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['严重', '高危', '中危', '低危', '信息'],
            datasets: [
                {
                    label: '当前',
                    data: [
                        currentData.critical || 0,
                        currentData.high || 0,
                        currentData.medium || 0,
                        currentData.low || 0,
                        currentData.info || 0
                    ],
                    backgroundColor: 'rgba(52, 152, 219, 0.7)',
                    borderColor: 'rgba(52, 152, 219, 1)',
                    borderWidth: 1
                },
                {
                    label: '历史',
                    data: [
                        previousData.critical || 0,
                        previousData.high || 0,
                        previousData.medium || 0,
                        previousData.low || 0,
                        previousData.info || 0
                    ],
                    backgroundColor: 'rgba(26, 188, 156, 0.7)',
                    borderColor: 'rgba(26, 188, 156, 1)',
                    borderWidth: 1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            },
            plugins: {
                tooltip: {
                    mode: 'index',
                    intersect: false
                },
                legend: {
                    display: true,
                    position: 'top'
                }
            }
        }
    });
}

/**
 * Create a task status distribution chart
 */
function createTaskStatusChart(elementId, data) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['待处理', '运行中', '已完成', '失败'],
            datasets: [{
                data: [
                    data.pending || 0,
                    data.running || 0,
                    data.completed || 0,
                    data.failed || 0
                ],
                backgroundColor: [
                    '#6c757d',
                    '#3498db',
                    '#2ecc71',
                    '#e74c3c'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                }
            },
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });
}

/**
 * Create a data validation result chart
 */
function createValidationChart(elementId, validCount, invalidCount) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    return new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['验证成功', '验证失败'],
            datasets: [{
                data: [validCount, invalidCount],
                backgroundColor: [
                    '#2ecc71',
                    '#e74c3c'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                }
            },
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });
}
