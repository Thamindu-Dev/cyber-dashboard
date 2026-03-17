// API Configuration
const API_BASE_URL = 'https://tharu00001-cyber-dashboard.hf.space';

// Required 81 columns in exact order
const REQUIRED_COLUMNS = [
    'Source Port', 'Destination Port', 'Protocol', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
    'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
    'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Inbound'
];

// Chart instances
let attackDistributionChart = null;
let severityDistributionChart = null;

// Selected file
let selectedFile = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeDropZone();
    initializeColumnList();
    initializeFileInput();
});

// Initialize Drag & Drop Zone
function initializeDropZone() {
    const dropZone = document.getElementById('dropZone');

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileSelect(files[0]);
        }
    });

    dropZone.addEventListener('click', (e) => {
        if (e.target === dropZone || e.target.closest('svg') || e.target.closest('p')) {
            document.getElementById('fileInput').click();
        }
    });
}

// Initialize File Input
function initializeFileInput() {
    const fileInput = document.getElementById('fileInput');
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });
}

// Handle File Selection
function handleFileSelect(file) {
    // Validate file type
    if (!file.name.endsWith('.csv')) {
        alert('❌ Invalid file type\n\nPlease select a CSV file (.csv extension required)');
        return;
    }

    // Validate file size (100MB limit)
    const MAX_FILE_SIZE = 100 * 1024 * 1024;
    if (file.size > MAX_FILE_SIZE) {
        const sizeMB = (file.size / (1024 * 1024)).toFixed(1);
        alert(`❌ File too large\n\nYour file is ${sizeMB}MB. Maximum size is 100MB.\n\n💡 Solution: Split your file into smaller parts.`);
        return;
    }

    // Check if file is empty
    if (file.size === 0) {
        alert('❌ Empty file\n\nThe selected file is empty. Please choose a file with data.');
        return;
    }

    selectedFile = file;

    // Update file info
    document.getElementById('fileName').textContent = file.name;
    document.getElementById('fileSize').textContent = formatFileSize(file.size);

    // Show file info, hide drop zone
    document.getElementById('fileInfo').classList.remove('hidden');
    document.getElementById('dropZone').classList.add('hidden');

    // Reset results
    document.getElementById('resultsSection').classList.add('hidden');

    // Show success feedback
    console.log(`✅ File selected: ${file.name} (${formatFileSize(file.size)})`);
}

// Format File Size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Analyze File
async function analyzeFile() {
    if (!selectedFile) {
        alert('Please select a file first');
        return;
    }

    // File size validation (max 100MB for HF Spaces)
    const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
    if (selectedFile.size > MAX_FILE_SIZE) {
        alert('File too large. Maximum size is 100MB. For larger files, please split them.');
        return;
    }

    // Show loading state
    document.getElementById('loadingState').classList.remove('hidden');
    document.getElementById('analyzeBtn').disabled = true;

    const formData = new FormData();
    formData.append('file', selectedFile);

    // Timeout for HF Spaces cold start (60 seconds)
    const TIMEOUT = 60000;

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), TIMEOUT);

        const response = await fetch(`${API_BASE_URL}/upload-csv`, {
            method: 'POST',
            body: formData,
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            // Parse error response
            let errorDetail = `Server error (${response.status})`;

            try {
                const errorData = await response.json();
                errorDetail = errorData.detail || errorDetail;
            } catch (e) {
                // If we can't parse JSON, use status text
                errorDetail = response.statusText || `Server error (${response.status})`;
            }

            // Handle specific HTTP status codes
            switch (response.status) {
                case 413:
                    throw new Error('❌ File too large\n\n' + errorDetail);
                case 400:
                    throw new Error('❌ Invalid file\n\n' + errorDetail);
                case 429:
                    throw new Error('⚠️ Too many requests\n\nRate limit exceeded. Please wait a minute and try again.');
                case 507:
                    throw new Error('💾 Insufficient memory\n\n' + errorDetail);
                case 500:
                    throw new Error('🔧 Server error\n\nThe server encountered an error. Please try again.');
                default:
                    throw new Error('❌ ' + errorDetail);
            }
        }

        const data = await response.json();
        displayResults(data);

    } catch (error) {
        console.error('Error:', error);

        let errorMessage = 'An error occurred during analysis. ';

        if (error.name === 'AbortError') {
            errorMessage = '⏱️ Request timeout (60s). The HuggingFace Space may be waking up from sleep.\n\n' +
                          '💡 Solution: Wait 30 seconds and try again.';
        } else if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            errorMessage = '🌐 Connection failed. The HuggingFace Space may be starting up.\n\n' +
                          '💡 Solution: Wait a moment and try again. If this persists, the space may be down.';
        } else if (error.message) {
            errorMessage += '\n\n' + error.message;
        }

        // Show error in alert
        alert(errorMessage);

        // Log for debugging
        console.error('Full error details:', {
            name: error.name,
            message: error.message,
            stack: error.stack
        });
    } finally {
        document.getElementById('loadingState').classList.add('hidden');
        document.getElementById('analyzeBtn').disabled = false;
    }
}

// Display Results
function displayResults(data) {
    // Show results section
    document.getElementById('resultsSection').classList.remove('hidden');

    // Update summary cards
    document.getElementById('totalFlows').textContent = data.summary.total_flows_analyzed.toLocaleString();
    document.getElementById('attackTypes').textContent = data.summary.unique_attack_types_detected;
    document.getElementById('avgSeverity').textContent = data.summary.average_severity_score + '%';
    document.getElementById('criticalAlerts').textContent = data.summary.critical_alerts_count;

    // Update charts
    updateAttackDistributionChart(data.attack_distribution);
    updateSeverityDistributionChart(data.severity_distribution);

    // Update critical alerts table
    updateCriticalAlertsTable(data.critical_alerts_sample);

    // Scroll to results
    document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
}

// Update Attack Distribution Chart
function updateAttackDistributionChart(distribution) {
    const ctx = document.getElementById('attackDistributionChart').getContext('2d');

    if (attackDistributionChart) {
        attackDistributionChart.destroy();
    }

    const labels = Object.keys(distribution);
    const data = Object.values(distribution);

    // Generate colors
    const colors = generateColors(labels.length);

    attackDistributionChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderColor: '#1a1a2e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#d1d5db',
                        font: {
                            size: 11
                        },
                        padding: 10
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value.toLocaleString()} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Update Severity Distribution Chart
function updateSeverityDistributionChart(distribution) {
    const ctx = document.getElementById('severityDistributionChart').getContext('2d');

    if (severityDistributionChart) {
        severityDistributionChart.destroy();
    }

    const labels = Object.keys(distribution);
    const data = Object.values(distribution);

    severityDistributionChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels.map(l => l.split(' (')[0]), // Remove percentage from label
            datasets: [{
                label: 'Number of Flows',
                data: data,
                backgroundColor: [
                    'rgba(34, 197, 94, 0.7)',   // low - green
                    'rgba(251, 146, 60, 0.7)',  // medium - orange
                    'rgba(251, 191, 36, 0.7)',  // high - yellow
                    'rgba(239, 68, 68, 0.7)'    // critical - red
                ],
                borderColor: [
                    'rgba(34, 197, 94, 1)',
                    'rgba(251, 146, 60, 1)',
                    'rgba(251, 191, 36, 1)',
                    'rgba(239, 68, 68, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.parsed.y.toLocaleString()} flows`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#d1d5db'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                x: {
                    ticks: {
                        color: '#d1d5db'
                    },
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

// Update Critical Alerts Table
function updateCriticalAlertsTable(alerts) {
    const tableBody = document.getElementById('criticalAlertsTable');
    const noAlertsDiv = document.getElementById('noCriticalAlerts');
    const criticalCount = document.getElementById('criticalCount');

    tableBody.innerHTML = '';

    if (alerts.length === 0) {
        noAlertsDiv.classList.remove('hidden');
        criticalCount.textContent = '0';
        return;
    }

    noAlertsDiv.classList.add('hidden');
    criticalCount.textContent = alerts.length + ' alerts';

    alerts.forEach((alert, index) => {
        const row = document.createElement('tr');
        row.className = 'border-b border-gray-800 critical-row table-row-animate';
        row.style.animationDelay = `${index * 0.05}s`;

        const severityClass = getSeverityClass(alert.severity_score);
        const protocolClass = getProtocolClass(alert.protocol);

        row.innerHTML = `
            <td class="py-3 px-4 text-gray-400">${index + 1}</td>
            <td class="py-3 px-4 text-white font-mono">${alert.flow_index.toLocaleString()}</td>
            <td class="py-3 px-4 text-white font-semibold">${alert.attack_type}</td>
            <td class="py-3 px-4">
                <span class="severity-badge ${severityClass}">${alert.severity_score}%</span>
            </td>
            <td class="py-3 px-4 text-gray-300 font-mono">${alert.source_port}</td>
            <td class="py-3 px-4 text-gray-300 font-mono">${alert.destination_port}</td>
            <td class="py-3 px-4">
                <span class="protocol-badge ${protocolClass}">${getProtocolName(alert.protocol)}</span>
            </td>
        `;

        tableBody.appendChild(row);
    });
}

// Get Severity Class
function getSeverityClass(score) {
    if (score >= 86) return 'severity-critical';
    if (score >= 61) return 'severity-high';
    if (score >= 31) return 'severity-medium';
    return 'severity-low';
}

// Get Protocol Class
function getProtocolClass(protocol) {
    const protocolNum = parseInt(protocol);
    if (protocolNum === 6) return 'protocol-tcp';
    if (protocolNum === 17) return 'protocol-udp';
    if (protocolNum === 1) return 'protocol-icmp';
    return '';
}

// Get Protocol Name
function getProtocolName(protocol) {
    const protocolNum = parseInt(protocol);
    switch (protocolNum) {
        case 1: return 'ICMP';
        case 6: return 'TCP';
        case 17: return 'UDP';
        default: return `Proto ${protocolNum}`;
    }
}

// Generate Colors for Chart
function generateColors(count) {
    const baseColors = [
        '#06b6d4', // cyan
        '#3b82f6', // blue
        '#8b5cf6', // violet
        '#ec4899', // pink
        '#f59e0b', // amber
        '#10b981', // emerald
        '#ef4444', // red
        '#6366f1', // indigo
        '#14b8a6', // teal
        '#f97316', // orange
        '#84cc16', // lime
        '#06b6d4', // cyan
        '#d946ef', // fuchsia
        '#22c55e'  // green
    ];

    const colors = [];
    for (let i = 0; i < count; i++) {
        colors.push(baseColors[i % baseColors.length]);
    }
    return colors;
}

// Initialize Column List
function initializeColumnList() {
    const container = document.getElementById('columnList');
    container.innerHTML = '';

    REQUIRED_COLUMNS.forEach((column, index) => {
        const div = document.createElement('div');
        div.className = 'column-item';
        div.innerHTML = `
            <span class="text-cyan-400 text-xs mr-2">${String(index + 1).padStart(2, '0')}.</span>
            <span class="text-gray-300">${column}</span>
        `;
        container.appendChild(div);
    });
}

// Toggle User Guide Modal
function toggleUserGuide() {
    const modal = document.getElementById('userGuideModal');
    modal.classList.toggle('hidden');
    if (!modal.classList.contains('hidden')) {
        modal.classList.add('show');
    }
}

// Toggle Column Reference Modal
function toggleColumnReference() {
    const modal = document.getElementById('columnRefModal');
    modal.classList.toggle('hidden');
    if (!modal.classList.contains('hidden')) {
        modal.classList.add('show');
    }
}

// Download Sample CSV
function downloadSampleCSV() {
    const csvContent = REQUIRED_COLUMNS.join(',') + '\n';

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ddos_detection_template.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    showNotification('Sample CSV template downloaded!');
}

// Copy Column List
function copyColumnList() {
    const text = REQUIRED_COLUMNS.join(',\n');

    navigator.clipboard.writeText(text).then(() => {
        showNotification('Column list copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy:', err);
        alert('Failed to copy to clipboard');
    });
}

// Show Notification
function showNotification(message) {
    const notification = document.createElement('div');
    notification.className = 'copy-notification';
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Close modals on escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.getElementById('userGuideModal').classList.add('hidden');
        document.getElementById('columnRefModal').classList.add('hidden');
    }
});

// Close modals on backdrop click
document.getElementById('userGuideModal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('userGuideModal')) {
        toggleUserGuide();
    }
});

document.getElementById('columnRefModal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('columnRefModal')) {
        toggleColumnReference();
    }
});
