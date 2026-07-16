let severityChart = null;
let isScanning = false;
let activeFilters = { high: true, medium: true, low: true };
let currentFindings = [];

async function loadDashboard() {
    if (isScanning) return;

    const statusEl = document.getElementById('status');
    statusEl.textContent = 'Loading...';
    statusEl.className = 'status-badge loading';

    try {
        const response = await fetch('/api/dashboard/stats');
        const data = await response.json();
        updateDashboard(data);
        
        // Update status to Ready
        statusEl.textContent = '✓ Ready';
        statusEl.className = 'status-badge ready';
    } catch (error) {
        console.error('Error loading dashboard:', error);
        statusEl.textContent = '⚠ Error';
        statusEl.className = 'status-badge error';
    }
}

function updateDashboard(data) {
    const summary = data.summary || {};
    const findings = data.findings || [];
    const providers = data.providers || {};
    currentFindings = findings;

    // Update risk score and level
    const riskScore = Math.min(100, findings.length * 10);
    const riskLevel = riskScore > 70 ? 'High' : riskScore > 30 ? 'Medium' : 'Low';
    const riskColor = riskScore > 70 ? '#ef4444' : riskScore > 30 ? '#f59e0b' : '#10b981';
    const riskMessage = riskScore > 70 ? 'Requires immediate attention' : riskScore > 30 ? 'Review findings' : 'Secure';

    document.getElementById('risk-score').textContent = riskScore;
    document.getElementById('risk-level').textContent = riskLevel;
    document.getElementById('risk-message').textContent = riskMessage;
    const riskCircle = document.getElementById('risk-circle');
    riskCircle.style.background = `linear-gradient(135deg, ${riskColor}, ${riskColor}cc)`;

    // Update stats
    document.getElementById('total-findings').textContent = findings.length;
    document.getElementById('critical-count').textContent = findings.filter(f => f.severity === 'high').length;
    document.getElementById('scanned-files').textContent = summary.scanned_files || 0;

    // Update filter buttons counts
    const severityCounts = {
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
    };
    document.getElementById('filter-high-count').textContent = severityCounts.high;
    document.getElementById('filter-medium-count').textContent = severityCounts.medium;
    document.getElementById('filter-low-count').textContent = severityCounts.low;

    // Update CWEs
    const cwes = summary.covered_cwes || [];
    const cweContainer = document.getElementById('cwe-tags');
    cweContainer.innerHTML = cwes.map(cwe => `<span class="cwe-tag">${cwe}</span>`).join('');

    // Update severity chart
    updateSeverityChart(findings);

    // Update findings list
    updateFindingsList(findings);

    // Update provider status
    updateProviderStatus(providers);

    // Update timestamp
    const now = new Date();
    document.getElementById('last-update').textContent = `Last update: ${now.toLocaleTimeString()}`;

    // Show export button if results exist
    const exportBtn = document.getElementById('export-btn');
    if (exportBtn) {
        if (findings.length > 0 || (summary && summary.scanned_files > 0)) {
            exportBtn.style.display = 'inline-block';
        } else {
            exportBtn.style.display = 'none';
        }
    }
}

function updateSeverityChart(findings) {
    const severityCounts = {
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
    };

    const ctx = document.getElementById('severityChart');
    if (!ctx) return;

    if (severityChart) {
        severityChart.destroy();
    }

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['High', 'Medium', 'Low'],
            datasets: [{
                data: [severityCounts.high, severityCounts.medium, severityCounts.low],
                backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6'],
                borderColor: 'white',
                borderWidth: 2,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false,
                },
            },
        },
    });

    // Apply active filter state visibility to the new chart slices
    const indexMap = { high: 0, medium: 1, low: 2 };
    for (const [sev, idx] of Object.entries(indexMap)) {
        if (!activeFilters[sev]) {
            severityChart.toggleDataVisibility(idx);
        }
    }
    severityChart.update();
}

function updateFindingsList(findings) {
    const container = document.getElementById('findings-list');
    
    // Sort findings by severity: high -> medium -> low
    const severityOrder = { high: 0, medium: 1, low: 2 };
    const sortedFindings = [...findings].sort((a, b) => {
        const sevA = (a.severity || 'low').toLowerCase();
        const sevB = (b.severity || 'low').toLowerCase();
        const orderA = severityOrder[sevA] !== undefined ? severityOrder[sevA] : 3;
        const orderB = severityOrder[sevB] !== undefined ? severityOrder[sevB] : 3;
        return orderA - orderB;
    });

    const filteredFindings = sortedFindings.filter(f => {
        const sev = (f.severity || 'low').toLowerCase();
        return activeFilters[sev] === true;
    });

    if (filteredFindings.length === 0) {
        container.innerHTML = '<p class="empty-state">No findings match the selected severity filters.</p>';
        return;
    }

    const html = filteredFindings.map(finding => {
        const displayPath = finding.file || 'N/A';
        const sev = (finding.severity || 'low').toLowerCase();
        
        return `
        <div class="finding-item ${sev}">
            <div>
                <div class="finding-rule">${finding.rule || 'Unknown'}</div>
                <div class="finding-cwe">${finding.cwe || 'N/A'}${finding.cwe_title ? `: ${finding.cwe_title}` : ''}</div>
                <div class="finding-description" style="font-size: 13px; color: var(--text-light); margin-top: 6px; font-weight: 500;">
                    ${finding.description || ''}
                </div>
                ${finding.cwe_description ? `
                <div class="cwe-description" style="font-size: 11px; font-style: italic; color: #888; margin-top: 4px; line-height: 1.4;">
                    <strong>MITRE CWE Detail:</strong> ${finding.cwe_description}
                </div>` : ''}
            </div>
            <div style="font-size: 13px; line-height: 1.5;">
                <div style="color: var(--text); word-break: break-all;">
                    <strong>File:</strong> <span class="finding-path" title="${finding.file || ''}">${displayPath}</span>
                </div>
                ${finding.line ? `
                <div style="color: var(--text-light); margin-top: 3px;">
                    <strong>Line:</strong> ${finding.line}
                </div>` : ''}
            </div>
            <div class="finding-severity ${sev}">
                ${sev.toUpperCase()}
            </div>
        </div>
        `;
    }).join('');

    container.innerHTML = html;
}

function updateProviderStatus(providers) {
    for (const [provider, status] of Object.entries(providers)) {
        const statusEl = document.getElementById(`status-${provider}`);
        const toggleEl = document.getElementById(`toggle-${provider}`);
        
        if (statusEl) {
            const isEnabled = status.enabled;
            statusEl.textContent = isEnabled ? 'Enabled' : 'Disabled';
            statusEl.className = `provider-status ${isEnabled ? '' : 'disabled'}`;
            statusEl.style.background = isEnabled ? '#d1fae5' : '#fee2e2';
            statusEl.style.color = isEnabled ? '#059669' : '#dc2626';
        }
        
        if (toggleEl) {
            toggleEl.checked = status.enabled;
        }
    }
}

// Provider toggle handling
document.querySelectorAll('.provider-toggle').forEach(toggle => {
    toggle.addEventListener('change', (e) => {
        const provider = e.target.getAttribute('data-provider');
        const isEnabled = e.target.checked;
        
        // Update status immediately
        const statusEl = document.getElementById(`status-${provider}`);
        if (statusEl) {
            statusEl.textContent = isEnabled ? 'Enabled' : 'Disabled';
            statusEl.style.background = isEnabled ? '#d1fae5' : '#fee2e2';
            statusEl.style.color = isEnabled ? '#059669' : '#dc2626';
        }
        
        // Store in localStorage for persistence
        const providerSettings = JSON.parse(localStorage.getItem('providerSettings') || '{}');
        providerSettings[provider] = { enabled: isEnabled };
        localStorage.setItem('providerSettings', JSON.stringify(providerSettings));
        
        console.log(`Provider ${provider} toggled to ${isEnabled ? 'Enabled' : 'Disabled'}`);
    });
});

// Tab switching
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        const tab = item.getAttribute('data-tab');

        document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
        item.classList.add('active');

        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(tab).classList.add('active');
    });
});

// Scan form handling
document.getElementById('scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const sourcePath = document.getElementById('source-path').value;
    const resultEl = document.getElementById('scan-result');
    const progressContainer = document.getElementById('scan-progress-container');
    const progressBarFill = document.getElementById('progress-bar-fill');
    const progressPercentage = document.getElementById('progress-percentage');
    const progressStatusText = document.getElementById('progress-status-text');
    const button = e.target.querySelector('button');
    const statusEl = document.getElementById('status');

    // Set scanning state
    isScanning = true;

    // Reset and show progress UI
    button.disabled = true;
    button.textContent = 'Scanning...';
    statusEl.textContent = 'Scanning...';
    statusEl.className = 'status-badge scanning';
    
    resultEl.classList.remove('show');
    progressContainer.classList.add('show');
    
    // Configure progress steps (texts only)
    const steps = [
        { minPct: 0, maxPct: 25, activeText: '🔍 Analyzing built-in AST heuristics...' },
        { minPct: 25, maxPct: 50, activeText: '🐍 Invoking Bandit Python static analyzer...' },
        { minPct: 50, maxPct: 75, activeText: '⚙️ Initializing CodeQL database check...' },
        { minPct: 75, maxPct: 95, activeText: '📁 Formatting and compiling JSON security report...' }
    ];

    let currentPct = 0;
    progressBarFill.style.width = '0%';
    progressPercentage.textContent = '0%';
    progressBarFill.style.background = 'linear-gradient(90deg, #3b82f6, #10b981)';

    const intervalTime = 100; // ms
    const totalSimulatedTime = 3000; // reach 95% in 3 seconds asymptotically
    const increment = 95 / (totalSimulatedTime / intervalTime);

    const progressInterval = setInterval(() => {
        if (currentPct < 95) {
            currentPct = Math.min(95, currentPct + increment);
            updateProgressUI(currentPct);
        }
    }, intervalTime);

    function updateProgressUI(pct) {
        const roundedPct = Math.round(pct);
        progressBarFill.style.width = `${roundedPct}%`;
        progressPercentage.textContent = `${roundedPct}%`;

        const currentStep = steps.find(step => pct >= step.minPct && pct < step.maxPct);
        if (currentStep) {
            progressStatusText.textContent = currentStep.activeText;
        }
    }

    // Get checked/enabled providers from checkboxes
    const providers = [];
    ['openai', 'claude', 'ollama', 'cursor'].forEach(p => {
        const toggle = document.getElementById(`toggle-${p}`);
        if (toggle && toggle.checked) {
            providers.push(p);
        }
    });

    try {
        const response = await fetch('/api/dashboard/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source_path: sourcePath, providers: providers }),
        });

        const data = await response.json();

        // Clear simulation and jump to 100%
        clearInterval(progressInterval);

        if (response.ok) {
            // Success animation
            currentPct = 100;
            progressBarFill.style.width = '100%';
            progressPercentage.textContent = '100%';
            progressStatusText.textContent = '✓ Scan complete!';

            // Pause briefly to let user appreciate the complete state
            await new Promise(resolve => setTimeout(resolve, 600));

            resultEl.className = 'scan-result show success';
            resultEl.innerHTML = `
                <h3>✓ Scan Completed Successfully</h3>
                <div style="margin-top: 10px; display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                    <div style="background: white; padding: 12px; border-radius: 6px; border: 1px solid #bbf7d0; text-align: center;">
                        <span style="font-size: 20px; display: block; margin-bottom: 4px;">⚠️</span>
                        <strong style="font-size: 18px; color: #0f172a;">${data.findings_count || 0}</strong>
                        <span style="font-size: 11px; display: block; color: #64748b; text-transform: uppercase;">Findings Detected</span>
                    </div>
                    <div style="background: white; padding: 12px; border-radius: 6px; border: 1px solid #bbf7d0; text-align: center;">
                        <span style="font-size: 20px; display: block; margin-bottom: 4px;">📁</span>
                        <strong style="font-size: 18px; color: #0f172a;">${data.scanned_files || 0}</strong>
                        <span style="font-size: 11px; display: block; color: #64748b; text-transform: uppercase;">Files Scanned</span>
                    </div>
                </div>
            `;
            statusEl.textContent = '✓ Ready';
            statusEl.className = 'status-badge ready';
            isScanning = false;
            await loadDashboard();
        } else {
            progressBarFill.style.background = 'var(--danger)';
            progressStatusText.textContent = '⚠ Scan failed';
            
            resultEl.className = 'scan-result show error';
            resultEl.textContent = `Error: ${data.detail || 'Failed to scan'}`;
            statusEl.textContent = '⚠ Error';
            statusEl.className = 'status-badge error';
        }
    } catch (error) {
        clearInterval(progressInterval);
        progressBarFill.style.background = 'var(--danger)';
        progressStatusText.textContent = '⚠ Scan failed';

        resultEl.className = 'scan-result show error';
        resultEl.textContent = `Error: ${error.message}`;
        statusEl.textContent = '⚠ Error';
        statusEl.className = 'status-badge error';
    } finally {
        isScanning = false;
        button.disabled = false;
        button.textContent = 'Start Scan';
    }
});

// Export report button handling
document.getElementById('export-btn').addEventListener('click', () => {
    window.location.href = '/api/dashboard/export';
});

document.addEventListener('DOMContentLoaded', () => {
    // Initialize provider settings from localStorage
    const providerSettings = JSON.parse(localStorage.getItem('providerSettings') || '{}');
    document.querySelectorAll('.provider-toggle').forEach(toggle => {
        const provider = toggle.getAttribute('data-provider');
        if (providerSettings[provider]) {
            toggle.checked = providerSettings[provider].enabled;
        }
    });

    // Initialize interactive severity filters click listeners
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const severity = btn.getAttribute('data-severity');
            activeFilters[severity] = !activeFilters[severity];
            
            // Toggle active styling
            if (activeFilters[severity]) {
                btn.classList.add('active');
                if (severity === 'high') {
                    btn.style.background = '#fee2e2';
                    btn.style.color = '#b91c1c';
                    btn.style.borderColor = '#ef4444';
                } else if (severity === 'medium') {
                    btn.style.background = '#fef3c7';
                    btn.style.color = '#b45309';
                    btn.style.borderColor = '#f59e0b';
                } else if (severity === 'low') {
                    btn.style.background = '#dbeafe';
                    btn.style.color = '#1d4ed8';
                    btn.style.borderColor = '#3b82f6';
                }
            } else {
                btn.classList.remove('active');
                btn.style.background = '#f3f4f6';
                btn.style.color = '#9ca3af';
                btn.style.borderColor = '#e5e7eb';
            }

            // Sync with Chart.js slice visibility
            if (severityChart) {
                const indexMap = { high: 0, medium: 1, low: 2 };
                const chartIndex = indexMap[severity];
                const isVisible = severityChart.getDataVisibility(chartIndex);
                if (isVisible !== activeFilters[severity]) {
                    severityChart.toggleDataVisibility(chartIndex);
                    severityChart.update();
                }
            }

            // Render filtered findings list
            updateFindingsList(currentFindings);
        });
    });
    
    // Load dashboard data
    loadDashboard();
});

// Refresh data every 30 seconds
setInterval(loadDashboard, 30000);
