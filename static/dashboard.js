let severityChart = null;
let isScanning = false;
let activeFilters = { critical: true, high: true, medium: true, low: true };
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
    // Count both critical secrets and high issues as critical count for dashboard top summary
    document.getElementById('critical-count').textContent = findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
    document.getElementById('scanned-files').textContent = summary.scanned_files || 0;

    // Update filter buttons counts
    const severityCounts = {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
    };
    document.getElementById('filter-critical-count').textContent = severityCounts.critical;
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

    // Render Security Policy Gate Card
    const gateCard = document.getElementById('gate-card');
    if (gateCard) {
        if (data.gate_status) {
            gateCard.style.display = 'flex';
            const gateBadge = document.getElementById('gate-badge');
            const gateReasons = document.getElementById('gate-reasons');
            
            gateBadge.textContent = data.gate_status;
            if (data.gate_status === 'PASS') {
                gateBadge.style.background = '#dcfce7';
                gateBadge.style.color = '#15803d';
                gateBadge.style.border = '1px solid #bbf7d0';
                gateReasons.style.color = '#16a34a';
                gateReasons.textContent = '✓ All security policies satisfied successfully.';
            } else {
                gateBadge.style.background = '#fee2e2';
                gateBadge.style.color = '#b91c1c';
                gateBadge.style.border = '1px solid #fca5a5';
                gateReasons.style.color = '#dc2626';
                if (data.gate_reasons && data.gate_reasons.length > 0) {
                    gateReasons.innerHTML = data.gate_reasons.map(r => `• ${r}`).join('<br>');
                } else {
                    gateReasons.textContent = '❌ Gate failed due to policy violations.';
                }
            }
        } else {
            gateCard.style.display = 'none';
        }
    }

    // Update timestamp
    const now = new Date();
    document.getElementById('last-update').textContent = `Last update: ${now.toLocaleTimeString()}`;

    // Show export button if results exist
    const exportBtn = document.getElementById('export-btn');
    const exportSarifBtn = document.getElementById('export-sarif-btn');
    const sbomContainer = document.getElementById('sbom-export-container');
    if (exportBtn) {
        if (findings.length > 0 || (summary && summary.scanned_files > 0)) {
            exportBtn.style.display = 'inline-block';
            if (exportSarifBtn) exportSarifBtn.style.display = 'inline-block';
            if (sbomContainer) sbomContainer.style.display = 'inline-block';
        } else {
            exportBtn.style.display = 'none';
            if (exportSarifBtn) exportSarifBtn.style.display = 'none';
            if (sbomContainer) sbomContainer.style.display = 'none';
        }
    }
}

function updateSeverityChart(findings) {
    const severityCounts = {
        critical: findings.filter(f => f.severity === 'critical').length,
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
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [severityCounts.critical, severityCounts.high, severityCounts.medium, severityCounts.low],
                backgroundColor: ['#b91c1c', '#ef4444', '#f59e0b', '#3b82f6'],
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
    const indexMap = { critical: 0, high: 1, medium: 2, low: 3 };
    for (const [sev, idx] of Object.entries(indexMap)) {
        if (!activeFilters[sev]) {
            severityChart.toggleDataVisibility(idx);
        }
    }
    severityChart.update();
}

function getFindingRiskPanelHtml(finding) {
    const conf = finding.confidence || 60;
    const riskScore = finding.risk_score !== undefined ? finding.risk_score : 5.0;
    const riskSeverity = (finding.severity || 'medium').toUpperCase();
    
    let riskColor = '#4b5563';
    if (finding.severity === 'critical') riskColor = '#b91c1c';
    else if (finding.severity === 'high') riskColor = '#ea580c';
    else if (finding.severity === 'medium') riskColor = '#d97706';
    
    const reachable = finding.reachable || 'YES';
    const reachableColor = reachable === 'YES' ? '#dc2626' : '#059669';
    
    const exposed = finding.internet_exposed || 'NO';
    const exposedColor = exposed === 'YES' ? '#dc2626' : '#059669';
    
    const exploit = finding.exploitability || 'MEDIUM';
    const exploitColor = exploit === 'HIGH' ? '#dc2626' : (exploit === 'MEDIUM' ? '#d97706' : '#4b5563');
    
    const detectors = finding.detected_by || [finding.rule.startsWith('ast-') ? 'AST' : (finding.rule.startsWith('bandit-') ? 'Bandit' : (finding.rule.startsWith('codeql-') ? 'CodeQL' : 'AI'))];

    return `
    <!-- Risk Prioritization Panel -->
    <div style="margin-top: 8px; display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; background: #fafafa; padding: 10px; border-radius: 6px; border: 1px dashed #e2e8f0; font-size: 11px; color: #475569; margin-bottom: 8px; line-height: 1.4;">
        <div><strong>Risk Score:</strong> <span style="font-weight: 700; color: ${riskColor}; font-size: 12px;">${riskScore} ${riskSeverity}</span></div>
        <div><strong>CVSS Base:</strong> <code style="font-weight: 600; color: #0f172a;">${finding.cvss || '6.5'}</code></div>
        <div><strong>Reachable:</strong> <span style="font-weight: 600; color: ${reachableColor};">${reachable}</span></div>
        <div><strong>Internet Exposed:</strong> <span style="font-weight: 600; color: ${exposedColor};">${exposed}</span></div>
        <div><strong>Confidence:</strong> <code style="font-weight: 600; color: #0f172a;">${conf}%</code></div>
        <div><strong>Exploitability:</strong> <span style="font-weight: 600; color: ${exploitColor};">${exploit}</span></div>
        <div style="grid-column: 1 / -1; display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-top: 4px; border-top: 1px solid #f1f5f9; padding-top: 6px;">
            <strong>Detected by:</strong>
            ${detectors.map(d => `<span style="background: #f1f5f9; color: #334155; border: 1px solid #e2e8f0; padding: 1px 6px; border-radius: 4px; font-weight: 600; font-size: 10px; display: inline-flex; align-items: center; gap: 2px;">✓ ${d}</span>`).join('')}
        </div>
        
        <!-- Interactive Remediation Buttons -->
        <div style="grid-column: 1 / -1; display: flex; gap: 8px; align-items: center; margin-top: 8px; border-top: 1px solid #f1f5f9; padding-top: 8px; flex-wrap: wrap;">
            <strong>Remediation:</strong>
            <button class="remediation-btn" onclick="triggerRemediation('${finding.fingerprint}', 'explain', this)" style="background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; border-radius: 4px; padding: 3px 8px; font-size: 10px; font-weight: 600; cursor: pointer; transition: all 0.2s;">Explain</button>
            <button class="remediation-btn" onclick="triggerRemediation('${finding.fingerprint}', 'patch', this)" style="background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; border-radius: 4px; padding: 3px 8px; font-size: 10px; font-weight: 600; cursor: pointer; transition: all 0.2s;">Generate Patch</button>
            <button class="remediation-btn" onclick="triggerRemediation('${finding.fingerprint}', 'dataflow', this)" style="background: #faf5ff; color: #6b21a8; border: 1px solid #e9d5ff; border-radius: 4px; padding: 3px 8px; font-size: 10px; font-weight: 600; cursor: pointer; transition: all 0.2s;">View Data Flow</button>
        </div>
        
        <!-- Expanded Remediation Details Container -->
        <div id="remediation-details-${finding.fingerprint}" style="grid-column: 1 / -1; display: none; margin-top: 8px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 10px; font-size: 11px; line-height: 1.5;">
        </div>
    </div>
    `;
}

function updateFindingsList(findings) {
    const container = document.getElementById('findings-list');
    
    // Sort findings by severity: critical -> high -> medium -> low
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const sortedFindings = [...findings].sort((a, b) => {
        const sevA = (a.severity || 'low').toLowerCase();
        const sevB = (b.severity || 'low').toLowerCase();
        const orderA = severityOrder[sevA] !== undefined ? severityOrder[sevA] : 4;
        const orderB = severityOrder[sevB] !== undefined ? severityOrder[sevB] : 4;
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
        const fingerprint = finding.fingerprint ? finding.fingerprint.substring(0, 12) : 'N/A';
        
        if (finding.type === 'IAC') {
            return `
            <div class="finding-item ${sev}">
                <div style="flex: 1; min-width: 0;">
                    <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                        <span class="finding-rule" style="color: #1e293b; background: #f1f5f9; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; border: 1px solid #e2e8f0;">
                            IaC: ${finding.rule}
                        </span>
                        <span class="finding-cwe" style="background: #f8fafc; color: #475569; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">
                            ${finding.cwe || 'N/A'}
                        </span>
                        <span style="font-family: monospace; font-size: 10px; color: #94a3b8; background: #fafafa; padding: 2px 6px; border: 1px dashed #e2e8f0; border-radius: 4px;" title="Fingerprint: ${finding.fingerprint || 'N/A'}">
                            FP: ${fingerprint}...
                        </span>
                    </div>
                    <div class="finding-description" style="font-size: 13px; color: var(--text-light); margin-top: 8px; font-weight: 500;">
                        ${finding.description || ''}
                    </div>
                    
                    ${getFindingRiskPanelHtml(finding)}
                    
                    <!-- Remediation Guidelines -->
                    <div class="remediation-recommendation" style="font-size: 12px; color: #b45309; background: #fffbeb; padding: 8px 12px; border-radius: 6px; border: 1px solid #fef3c7; margin-top: 10px; line-height: 1.4;">
                        <strong>🔧 Remediation:</strong> ${finding.remediation || 'Correct the configuration file as advised.'}
                    </div>
                </div>
                <div style="font-size: 13px; line-height: 1.5; min-width: 180px; max-width: 250px;">
                    <div style="color: var(--text); word-break: break-all;">
                        <strong>Config:</strong> <span class="finding-path" title="${finding.file || ''}">${displayPath}</span>
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
        }

        if (finding.type === 'SCA') {
            return `
            <div class="finding-item ${sev}">
                <div style="flex: 1; min-width: 0;">
                    <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                        <span class="finding-rule" style="color: #475569; background: #e2e8f0; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;">
                            SCA: ${finding.package}
                        </span>
                        <span class="finding-cwe" style="background: #f1f5f9; color: #475569; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">
                            ${finding.cve || 'N/A'}
                        </span>
                        <span style="font-family: monospace; font-size: 10px; color: #94a3b8; background: #fafafa; padding: 2px 6px; border: 1px dashed #e2e8f0; border-radius: 4px;" title="Fingerprint: ${finding.fingerprint || 'N/A'}">
                            FP: ${fingerprint}...
                        </span>
                    </div>
                    <div style="margin-top: 8px; display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 10px; background: #fafafa; padding: 10px; border-radius: 6px; border: 1px solid #f1f5f9; font-size: 12px; margin-bottom: 8px;">
                        <div><strong>Package:</strong> <code style="color: #0f172a; font-weight: 600;">${finding.package}</code></div>
                        <div><strong>Installed:</strong> <code style="color: #dc2626; font-weight: 600;">${finding.installed}</code></div>
                        <div><strong>Affected:</strong> <code style="color: #b45309; font-weight: 600;">${finding.affected}</code></div>
                        <div><strong>Fix:</strong> <span style="color: #10b981; font-weight: 600;">${finding.fix}</span></div>
                    </div>
                    <div class="finding-description" style="font-size: 13px; color: var(--text-light); margin-top: 6px; font-weight: 500;">
                        ${finding.description || ''}
                    </div>
                    
                    ${getFindingRiskPanelHtml(finding)}
                    
                    <!-- Remediation Guidelines -->
                    <div class="remediation-recommendation" style="font-size: 12px; color: #0f766e; background: #f0fdfa; padding: 8px 12px; border-radius: 6px; border: 1px solid #ccfbf1; margin-top: 10px; line-height: 1.4;">
                        <strong>🔧 Remediation:</strong> ${finding.remediation || 'Upgrade dependency as suggested.'}
                    </div>
                </div>
                <div style="font-size: 13px; line-height: 1.5; min-width: 180px; max-width: 250px;">
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
        }

        return `
        <div class="finding-item ${sev}">
            <div style="flex: 1; min-width: 0;">
                <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                    <span class="finding-rule">${finding.rule || 'Unknown'}</span>
                    <span class="finding-cwe" style="background: #f1f5f9; color: #475569; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">
                        ${finding.cwe || 'N/A'} (CVE: ${finding.cve || 'N/A'})
                    </span>
                    <span style="font-family: monospace; font-size: 10px; color: #94a3b8; background: #fafafa; padding: 2px 6px; border: 1px dashed #e2e8f0; border-radius: 4px;" title="Fingerprint: ${finding.fingerprint || 'N/A'}">
                        FP: ${fingerprint}...
                    </span>
                </div>
                <div style="margin-top: 4px; font-size: 12px; font-weight: 600; color: #475569;">
                    ${finding.cwe_title || ''}
                </div>
                <div class="finding-description" style="font-size: 13px; color: var(--text-light); margin-top: 6px; font-weight: 500;">
                    ${finding.description || ''}
                    ${finding.secret ? `
                    <div style="margin-top: 6px; font-family: monospace; background: #fef2f2; color: #991b1b; padding: 4px 8px; border-radius: 4px; display: inline-block; font-size: 11px; border: 1px dashed #f87171;">
                        <strong>Secret:</strong> <code>${finding.secret}</code>
                    </div>` : ''}
                </div>
                
                ${getFindingRiskPanelHtml(finding)}
                
                <!-- Remediation Guidelines -->
                <div class="remediation-recommendation" style="font-size: 12px; color: #0f766e; background: #f0fdfa; padding: 8px 12px; border-radius: 6px; border: 1px solid #ccfbf1; margin-top: 10px; line-height: 1.4;">
                    <strong>🔧 Remediation:</strong> ${finding.remediation || 'Perform standard sanitization.'}
                </div>

                ${finding.cwe_description ? `
                <div class="cwe-description" style="font-size: 11px; font-style: italic; color: #888; margin-top: 8px; line-height: 1.4;">
                    <strong>MITRE CWE Detail:</strong> ${finding.cwe_description}
                </div>` : ''}
            </div>
            <div style="font-size: 13px; line-height: 1.5; min-width: 180px; max-width: 250px;">
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

// Toggle source fields based on radio selection
document.querySelectorAll('input[name="source_type"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
        const localGroup = document.getElementById('local-source-group');
        const gitGroup = document.getElementById('github-source-group');
        const sourcePath = document.getElementById('source-path');
        const repoUrl = document.getElementById('repo-url');
        
        if (e.target.value === 'git') {
            localGroup.style.display = 'none';
            gitGroup.style.display = 'flex';
            sourcePath.removeAttribute('required');
            repoUrl.setAttribute('required', 'true');
        } else {
            localGroup.style.display = 'block';
            gitGroup.style.display = 'none';
            sourcePath.setAttribute('required', 'true');
            repoUrl.removeAttribute('required');
        }
    });
});

// Scan form handling
document.getElementById('scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const sourceType = document.querySelector('input[name="source_type"]:checked').value;
    const sourcePath = document.getElementById('source-path').value;
    const repoUrl = document.getElementById('repo-url').value;
    const branch = document.getElementById('branch').value;
    const scanProfile = document.getElementById('scan-profile').value;

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
        { minPct: 0, maxPct: 20, activeText: '📦 Creating isolated ephemeral sandbox...' },
        { minPct: 20, maxPct: 40, activeText: '📁 Copying repository source code to sandbox...' },
        { minPct: 40, maxPct: 60, activeText: '🔒 Disabling sandbox network & applying resource limits...' },
        { minPct: 60, maxPct: 85, activeText: '⚙️ Running static analysis (Bandit & AST) inside sandbox...' },
        { minPct: 85, maxPct: 95, activeText: '📥 Extracting structured findings & wiping sandbox...' }
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
        const payload = {
            source_type: sourceType,
            source_path: sourcePath,
            repo_url: repoUrl,
            branch: branch,
            scan_profile: scanProfile,
            providers: providers
        };

        const response = await fetch('/api/dashboard/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
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
                <div style="font-size: 13px; color: #64748b; margin-top: 8px; margin-bottom: 12px; background: #f8fafc; padding: 6px 12px; border-radius: 4px; border: 1px solid #e2e8f0; display: inline-block;">
                    <strong>Scan ID:</strong> <span style="font-family: monospace;">${data.scan_id || 'N/A'}</span> &nbsp;|&nbsp; <strong>Sandbox:</strong> Destroyed
                </div>
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

// Export SARIF button handling
document.getElementById('export-sarif-btn').addEventListener('click', () => {
    window.location.href = '/api/dashboard/sarif';
});

// SBOM Export Dropdown and actions
const exportSbomBtn = document.getElementById('export-sbom-btn');
const sbomDropdown = document.getElementById('sbom-dropdown');

if (exportSbomBtn && sbomDropdown) {
    exportSbomBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const display = sbomDropdown.style.display;
        sbomDropdown.style.display = display === 'block' ? 'none' : 'block';
    });

    document.getElementById('export-sbom-cyclonedx').addEventListener('click', (e) => {
        e.preventDefault();
        window.location.href = '/api/dashboard/sbom?format=cyclonedx';
        sbomDropdown.style.display = 'none';
    });

    document.getElementById('export-sbom-spdx').addEventListener('click', (e) => {
        e.preventDefault();
        window.location.href = '/api/dashboard/sbom?format=spdx';
        sbomDropdown.style.display = 'none';
    });

    document.addEventListener('click', () => {
        sbomDropdown.style.display = 'none';
    });
}

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
                if (severity === 'critical') {
                    btn.style.background = '#fef2f2';
                    btn.style.color = '#991b1b';
                    btn.style.borderColor = '#b91c1c';
                } else if (severity === 'high') {
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
                const indexMap = { critical: 0, high: 1, medium: 2, low: 3 };
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

async function triggerRemediation(fingerprint, action, buttonEl) {
    const container = document.getElementById(`remediation-details-${fingerprint}`);
    if (!container) return;
    
    // If container is already visible and matches current action, hide it
    if (container.style.display === 'block' && container.dataset.activeAction === action) {
        container.style.display = 'none';
        container.innerHTML = '';
        return;
    }
    
    // Show loading state
    container.style.display = 'block';
    container.dataset.activeAction = action;
    container.innerHTML = `
        <div style="display: flex; align-items: center; gap: 8px; color: #475569;">
            <svg style="animation: spin 1s linear infinite; width: 14px; height: 14px;" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle style="opacity: 0.25; stroke: #cbd5e1;" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path style="opacity: 0.75;" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
            </svg>
            Generating remediation details...
        </div>
    `;
    
    try {
        const response = await fetch('/api/remediation/remediate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fingerprint, action })
        });
        
        if (!response.ok) {
            throw new Error('Remediation request failed');
        }
        
        const resData = await response.json();
        const details = resData.details;
        
        if (action === 'explain') {
            container.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <div><strong style="color: #0f172a;">Why is this vulnerable?</strong><p style="margin: 3px 0 0 0; color: #334155;">${details.why}</p></div>
                    <div style="border-top: 1px solid #f1f5f9; padding-top: 6px;"><strong style="color: #0f172a;">How could it be exploited?</strong><p style="margin: 3px 0 0 0; color: #334155;">${details.exploit}</p></div>
                    <div style="border-top: 1px solid #f1f5f9; padding-top: 6px;"><strong style="color: #0f172a;">Applicable CWE:</strong><p style="margin: 3px 0 0 0; color: #475569; font-weight: 500;">${details.cwe}</p></div>
                </div>
            `;
        } else if (action === 'patch') {
            const escapedOrig = details.original_code.replace(/'/g, "\\'").replace(/"/g, '\\"');
            const escapedSecure = details.secure_code.replace(/'/g, "\\'").replace(/"/g, '\\"');
            
            container.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <div><strong style="color: #0f172a;">How to fix:</strong><p style="margin: 3px 0 0 0; color: #334155;">${details.fix_desc}</p></div>
                    <div style="margin-top: 4px;">
                        <strong style="color: #0f172a;">Secure Code Comparison:</strong>
                        <div style="font-family: monospace; font-size: 11px; margin-top: 6px; border-radius: 6px; overflow: hidden; border: 1px solid #e2e8f0; line-height: 1.4;">
                            <div style="background: #fef2f2; color: #991b1b; padding: 8px 12px; border-bottom: 1px solid #fca5a5; white-space: pre-wrap; font-family: monospace;">- ${details.original_code}</div>
                            <div style="background: #f0fdf4; color: #166534; padding: 8px 12px; white-space: pre-wrap; font-family: monospace;">+ ${details.secure_code}</div>
                        </div>
                    </div>
                    <div style="margin-top: 6px; display: flex; align-items: center; gap: 10px;">
                        <button id="apply-patch-btn-${fingerprint}" onclick="applyPatch('${fingerprint}', '${escapedOrig}', '${escapedSecure}')" style="background: #10b981; color: white; border: none; border-radius: 4px; padding: 4px 10px; font-size: 11px; font-weight: 600; cursor: pointer; transition: background 0.2s;">
                            Apply Patch
                        </button>
                        <span id="patch-status-${fingerprint}" style="font-size: 11px; font-weight: 600; color: #475569;"></span>
                    </div>
                </div>
            `;
        } else if (action === 'dataflow') {
            const flowHtml = details.data_flow.map((node, idx) => {
                let bg = '#f8fafc';
                let border = '#e2e8f0';
                let textColor = '#334155';
                let badgeBg = '#64748b';
                
                if (node.type === 'SOURCE') {
                    bg = '#eff6ff';
                    border = '#bfdbfe';
                    textColor = '#1e3a8a';
                    badgeBg = '#3b82f6';
                } else if (node.type === 'SINK') {
                    bg = '#fef2f2';
                    border = '#fca5a5';
                    textColor = '#7f1d1d';
                    badgeBg = '#ef4444';
                }
                
                return `
                <div style="background: ${bg}; border: 1px solid ${border}; border-radius: 6px; padding: 10px; display: flex; flex-direction: column; gap: 6px; position: relative;">
                    <!-- Node Header -->
                    <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 6px;">
                        <span style="font-weight: 700; font-size: 11px; color: ${textColor}; display: flex; align-items: center; gap: 4px;">
                            <span style="background: ${textColor}; color: #ffffff; border-radius: 50%; width: 16px; height: 16px; display: inline-flex; align-items: center; justify-content: center; font-size: 9px;">${node.step}</span>
                            ${node.label}
                        </span>
                        <span style="background: ${badgeBg}; color: white; border-radius: 4px; padding: 1px 6px; font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">${node.type}</span>
                    </div>
                    
                    <!-- Node Statement Code -->
                    ${node.code ? `
                    <div style="font-family: monospace; font-size: 10px; background: #ffffff; border: 1px solid #e2e8f0; padding: 6px 10px; border-radius: 4px; color: #0f172a; white-space: pre-wrap; font-family: monospace;">${node.code}</div>
                    ` : ''}
                    
                    <!-- Node Description -->
                    <p style="margin: 0; color: #475569; font-size: 10px; line-height: 1.4;">${node.description || ''}</p>
                </div>
                ${idx < details.data_flow.length - 1 ? `
                <div style="display: flex; justify-content: center; margin: 4px 0; color: #94a3b8; font-size: 16px; font-weight: 700;">
                    ↓
                </div>
                ` : ''}
                `;
            }).join('');
            
            container.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #f1f5f9; padding-bottom: 6px;">
                        <strong style="color: #0f172a; font-size: 12px; display: flex; align-items: center; gap: 4px;">
                            <svg style="width: 14px; height: 14px; color: #6b21a8;" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M18 18.72a9.094 9.094 0 003.741-.479 3 3 0 00-4.682-2.72m.94 3.198l.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0112 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 016 18.719m12 0a5.971 5.971 0 00-.941-3.197m0 0A5.995 5.995 0 0012 12.75a5.995 5.995 0 00-5.058 2.772m0 0a3 3 0 00-4.681 2.72 8.986 8.986 0 003.74.477m.94-3.197a5.971 5.971 0 00-.94 3.197M15 6.75a3 3 0 11-6 0 3 3 0 016 0zm6 3a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zm-13.5 0a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0z"></path>
                            </svg>
                            Semantic Source → Sink Trace
                        </strong>
                        <span style="font-size: 10px; color: #64748b; font-weight: 500;">Taint Analysis Path</span>
                    </div>
                    <div style="display: flex; flex-direction: column; gap: 2px;">
                        ${flowHtml}
                    </div>
                </div>
            `;
        }
    } catch (err) {
        container.innerHTML = `<span style="color: #dc2626; font-weight: 600;">Failed to generate remediation information.</span>`;
    }
}

async function applyPatch(fingerprint, originalCode, patchCode) {
    const confirmed = confirm("Are you sure you want to apply this secure code patch? This will modify the source code file directly in your workspace.");
    if (!confirmed) return;
    
    const btn = document.getElementById(`apply-patch-btn-${fingerprint}`);
    const statusText = document.getElementById(`patch-status-${fingerprint}`);
    if (btn) btn.disabled = true;
    if (statusText) {
        statusText.style.color = '#475569';
        statusText.textContent = "Applying patch...";
    }
    
    try {
        const response = await fetch('/api/remediation/apply', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ fingerprint, original_code: originalCode, patch_code: patchCode })
        });
        
        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.detail || 'Failed to apply patch');
        }
        
        const data = await response.json();
        if (statusText) {
            statusText.style.color = '#059669';
            statusText.textContent = "✓ Patch successfully applied! Run another scan to verify.";
        }
        if (btn) btn.style.display = 'none';
    } catch (err) {
        if (statusText) {
            statusText.style.color = '#dc2626';
            statusText.textContent = `Error: ${err.message}`;
        }
        if (btn) btn.disabled = false;
    }
}

// GitHub PR simulation handler
document.getElementById('simulate-pr-btn').addEventListener('click', async () => {
    const btn = document.getElementById('simulate-pr-btn');
    const repo = document.getElementById('pr-repo').value;
    const branch = document.getElementById('pr-branch').value;
    const prNum = parseInt(document.getElementById('pr-num').value);
    const sha = document.getElementById('pr-sha').value;
    
    btn.disabled = true;
    btn.textContent = 'Running Pipeline Scan...';
    
    try {
        const response = await fetch('/api/github/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                repo_name: repo,
                pr_number: prNum,
                commit_sha: sha,
                branch: branch
            })
        });
        
        if (!response.ok) {
            throw new Error('Simulation failed');
        }
        
        const report = await response.json();
        
        // Show simulated PR view card
        const viewCard = document.getElementById('simulated-pr-view');
        viewCard.style.display = 'block';
        
        // Render Header
        document.getElementById('sim-pr-title').textContent = `${report.repo_name} #${report.pr_number}`;
        document.getElementById('sim-pr-branch').textContent = `${report.branch} → main`;
        document.getElementById('sim-pr-meta').textContent = `Commit: ${report.commit_sha} | Scan timestamp: ${report.timestamp}`;
        
        // Render Check Run Box
        const checkRunBox = document.getElementById('sim-check-run-box');
        const check = report.check_run;
        if (check.conclusion === 'failure') {
            checkRunBox.style.background = '#fef2f2';
            checkRunBox.style.border = '1px solid #fca5a5';
            checkRunBox.style.color = '#991b1b';
            checkRunBox.innerHTML = `
                <div style="font-size: 24px; line-height: 1;">❌</div>
                <div>
                    <strong style="font-size: 14px; display: block;">Security Gate Failed</strong>
                    <span style="font-size: 12px; font-weight: 500; opacity: 0.9;">${check.summary}</span>
                </div>
            `;
        } else {
            checkRunBox.style.background = '#f0fdf4';
            checkRunBox.style.border = '1px solid #bbf7d0';
            checkRunBox.style.color = '#166534';
            checkRunBox.innerHTML = `
                <div style="font-size: 24px; line-height: 1;">✓</div>
                <div>
                    <strong style="font-size: 14px; display: block;">Security Gate Passed</strong>
                    <span style="font-size: 12px; font-weight: 500; opacity: 0.9;">${check.summary}</span>
                </div>
            `;
        }
        
        // Render Comments List
        const commentsList = document.getElementById('sim-comments-list');
        if (report.pr_comments.length === 0) {
            commentsList.innerHTML = `<div style="color: #64748b; font-style: italic; font-size: 12px; padding: 10px 0;">No comments generated (all checks clean).</div>`;
        } else {
            commentsList.innerHTML = report.pr_comments.map(comment => `
                <div style="border: 1px solid #e2e8f0; border-radius: 6px; overflow: hidden; font-size: 12px; background: #ffffff;">
                    <!-- File line indicator header -->
                    <div style="background: #f8fafc; border-bottom: 1px solid #e2e8f0; padding: 6px 12px; font-weight: 600; color: #475569; display: flex; justify-content: space-between;">
                        <span>📂 ${comment.file}</span>
                        <span>Line ${comment.line}</span>
                    </div>
                    
                    <!-- Code location display block -->
                    <div style="font-family: monospace; font-size: 11px; padding: 10px 12px; background: #fdfdfd; border-bottom: 1px dashed #e2e8f0; color: #0f172a; white-space: pre-wrap; font-family: monospace;"># line ${comment.line}</div>
                    
                    <!-- GitHub review comment block -->
                    <div style="padding: 12px; background: #ffffff;">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                            <div style="background: #1e293b; color: white; border-radius: 50%; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; font-size: 10px; font-weight: bold;">🛡️</div>
                            <strong style="color: #0f172a; font-size: 11px;">Agentic Security Check bot</strong>
                            <span style="background: #f1f5f9; color: #475569; border-radius: 4px; padding: 1px 5px; font-size: 9px; font-weight: 700;">BOT</span>
                        </div>
                        <div style="color: #334155; line-height: 1.5; margin-left: 28px;">
                            ${comment.body.replace(/\n/g, '<br>')}
                        </div>
                    </div>
                </div>
            `).join('');
        }
        
    } catch (err) {
        alert('Failed to simulate PR scan: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Trigger PR Pipeline Scan';
    }
});
