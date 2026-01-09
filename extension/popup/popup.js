/**
 * Cert-Monitor v2.0 - Popup Script
 */

document.addEventListener('DOMContentLoaded', async () => {
    const contentDiv = document.getElementById('content');

    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.url) {
        showError('Cannot access this page');
        return;
    }

    try {
        const url = new URL(tab.url);

        if (url.protocol !== 'https:' && url.protocol !== 'http:') {
            showSpecialPage(url.protocol);
            return;
        }

        const domain = url.hostname;

        // Get status from background
        const status = await chrome.runtime.sendMessage({ action: 'get_status', domain });
        const settings = await chrome.runtime.sendMessage({ action: 'get_settings' });

        if (status.status === 'cached') {
            showResult(domain, status.result, settings);
        } else if (status.status === 'pending') {
            showPending(domain);
        } else {
            showUnknown(domain, settings);
        }

    } catch (error) {
        showError(error.message);
    }
});

function showResult(domain, result, settings) {
    const statusClass = getStatusClass(result.verdict);
    const statusIcon = getStatusIcon(result.verdict);
    const statusText = getStatusText(result.verdict);

    let dimensionsHtml = '';
    if (result.dimensions) {
        dimensionsHtml = result.dimensions.map(dim => `
      <div class="dimension-item">
        <div class="dimension-status ${dim.status.toLowerCase()}">${getDimensionIcon(dim.status)}</div>
        <div class="dimension-info">
          <div class="dimension-name">${formatDimensionName(dim.dimension)}</div>
          <div class="dimension-details">${truncate(dim.details, 50)}</div>
        </div>
        <div class="dimension-score">${(dim.score * 100).toFixed(0)}%</div>
      </div>
    `).join('');
    }

    const content = `
    <div class="status-card ${statusClass}">
      <div class="status-icon">${statusIcon}</div>
      <div class="status-text">${statusText}</div>
      <div class="status-domain">${domain}</div>
    </div>
    
    <div class="score-section">
      <div class="score-item">
        <div class="score-value ${getScoreClass(result.security_score)}">${result.security_score.toFixed(0)}</div>
        <div class="score-label">Security Score</div>
      </div>
      <div class="score-item">
        <div class="score-value ${result.anomaly_score > 0.5 ? 'bad' : 'good'}">${(result.anomaly_score * 100).toFixed(0)}%</div>
        <div class="score-label">Anomaly Score</div>
      </div>
      <div class="score-item">
        <div class="score-value">${result.latency_ms || 0}</div>
        <div class="score-label">Latency (ms)</div>
      </div>
    </div>
    
    ${dimensionsHtml ? `
    <div class="dimensions-section">
      <div class="dimensions-title">Validation Dimensions</div>
      ${dimensionsHtml}
    </div>
    ` : ''}
    
    <div class="controls">
      <button class="btn btn-primary" id="verify-btn">🔄 Re-verify</button>
      <button class="btn btn-secondary" id="settings-btn">⚙️ Settings</button>
    </div>
    
    <div class="toggle-container">
      <span class="toggle-label">Protection Enabled</span>
      <label class="toggle">
        <input type="checkbox" id="enabled-toggle" ${settings.enabled ? 'checked' : ''}>
        <span class="toggle-slider"></span>
      </label>
    </div>
    
    <div class="stats-section">
      <div class="stats-grid">
        <div class="stat-item">
          <div class="stat-value">${settings.stats?.domainsChecked || 0}</div>
          <div class="stat-label">Domains Checked</div>
        </div>
        <div class="stat-item">
          <div class="stat-value">${settings.stats?.mitmDetected || 0}</div>
          <div class="stat-label">MITM Detected</div>
        </div>
        <div class="stat-item">
          <div class="stat-value">${result.cached ? 'Yes' : 'No'}</div>
          <div class="stat-label">Cached</div>
        </div>
      </div>
    </div>
  `;

    document.getElementById('content').innerHTML = content;

    // Event listeners
    document.getElementById('verify-btn').addEventListener('click', () => verifyNow(domain));
    document.getElementById('settings-btn').addEventListener('click', openSettings);
    document.getElementById('enabled-toggle').addEventListener('change', toggleEnabled);
}

function showUnknown(domain, settings) {
    const content = `
    <div class="status-card unknown">
      <div class="status-icon">❓</div>
      <div class="status-text">Not Verified</div>
      <div class="status-domain">${domain}</div>
    </div>
    
    <div class="controls" style="padding: 24px;">
      <button class="btn btn-primary" id="verify-btn">🔍 Verify Now</button>
    </div>
    
    <div class="toggle-container">
      <span class="toggle-label">Protection Enabled</span>
      <label class="toggle">
        <input type="checkbox" id="enabled-toggle" ${settings.enabled ? 'checked' : ''}>
        <span class="toggle-slider"></span>
      </label>
    </div>
  `;

    document.getElementById('content').innerHTML = content;

    document.getElementById('verify-btn').addEventListener('click', () => verifyNow(domain));
    document.getElementById('enabled-toggle').addEventListener('change', toggleEnabled);
}

function showPending(domain) {
    const content = `
    <div class="status-card unknown">
      <div class="loading" style="padding: 20px;">
        <div class="spinner"></div>
      </div>
      <div class="status-text">Verifying...</div>
      <div class="status-domain">${domain}</div>
    </div>
  `;

    document.getElementById('content').innerHTML = content;

    // Poll for result
    setTimeout(() => location.reload(), 2000);
}

function showSpecialPage(protocol) {
    const content = `
    <div class="status-card unknown">
      <div class="status-icon">📄</div>
      <div class="status-text">Special Page</div>
      <div class="status-domain">${protocol} page</div>
    </div>
    <p style="text-align: center; padding: 16px; color: #9ca3af; font-size: 13px;">
      Certificate verification is only available for HTTP/HTTPS pages.
    </p>
  `;

    document.getElementById('content').innerHTML = content;
}

function showError(message) {
    const content = `
    <div class="status-card mitm">
      <div class="status-icon">⚠️</div>
      <div class="status-text">Error</div>
      <div class="status-domain">${message}</div>
    </div>
  `;

    document.getElementById('content').innerHTML = content;
}

async function verifyNow(domain) {
    document.getElementById('content').innerHTML = `
    <div class="loading" style="padding: 80px;">
      <div class="spinner"></div>
    </div>
  `;

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const result = await chrome.runtime.sendMessage({ action: 'verify_now', domain });
    const settings = await chrome.runtime.sendMessage({ action: 'get_settings' });

    showResult(domain, result, settings);
}

async function toggleEnabled(event) {
    await chrome.runtime.sendMessage({
        action: 'update_settings',
        settings: { enabled: event.target.checked }
    });
}

function openSettings() {
    chrome.runtime.openOptionsPage();
}

// Helper functions
function getStatusClass(verdict) {
    switch (verdict) {
        case 'SAFE':
        case 'CACHED_SAFE':
            return 'safe';
        case 'MITM_DETECTED':
            return 'mitm';
        case 'SUSPICIOUS':
            return 'suspicious';
        default:
            return 'unknown';
    }
}

function getStatusIcon(verdict) {
    switch (verdict) {
        case 'SAFE':
        case 'CACHED_SAFE':
            return '✅';
        case 'MITM_DETECTED':
            return '🚨';
        case 'SUSPICIOUS':
            return '⚠️';
        default:
            return '❓';
    }
}

function getStatusText(verdict) {
    switch (verdict) {
        case 'SAFE':
            return 'Connection Secure';
        case 'CACHED_SAFE':
            return 'Verified (Cached)';
        case 'MITM_DETECTED':
            return 'MITM Attack Detected!';
        case 'SUSPICIOUS':
            return 'Suspicious Certificate';
        default:
            return 'Unknown';
    }
}

function getScoreClass(score) {
    if (score >= 70) return 'good';
    if (score >= 40) return 'warning';
    return 'bad';
}

function getDimensionIcon(status) {
    switch (status) {
        case 'PASS': return '✓';
        case 'FAIL': return '✗';
        case 'WARNING': return '!';
        default: return '?';
    }
}

function formatDimensionName(dim) {
    return dim.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
}
