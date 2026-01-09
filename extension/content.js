/**
 * Cert-Monitor v2.0 - Content Script
 * Handles input locking and MITM warning display
 */

(function () {
    'use strict';

    // State
    let isLocked = false;
    let warningOverlay = null;
    let statusIndicator = null;

    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        switch (message.action) {
            case 'lock_inputs':
                lockSensitiveInputs();
                sendResponse({ success: true });
                break;

            case 'unlock_inputs':
                unlockInputs();
                sendResponse({ success: true });
                break;

            case 'show_mitm_warning':
                showMITMWarning(message.domain, message.result);
                sendResponse({ success: true });
                break;

            case 'verification_complete':
                handleVerificationComplete(message.domain, message.result);
                sendResponse({ success: true });
                break;

            case 'show_status':
                showStatusIndicator(message.status, message.message);
                sendResponse({ success: true });
                break;
        }
        return true;
    });

    // Lock sensitive inputs during verification
    function lockSensitiveInputs() {
        if (isLocked) return;
        isLocked = true;

        const sensitiveInputs = document.querySelectorAll(
            'input[type="password"], input[type="text"][name*="user"], input[type="text"][name*="email"], input[type="email"], input[type="text"][autocomplete="username"], button[type="submit"], input[type="submit"]'
        );

        sensitiveInputs.forEach(input => {
            input.dataset.certMonitorDisabled = input.disabled;
            input.disabled = true;
            input.style.opacity = '0.5';
            input.style.cursor = 'not-allowed';
        });

        showStatusIndicator('verifying', 'Verifying certificate...');
        console.log('[Cert-Monitor] Inputs locked during verification');
    }

    // Unlock inputs after verification
    function unlockInputs() {
        if (!isLocked) return;
        isLocked = false;

        const sensitiveInputs = document.querySelectorAll('[data-cert-monitor-disabled]');

        sensitiveInputs.forEach(input => {
            input.disabled = input.dataset.certMonitorDisabled === 'true';
            delete input.dataset.certMonitorDisabled;
            input.style.opacity = '';
            input.style.cursor = '';
        });

        hideStatusIndicator();
        console.log('[Cert-Monitor] Inputs unlocked');
    }

    // Show MITM warning overlay
    function showMITMWarning(domain, result) {
        if (warningOverlay) {
            warningOverlay.remove();
        }

        warningOverlay = document.createElement('div');
        warningOverlay.id = 'cert-monitor-warning';
        warningOverlay.innerHTML = `
      <style>
        #cert-monitor-warning {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.95);
          z-index: 2147483647;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        .cert-monitor-modal {
          background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
          border: 2px solid #ef4444;
          border-radius: 16px;
          padding: 40px;
          max-width: 600px;
          text-align: center;
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        
        .cert-monitor-icon {
          font-size: 64px;
          margin-bottom: 20px;
          animation: pulse 1s ease-in-out infinite;
        }
        
        @keyframes pulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.1); }
        }
        
        .cert-monitor-title {
          color: #ef4444;
          font-size: 28px;
          font-weight: 700;
          margin-bottom: 16px;
        }
        
        .cert-monitor-domain {
          color: #f59e0b;
          font-size: 20px;
          font-family: monospace;
          background: rgba(245, 158, 11, 0.1);
          padding: 8px 16px;
          border-radius: 8px;
          margin-bottom: 20px;
          display: inline-block;
        }
        
        .cert-monitor-message {
          color: #e5e7eb;
          font-size: 16px;
          line-height: 1.6;
          margin-bottom: 24px;
        }
        
        .cert-monitor-score {
          color: #ef4444;
          font-size: 48px;
          font-weight: 700;
          margin-bottom: 20px;
        }
        
        .cert-monitor-details {
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.3);
          border-radius: 8px;
          padding: 16px;
          margin-bottom: 24px;
          text-align: left;
          color: #d1d5db;
          font-size: 14px;
        }
        
        .cert-monitor-buttons {
          display: flex;
          gap: 16px;
          justify-content: center;
        }
        
        .cert-monitor-btn {
          padding: 12px 24px;
          border-radius: 8px;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
          border: none;
        }
        
        .cert-monitor-btn-danger {
          background: #ef4444;
          color: white;
        }
        
        .cert-monitor-btn-danger:hover {
          background: #dc2626;
        }
        
        .cert-monitor-btn-secondary {
          background: transparent;
          color: #9ca3af;
          border: 1px solid #4b5563;
        }
        
        .cert-monitor-btn-secondary:hover {
          background: rgba(255, 255, 255, 0.1);
        }
      </style>
      
      <div class="cert-monitor-modal">
        <div class="cert-monitor-icon">🚨</div>
        <div class="cert-monitor-title">MITM Attack Detected!</div>
        <div class="cert-monitor-domain">${escapeHtml(domain)}</div>
        <div class="cert-monitor-message">
          Your connection to this website is being <strong>intercepted</strong>.<br>
          Someone may be reading or modifying the data you send.
        </div>
        <div class="cert-monitor-score">${result.security_score.toFixed(1)}<span style="font-size: 24px; color: #9ca3af">/100</span></div>
        <div class="cert-monitor-details">
          <strong>Detection Details:</strong><br>
          ${result.dimensions ? result.dimensions.map(d =>
            `• ${d.dimension}: ${d.status} (${(d.score * 100).toFixed(0)}%)`
        ).join('<br>') : 'Split-View fingerprint mismatch detected'}
        </div>
        <div class="cert-monitor-buttons">
          <button class="cert-monitor-btn cert-monitor-btn-danger" onclick="window.history.back()">
            ← Go Back (Recommended)
          </button>
          <button class="cert-monitor-btn cert-monitor-btn-secondary" id="cert-monitor-proceed">
            Proceed Anyway (Unsafe)
          </button>
        </div>
      </div>
    `;

        document.body.appendChild(warningOverlay);

        // Handle proceed anyway (requires confirmation)
        document.getElementById('cert-monitor-proceed').addEventListener('click', () => {
            if (confirm('⚠️ SECURITY WARNING ⚠️\n\nProceeding is extremely dangerous. Your data may be stolen.\n\nOnly proceed if you understand the risks and trust this network.\n\nAre you absolutely sure?')) {
                warningOverlay.remove();
                warningOverlay = null;
            }
        });

        // Block all interaction with the page
        document.body.style.overflow = 'hidden';
    }

    // Handle verification complete
    function handleVerificationComplete(domain, result) {
        if (isLocked) {
            unlockInputs();
        }

        if (result.verdict === 'SAFE' || result.verdict === 'CACHED_SAFE') {
            showStatusIndicator('safe', 'Connection verified ✓', 3000);
        } else if (result.verdict === 'SUSPICIOUS') {
            showStatusIndicator('warning', 'Certificate has unusual characteristics', 5000);
        }
        // MITM is handled by showMITMWarning
    }

    // Show status indicator
    function showStatusIndicator(status, message, autoHide = 0) {
        if (statusIndicator) {
            statusIndicator.remove();
        }

        const colors = {
            verifying: { bg: '#3b82f6', text: 'white' },
            safe: { bg: '#10b981', text: 'white' },
            warning: { bg: '#f59e0b', text: 'black' },
            error: { bg: '#ef4444', text: 'white' }
        };

        const color = colors[status] || colors.verifying;

        statusIndicator = document.createElement('div');
        statusIndicator.id = 'cert-monitor-status';
        statusIndicator.innerHTML = `
      <style>
        #cert-monitor-status {
          position: fixed;
          top: 16px;
          right: 16px;
          background: ${color.bg};
          color: ${color.text};
          padding: 12px 20px;
          border-radius: 8px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          font-size: 14px;
          font-weight: 500;
          z-index: 2147483646;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
          display: flex;
          align-items: center;
          gap: 8px;
          animation: slideIn 0.3s ease-out;
        }
        
        @keyframes slideIn {
          from {
            transform: translateX(100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
        
        #cert-monitor-status .spinner {
          width: 16px;
          height: 16px;
          border: 2px solid rgba(255,255,255,0.3);
          border-radius: 50%;
          border-top-color: white;
          animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      </style>
      ${status === 'verifying' ? '<div class="spinner"></div>' : ''}
      <span>${escapeHtml(message)}</span>
    `;

        document.body.appendChild(statusIndicator);

        if (autoHide > 0) {
            setTimeout(() => hideStatusIndicator(), autoHide);
        }
    }

    // Hide status indicator
    function hideStatusIndicator() {
        if (statusIndicator) {
            statusIndicator.style.animation = 'slideIn 0.3s ease-out reverse';
            setTimeout(() => {
                if (statusIndicator) {
                    statusIndicator.remove();
                    statusIndicator = null;
                }
            }, 300);
        }
    }

    // Escape HTML to prevent XSS
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    console.log('[Cert-Monitor] Content script loaded');
})();
