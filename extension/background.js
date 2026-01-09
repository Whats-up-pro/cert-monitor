/**
 * Cert-Monitor v2.0 - Background Service Worker
 * Handles certificate verification using Split-View Validation
 */

// Configuration
const CONFIG = {
  AGENT_URL: 'http://localhost:8080',
  NATIVE_HOST_NAME: 'com.certmonitor.host',
  VERIFICATION_TIMEOUT: 30000, // 30 seconds
  CACHE_TTL: 24 * 60 * 60 * 1000, // 24 hours
  MODE: 'passive', // 'passive' or 'strict'
  ENABLED: true
};

// Verification cache (TOFU)
const verificationCache = new Map();

// Pending verifications
const pendingVerifications = new Map();

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('Cert-Monitor v2.0 installed');
  
  // Set default settings
  chrome.storage.local.set({
    enabled: true,
    mode: 'passive',
    agentUrl: CONFIG.AGENT_URL,
    notifications: true,
    stats: {
      domainsChecked: 0,
      mitmDetected: 0,
      lastCheck: null
    }
  });
  
  // Create alarm for periodic cache cleanup
  chrome.alarms.create('cache-cleanup', { periodInMinutes: 60 });
});

// Handle alarms
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cache-cleanup') {
    cleanupCache();
  }
});

// Listen for navigation events
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only main frame
  
  const settings = await chrome.storage.local.get(['enabled', 'mode']);
  if (!settings.enabled) return;
  
  const url = new URL(details.url);
  if (url.protocol !== 'https:') return; // Only HTTPS
  
  const domain = url.hostname;
  
  // Check cache first
  const cached = getCachedVerification(domain);
  if (cached) {
    console.log(`[Cache Hit] ${domain}: ${cached.verdict}`);
    updateBadge(cached.verdict);
    return;
  }
  
  if (settings.mode === 'strict') {
    // In strict mode, we would block and verify first
    // This requires more complex implementation with webRequest blocking
    console.log(`[Strict Mode] Would verify ${domain} before loading`);
  }
  
  // Passive mode: verify in background
  verifyDomain(details.tabId, domain);
});

// Listen for completed navigation
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  
  const url = new URL(details.url);
  if (url.protocol !== 'https:') return;
  
  const domain = url.hostname;
  
  // Check if verification is pending
  if (pendingVerifications.has(domain)) {
    console.log(`[Pending] Waiting for verification of ${domain}`);
    return;
  }
  
  // Quick verification check
  const cached = getCachedVerification(domain);
  if (!cached) {
    verifyDomain(details.tabId, domain);
  }
});

// Verify domain using the Agent API
async function verifyDomain(tabId, domain) {
  // Skip if already pending
  if (pendingVerifications.has(domain)) {
    return pendingVerifications.get(domain);
  }
  
  const verificationPromise = performVerification(tabId, domain);
  pendingVerifications.set(domain, verificationPromise);
  
  try {
    const result = await verificationPromise;
    return result;
  } finally {
    pendingVerifications.delete(domain);
  }
}

async function performVerification(tabId, domain) {
  console.log(`[Verify] Starting verification for ${domain}`);
  
  const startTime = Date.now();
  const settings = await chrome.storage.local.get(['agentUrl']);
  const agentUrl = settings.agentUrl || CONFIG.AGENT_URL;
  
  try {
    // Get client-side certificate fingerprint (via native host or browser API)
    const clientFingerprint = await getClientCertificateFingerprint(domain);
    
    // Build verification request
    const request = {
      domain: domain,
      client_fingerprint: clientFingerprint,
      request_id: `ext-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Math.floor(Date.now() / 1000)
    };
    
    // Send to verification agent
    const response = await fetch(`${agentUrl}/api/v2/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(request)
    });
    
    if (!response.ok) {
      throw new Error(`Agent returned ${response.status}`);
    }
    
    const result = await response.json();
    const latency = Date.now() - startTime;
    
    console.log(`[Verify] ${domain}: ${result.verdict} (${latency}ms)`);
    
    // Cache the result
    cacheVerification(domain, result);
    
    // Update UI
    updateBadge(result.verdict, tabId);
    
    // Handle result
    await handleVerificationResult(tabId, domain, result);
    
    // Update stats
    updateStats(result.verdict);
    
    return result;
    
  } catch (error) {
    console.error(`[Verify] Error verifying ${domain}:`, error);
    updateBadge('ERROR', tabId);
    return { verdict: 'ERROR', error: error.message };
  }
}

// Get certificate fingerprint from client perspective
async function getClientCertificateFingerprint(domain) {
  // Method 1: Use Native Host (preferred)
  try {
    const response = await chrome.runtime.sendNativeMessage(
      CONFIG.NATIVE_HOST_NAME,
      { action: 'get_certificate', domain: domain }
    );
    if (response && response.fingerprint) {
      return response.fingerprint;
    }
  } catch (error) {
    console.log('[Native Host] Not available, using fallback');
  }
  
  // Method 2: Fallback - empty fingerprint (Agent will do server-only check)
  return '';
}

// Cache verification result
function cacheVerification(domain, result) {
  verificationCache.set(domain, {
    ...result,
    cachedAt: Date.now()
  });
}

// Get cached verification
function getCachedVerification(domain) {
  const cached = verificationCache.get(domain);
  if (!cached) return null;
  
  // Check if expired
  if (Date.now() - cached.cachedAt > CONFIG.CACHE_TTL) {
    verificationCache.delete(domain);
    return null;
  }
  
  return cached;
}

// Clean up expired cache entries
function cleanupCache() {
  const now = Date.now();
  for (const [domain, entry] of verificationCache) {
    if (now - entry.cachedAt > CONFIG.CACHE_TTL) {
      verificationCache.delete(domain);
    }
  }
  console.log(`[Cache] Cleanup complete. ${verificationCache.size} entries remaining.`);
}

// Update extension badge
function updateBadge(verdict, tabId = null) {
  let color, text;
  
  switch (verdict) {
    case 'SAFE':
    case 'CACHED_SAFE':
      color = '#10b981'; // Green
      text = '✓';
      break;
    case 'MITM_DETECTED':
      color = '#ef4444'; // Red
      text = '!';
      break;
    case 'SUSPICIOUS':
      color = '#f59e0b'; // Orange
      text = '?';
      break;
    case 'ERROR':
      color = '#6b7280'; // Gray
      text = 'E';
      break;
    default:
      color = '#3b82f6'; // Blue
      text = '';
  }
  
  const options = { color: color };
  const textOptions = { text: text };
  
  if (tabId) {
    chrome.action.setBadgeBackgroundColor({ ...options, tabId });
    chrome.action.setBadgeText({ ...textOptions, tabId });
  } else {
    chrome.action.setBadgeBackgroundColor(options);
    chrome.action.setBadgeText(textOptions);
  }
}

// Handle verification result
async function handleVerificationResult(tabId, domain, result) {
  const settings = await chrome.storage.local.get(['notifications', 'mode']);
  
  if (result.verdict === 'MITM_DETECTED') {
    // Always notify on MITM detection
    if (settings.notifications) {
      chrome.notifications.create(`mitm-${domain}`, {
        type: 'basic',
        iconUrl: 'assets/icon128.png',
        title: '🚨 MITM Attack Detected!',
        message: `Connection to ${domain} is being intercepted. Security Score: ${result.security_score.toFixed(1)}/100`,
        priority: 2,
        requireInteraction: true
      });
    }
    
    // In strict mode, we would block the page
    if (settings.mode === 'strict') {
      // Send message to content script to show warning
      chrome.tabs.sendMessage(tabId, {
        action: 'show_mitm_warning',
        domain: domain,
        result: result
      });
    }
    
  } else if (result.verdict === 'SUSPICIOUS') {
    if (settings.notifications) {
      chrome.notifications.create(`suspicious-${domain}`, {
        type: 'basic',
        iconUrl: 'assets/icon128.png',
        title: '⚠️ Suspicious Certificate',
        message: `${domain} has unusual certificate characteristics. Security Score: ${result.security_score.toFixed(1)}/100`,
        priority: 1
      });
    }
  }
  
  // Send result to content script
  try {
    await chrome.tabs.sendMessage(tabId, {
      action: 'verification_complete',
      domain: domain,
      result: result
    });
  } catch (error) {
    // Tab may have navigated away
  }
}

// Update statistics
async function updateStats(verdict) {
  const { stats } = await chrome.storage.local.get(['stats']);
  
  stats.domainsChecked = (stats.domainsChecked || 0) + 1;
  if (verdict === 'MITM_DETECTED') {
    stats.mitmDetected = (stats.mitmDetected || 0) + 1;
  }
  stats.lastCheck = Date.now();
  
  await chrome.storage.local.set({ stats });
}

// Listen for messages from popup and content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case 'get_status':
      handleGetStatus(message.domain).then(sendResponse);
      return true;
      
    case 'verify_now':
      verifyDomain(sender.tab?.id, message.domain).then(sendResponse);
      return true;
      
    case 'get_settings':
      chrome.storage.local.get(null).then(sendResponse);
      return true;
      
    case 'update_settings':
      chrome.storage.local.set(message.settings).then(() => sendResponse({ success: true }));
      return true;
      
    case 'clear_cache':
      verificationCache.clear();
      sendResponse({ success: true });
      break;
      
    case 'get_cache_stats':
      sendResponse({
        size: verificationCache.size,
        entries: Array.from(verificationCache.keys())
      });
      break;
  }
});

async function handleGetStatus(domain) {
  const cached = getCachedVerification(domain);
  if (cached) {
    return { status: 'cached', result: cached };
  }
  
  if (pendingVerifications.has(domain)) {
    return { status: 'pending' };
  }
  
  return { status: 'unknown' };
}

// Export for testing
if (typeof module !== 'undefined') {
  module.exports = {
    verifyDomain,
    getCachedVerification,
    cacheVerification
  };
}
