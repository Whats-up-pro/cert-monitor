// File: background.js

// --- CẤU HÌNH ---
const API_ENDPOINT = 'http://localhost:8080/check-cert';
const NATIVE_HOST_NAME = "com.certmonitor.native"; // Phải khớp với file nm_host.json

// Cache Whitelist phiên làm việc
const safeSessionCache = {}; 

// Biến toàn cục lưu trạng thái Strict Mode
let isStrictMode = false;

// --- KHỞI TẠO ---
chrome.storage.sync.get(['strictMode'], (result) => {
    isStrictMode = result.strictMode || false;
});

chrome.storage.onChanged.addListener((changes, namespace) => {
    if (changes.strictMode) {
        isStrictMode = changes.strictMode.newValue;
        if (!isStrictMode) { 
            for (let member in safeSessionCache) delete safeSessionCache[member];
        }
    }
});

// --- HÀM GỌI NATIVE APP ---
function getNativeFingerprint(domain) {
    return new Promise((resolve) => {
        try {
            console.log(`[Native] Asking OS for certificate of: ${domain}`);
            chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, { domain: domain }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("Native Error:", chrome.runtime.lastError.message);
                    resolve(null);
                } else {
                    if (response && response.fingerprint) {
                        resolve(response.fingerprint);
                    } else {
                        resolve(null);
                    }
                }
            });
        } catch (e) {
            console.error(e);
            resolve(null);
        }
    });
}

// --- PHẦN 1: LOGIC CHẶN (STRICT MODE) ---
function shouldIntercept(url) {
    try {
        const urlObj = new URL(url);
        if (urlObj.protocol !== 'https:') return false;
        if (url.startsWith(chrome.runtime.getURL(""))) return false;

        const hostname = urlObj.hostname;
        
        if (safeSessionCache[hostname] && (Date.now() - safeSessionCache[hostname] < 600000)) {
            return false;
        }
        return true;
    } catch (e) { return false; }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (tab.url && (changeInfo.status === 'loading' || changeInfo.url)) {
        if (isStrictMode) {
            if (shouldIntercept(tab.url)) {
                const checkingUrl = chrome.runtime.getURL('checking.html') + 
                                    `?target=${encodeURIComponent(tab.url)}`;
                chrome.tabs.update(tabId, { url: checkingUrl });
            }
        } else {
            // Passive Mode
            if (tab.url.startsWith('https') && changeInfo.status === 'complete') {
                checkAndSendResult(tab.url, tabId);
            }
        }
    }
});

// --- PHẦN 2: XỬ LÝ TIN NHẮN (QUAN TRỌNG) ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    
    // 2.1. Whitelist
    if (request.action === "mark_as_safe") {
        const hostname = new URL(request.url).hostname;
        safeSessionCache[hostname] = Date.now();
        sendResponse({status: "ok"});
    }

    // 2.2. VALIDATE TOFU (STRICT MODE)
    // SỬA ĐỔI: Hỗ trợ kiểm tra danh sách Fingerprints (Multi-IP)
    if (request.action === "validate_tofu") {
        const domain = request.domain;
        
        // Nhận cả danh sách (nếu có) hoặc 1 cái (fallback)
        const validFingerprints = request.fingerprints || [];
        if (request.fingerprint) validFingerprints.push(request.fingerprint);

        getNativeFingerprint(domain).then((localFingerprint) => {
            let isSafe = true;
            let error = "";

            if (!localFingerprint) {
                isSafe = false;
                error = "Native Host Unreachable";
            } else {
                const localClean = localFingerprint.toLowerCase();
                
                // SO SÁNH THÔNG MINH: Local có nằm trong danh sách Valid không?
                const isMatch = validFingerprints.some(fp => fp.toLowerCase() === localClean);

                if (!isMatch) {
                    isSafe = false;
                    error = `MITM DETECTED! Local (${localClean.substring(0,8)}...) not found in valid Agent list.`;
                    console.warn(`MITM ALERT ${domain}: Local mismatch`);
                } else {
                    console.log(`Integrity Confirmed for ${domain}`);
                }
            }

            sendResponse({ isSafe: isSafe, error: error });
        });

        return true; 
    }

    // 2.3. Passive Check
    if (request.action === "request_cert_check") {
        checkAndSendResult(request.url, request.tabId);
        return true;
    }
});

// --- PHẦN 3: LOGIC CHECK PASSIVE ---
async function checkAndSendResult(url, tabId) {
    let result = {
        issuer: "Checking...",
        securityScore: 0,
        riskLevel: "UNKNOWN",
        isMITM: false,
        error: null
    };

    try {
        const hostname = new URL(url).hostname;

        // 1. Gọi API Go Server
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: hostname })
        });
        
        if(!response.ok) throw new Error("Agent Failed");
        const apiData = await response.json();
        
        result = { ...result, ...apiData };

        // 2. Lấy Native Fingerprint
        const localFingerprint = await getNativeFingerprint(hostname);

        // 3. SO SÁNH (MULTI-IP AWARE)
        if (localFingerprint) {
            const localClean = localFingerprint.toLowerCase();
            let isMatch = false;

            // Ưu tiên check mảng fingerprints
            if (apiData.fingerprints && apiData.fingerprints.length > 0) {
                isMatch = apiData.fingerprints.some(fp => fp.toLowerCase() === localClean);
            } else if (apiData.fingerprint) {
                isMatch = (localClean === apiData.fingerprint.toLowerCase());
            }

            if (!isMatch) {
                result.isMITM = true;
                result.error = "MITM DETECTED (Native Check)";
                result.shouldAlert = true;
                result.securityScore = 0;
            }
        }

    } catch (e) {
        console.error(e);
        result.error = e.message;
    }

    chrome.runtime.sendMessage({ action: "cert_status_update", ...result }).catch(()=>{});
    updateBadge(tabId, result);
}

function updateBadge(tabId, result) {
    let color = '#00AA00';
    let text = result.securityScore ? result.securityScore.toString() : "";
    if (result.isMITM) { color = '#FF0000'; text = "MITM"; }
    else if (result.shouldAlert) { color = '#FF0000'; text = "!"; }
    
    if (tabId) {
        try {
            chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
            chrome.action.setBadgeText({ text: text, tabId: tabId });
        } catch(e) {}
    }
}