// File: background.js
const API_ENDPOINT = 'http://localhost:8080/check-cert';

// Cache dùng cho Passive Mode (TOFU)
const certCache = {}; 
// Cache dùng cho Strict Mode (Whitelist các trang đã qua phòng cách ly)
const safeSessionCache = {}; 

// --- PHẦN 1: LOGIC CHẶN CỦA STRICT MODE ---
function shouldIntercept(url) {
    try {
        const urlObj = new URL(url);
        // Chỉ chặn HTTPS và không chặn trang nội bộ extension
        if (urlObj.protocol !== 'https:') return false;
        if (url.startsWith(chrome.runtime.getURL(""))) return false;

        const hostname = urlObj.hostname;
        
        // Nếu đã nằm trong whitelist (đã check an toàn trong 10 phút)
        if (safeSessionCache[hostname] && (Date.now() - safeSessionCache[hostname] < 600000)) {
            return false;
        }
        return true;
    } catch (e) { return false; }
}

// Lắng nghe sự kiện chuyển trang (Navigation)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Khi trang bắt đầu load
    if (changeInfo.status === 'loading' && tab.url) {
        
        // Kiểm tra xem người dùng đang Bật hay Tắt Strict Mode
        chrome.storage.sync.get(['strictMode'], function(result) {
            if (result.strictMode) {
                // [STRICT MODE] -> Kiểm tra chặn
                if (shouldIntercept(tab.url)) {
                    console.log("[Strict Mode] Intercepting: " + tab.url);
                    const checkingUrl = chrome.runtime.getURL('checking.html') + 
                                        `?target=${encodeURIComponent(tab.url)}`;
                    chrome.tabs.update(tabId, { url: checkingUrl });
                }
            } else {
                // [PASSIVE MODE] -> Chỉ check ngầm, không chặn
                // Gọi hàm check để cập nhật icon badge
                if (tab.url.startsWith('https')) {
                    checkAndSendResult(tab.url, tabId);
                }
            }
        });
    }
});

// Nhận tin nhắn từ "Phòng cách ly" (checking.js)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "mark_as_safe") {
        const hostname = new URL(request.url).hostname;
        safeSessionCache[hostname] = Date.now(); // Thêm vào whitelist
        sendResponse({status: "ok"});
    }

    if (request.action === "validate_tofu") {
        const domain = request.domain;
        const newFingerprint = request.fingerprint;
        
        let isSafe = true;
        let error = "";

        // So sánh với Cache trong Background
        if (certCache[domain]) {
            if (certCache[domain] !== newFingerprint) {
                isSafe = false;
                error = "Fingerprint mismatch with Local Cache (TOFU)!";
            }
        } else {
            // Nếu chưa có thì lưu luôn (Trust First Use)
            certCache[domain] = newFingerprint;
        }

        sendResponse({ isSafe: isSafe, error: error });
        return true; // Giữ kết nối async
    }
});


// --- PHẦN 2: LOGIC KIỂM TRA & TOFU (Dùng cho cả Passive & Popup) ---
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

        // Gọi API Go Server
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: hostname })
        });

        if (!response.ok) throw new Error("Agent Connection Failed");

        const apiData = await response.json();

        if (apiData.error) throw new Error(apiData.error);

        // Map dữ liệu
        result.issuer = apiData.issuer;
        result.expiryDate = new Date(apiData.expiryDate).toLocaleDateString();
        result.daysLeft = apiData.daysLeft;
        result.securityScore = apiData.security_score;
        result.riskLevel = apiData.risk_level;
        result.fingerprint = apiData.fingerprint;
        result.signatureAlgorithm = apiData.signatureAlgorithm;
        result.shouldAlert = apiData.shouldAlert;

        // TOFU Logic (Trust On First Use)
        if (certCache[hostname]) {
            if (certCache[hostname] !== result.fingerprint) {
                result.isMITM = true;
                result.error = "Certificate Fingerprint changed!";
                result.shouldAlert = true;
                result.securityScore = 0;
            }
        } else {
            certCache[hostname] = result.fingerprint;
        }

    } catch (e) {
        console.error(e);
        result.error = e.message;
    }

    // Gửi kết quả về Popup (nếu đang mở)
    chrome.runtime.sendMessage({
        action: "cert_status_update",
        ...result
    }).catch(() => {});

    // Cập nhật Badge trên Icon
    updateBadge(tabId, result);
}

function updateBadge(tabId, result) {
    let color = '#00AA00'; // Xanh
    let text = result.securityScore ? result.securityScore.toString() : "";

    if (result.isMITM) {
        color = '#FF0000'; text = "MITM";
    } else if (result.shouldAlert || result.riskLevel === 'CRITICAL') {
        color = '#FF0000'; text = "!";
    } else if (result.riskLevel === 'WARNING') {
        color = '#FFA500'; 
    }

    chrome.action.setBadgeBackgroundColor({ color: color });
    chrome.action.setBadgeText({ tabId: tabId, text: text });
}

// Lắng nghe yêu cầu từ Popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "request_cert_check") {
        checkAndSendResult(request.url, request.tabId);
        return true;
    }
});