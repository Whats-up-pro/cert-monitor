// File: background.js

// --- CẤU HÌNH ---
const API_ENDPOINT = 'http://localhost:8080/check-cert';
const NATIVE_HOST_NAME = "com.certmonitor.native"; // Phải khớp với file nm_host.json

// Cache Whitelist phiên làm việc (Để Strict Mode không chặn lặp lại các trang đã an toàn)
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
        if (!isStrictMode) { // Tắt Strict -> Xóa whitelist
            for (let member in safeSessionCache) delete safeSessionCache[member];
        }
    }
});

// --- HÀM GỌI NATIVE APP (Lấy Fingerprint thật từ Windows) ---
function getNativeFingerprint(domain) {
    return new Promise((resolve) => {
        try {
            console.log(`[Native] Asking OS for certificate of: ${domain}`);
            chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, { domain: domain }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("Native Error:", chrome.runtime.lastError.message);
                    resolve(null); // Lỗi: Chưa cài App Native hoặc sai cấu hình
                } else {
                    // Native App trả về: { fingerprint: "...", error: "" }
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
        if (url.startsWith(chrome.runtime.getURL(""))) return false; // Không chặn trang nội bộ

        const hostname = urlObj.hostname;
        
        // Nếu đã Whitelist (trong 10 phút)
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
                // CHẶN & ĐÁ SANG PHÒNG CÁCH LY
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
    
    // 2.1. Whitelist (Từ checking.js báo về)
    if (request.action === "mark_as_safe") {
        const hostname = new URL(request.url).hostname;
        safeSessionCache[hostname] = Date.now();
        sendResponse({status: "ok"});
    }

    // 2.2. VALIDATE TOFU (Dùng Native App thay vì Cache RAM)
    // checking.js gửi Fingerprint chuẩn (từ Server) về -> Background so sánh với máy thật
    if (request.action === "validate_tofu") {
        const domain = request.domain;
        const serverFingerprint = request.fingerprint;
        
        // Gọi xuống file .exe để lấy cert thực tế đang hiển thị trên máy
        getNativeFingerprint(domain).then((localFingerprint) => {
            let isSafe = true;
            let error = "";

            if (!localFingerprint) {
                // Không lấy được (Lỗi Native App) -> Tùy bạn muốn chặn hay cho qua
                // Ở đây ta báo lỗi để biết đường fix
                isSafe = false;
                error = "Native Host Error: Cannot read OS Certificate (Did you install the Native App?)";
            } else if (localFingerprint !== serverFingerprint) {
                // ==> PHÁT HIỆN MITM TỰ ĐỘNG <==
                // Server (mạng sạch) thấy A. Máy (qua Burp) thấy B.
                isSafe = false;
                error = `MITM DETECTED! Local fingerprint (${localFingerprint.substring(0,8)}...) differs from Agent (${serverFingerprint.substring(0,8)}...)`;
                
                console.warn(`MITM ALERT on ${domain}!`);
                console.warn(`Local (OS): ${localFingerprint}`);
                console.warn(`Remote (Go): ${serverFingerprint}`);
            }

            sendResponse({ isSafe: isSafe, error: error });
        });

        return true; // Giữ kết nối async
    }

    // 2.3. Passive Check
    if (request.action === "request_cert_check") {
        checkAndSendResult(request.url, request.tabId);
        return true;
    }
});

// --- PHẦN 3: LOGIC CHECK PASSIVE (Cũng dùng Native) ---
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
        
        // Merge dữ liệu
        result = { ...result, ...apiData };

        // 2. Lấy dữ liệu từ Native App (Local)
        const localFingerprint = await getNativeFingerprint(hostname);

        // 3. SO SÁNH (LOGIC MỚI - Hỗ trợ Mảng Fingerprints)
        if (localFingerprint) {
            const localFpClean = localFingerprint.toLowerCase();
            let isMatch = false;

            // Kiểm tra: Server có trả về danh sách fingerprints không?
            if (apiData.fingerprints && Array.isArray(apiData.fingerprints) && apiData.fingerprints.length > 0) {
                // Cách 1: Duyệt mảng để tìm
                // Nếu vân tay local nằm trong danh sách các vân tay hợp lệ của Server -> AN TOÀN
                isMatch = apiData.fingerprints.some(fp => fp.toLowerCase() === localFpClean);
                
                console.log(`[Check] Local: ${localFpClean}`);
                console.log(`[Check] Remote List:`, apiData.fingerprints);
                console.log(`[Check] Match Found: ${isMatch}`);

            } else if (apiData.fingerprint) {
                // Cách 2: Fallback (Nếu Server bản cũ chỉ trả về 1 cái)
                isMatch = (localFpClean === apiData.fingerprint.toLowerCase());
            }

            // KẾT LUẬN
            if (!isMatch) {
                result.isMITM = true;
                result.error = "MITM DETECTED! Local cert does not match any valid Agent certs.";
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