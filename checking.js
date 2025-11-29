// File: checking.js
const API_ENDPOINT = 'http://localhost:8080/check-cert';

const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('target');

if (targetUrl) {
    performCheck();
} else {
    document.body.innerHTML = "<h1>Invalid Target URL</h1>";
}

async function performCheck() {
    try {
        const hostname = new URL(targetUrl).hostname;

        // BƯỚC 1: Gọi Go Server (Check điểm số & Risk)
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: hostname })
        });

        if (!response.ok) throw new Error("Agent connection failed");
        const data = await response.json();

        // Check sơ bộ từ Server
        if (data.security_score < 50 || data.risk_level === 'CRITICAL') {
            showBlockScreen(hostname, data.error || "Low Security Score", data.security_score);
            return; // Dừng ngay
        }

        // BƯỚC 2: ==> THÊM MỚI: Hỏi Background xem có khớp Cache (TOFU) không?
        chrome.runtime.sendMessage({ 
            action: "validate_tofu", 
            domain: hostname,
            fingerprint: data.fingerprint 
        }, (tofuResult) => {
            
            if (tofuResult.isSafe) {
                // --- CẢ 2 ĐỀU OK: Server OK + Cache OK ---
                // Báo whitelist và chuyển trang
                chrome.runtime.sendMessage({ action: "mark_as_safe", url: targetUrl }, () => {
                    window.location.replace(targetUrl);
                });
            } else {
                // --- SERVER OK NHƯNG CACHE SAI (MITM) ---
                showBlockScreen(hostname, tofuResult.error, 0);
            }
        });

    } catch (e) {
        showBlockScreen(new URL(targetUrl).hostname, e.message, 0);
    }
}

function showBlockScreen(domain, error, score) {
    document.getElementById('loading-view').classList.add('hidden');
    document.getElementById('blocked-view').classList.remove('hidden');
    document.getElementById('main-card').classList.add('blocked');
    
    document.getElementById('target-domain').textContent = domain;
    document.getElementById('error-reason').textContent = error;
    document.getElementById('security-score').textContent = score;
}