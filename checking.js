// File: checking.js
const API_ENDPOINT = 'http://localhost:8080/check-cert';

// Lấy tham số URL
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

        // BƯỚC 1: Gọi Go Server (Lấy Fingerprint chuẩn)
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: hostname })
        });

        if (!response.ok) throw new Error("Agent connection failed");
        const data = await response.json();

        // Check sơ bộ từ Server (Điểm số)
        if (data.security_score < 50 || data.risk_level === 'CRITICAL') {
            showBlockScreen(hostname, data.error || "Low Security Score", data.security_score);
            return;
        }

        // BƯỚC 2: QUAN TRỌNG - Hỏi Background xem có khớp Cache (TOFU) không?
        // Đây là bước còn thiếu trong code cũ của bạn
        chrome.runtime.sendMessage({ 
            action: "validate_tofu", 
            domain: hostname, 
            fingerprint: data.fingerprint 
        }, (tofuResult) => {
            
            if (tofuResult && tofuResult.isSafe) {
                // --- AN TOÀN (Server OK + Cache OK) ---
                // Báo whitelist để lần sau không chặn nữa
                chrome.runtime.sendMessage({ action: "mark_as_safe", url: targetUrl }, () => {
                    // Chuyển hướng người dùng về trang đích
                    window.location.replace(targetUrl);
                });
            } else {
                // --- PHÁT HIỆN MITM (Server OK nhưng Cache Lệch) ---
                const errorMsg = tofuResult ? tofuResult.error : "TOFU Validation Failed";
                showBlockScreen(hostname, errorMsg, 0);
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