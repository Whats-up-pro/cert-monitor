// File: checking.js
const API_ENDPOINT = 'http://localhost:8080/check-cert';

const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('target');

if (targetUrl) {
    performCheck();
} else {
    document.body.innerHTML = "<h1>Invalid Target URL</h1>";
}

// Xử lý sự kiện nút Bypass
document.getElementById('bypass-btn').addEventListener('click', () => {
    if (confirm("WARNING: You are bypassing security checks.\nIf the Agent is unreachable due to an attack, your connection might be compromised.\n\nAre you sure you want to proceed?")) {
        allowAccess();
    }
});

async function performCheck() {
    let hostname = "";
    try {
        hostname = new URL(targetUrl).hostname;
    } catch (e) {
        showBlockScreen("Unknown", "Invalid URL format", 0, false);
        return;
    }

    // Thiết lập Timeout 3 giây (Fail-safe)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);

    try {
        // BƯỚC 1: Gọi Go Server (Lấy Fingerprint chuẩn)
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: hostname }),
            signal: controller.signal // Gắn tín hiệu ngắt
        });
        clearTimeout(timeoutId); // Hủy timeout nếu thành công

        if (!response.ok) throw new Error("Agent connection failed");
        const data = await response.json();

        // Check sơ bộ từ Server (Điểm số)
        if (data.security_score < 50 || data.risk_level === 'CRITICAL') {
            // Lỗi bảo mật thật -> Chặn cứng (Không cho Bypass)
            showBlockScreen(hostname, data.error || "Low Security Score", data.security_score, false);
            return;
        }

        // BƯỚC 2: Hỏi Background (Native Host) xem có khớp không?
        chrome.runtime.sendMessage({ 
            action: "validate_tofu", 
            domain: hostname, 
            fingerprints: data.fingerprints 
        }, (tofuResult) => {
            
            if (tofuResult && tofuResult.isSafe) {
                // --- AN TOÀN ---
                allowAccess();
            } else {
                // --- MITM THẬT (Server OK nhưng Local Lệch) ---
                // Chặn cứng (Không cho Bypass)
                const errorMsg = tofuResult ? tofuResult.error : "TOFU Validation Failed";
                showBlockScreen(hostname, errorMsg, 0, false);
            }
        });

    } catch (e) {
        // --- FAIL-SAFE: LỖI MẠNG / TIMEOUT ---
        // Nếu không gọi được Agent, cho phép người dùng tự quyết định (Soft Fail)
        console.warn("Agent unreachable:", e);
        
        let reason = "Verification Agent Unreachable (Timeout/Network Error).";
        reason += "<br><small>Cannot verify certificate integrity.</small>";

        // Hiện màn hình chặn nhưng CHO PHÉP nút Bypass
        showBlockScreen(hostname, reason, "?", true);
    }
}

function allowAccess() {
    // Báo whitelist để lần sau không chặn nữa
    chrome.runtime.sendMessage({ action: "mark_as_safe", url: targetUrl }, () => {
        window.location.replace(targetUrl);
    });
}

function showBlockScreen(domain, error, score, allowBypass) {
    document.getElementById('loading-view').classList.add('hidden');
    document.getElementById('blocked-view').classList.remove('hidden');
    
    const mainCard = document.getElementById('main-card');
    const title = document.getElementById('status-title');
    
    document.getElementById('target-domain').textContent = domain;
    document.getElementById('error-reason').innerHTML = error; // Dùng innerHTML để xuống dòng
    document.getElementById('security-score').textContent = score;

    const bypassBtn = document.getElementById('bypass-btn');

    if (allowBypass) {
        // Chế độ Cảnh báo (Warning) - Cho phép đi tiếp
        bypassBtn.style.display = 'inline-block';
        mainCard.classList.remove('blocked');
        mainCard.classList.add('warning'); // Viền màu cam
        title.style.color = "#f39c12";
        title.textContent = "Connection Warning";
    } else {
        // Chế độ Chặn (Blocked) - MITM hoặc rủi ro cao
        bypassBtn.style.display = 'none';
        mainCard.classList.remove('warning');
        mainCard.classList.add('blocked'); // Viền màu đỏ
        title.style.color = "#c0392b";
        title.textContent = "Connection Blocked";
    }
}