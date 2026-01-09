// File: popup.js
document.addEventListener('DOMContentLoaded', function() {
    const statusDiv = document.getElementById('status');
    const strictToggle = document.getElementById('strictModeToggle');
  
    // 1. Load trạng thái Strict Mode từ bộ nhớ
    chrome.storage.sync.get(['strictMode'], function(result) {
        strictToggle.checked = result.strictMode || false;
    });
  
    // 2. Lắng nghe sự kiện Bật/Tắt Switch
    strictToggle.addEventListener('change', function() {
        const isStrict = strictToggle.checked;
        chrome.storage.sync.set({ strictMode: isStrict }, function() {
            console.log("Strict Mode set to " + isStrict);
            // Reload tab hiện tại để áp dụng ngay lập tức
            chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                if(tabs[0]) chrome.tabs.reload(tabs[0].id);
            });
        });
    });
  
    // 3. Logic hiển thị thông tin cũ
    statusDiv.innerHTML = "<p>Connecting to Hybrid Agent...</p>"; 
  
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "cert_status_update") {
          renderResult(request);
        }
    });
  
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs[0] && tabs[0].url.startsWith("https")) {
        chrome.runtime.sendMessage({ 
            action: "request_cert_check", 
            url: tabs[0].url,
            tabId: tabs[0].id
        });
      } else {
        statusDiv.innerHTML = "<p style='color:gray; padding:10px;'>Please verify an HTTPS website.</p>";
      }
    });
  });
  
  function renderResult(data) {
      const statusDiv = document.getElementById('status');
      
      let scoreColor = '#2ecc71'; // Green
      if (data.securityScore < 50) scoreColor = '#e74c3c'; // Red
      else if (data.securityScore < 80) scoreColor = '#f39c12'; // Orange
  
      let html = `
          <div style="text-align: center; padding: 15px; background: #f9f9f9; border-bottom: 1px solid #eee;">
              <div style="font-size: 36px; color: ${scoreColor}; font-weight: bold;">
                  ${data.securityScore !== undefined ? data.securityScore : "?"}
              </div>
              <div style="font-size: 12px; color: #7f8c8d; text-transform: uppercase; letter-spacing: 1px;">Security Score</div>
          </div>
      `;
  
      if (data.isMITM) {
          html += `
              <div style="background-color: #c0392b; color: white; padding: 10px; margin: 10px 0; font-weight: bold; text-align: center; border-radius: 4px;">
                  🚨 MITM ATTACK DETECTED 🚨
                  <div style="font-size: 10px; font-weight: normal;">Certificate fingerprint mismatch!</div>
              </div>
          `;
      } else if (data.error) {
          html += `<div style="color: #c0392b; padding: 10px; font-size: 12px;">Error: ${data.error}</div>`;
      }
  
      if (data.issuer) {
          html += `
              <div style="padding: 15px; font-size: 13px; line-height: 1.6;">
                  <div><strong>Issuer:</strong> ${data.issuer}</div>
                  <div><strong>Expires:</strong> ${data.expiryDate}</div>
                  <div><strong>Days Left:</strong> <span style="color:${data.daysLeft < 30 ? 'red' : 'green'}">${data.daysLeft}</span></div>
                  <div><strong>Algorithm:</strong> ${data.signatureAlgorithm}</div>
                  <div style="margin-top: 8px; font-size: 10px; color: #95a5a6; word-break: break-all;">
                      <strong>Fingerprint (SHA256):</strong><br>
                      ${data.fingerprint ? data.fingerprint.substring(0, 20) + "..." : "N/A"}
                  </div>
              </div>
          `;
      }
  
      statusDiv.innerHTML = html;
  }