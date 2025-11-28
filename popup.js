document.addEventListener('DOMContentLoaded', function() {
  const statusDiv = document.getElementById('status');
  statusDiv.textContent = "Waiting for check results..."; 

  chrome.runtime.onMessage.addListener(
    function(request, sender, sendResponse) {
      if (request.action === "cert_status_update") {
        
        let daysLeftStyle = request.shouldAlert ? 'color: red; font-weight: bold;' : 'color: green; font-weight: bold;';
        
        // Cập nhật HTML để hiển thị thông tin chi tiết
        statusDiv.innerHTML = `
          <div style="font-size: 13px;">
            <p style="line-height: 1.5;">
                <strong>Issuer:</strong> ${request.issuer}<br>
                <strong>Expiration Date:</strong> ${request.expiryDate}<br>
                <strong>Days Remaining:</strong> <span style="${daysLeftStyle}">${request.daysLeft} days</span><br>
                <strong>Public Key Type:</strong> ${request.publicKeyType}<br>
                <strong>Signature Algorithm:</strong> ${request.signatureAlgorithm}
            </p>
            ${request.error ? `<hr><span style="color: gray; font-size: 11px; font-weight: normal;">Error: ${request.error}</span>` : ''}
          </div>
        `;
      }
    }
  );

  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (tabs[0] && tabs[0].url) {
      
      statusDiv.textContent = `Checking ${new URL(tabs[0].url).hostname}...`; 
      
      chrome.runtime.sendMessage({ 
          action: "request_cert_check", 
          url: tabs[0].url,
          tabId: tabs[0].id
      });
    } else {
       statusDiv.textContent = "Please navigate to an HTTPS website.";
    }
  });
});