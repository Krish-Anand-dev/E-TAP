// background.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyzeEmail') {
        const emailData = request.data;
        
        // Construct a raw EML structure dynamically
        const emlContent = `From: ${emailData.sender || 'unknown@example.com'}
To: current_user@domain.com
Subject: ${emailData.subject || 'No Subject'}
Date: ${new Date().toUTCString()}
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

${emailData.body}`;

        // Create a blob representing the EML file
        const blob = new Blob([emlContent], { type: 'message/rfc822' });
        
        // Create FormData matching the FastAPI '/analyze' endpoint
        const formData = new FormData();
        formData.append('file', blob, 'extension_scan.eml');
        
        // Hit the live Render API
        fetch('https://threat-email-platform-1.onrender.com/analyze', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('API Request Failed');
            }
            return response.json();
        })
        .then(data => {
            sendResponse({ success: true, report: data });
        })
        .catch(error => {
            console.error('PhishGuard API Error:', error);
            sendResponse({ success: false, error: error.toString() });
        });
        
        // Return true to indicate asynchronous response
        return true;
    }
});
