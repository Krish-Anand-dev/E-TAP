// E-TAP Gmail prototype. Change this URL when deploying the backend.
const ETAP_API_BASE_URL = 'https://etap-backend-od1c.onrender.com';

// Free hosting can take ~1 minute to wake from sleep.
const ETAP_REQUEST_TIMEOUT_MS = 90000;

// Header values must be a single line; never let page text inject extra headers.
function oneLine(value, fallback) {
    const cleaned = String(value || '').replace(/[\r\n]+/g, ' ').trim();
    return cleaned || fallback;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action !== 'analyzeEmail') return;

    const emailData = request.data || {};

    // Gmail only gives us what is visible on screen, so this is a
    // RECONSTRUCTION, not the original message. We deliberately do not invent
    // transport headers (no Received / Authentication-Results / Message-ID),
    // nor a To: or Date: we never saw. The backend is told via `source`, so it
    // reports headers as "not available" instead of analysing made-up ones.
    const emlContent = [
        `From: ${oneLine(emailData.sender, 'unknown@invalid')}`,
        `Subject: ${oneLine(emailData.subject, 'No Subject')}`,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset="utf-8"',
        'Content-Transfer-Encoding: 8bit',
        '',
        String(emailData.body || ''),
    ].join('\r\n');

    const formData = new FormData();
    formData.append('file', new Blob([emlContent], { type: 'message/rfc822' }), 'extension_scan.eml');
    formData.append('source', 'quick_content_check');

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ETAP_REQUEST_TIMEOUT_MS);

    chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
    chrome.storage.session.get('apiKey').then(({ apiKey }) => {
      if (!apiKey) { const error = new Error('Configure your API key in extension options.'); error.status = 401; throw error; }
      return fetch(`${ETAP_API_BASE_URL}/analyze`, {
        headers: { Authorization: `Bearer ${apiKey}` },
        method: 'POST',
        body: formData,
        signal: controller.signal,
    }); })
        .then((response) => {
            if (!response.ok) {
                const err = new Error(`HTTP ${response.status}`);
                err.status = response.status;
                throw err;
            }
            return response.json();
        })
        .then((data) => sendResponse({ success: true, report: data }))
        .catch((error) => {
            let code = 'network';
            if (error.name === 'AbortError') code = 'timeout';
            else if (error.status === 401) code = 'unauthenticated';
            else if (error.status === 429) code = 'rate_limited';
            else if (error.status === 413) code = 'too_large';
            else if (error.status >= 500) code = 'server_error';
            else if (error.status) code = 'http_error';
            console.error('E-TAP API Error:', code, error.message);
            sendResponse({ success: false, code, status: error.status || null });
        })
        .finally(() => clearTimeout(timer));

    // Return true to indicate asynchronous response
    return true;
});
