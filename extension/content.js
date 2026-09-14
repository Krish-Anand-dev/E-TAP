// content.js

// Keep track of emails we've already scanned to prevent infinite loops
const scannedEmails = new Set();

function extractEmailData(emailContainer) {
    // Gmail uses specific obfuscated classes, but generally elements can be found by standard selectors within the email pane
    const subjectEl = document.querySelector('h2[data-thread-perm-id]');
    const senderEl = emailContainer.querySelector('span[email]');
    const bodyEl = emailContainer.querySelector('.ii.gt');
    
    if (!bodyEl) return null;

    return {
        subject: subjectEl ? subjectEl.innerText : 'No Subject',
        sender: senderEl ? senderEl.getAttribute('email') : 'Unknown Sender',
        body: bodyEl.innerText,
    };
}

function injectBanner(emailContainer, reportData) {
    if (emailContainer.querySelector('.phishguard-banner')) {
        return; // Banner already exists
    }

    const banner = document.createElement('div');
    banner.className = 'phishguard-banner';

    // Parse the report from the backend (API returns risk_score at top level, and final_assessment inside ai_analysis)
    const riskScore = reportData.risk_score || 0;
    const verdict = reportData.verdict || 'Unknown';
    
    // Explanation is nested deeply inside ai_analysis
    let explanation = 'No explanation provided.';
    if (reportData.ai_analysis && reportData.ai_analysis.final_assessment && reportData.ai_analysis.final_assessment.supporting_evidence) {
        explanation = reportData.ai_analysis.final_assessment.supporting_evidence[0] || explanation;
    }

    // Traffic light styling
    const reportLink = reportData.email_id 
        ? `https://phishguard-p29b.onrender.com/?dossier=${reportData.email_id}` 
        : 'https://phishguard-p29b.onrender.com';

    if (riskScore >= 65) {
        banner.classList.add('banner-red');
        banner.innerHTML = `<strong>🚨 High-Risk: ${verdict}</strong> - ${explanation} <a href="${reportLink}" target="_blank" class="phishguard-btn">View Full Report</a>`;
    } else if (riskScore >= 40) {
        banner.classList.add('banner-yellow');
        banner.innerHTML = `<strong>⚠️ Suspicious</strong> - ${explanation} <a href="${reportLink}" target="_blank" class="phishguard-btn">View Full Report</a>`;
    } else {
        banner.classList.add('banner-green');
        banner.innerHTML = `<strong>✅ Safe</strong> - Email scanned by PhishGuard and looks clean. <a href="${reportLink}" target="_blank" class="phishguard-btn">View Full Report</a>`;
    }

    // Insert banner at the top of the email body
    const bodyContainer = emailContainer.querySelector('.ii.gt');
    if (bodyContainer) {
        bodyContainer.parentNode.insertBefore(banner, bodyContainer);
    }
}

function scanVisibleEmails() {
    // Gmail reading panes
    const emailContainers = document.querySelectorAll('.adO, .gs, .nH.hx');
    
    emailContainers.forEach(container => {
        // Check if we have already injected a banner (loading or final) into this specific email view
        if (!container.querySelector('.phishguard-banner')) {
            const data = extractEmailData(container);
            
            if (data && data.body.length > 10) {
                console.log(`[PhishGuard] Extracted Email:`, data.subject);
                
                // 1. Immediately inject the loading banner so we don't scan it again on the next tick
                const loadingBanner = document.createElement('div');
                loadingBanner.className = 'phishguard-banner banner-loading';
                loadingBanner.innerText = '🛡️ PhishGuard is analyzing this email...';
                
                const bodyContainer = container.querySelector('.ii.gt');
                if (bodyContainer) {
                    bodyContainer.parentNode.insertBefore(loadingBanner, bodyContainer);
                }

                // 2. Send to background script for analysis
                chrome.runtime.sendMessage({ action: 'analyzeEmail', data: data }, response => {
                    // Remove the loading banner
                    if (loadingBanner.parentNode) {
                        loadingBanner.parentNode.removeChild(loadingBanner);
                    }
                    // Inject the final banner or error banner
                    if (response && response.success) {
                        injectBanner(container, response.report);
                    } else {
                        console.error('PhishGuard Analysis Failed:', response?.error);
                        
                        // Inject an error banner so we don't infinitely retry
                        const errorBanner = document.createElement('div');
                        errorBanner.className = 'phishguard-banner banner-red';
                        errorBanner.innerHTML = `<strong>❌ API Error</strong> - Failed to analyze email. Check terminal for backend crashes.`;
                        const bodyContainer = container.querySelector('.ii.gt');
                        if (bodyContainer) bodyContainer.parentNode.insertBefore(errorBanner, bodyContainer);
                    }
                });
            }
        }
    });
}

// Run scanner periodically to catch newly opened emails in Gmail's SPA
setInterval(scanVisibleEmails, 2000);
