const EtapAnalysis = (() => {
    function oneLine(value, fallback) {
        return String(value || '').replace(/[\r\n]+/g, ' ').trim() || fallback;
    }
    function visibleMessage(data) {
        return new TextEncoder().encode([
            `From: ${oneLine(data.sender, 'unknown@invalid')}`,
            `Subject: ${oneLine(data.subject, 'No Subject')}`,
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset="utf-8"',
            'Content-Transfer-Encoding: 8bit',
            '', String(data.body || ''),
        ].join('\r\n'));
    }
    function payloadFor(job) {
        const original = Boolean(job.rawEmailBase64);
        const bytes = original ? EtapGmailOriginal.decode(job.rawEmailBase64) : visibleMessage(job.data || {});
        if (bytes.length > EtapGmailOriginal.MAX_BYTES) throw new Error('This email exceeds the 25 MB upload limit.');
        const form = new FormData();
        form.append('file', new Blob([bytes], { type: 'message/rfc822' }), original ? 'gmail_original.eml' : 'gmail_visible_content.eml');
        // Never present a reconstruction as original-header forensics.
        form.append('source', original ? 'full_message' : 'quick_content_check');
        // Deeper analysis needs the original attachments, so only full messages ask for it.
        if (job.deep && original) form.append('deep_analysis', '1');
        return form;
    }
    async function submit(job, signal, sandboxToken = null) {
        const headers = sandboxToken && job.deep ? { 'X-ETAP-Sandbox-Token': sandboxToken } : {};
        const response = await fetch(`${ETAP_CONFIG.apiBaseUrl}/analyze`, {
            method: 'POST', body: payloadFor(job), headers, signal,
        });
        if (!response.ok) {
            const messages = {
                413: 'This email exceeds the 25 MB upload limit.',
                429: 'Too many analyses. Wait a minute and try again.',
            };
            throw new Error(messages[response.status] || `The analysis service returned HTTP ${response.status}. You can retry here or open E-TAP.`);
        }
        const report = await response.json();
        if (!report.email_id) throw new Error('The service did not return a report link. Retry or open E-TAP.');
        return report;
    }
    function reportUrl(report) {
        const url = new URL(ETAP_CONFIG.appBaseUrl);
        url.searchParams.set('dossier', report.email_id);
        return url.href;
    }
    return { payloadFor, submit, reportUrl };
})();
