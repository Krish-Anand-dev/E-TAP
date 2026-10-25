importScripts('config.js', 'gmail-original.js', 'handoff-store.js', 'sandbox-pairing.js');

function gmailSender(sender) {
    try { return new URL(sender.url).origin === 'https://mail.google.com' && Number.isInteger(sender.tab?.id); }
    catch { return false; }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (!['startEmailAnalysis', 'prepareEmailAnalysis', 'focusEmailAnalysis', 'sandboxStatus'].includes(request.action)) return;
    if (!gmailSender(sender)) {
        sendResponse({ success: false, code: 'invalid_sender' });
        return;
    }
    (async () => {
        if (request.action === 'sandboxStatus') {
            const state = await EtapSandbox.status();
            return { success: true, state: { available: Boolean(state.available), paired: Boolean(state.paired), online: Boolean(state.online), problem: state.problem || null } };
        }
        if (request.action === 'startEmailAnalysis') {
            const id = crypto.randomUUID();
            const job = {
                id, createdAt: Date.now(), gmailTabId: sender.tab.id, state: 'retrieving',
                deep: request.deep === true,
                data: {
                    sender: String(request.data?.sender || ''),
                    subject: String(request.data?.subject || ''),
                    body: String(request.data?.body || ''),
                },
            };
            if (new TextEncoder().encode(JSON.stringify(job.data)).length > EtapGmailOriginal.MAX_BYTES) throw new Error('too_large');
            await EtapHandoffStore.create(job);
            let tab;
            try {
                tab = await chrome.tabs.create({ url: chrome.runtime.getURL(`analysis.html?job=${id}`), active: true });
            } catch (error) {
                await EtapHandoffStore.remove(id);
                throw error;
            }
            await EtapHandoffStore.update(id, (current) => ({ ...current, analysisTabId: tab.id }));
            return { success: true, jobId: id };
        }
        const job = await EtapHandoffStore.get(request.jobId);
        if (!job || job.gmailTabId !== sender.tab.id) throw new Error('handoff_expired');
        if (request.action === 'focusEmailAnalysis') {
            await chrome.tabs.update(job.analysisTabId, { active: true });
            return { success: true };
        }
        if (request.rawEmailBase64) EtapGmailOriginal.decode(request.rawEmailBase64);
        await EtapHandoffStore.update(job.id, (current) => current.state !== 'retrieving' ? current : {
            ...current, state: 'ready', rawEmailBase64: request.rawEmailBase64 || null,
            retrievalError: request.retrievalError || null,
        });
        return { success: true };
    })().then(sendResponse).catch((error) => {
        sendResponse({ success: false, code: error.code || error.message || 'handoff_failed' });
    });
    return true;
});

// Always provide a way into the platform, even outside an open message.
chrome.action.onClicked.addListener(() => chrome.tabs.create({ url: ETAP_CONFIG.appBaseUrl }));
