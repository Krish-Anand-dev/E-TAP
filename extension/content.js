// Page watching only reads local DOM text to place banners. Analysis and
// retrieval start after a click. The full report opens in its own tab.
const ETAP_APP_BASE_URL = ETAP_CONFIG.appBaseUrl;
const ETAP_BODY_SELECTOR = '.ii.gt';

function extractEmailData(container) {
    const body = container.querySelector(ETAP_BODY_SELECTOR);
    if (!body) return null;
    const scope = body.closest('.gs') || container;
    const sender = scope.querySelector('span[email]');
    const subject = document.querySelector('h2[data-thread-perm-id]');
    return {
        messageId: EtapGmailOriginal.messageIdFor(body),
        sender: sender?.getAttribute('email') || 'unknown@invalid',
        subject: subject?.innerText || 'No Subject',
        body: body.innerText || '',
    };
}
function emailKey(data) {
    return `${data.messageId || ''}|${data.subject}|${data.body.slice(0, 200)}`;
}
function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}
function bannerFor(container) {
    const previous = container.querySelector(ETAP_BODY_SELECTOR)?.previousElementSibling;
    return previous?.classList.contains('etap-banner') ? previous : null;
}
function replaceBanner(container, oldBanner, banner) {
    oldBanner?.remove();
    const body = container.querySelector(ETAP_BODY_SELECTOR);
    if (body) body.parentNode.insertBefore(banner, body);
}
function platformLink() {
    const link = el('a', 'etap-btn', 'Open E-TAP');
    link.href = ETAP_APP_BASE_URL;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    return link;
}
function banner(container, existing, key, state, title, description) {
    const node = el('div', `etap-banner etap-banner-rich ${state}`);
    node.dataset.etapKey = key;
    node.dataset.etapVersion = ETAP_CONFIG.version;
    const row = el('div', 'etap-row');
    row.append(el('strong', null, `E-TAP ${ETAP_CONFIG.version} · ${title}`), platformLink());
    node.append(row, el('span', 'etap-sub', description));
    replaceBanner(container, existing, node);
    return node;
}
function renderIdle(container, existing, key) {
    const node = banner(container, existing, key, 'banner-idle', 'E-TAP Email Analysis',
        'Opens a report in a new tab. Tries the original email first; if unavailable, runs a clearly labeled content-only check. Email contents are sent to E-TAP only after you click.');
    const button = el('button', 'etap-btn etap-btn-primary', 'Analyze in E-TAP');
    button.type = 'button';
    button.addEventListener('click', () => runAnalysis(container, node, key));
    node.append(button);
}
function send(request) {
    return new Promise((resolve, reject) => chrome.runtime.sendMessage(request, (response) => {
        const error = chrome.runtime.lastError;
        if (error || !response?.success) reject(new Error(response?.code || error?.message || 'handoff_failed'));
        else resolve(response);
    }));
}
async function runAnalysis(container, existing, key) {
    const data = extractEmailData(container);
    if (!data) return;
    let current = banner(container, existing, key, 'banner-loading', 'Opening your analysis tab…',
        'E-TAP will retrieve as much evidence as Gmail makes available.');
    // Capture this specific message before opening another tab or navigating.
    let reference;
    try { reference = EtapGmailOriginal.referenceFor(container.querySelector(ETAP_BODY_SELECTOR), location.href); } catch { /* Content fallback remains available. */ }
    let jobId;
    try {
        ({ jobId } = await send({ action: 'startEmailAnalysis', data }));
        const now = extractEmailData(container);
        if (current.isConnected && now && emailKey(now) === key) {
            current = banner(container, current, key, 'banner-neutral', 'Continue in your analysis tab',
                'Your report will open there automatically. If original headers cannot be retrieved, the report will explain what was unavailable.');
            const reopen = el('button', 'etap-btn', 'Open analysis tab');
            reopen.type = 'button';
            reopen.addEventListener('click', () => send({ action: 'focusEmailAnalysis', jobId }).catch(() => window.open(ETAP_APP_BASE_URL, '_blank', 'noopener,noreferrer')));
            current.append(reopen);
        }
    } catch (error) {
        banner(container, current, key, 'banner-error', 'Open E-TAP to continue',
            error.message === 'too_large' ? 'This email exceeds the upload limit. Use Open E-TAP to choose a different file.' : 'The extension could not create an analysis tab. Use Open E-TAP above; refresh Gmail to retry the handoff.');
        return;
    }
    try {
        if (!reference) throw new Error('original_unavailable');
        const rawEmailBase64 = await EtapGmailOriginal.fetchOriginal(reference);
        await send({ action: 'prepareEmailAnalysis', jobId, rawEmailBase64 });
    } catch (error) {
        // The new tab already has a message snapshot. Failure to obtain raw
        // headers must not remove access to a report or the platform.
        await send({ action: 'prepareEmailAnalysis', jobId, retrievalError: error.code || 'original_unavailable' }).catch(() => {});
    }
}
function syncBanners() {
    document.querySelectorAll('.adO, .gs, .nH.hx').forEach((container) => {
        const data = extractEmailData(container);
        if (!data) return;
        const key = emailKey(data);
        const existing = bannerFor(container);
        if (existing?.dataset.etapKey === key && existing.dataset.etapVersion === ETAP_CONFIG.version) return;
        renderIdle(container, existing, key);
    });
}
let etapSyncTimer = null;
const etapObserver = new MutationObserver(() => {
    clearTimeout(etapSyncTimer);
    etapSyncTimer = setTimeout(syncBanners, 400);
});
etapObserver.observe(document.body, { childList: true, subtree: true });
syncBanners();
