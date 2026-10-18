// Shared by the Gmail content script and the service worker. Gmail's normal
// message DOM does not contain the transport headers. Download the original
// message using the signed-in Gmail session. A reconstruction is handled
// separately by analysis-core.js and is always marked quick_content_check.
const EtapGmailOriginal = (() => {
    const MAX_BYTES = 25 * 1024 * 1024;
    const DOWNLOAD_TIMEOUT_MS = 30000;

    function failure(code = 'original_unavailable') {
        return Object.assign(new Error(code), { code });
    }

    function normalizeMessageId(value) {
        const id = String(value || '').replace(/^#/, '');
        if (/^[a-f0-9]{10,32}$/i.test(id)) return id.toLowerCase();
        return null;
    }

    function identifiersFor(body) {
        let message = body.closest('[data-legacy-message-id], [data-message-id]');
        while (message) {
            const current = String(message.getAttribute('data-message-id') || '').replace(/^#/, '');
            const messageId = normalizeMessageId(message.getAttribute('data-legacy-message-id')) || normalizeMessageId(current);
            const permanentMessageId = /^msg-[af]:[A-Za-z0-9_-]{1,160}$/.test(current) ? current : null;
            if (messageId || permanentMessageId) return { messageId, permanentMessageId };
            message = message.parentElement?.closest('[data-legacy-message-id], [data-message-id]');
        }
        return { messageId: null, permanentMessageId: null };
    }

    function messageIdFor(body) {
        const ids = identifiersFor(body);
        return ids.messageId || ids.permanentMessageId;
    }

    function referenceFor(body, pageUrl) {
        const page = new URL(pageUrl);
        const ids = identifiersFor(body);
        if (page.origin !== 'https://mail.google.com' || !(ids.messageId || ids.permanentMessageId)) throw failure();
        // Keep the active Gmail account, including Workspace delegated paths.
        const path = page.pathname.match(/^\/mail\/(?:(?:b\/[^/]+\/)?u\/\d+(?:\/d\/[^/]+)?(?:\/|$))?/);
        if (!path) throw failure();
        const account = new URL(path[0].replace(/\/?$/, '/'), page.origin);
        if (page.searchParams.has('authuser')) account.searchParams.set('authuser', page.searchParams.get('authuser'));
        return { ...ids, accountUrl: account.href };
    }

    function originalUrl(reference, view, permanent = false) {
        const url = new URL(reference.accountUrl);
        url.searchParams.set('view', view);
        // This is the individual message ID, never the conversation URL/hash.
        // Gmail's new-style IDs use permmsgid, not a guessed hex conversion.
        url.searchParams.set(permanent ? 'permmsgid' : 'th', permanent ? reference.permanentMessageId : reference.messageId);
        if (view === 'att') {
            url.searchParams.set('attid', '0');
            url.searchParams.set('disp', 'comp');
            url.searchParams.set('safe', '1');
            url.searchParams.set('zw', '');
        }
        return url;
    }

    function isOriginal(bytes) {
        // Inspect headers only; keep the original bytes for the upload (8-bit
        // MIME parts and attachments must not pass through UTF-8 re-encoding).
        const prefix = new TextDecoder().decode(bytes.subarray(0, 256 * 1024));
        const end = prefix.search(/\r?\n\r?\n/);
        if (end < 0) return false;
        const headers = prefix.slice(0, end);
        return /^From:/im.test(headers) && /^(Date|Message-ID|Received):/im.test(headers) &&
            headers.split(/\r?\n/).every((line) => /^[ \t]/.test(line) || /^[!-9;-~]+:/.test(line));
    }

    function encode(bytes) {
        const chunks = [];
        for (let i = 0; i < bytes.length; i += 32768) {
            chunks.push(String.fromCharCode(...bytes.subarray(i, i + 32768)));
        }
        return btoa(chunks.join(''));
    }

    function decode(encoded) {
        if (typeof encoded !== 'string' || !encoded.length) throw failure();
        if (encoded.length > 4 * Math.ceil(MAX_BYTES / 3)) throw failure('too_large');
        let binary;
        try { binary = atob(encoded); } catch { throw failure(); }
        if (binary.length > MAX_BYTES) throw failure('too_large');
        const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
        if (!isOriginal(bytes)) throw failure();
        return bytes;
    }

    async function readBytes(response) {
        if (!response.ok) throw failure();
        if (Number(response.headers.get('content-length')) > MAX_BYTES) throw failure('too_large');
        const reader = response.body.getReader();
        const chunks = [];
        let size = 0;
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                size += value.length;
                if (size > MAX_BYTES) throw failure('too_large');
                chunks.push(value);
            }
        } catch (error) {
            await reader.cancel().catch(() => {});
            throw error;
        } finally {
            reader.releaseLock();
        }
        const bytes = new Uint8Array(size);
        let offset = 0;
        chunks.forEach((chunk) => { bytes.set(chunk, offset); offset += chunk.length; });
        return bytes;
    }

    async function fetchOriginal(reference) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), DOWNLOAD_TIMEOUT_MS);
        const download = async (url) => readBytes(await fetch(url.href, {
            credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
        }));
        try {
            // Gmail's Download message / Download original endpoint returns the
            // RFC 822 bytes, including authentication, routing and MIME parts.
            const methods = [];
            if (reference.permanentMessageId) methods.push(true);
            if (reference.messageId) methods.push(false);
            for (const permanent of methods) {
                try {
                    const bytes = await download(originalUrl(reference, 'att', permanent));
                    if (isOriginal(bytes)) return encode(bytes);
                } catch (error) {
                    if (controller.signal.aborted || error.code === 'too_large') throw error;
                }
            }

            // Some Gmail variants require the download URL (with session
            // parameters) from Show original. Parse only that link; never
            // upload the HTML wrapper or reconstruct mail from a <pre>.
            const pageUrl = originalUrl(reference, 'om', !reference.messageId);
            const pageBytes = await download(pageUrl);
            if (isOriginal(pageBytes)) return encode(pageBytes);
            const doc = new DOMParser().parseFromString(new TextDecoder().decode(pageBytes), 'text/html');
            const account = new URL(reference.accountUrl);
            for (const anchor of doc.querySelectorAll('a[href]')) {
                let url;
                try { url = new URL(anchor.getAttribute('href'), pageUrl); } catch { continue; }
                if (url.origin !== account.origin || url.pathname !== account.pathname ||
                    url.searchParams.get('view') !== 'att' || url.searchParams.get('attid') !== '0' ||
                    !((reference.messageId && url.searchParams.get('th') === reference.messageId) ||
                        (reference.permanentMessageId && url.searchParams.get('permmsgid') === reference.permanentMessageId))) continue;
                if (account.searchParams.has('authuser')) {
                    const authuser = account.searchParams.get('authuser');
                    if (url.searchParams.has('authuser') && url.searchParams.get('authuser') !== authuser) continue;
                    url.searchParams.set('authuser', authuser);
                }
                const bytes = await download(url);
                if (isOriginal(bytes)) return encode(bytes);
            }
            throw failure();
        } catch (error) {
            if (controller.signal.aborted) throw failure('original_timeout');
            throw failure(error.code === 'too_large' ? 'too_large' : 'original_unavailable');
        } finally {
            clearTimeout(timer);
            controller.abort();
        }
    }

    return { messageIdFor, referenceFor, fetchOriginal, encode, decode, isOriginal, MAX_BYTES };
})();
