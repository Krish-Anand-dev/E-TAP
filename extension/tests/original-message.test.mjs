import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const helperSource = readFileSync(new URL('../gmail-original.js', import.meta.url), 'utf8');
const workerSource = readFileSync(new URL('../background.js', import.meta.url), 'utf8');
const contentSource = readFileSync(new URL('../content.js', import.meta.url), 'utf8');
const raw = Buffer.concat([
    Buffer.from('Delivered-To: reader@example.test\r\n' +
        'Received: from relay.example.test by mx.google.com; Sun, 18 Oct 2026 08:00:00 +0000\r\n' +
        'Received: from sender.example.test by relay.example.test; Sun, 18 Oct 2026 07:59:59 +0000\r\n' +
        'Authentication-Results: mx.google.com; spf=pass;\r\n\tdkim=pass; dmarc=pass\r\n' +
        'From: Sender <sender@example.test>\r\nTo: reader@example.test\r\n' +
        'Date: Sun, 18 Oct 2026 08:00:00 +0000\r\nMessage-ID: <original@example.test>\r\n' +
        'Subject: Original message\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n' +
        '--x\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\ncaf'),
    Buffer.from([0xe9]),
    Buffer.from('\r\n--x\r\nContent-Type: application/octet-stream\r\n' +
        'Content-Disposition: attachment; filename=sample.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAP+A\r\n--x--\r\n'),
]);

function context(overrides = {}) {
    const sandbox = vm.createContext({
        URL, TextDecoder, TextEncoder, Uint8Array, Blob, FormData, AbortController, atob, btoa,
        setTimeout, clearTimeout, console, ...overrides,
    });
    vm.runInContext(helperSource, sandbox);
    sandbox.api = vm.runInContext('EtapGmailOriginal', sandbox);
    return sandbox;
}

function bodyWith(attrs) {
    return { closest: () => attrs ? { getAttribute: (key) => attrs[key] || null } : null };
}

function reference(sandbox, attrs = { 'data-legacy-message-id': '19a013bbcac120ab' }) {
    return sandbox.api.referenceFor(bodyWith(attrs), 'https://mail.google.com/mail/u/2/#inbox/DIFFERENT_THREAD_ID');
}

test('selects the individual message ID and preserves the active Gmail account', () => {
    const sandbox = context();
    const ref = reference(sandbox);
    assert.equal(ref.messageId, '19a013bbcac120ab');
    assert.equal(ref.accountUrl, 'https://mail.google.com/mail/u/2/');
    const second = reference(sandbox, { 'data-legacy-message-id': '19a013bbcac120ac' });
    assert.notEqual(ref.messageId, second.messageId);
    assert.throws(() => reference(sandbox, null), { code: 'original_unavailable' });
});

test('keeps modern message IDs intact instead of guessing a legacy ID', () => {
    const sandbox = context();
    const decimal = BigInt('0x19a013bbcac120ab').toString();
    const ref = reference(sandbox, { 'data-message-id': `#msg-f:${decimal}` });
    assert.equal(ref.messageId, null);
    assert.equal(ref.permanentMessageId, `msg-f:${decimal}`);
    assert.throws(() => reference(sandbox, { 'data-message-id': '#thread-f:1234567890' }), { code: 'original_unavailable' });
    assert.throws(() => sandbox.api.referenceFor(bodyWith({ 'data-legacy-message-id': ref.messageId }), 'https://example.test/mail/u/0/'));
});

test('keeps delegated mailbox paths and authuser selection', () => {
    const sandbox = context();
    const body = bodyWith({ 'data-legacy-message-id': '19a013bbcac120ab' });
    assert.equal(sandbox.api.referenceFor(body, 'https://mail.google.com/mail/u/0/d/delegated-mailbox/#inbox').accountUrl,
        'https://mail.google.com/mail/u/0/d/delegated-mailbox/');
    assert.equal(sandbox.api.referenceFor(body, 'https://mail.google.com/mail/?authuser=reader%40example.test#inbox').accountUrl,
        'https://mail.google.com/mail/?authuser=reader%40example.test');
});

test('downloads and passes every original byte, including repeated headers and non-UTF-8 MIME', async () => {
    const calls = [];
    const sandbox = context({ fetch: async (url, options) => {
        calls.push({ url: new URL(url), options });
        return new Response(raw, { headers: { 'content-type': 'message/rfc822' } });
    } });
    const encoded = await sandbox.api.fetchOriginal(reference(sandbox));
    assert.deepEqual(Buffer.from(sandbox.api.decode(encoded)), raw);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url.pathname, '/mail/u/2/');
    assert.equal(calls[0].url.searchParams.get('th'), '19a013bbcac120ab');
    assert.equal(calls[0].url.searchParams.get('view'), 'att');
    assert.equal(calls[0].url.searchParams.get('attid'), '0');
    assert.equal(calls[0].options.credentials, 'same-origin');
    assert.equal(calls[0].options.redirect, 'error');
});

test('uses the Show original download link when Gmail requires session parameters', async () => {
    const urls = [];
    const links = [
        'http://[invalid',
        'https://evil.example/mail/u/2/?view=att&attid=0&th=19a013bbcac120ab',
        '/mail/u/0/?view=att&attid=0&th=19a013bbcac120ab',
        '/mail/u/2/?view=att&attid=0&th=19a013bbcac120ac',
        '/mail/u/2/?view=att&attid=0&th=19a013bbcac120ab&ik=session-value',
    ];
    const sandbox = context({
        DOMParser: class { parseFromString() { return { querySelectorAll: () => links.map((href) => ({ getAttribute: () => href })) }; } },
        fetch: async (url) => {
            urls.push(new URL(url));
            return urls.length < 3 ? new Response('<html>Show original</html>') : new Response(raw);
        },
    });
    assert.deepEqual(Buffer.from(sandbox.api.decode(await sandbox.api.fetchOriginal(reference(sandbox)))), raw);
    assert.equal(urls.length, 3);
    assert.equal(urls[1].searchParams.get('view'), 'om');
    assert.equal(urls[2].searchParams.get('ik'), 'session-value');
    assert.ok(urls.every((url) => url.origin === 'https://mail.google.com' && url.pathname === '/mail/u/2/'));
});

test('rejects sign-in/HTML responses and never promotes page text to original mail', async () => {
    const sandbox = context({
        fetch: async () => new Response('<html>Sign in to continue</html>'),
        DOMParser: class { parseFromString() { return { querySelectorAll: () => [] }; } },
    });
    await assert.rejects(sandbox.api.fetchOriginal(reference(sandbox)), { code: 'original_unavailable' });
    for (const invalid of ['<html>Gmail</html>', 'From: visible@example.test\r\nSubject: Rebuilt\r\n\r\ntext']) {
        assert.throws(() => sandbox.api.decode(Buffer.from(invalid).toString('base64')), { code: 'original_unavailable' });
    }
});

test('rejects oversized downloads before handing them to the service worker', async () => {
    const sandbox = context({ fetch: async () => new Response('small', { headers: { 'content-length': String(26 * 1024 * 1024) } }) });
    await assert.rejects(sandbox.api.fetchOriginal(reference(sandbox)), { code: 'too_large' });
});


const configSource = readFileSync(new URL('../config.js', import.meta.url), 'utf8');
const coreSource = readFileSync(new URL('../analysis-core.js', import.meta.url), 'utf8');
const pageSource = readFileSync(new URL('../analysis.js', import.meta.url), 'utf8');
function withCore(overrides = {}) {
    const sandbox = context(overrides);
    vm.runInContext(configSource, sandbox);
    vm.runInContext(coreSource, sandbox);
    sandbox.analysis = vm.runInContext('EtapAnalysis', sandbox);
    return sandbox;
}

test('modern Gmail retrieval uses permmsgid, including msg-a identifiers', async () => {
    let requested;
    const sandbox = context({ fetch: async (url) => { requested = new URL(url); return new Response(raw); } });
    const ref = reference(sandbox, { 'data-message-id': '#msg-a:r-1234567890123456789' });
    assert.deepEqual(Buffer.from(sandbox.api.decode(await sandbox.api.fetchOriginal(ref))), raw);
    assert.equal(requested.searchParams.get('permmsgid'), 'msg-a:r-1234567890123456789');
    assert.equal(requested.searchParams.has('th'), false);
    assert.equal(requested.searchParams.has('ui'), false);
});

test('full-message handoff uploads original bytes and builds the hosted dossier URL', async () => {
    let uploaded;
    const sandbox = withCore({ fetch: async (url, options) => {
        uploaded = options.body;
        return Response.json({ email_id: 'urn:uuid:synthetic-report' });
    } });
    const report = await sandbox.analysis.submit({ rawEmailBase64: raw.toString('base64') });
    assert.equal(uploaded.get('source'), 'full_message');
    assert.deepEqual(Buffer.from(await uploaded.get('file').arrayBuffer()), raw);
    const url = new URL(sandbox.analysis.reportUrl(report));
    assert.equal(url.origin, 'https://e-tap-lac.vercel.app');
    assert.equal(url.searchParams.get('dossier'), report.email_id);
    assert.equal(url.searchParams.has('body'), false);
});

test('failed retrieval can produce a full report with honest content-only provenance', async () => {
    let uploaded;
    const sandbox = withCore({ fetch: async (url, options) => { uploaded = options.body; return Response.json({ email_id: 'limited-report' }); } });
    const report = await sandbox.analysis.submit({ data: { sender: 'sender@example.test', subject: 'Original unavailable', body: 'Visible content' }, retrievalError: 'original_unavailable' });
    assert.equal(uploaded.get('source'), 'quick_content_check');
    assert.match(await uploaded.get('file').text(), /Visible content/);
    assert.doesNotMatch(await uploaded.get('file').text(), /Authentication-Results:|Received:/);
    assert.equal(new URL(sandbox.analysis.reportUrl(report)).searchParams.get('dossier'), 'limited-report');
});

test('visible-page fields cannot inject forged authentication headers into the fallback', async () => {
    const sandbox = withCore();
    const form = sandbox.analysis.payloadFor({ data: { sender: 'sender@example.test\r\nAuthentication-Results: spf=pass', subject: 'Hello\r\nReceived: fake', body: 'Hello' } });
    const eml = await form.get('file').text();
    assert.doesNotMatch(eml, /^Authentication-Results:|^Received:/m);
    assert.equal(form.get('source'), 'quick_content_check');
});

test('invalid original bytes are never mislabeled full_message', () => {
    const sandbox = withCore();
    assert.throws(() => sandbox.analysis.payloadFor({ rawEmailBase64: btoa('<html>Sign in</html>') }));
});

function worker() {
    let listener;
    let action;
    const jobs = new Map();
    const tabs = [];
    const sandbox = context({
        crypto: { randomUUID: () => 'handoff-123' },
        chrome: {
            runtime: { getURL: (path) => `chrome-extension://test/${path}`, onMessage: { addListener: (fn) => { listener = fn; } } },
            action: { onClicked: { addListener: (fn) => { action = fn; } } },
            tabs: { create: async (options) => { tabs.push(options); return { id: 9 }; }, update: async (id, options) => { tabs.push({ id, ...options }); } },
        },
        EtapHandoffStore: {
            create: async (job) => jobs.set(job.id, structuredClone(job)),
            get: async (id) => structuredClone(jobs.get(id)),
            update: async (id, fn) => { const value = fn(jobs.get(id)); jobs.set(id, value); return value; },
            remove: async (id) => jobs.delete(id),
        },
    });
    vm.runInContext(configSource, sandbox);
    sandbox.importScripts = () => {};
    vm.runInContext(workerSource, sandbox);
    const send = (request, sender = { url: 'https://mail.google.com/mail/u/2/', tab: { id: 2 } }) => new Promise((resolve) => listener(request, sender, resolve));
    return { send, jobs, tabs, action };
}

test('worker opens the handoff tab before original retrieval and never puts mail in the URL', async () => {
    const { send, jobs, tabs } = worker();
    const result = await send({ action: 'startEmailAnalysis', data: { sender: 'sender@example.test', subject: 'Private subject', body: 'Private body' } });
    assert.equal(result.success, true);
    assert.equal(jobs.get(result.jobId).state, 'retrieving');
    assert.equal(jobs.get(result.jobId).analysisTabId, 9);
    assert.equal(tabs[0].url, 'chrome-extension://test/analysis.html?job=handoff-123');
    assert.equal(tabs[0].active, true);
    assert.equal((await send({ action: 'prepareEmailAnalysis', jobId: result.jobId, rawEmailBase64: raw.toString('base64') })).success, true);
    assert.equal(jobs.get(result.jobId).rawEmailBase64, raw.toString('base64'));
});

test('retrieval errors prepare a usable fallback job instead of blocking the report', async () => {
    const { send, jobs } = worker();
    const { jobId } = await send({ action: 'startEmailAnalysis', data: { body: 'Visible body' } });
    await send({ action: 'prepareEmailAnalysis', jobId, retrievalError: 'original_unavailable' });
    assert.equal(jobs.get(jobId).state, 'ready');
    assert.equal(jobs.get(jobId).rawEmailBase64, null);
    assert.equal(jobs.get(jobId).data.body, 'Visible body');
});

test('handoffs are scoped to the originating Gmail tab and the toolbar always opens E-TAP', async () => {
    const { send, tabs, action } = worker();
    assert.equal((await send({ action: 'startEmailAnalysis' }, { url: 'https://evil.example', tab: { id: 3 } })).success, false);
    const { jobId } = await send({ action: 'startEmailAnalysis', data: {} });
    assert.equal((await send({ action: 'prepareEmailAnalysis', jobId }, { url: 'https://mail.google.com/', tab: { id: 3 } })).success, false);
    await action();
    assert.equal(tabs.at(-1).url, 'https://e-tap-lac.vercel.app');
});

class Element {
    constructor() { this.children = []; this.dataset = {}; this.isConnected = true; this.listeners = {}; this.hidden = false; this.files = []; }
    append(...nodes) { this.children.push(...nodes); }
    addEventListener(type, fn) { this.listeners[type] = fn; }
    remove() { this.isConnected = false; }
}
function content(sendMessage) {
    const sandbox = context({
        document: { body: {}, querySelectorAll: () => [], createElement: () => new Element() },
        MutationObserver: class { observe() {} },
        location: { href: 'https://mail.google.com/mail/u/2/' },
        chrome: { runtime: { sendMessage } },
    });
    vm.runInContext(configSource, sandbox);
    vm.runInContext(contentSource, sandbox);
    vm.runInContext('replaceBanner = (container, old, banner) => { rendered = banner; };', sandbox);
    vm.runInContext(`
        extractEmailData = () => ({ messageId: 'message1', subject: 'Hi', body: '', sender: 'sender@example.test' });
        container = { querySelector: () => ({}) };
    `, sandbox);
    return sandbox;
}
function allText(node) { return [node.textContent || '', ...(node.children || []).map(allText)].join(' '); }

test('content click creates a new-tab handoff before downloading original mail', async () => {
    const calls = [];
    const sandbox = content((request, callback) => { calls.push(request); callback({ success: true, jobId: 'job1' }); });
    sandbox.api.referenceFor = () => ({});
    sandbox.api.fetchOriginal = async () => { assert.equal(calls[0].action, 'startEmailAnalysis'); return raw.toString('base64'); };
    await vm.runInContext('runAnalysis(container, null, emailKey(extractEmailData()))', sandbox);
    assert.equal(calls[1].action, 'prepareEmailAnalysis');
    assert.equal(calls[1].rawEmailBase64, raw.toString('base64'));
    assert.match(allText(sandbox.rendered), /Open E-TAP/);
});

test('Gmail extraction failure still leaves an analysis tab and a platform link', async () => {
    const calls = [];
    const sandbox = content((request, callback) => { calls.push(request); callback({ success: true, jobId: 'job1' }); });
    sandbox.api.referenceFor = () => { throw new Error('Unsupported Gmail ID'); };
    await vm.runInContext('runAnalysis(container, null, emailKey(extractEmailData()))', sandbox);
    assert.equal(calls[0].action, 'startEmailAnalysis');
    assert.equal(calls[1].retrievalError, 'original_unavailable');
    assert.match(allText(sandbox.rendered), /Open E-TAP/);
    assert.match(allText(sandbox.rendered), /Open analysis tab/);
});

async function page(job, fetch) {
    const nodes = Object.fromEntries(['heading', 'status', 'coverage', 'retry', 'limited', 'original', 'platform', 'subject'].map((id) => [id, new Element()]));
    let destination;
    const sandbox = withCore({
        fetch,
        URLSearchParams,
        document: { getElementById: (id) => nodes[id] },
        location: { search: '?job=job1', replace: (url) => { destination = url; } },
        window: { addEventListener() {} },
        EtapHandoffStore: {
            get: async () => job,
            update: async (id, mutate) => { job = mutate(job); return job; },
            remove: async () => { job = null; },
        },
    });
    await vm.runInContext(pageSource, sandbox);
    return { nodes, destination, sandbox };
}

test('analysis page redirects to the full report for either original or limited input', async () => {
    for (const rawEmailBase64 of [raw.toString('base64'), null]) {
        const result = await page({ id: 'job1', state: 'ready', rawEmailBase64, data: { body: 'Visible' } }, async () => Response.json({ email_id: 'report1' }));
        assert.equal(new URL(result.destination).searchParams.get('dossier'), 'report1');
        assert.equal(result.nodes.platform.href, 'https://e-tap-lac.vercel.app');
        assert.match(result.nodes.coverage.textContent, rawEmailBase64 ? /original .eml/ : /unavailable/);
    }
});

test('backend errors retain retry, original-file upload, and platform access', async () => {
    const result = await page({ state: 'ready', data: { body: 'Visible' } }, async () => new Response('', { status: 503 }));
    assert.equal(result.destination, undefined);
    assert.equal(result.nodes.retry.hidden, false);
    assert.equal(result.nodes.original.disabled, false);
    assert.equal(result.nodes.platform.href, 'https://e-tap-lac.vercel.app');
    assert.match(result.nodes.status.textContent, /HTTP 503/);
});

test('expired handoffs retain a manual original-file import and platform access', async () => {
    const result = await page(null, () => assert.fail('Expired job must not upload'));
    assert.match(result.nodes.status.textContent, /expired/);
    assert.equal(result.nodes.platform.href, 'https://e-tap-lac.vercel.app');
    assert.notEqual(result.nodes.original.disabled, true);
});

test('deeper analysis sends the flag and sandbox token only with original mail', async () => {
    let request;
    const sandbox = withCore({ fetch: async (url, options) => { request = options; return Response.json({ email_id: 'deep1' }); } });
    await sandbox.analysis.submit({ rawEmailBase64: raw.toString('base64'), deep: true }, undefined, 'ets_token');
    assert.equal(request.body.get('deep_analysis'), '1');
    assert.equal(request.headers['X-ETAP-Sandbox-Token'], 'ets_token');
    await sandbox.analysis.submit({ data: { body: 'Visible' }, deep: true }, undefined, 'ets_token');
    assert.equal(request.body.get('deep_analysis'), null);
    await sandbox.analysis.submit({ rawEmailBase64: raw.toString('base64') }, undefined, 'ets_token');
    assert.equal(request.headers['X-ETAP-Sandbox-Token'], undefined);
});

test('worker records the deeper-analysis choice on the handoff', async () => {
    const { send, jobs } = worker();
    const { jobId } = await send({ action: 'startEmailAnalysis', data: {}, deep: true });
    assert.equal(jobs.get(jobId).deep, true);
    const second = await send({ action: 'startEmailAnalysis', data: {}, deep: 'yes' });
    assert.equal(jobs.get(second.jobId).deep, false);
});

test('Analyze asks standard or deeper first, with the requirement explained', async () => {
    const calls = [];
    const sandbox = content((request, callback) => {
        calls.push(request);
        callback(request.action === 'sandboxStatus'
            ? { success: true, state: { available: true, paired: true, online: true } }
            : { success: true, jobId: 'job1' });
    });
    vm.runInContext('renderChoice(container, null, emailKey(extractEmailData()))', sandbox);
    const text = allText(sandbox.rendered);
    assert.match(text, /Standard analysis/);
    assert.match(text, /Deeper attachment analysis/);
    const info = sandbox.rendered.children[2].children[1].children[1];
    assert.match(info.title, /VirtualBox VM/);
    assert.match(info.title, /Windows Pro/);
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.match(allText(sandbox.rendered), /Your sandbox: online/);
    assert.equal(calls[0].action, 'sandboxStatus');
});
