// Deeper attachment analysis: pairing with the user's own E-TAP Sandbox Agent.
// The sandbox token from pairing stays in extension storage (never a page or a
// URL) and is sent only to the E-TAP API, in the X-ETAP-Sandbox-Token header.
const EtapSandbox = (() => {
    const KEY = 'etapSandboxToken';
    const api = () => ETAP_CONFIG.apiBaseUrl;

    async function token() {
        const stored = await chrome.storage.local.get(KEY);
        return stored[KEY] || null;
    }
    function headers(value) {
        return value ? { 'X-ETAP-Sandbox-Token': value } : {};
    }
    // { available, paired, online, name, vm_name, last_seen_seconds, queued_jobs }
    async function status() {
        const value = await token();
        try {
            const response = await fetch(`${api()}/sandbox/pairing`, { headers: headers(value) });
            if (!response.ok) return { available: false, paired: false, online: false };
            const body = await response.json();
            // A token the server no longer recognises is useless; forget it.
            if (value && body.available && !body.paired) await chrome.storage.local.remove(KEY);
            return body;
        } catch {
            return { available: false, paired: Boolean(value), online: false, unreachable: true };
        }
    }
    async function pair(code) {
        const response = await fetch(`${api()}/sandbox/pair`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: String(code || '').trim() }),
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok || !body.sandbox_token) {
            throw new Error(body.detail || (response.status === 429 ? 'Too many tries. Wait a minute.' : 'Pairing failed.'));
        }
        await chrome.storage.local.set({ [KEY]: body.sandbox_token });
        return body;
    }
    async function unpair() {
        const value = await token();
        if (value) await fetch(`${api()}/sandbox/pairing`, { method: 'DELETE', headers: headers(value) }).catch(() => {});
        await chrome.storage.local.remove(KEY);
    }
    // online = the agent runs AND reports a usable VM; online with a problem is "needs attention".
    function label(state) {
        if (!state?.paired) return 'Your sandbox: not paired';
        if (!state.online) return 'Your sandbox: offline';
        return state.problem ? 'Your sandbox: needs attention' : 'Your sandbox: online';
    }
    function tone(state) {
        if (!state?.paired) return '';
        if (!state.online) return 'offline';
        return state.problem ? 'attention' : 'online';
    }
    const downloadUrl = () => `${api()}/sandbox/agent/download`;
    return { token, status, pair, unpair, label, tone, downloadUrl };
})();
