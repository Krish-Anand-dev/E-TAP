import apiClient from './client';

// The sandbox token from pairing stays in this browser only. It is sent to
// the E-TAP API in X-ETAP-Sandbox-Token, never in a URL.
const KEY = 'etap.sandboxToken';

export function sandboxToken() {
  try { return window.localStorage.getItem(KEY); } catch { return null; }
}
function saveToken(value) {
  try {
    if (value) window.localStorage.setItem(KEY, value);
    else window.localStorage.removeItem(KEY);
  } catch { /* private mode: pairing lasts for this page only */ }
}
const headers = () => {
  const token = sandboxToken();
  return token ? { 'X-ETAP-Sandbox-Token': token } : {};
};

/** { available, paired, online, name, vm_name, last_seen_seconds, queued_jobs } */
export async function getSandboxPairing() {
  const response = await apiClient.get('/sandbox/pairing', { headers: headers(), timeout: 15000 });
  if (response.data.available && !response.data.paired && sandboxToken()) saveToken(null);
  return response.data;
}

export async function pairSandbox(code) {
  try {
    const response = await apiClient.post('/sandbox/pair', { code });
    saveToken(response.data.sandbox_token);
    return response.data;
  } catch (error) {
    throw new Error(error.response?.data?.detail || 'Pairing failed. Check the code and try again.');
  }
}

export async function unpairSandbox() {
  try { await apiClient.delete('/sandbox/pairing', { headers: headers() }); } finally { saveToken(null); }
}

export function agentDownloadUrl() {
  return `${apiClient.defaults.baseURL || ''}/sandbox/agent/download`;
}

export function sandboxRequestHeaders() {
  return headers();
}

/** online = the agent runs AND reports a usable VM; online with a problem is "needs attention". */
export function sandboxStateLabel(state) {
  if (!state?.paired) return 'Your sandbox: not paired';
  if (!state.online) return 'Your sandbox: offline';
  return state.problem ? 'Your sandbox: needs attention' : 'Your sandbox: online';
}

/** CSS tone for the status pill: '' | 'online' | 'attention' | 'offline'. */
export function sandboxStateTone(state) {
  if (!state?.paired) return '';
  if (!state.online) return 'offline';
  return state.problem ? 'attention' : 'online';
}
