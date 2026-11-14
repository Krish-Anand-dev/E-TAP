// The optional sign-in session lives in this browser only. It is sent to the E-TAP API
// as a Bearer header, never in a URL. Everything works without it.
const TOKEN_KEY = 'etap.loginToken';
const EMAIL_KEY = 'etap.loginEmail';

export function loginToken() {
  try { return window.localStorage.getItem(TOKEN_KEY); } catch { return null; }
}

export function loginEmail() {
  try { return window.localStorage.getItem(EMAIL_KEY); } catch { return null; }
}

export function saveSession(token, email) {
  try {
    if (token) {
      window.localStorage.setItem(TOKEN_KEY, token);
      window.localStorage.setItem(EMAIL_KEY, email || '');
    } else {
      window.localStorage.removeItem(TOKEN_KEY);
      window.localStorage.removeItem(EMAIL_KEY);
    }
    window.dispatchEvent(new Event('etap-login-change'));
  } catch { /* private mode: sign-in lasts for this page only */ }
}

export function authHeaders() {
  const token = loginToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}
