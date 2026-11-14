import apiClient from './client';
import { loginToken, saveSession } from './session';

const detail = (error, fallback) => error.response?.data?.detail || fallback;

/** True when the server can send sign-in codes. When false the sign-in card stays hidden. */
export async function loginAvailable() {
  try {
    const response = await apiClient.get('/auth/status', { timeout: 15000 });
    return Boolean(response.data.enabled);
  } catch {
    return false;
  }
}

export async function requestLoginCode(email) {
  try {
    await apiClient.post('/auth/request-code', { email });
  } catch (error) {
    throw new Error(detail(error, 'Could not send the code. Try again in a moment.'));
  }
}

export async function verifyLoginCode(email, code) {
  try {
    const response = await apiClient.post('/auth/verify-code', { email, code });
    saveSession(response.data.token, response.data.email);
    return response.data.email;
  } catch (error) {
    throw new Error(detail(error, 'That code did not work. Try again.'));
  }
}

/** Drop a session the server no longer knows (expired or signed out elsewhere). */
export async function checkSession() {
  if (!loginToken()) return null;
  try {
    const response = await apiClient.get('/auth/me', { timeout: 15000 });
    return response.data.email;
  } catch (error) {
    if (error.response?.status === 401) saveSession(null);
    return null;
  }
}

export async function signOut() {
  try { await apiClient.post('/auth/logout', null, { timeout: 15000 }); } finally { saveSession(null); }
}
