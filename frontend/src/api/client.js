import axios from 'axios';
import { authHeaders } from './session';

// API base URL: defaults to empty string to use Vite's proxy in dev,
// or import.meta.env.VITE_API_BASE_URL if configured directly (e.g. http://127.0.0.1:5000).
const baseURL = import.meta.env.VITE_API_BASE_URL || '';

export const apiClient = axios.create({
  baseURL,
  timeout: 120000, // 2 minutes for deep AI extraction & threat intel queries
});

// When signed in, every call carries the session so new reports are filed under the account.
// Signed-out use sends nothing extra.
apiClient.interceptors.request.use((config) => {
  const headers = authHeaders();
  if (headers.Authorization && !config.headers?.Authorization) config.headers.set('Authorization', headers.Authorization);
  return config;
});

export const askSocAssistant = async (question, emailId = null, emailContext = null) => {
  const payload = { question };
  if (emailId) payload.email_id = emailId;
  // Only server-owned records may supply chat context.
  const response = await apiClient.post('/chat', payload);
  return response.data;
};

export default apiClient;
