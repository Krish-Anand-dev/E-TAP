import apiClient from './client';

/**
 * Upload an .eml or .msg file to the backend for forensic analysis.
 * @param {File} file - Suspicious email file object (.eml or .msg)
 * @param {Function} [onUploadProgress] - Optional upload progress callback
 * @returns {Promise<Object>} Full analysis JSON report
 */
export async function analyzeEmailFile(file, onUploadProgress) {
  const formData = new FormData();
  formData.append('file', file, file.name);

  const response = await apiClient.post('/analyze', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress,
  });

  return response.data;
}

/**
 * Ping backend health endpoint to check connection status.
 * @returns {Promise<boolean>}
 */
export async function checkBackendHealth() {
  try {
    const response = await apiClient.get('/health', { timeout: 15000 });
    return response.status === 200 && response.data?.status === 'ok';
  } catch {
    return false;
  }
}

/**
 * Fetch a specific full investigation report by its email ID.
 * @param {string} id - The email_id to fetch
 * @returns {Promise<Object>} Full analysis JSON report
 */
export async function fetchInvestigation(id) {
  const response = await apiClient.get(`/investigations/${id}`);
  return response.data;
}
