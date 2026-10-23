import apiClient from './client';
import { sandboxRequestHeaders } from './sandbox';

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
    const response = await apiClient.get('/ready', { timeout: 10000 });
    return response.status === 200 && response.data?.status === 'ready';
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

/**
 * Start a background analysis and return { job_id, stages } immediately.
 * Poll getAnalysisJob(job_id) to follow live stage progress.
 */
export async function startAnalysisJob(file, source, { deep = false } = {}) {
  const formData = new FormData();
  formData.append('file', file, file.name);
  if (source) formData.append('source', source);
  // Deeper analysis also opens attachments in the user's paired sandbox.
  if (deep) formData.append('deep_analysis', '1');
  const response = await apiClient.post('/analyze/jobs', formData, {
    headers: { 'Content-Type': 'multipart/form-data', ...(deep ? sandboxRequestHeaders() : {}) },
  });
  return response.data;
}

export async function getAnalysisJob(jobId) {
  const response = await apiClient.get(`/analyze/jobs/${jobId}`, { timeout: 15000 });
  return response.data;
}
