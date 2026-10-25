import React, { useState } from 'react';
import apiClient from '../../api/client';

export default function TrustControls({ data, onDeleted }) {
  const [days, setDays] = useState(data.retention?.days || 30);
  const [message, setMessage] = useState('');
  async function run(action) {
    try { await action(); } catch { setMessage('Request failed. Check access and connection.'); }
  }
  return <section className="forensic-panel" aria-label="Retention and sharing" style={{ padding: 20 }}>
    <h2>Retention and sharing</h2>
    <p>Hosted analysis processes the uploaded artifact. The Privacy panel below describes storage and external provider flows. Deletion cannot recall data already sent to providers or downloaded exports.</p>
    <label htmlFor="retention-days">Retention for future reports (days)</label>
    <input id="retention-days" type="number" min="1" max="365" value={days} onChange={e => setDays(Number(e.target.value))} />
    <button onClick={() => run(async () => { await apiClient.put('/preferences', { retention_days: days }); setMessage('Retention saved for future analyses.'); })}>Save retention</button>
    <button onClick={() => run(async () => {
      const { data: pack } = await apiClient.get(`/investigations/${encodeURIComponent(data.email_id)}/share`);
      const url = URL.createObjectURL(new Blob([JSON.stringify(pack, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a'); a.href = url; a.download = 'etap-share-pack.json'; a.click(); URL.revokeObjectURL(url);
      setMessage('Redacted pack exported. URLs, domains, addresses and free-form text are omitted.');
    })}>Export redacted share pack</button>
    <button onClick={() => run(async () => { if (!window.confirm('Delete this stored investigation and its search data?')) return; await apiClient.delete(`/investigations/${encodeURIComponent(data.email_id)}`); sessionStorage.removeItem('E-TAP_investigations_history_v1'); onDeleted(); })}>Delete investigation</button>
    <button onClick={() => run(async () => { if (!window.confirm('Delete ALL stored investigations? This cannot be undone.')) return; await apiClient.delete('/investigations'); sessionStorage.removeItem('E-TAP_investigations_history_v1'); onDeleted(); })}>Delete all investigations</button>
    <p role="status">{message}</p>
  </section>;
}
