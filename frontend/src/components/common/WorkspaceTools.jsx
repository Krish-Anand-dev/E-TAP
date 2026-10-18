import React, { useState } from 'react';
import apiClient from '../../api/client';

export default function WorkspaceTools() {
  const [stats, setStats] = useState(null);
  const [domains, setDomains] = useState('');
  const [message, setMessage] = useState('');
  return <details style={{padding:20}}><summary>My workspace: analytics and baseline context</summary>
    <button onClick={async () => { try { const [a,b] = await Promise.all([apiClient.get('/analytics'),apiClient.get('/baselines')]); setStats(a.data); setDomains(b.data.domains.join('\n')); } catch { setMessage('Workspace data unavailable.'); } }}>Load measured workspace data</button>
    {stats && <div><p>{stats.scope}</p><p>Investigations: {stats.investigations}. Mean analysis latency: {stats.mean_latency_ms ?? 'not measured'} ms ({stats.latency_samples} samples). Mean time to triage: {stats.mean_time_to_triage_seconds ?? 'not measured'} seconds ({stats.triage_samples} samples).</p>
      <details><summary>Outcomes, provider statuses, campaigns, indicators and feedback</summary><pre style={{whiteSpace:'pre-wrap'}}>{JSON.stringify(stats,null,2)}</pre></details></div>}
    <label htmlFor="baseline-domains">Expected vendor domains (one per line)</label><textarea id="baseline-domains" value={domains} onChange={e => setDomains(e.target.value)} />
    <p>User-declared context only. Matching a baseline does not override malicious evidence.</p>
    <button onClick={async () => { try { await apiClient.put('/baselines',{domains:domains.split('\n').map(x => x.trim()).filter(Boolean)}); setMessage('Baseline context saved for future analyses.'); } catch { setMessage('Use valid bare domains; the request was not saved.'); } }}>Save baseline context</button><p role="status">{message}</p>
  </details>;
}
