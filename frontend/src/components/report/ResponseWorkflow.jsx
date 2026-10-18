import React, { useEffect, useState } from 'react';
import { plainSummary } from '../../utils/plainSummary';
import apiClient from '../../api/client';

export default function ResponseWorkflow({ emailId, band, baseline }) {
  const [language, setLanguage] = useState('en');
  const [guidance, setGuidance] = useState([]);
  const [selected, setSelected] = useState('');
  const [workflow, setWorkflow] = useState(null);
  const [related, setRelated] = useState(null);
  const [state, setState] = useState('needs_review');
  const [note, setNote] = useState('');
  const [explanation, setExplanation] = useState('');
  const [error, setError] = useState('');
  const path = `/investigations/${encodeURIComponent(emailId)}`;
  useEffect(() => {
    let active = true;
    Promise.all([apiClient.get('/recovery'), apiClient.get(`${path}/workflow`), apiClient.get(`${path}/related`)])
      .then(([g,w,r]) => { if (active) { setGuidance(g.data); setWorkflow(w.data); setRelated(r.data); } })
      .catch(() => { if (active) setError('Workflow unavailable for this report.'); });
    return () => { active = false; };
  }, [emailId]);
  const chosen = guidance.find(g => g.interaction === selected);
  return <section className="forensic-panel" style={{ padding: 20 }}>
    <label htmlFor="summary-language">Plain-language summary</label><select id="summary-language" value={language} onChange={e => setLanguage(e.target.value)}><option value="en">English</option><option value="es">Español</option><option value="hi">हिन्दी</option></select>
    <p lang={language}>{plainSummary(band, language)}</p><p>Only this fixed summary is translated; technical evidence and verdict IDs stay unchanged. Translations have not had professional language review.</p>
    <p>Baseline context: {(baseline?.matched_domains || []).join(', ') || 'No declared matches'}. This does not change the verdict.</p>
    <h2>Have you already interacted with this email?</h2>
    <label htmlFor="interaction">Choose the closest situation</label>
    <select id="interaction" value={selected} onChange={e => setSelected(e.target.value)}><option value="">Select an interaction</option>{guidance.map(g => <option key={g.interaction} value={g.interaction}>{g.title}</option>)}</select>
    {chosen && <div><p>{chosen.uncertainty}</p><ol>{chosen.steps.map(s => <li key={s}>{s}</li>)}</ol><small>Guidance version {chosen.version}</small></div>}
    <h2>Report review</h2><p>Status: {workflow?.state || 'unavailable'}</p><p>{workflow?.explanation}</p>
    <form onSubmit={async e => { e.preventDefault(); try { const r = await apiClient.patch(`${path}/workflow`, { state, expected_state:workflow.state, note, explanation }); setWorkflow(r.data); setError('Review saved.'); } catch { setError('Review changed or failed. Refresh the report before retrying.'); } }}>
      <label htmlFor="review-state">Next status</label><select id="review-state" value={state} onChange={e => setState(e.target.value)}>{['needs_review','confirmed_malicious','benign_or_spam','unresolved'].map(s => <option key={s}>{s}</option>)}</select>
      <label htmlFor="review-note">Review note</label><textarea id="review-note" maxLength={2000} value={note} onChange={e => setNote(e.target.value)} />
      <label htmlFor="review-explanation">Reporter-facing explanation</label><textarea id="review-explanation" maxLength={1000} value={explanation} onChange={e => setExplanation(e.target.value)} />
      <button disabled={!workflow}>Save review</button>
    </form><p role="status">{error}</p>
    <details><summary>Review history and notes</summary>{(workflow?.notes || []).map((n,i) => <p key={i}>{n.at} · {n.state}: {n.text}</p>)}</details>
    <button onClick={async () => { try { await apiClient.put(`${path}/feedback`, {value:'helpful'}); setError('Feedback saved.'); } catch { setError('Feedback failed.'); } }}>Explanation helpful</button>
    <button onClick={async () => { try { await apiClient.put(`${path}/feedback`, {value:'incorrect'}); setError('Feedback saved.'); } catch { setError('Feedback failed.'); } }}>Explanation incorrect</button>
    <button onClick={async () => { try { await apiClient.put(`${path}/case`,{label:'Investigation review',assignee:'analyst'}); setError('Case marked for review.'); } catch { setError('Assignment failed.'); } }}>Mark as case for review</button>
    <h2>Related submissions</h2><p>{related?.scope}</p><p>First seen: {related?.first_seen || 'unknown'}; last seen: {related?.last_seen || 'unknown'}</p>
    {(related?.matches || []).map(m => <details key={m.email_id}><summary>{m.email_id} · similarity {m.subject_similarity} · {m.basis}</summary><pre style={{whiteSpace:'pre-wrap'}}>{JSON.stringify(m.differences,null,2)}</pre></details>)}
  </section>;
}
