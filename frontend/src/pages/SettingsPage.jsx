import React, { useEffect, useState } from 'react';
import apiClient from '../api/client';
import Icon from '../components/common/Icon';
import SandboxPairing from '../components/settings/SandboxPairing';

const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

function cleanDomain(raw) {
  let d = String(raw || '').trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '').replace(/^[^@]*@/, '').split(/[/?#:]/)[0].replace(/^www\./, '').replace(/\.$/, '');
  return d;
}

export default function SettingsPage() {
  const [domains, setDomains] = useState([]);
  const [saved, setSaved] = useState([]);
  const [draft, setDraft] = useState('');
  const [retention, setRetention] = useState(30);
  const [savedRetention, setSavedRetention] = useState(30);
  const [message, setMessage] = useState(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    Promise.all([apiClient.get('/baselines'), apiClient.get('/preferences')])
      .then(([b, p]) => {
        setDomains(b.data.domains || []); setSaved(b.data.domains || []);
        setRetention(p.data.retention_days || 30); setSavedRetention(p.data.retention_days || 30);
      })
      .catch(() => setMessage({ tone: 'bad', text: 'Preferences could not be loaded. Check that the analysis engine is online.' }))
      .finally(() => setLoaded(true));
  }, []);

  const add = () => {
    const parts = draft.split(/[\s,;]+/).map(cleanDomain).filter(Boolean);
    const bad = parts.filter((d) => !DOMAIN_RE.test(d));
    if (bad.length) { setMessage({ tone: 'bad', text: `Not a valid domain: ${bad.join(', ')}` }); return; }
    setDomains((prev) => [...new Set([...prev, ...parts])].sort());
    setDraft('');
    setMessage(null);
  };

  const save = async () => {
    try {
      const [b] = await Promise.all([
        apiClient.put('/baselines', { domains }),
        retention !== savedRetention ? apiClient.put('/preferences', { retention_days: Number(retention) }) : Promise.resolve(null),
      ]);
      setSaved(b.data.domains || domains);
      setSavedRetention(retention);
      setMessage({ tone: 'ok', text: 'Saved. These settings apply to emails you analyse from now on.' });
    } catch {
      setMessage({ tone: 'bad', text: 'Could not save. Use plain domain names such as vendor.com.' });
    }
  };

  const dirty = JSON.stringify(domains) !== JSON.stringify(saved) || retention !== savedRetention;

  return (
    <div className="v2-page settings-page">
      <div className="v2-section-head"><div><h1 className="page-title">Trusted domains</h1><p className="page-sub">Tell E-TAP which senders you know, so genuine mail from them is not over-flagged.</p></div></div>

      <div className="settings-grid">
        <section className="v2-card">
          <div className="v2-card-head"><div><h3>Your trusted sender domains</h3><p>{domains.length} domain{domains.length === 1 ? '' : 's'} · subdomains are included (mail.vendor.com counts as vendor.com)</p></div></div>
          <form className="domain-add" onSubmit={(e) => { e.preventDefault(); add(); }}>
            <input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="e.g. yourbank.com, payroll-provider.com" aria-label="Domain to trust" disabled={!loaded} />
            <button type="submit" className="btn-ghost" disabled={!draft.trim()}><Icon name="plus" size={16} />Add</button>
          </form>
          {domains.length ? (
            <ul className="domain-chips">
              {domains.map((d) => (
                <li key={d}><Icon name="globe" size={14} />{d}<button type="button" aria-label={`Remove ${d}`} onClick={() => setDomains(domains.filter((x) => x !== d))}><Icon name="x" size={14} /></button></li>
              ))}
            </ul>
          ) : <p className="v2-empty-line">No trusted domains yet.</p>}

          <div className="settings-row">
            <label htmlFor="retention">Keep reports for</label>
            <select id="retention" value={retention} onChange={(e) => setRetention(Number(e.target.value))}>
              {[7, 14, 30, 90, 180, 365].map((d) => <option key={d} value={d}>{d} days</option>)}
            </select>
          </div>

          <div className="settings-actions">
            <button type="button" className="btn-primary-action" onClick={save} disabled={!dirty}>Save changes</button>
            {message && <span className={`settings-msg ${message.tone}`} role="status">{message.text}</span>}
          </div>
        </section>

        <section className="v2-card how-trust">
          <h3>How trust works</h3>
          <p>Attackers often pretend to be exactly the companies you trust, so E-TAP never trusts a name alone.</p>
          <ol>
            <li><Icon name="check" size={16} /><span>The sender's domain is on your list,</span></li>
            <li><Icon name="check" size={16} /><span>it passes <b>SPF</b>, <b>DKIM</b> and <b>DMARC</b> (proof it really came from them),</span></li>
            <li><Icon name="check" size={16} /><span>and there are no lookalike-domain, attachment or reputation warnings.</span></li>
          </ol>
          <p className="trust-result ok"><Icon name="shield" size={16} />Then the risk score is lowered by 25 points and the report shows <b>Verified trusted sender</b>.</p>
          <p className="trust-result warn"><Icon name="alert" size={16} />If any check fails, nothing is lowered and the report warns of a possible impersonation.</p>
        </section>
      </div>
      <SandboxPairing />
    </div>
  );
}
