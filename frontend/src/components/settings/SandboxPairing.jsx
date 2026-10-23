import React, { useEffect, useState } from 'react';
import Icon from '../common/Icon';
import { agentDownloadUrl, getSandboxPairing, pairSandbox, sandboxStateLabel, unpairSandbox } from '../../api/sandbox';

/** Settings card: pair this browser with the user's E-TAP Sandbox Agent (once). */
export default function SandboxPairing() {
  const [state, setState] = useState(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  const refresh = () => getSandboxPairing().then(setState).catch(() => setState({ available: false, unreachable: true }));
  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 15000);
    return () => clearInterval(timer);
  }, []);

  if (!state) return null;
  if (!state.available) {
    return (
      <section className="v2-card sandbox-pairing">
        <h3>Deeper attachment analysis</h3>
        <p className="v2-empty-line">{state.unreachable ? 'The analysis engine could not be reached.' : 'This E-TAP server does not offer deeper attachment analysis.'}</p>
      </section>
    );
  }

  const pair = async (event) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await pairSandbox(code);
      setCode('');
      setMessage({ tone: 'ok', text: 'Paired. Deeper attachment analysis is now available on the Analyze page.' });
      await refresh();
    } catch (error) {
      setMessage({ tone: 'bad', text: error.message });
    } finally {
      setBusy(false);
    }
  };
  const unpair = async () => {
    setBusy(true);
    try { await unpairSandbox(); await refresh(); setMessage({ tone: 'ok', text: 'This browser is no longer paired.' }); } finally { setBusy(false); }
  };
  const tone = state.paired ? (state.online ? 'online' : 'offline') : '';

  return (
    <section className="v2-card sandbox-pairing">
      <div className="v2-card-head">
        <div><h3>Deeper attachment analysis</h3><p>Open attachments inside a virtual machine you own and see what they do.</p></div>
        <span className={`sandbox-pill ${tone}`}><Icon name="box" size={14} />{sandboxStateLabel(state)}</span>
      </div>
      {state.paired ? (
        <div className="sandbox-paired">
          <p>
            Paired with <b>{state.name || 'your sandbox'}</b>{state.vm_name ? <> (VM <b>{state.vm_name}</b>)</> : null}.
            {' '}{state.online ? 'It is ready for deeper analyses.' : 'Start the E-TAP Sandbox Agent on that PC to bring it online; queued attachments wait for it.'}
            {state.queued_jobs ? <> {state.queued_jobs} waiting.</> : null}
          </p>
          <button type="button" className="btn-ghost" onClick={unpair} disabled={busy}>Unpair this browser</button>
        </div>
      ) : (
        <>
          <ol className="pair-steps">
            <li><span>1</span><div><a href={agentDownloadUrl()} target="_blank" rel="noopener noreferrer">Download the E-TAP Sandbox Agent</a> and unzip it on the PC that has your VirtualBox VM.</div></li>
            <li><span>2</span><div>Double-click <b>start-agent.cmd</b>. It checks your computer, asks before each step and shows a pairing code.</div></li>
            <li><span>3</span><div>Enter the code below. You only do this once.</div></li>
          </ol>
          <form className="domain-add pair-form" onSubmit={pair}>
            <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="ABCD-1234" aria-label="Pairing code" maxLength={12} spellCheck={false} autoComplete="off" />
            <button type="submit" className="btn-primary-action" disabled={busy || code.replace(/[^a-z0-9]/gi, '').length !== 8}>Pair</button>
          </form>
          <p className="pair-req"><Icon name="alert" size={14} />Requires a VirtualBox VM with Sysmon and a clean snapshot. Windows Sandbox (Windows Pro) support is planned.</p>
        </>
      )}
      {message && <p className={`settings-msg ${message.tone}`} role="status">{message.text}</p>}
    </section>
  );
}
