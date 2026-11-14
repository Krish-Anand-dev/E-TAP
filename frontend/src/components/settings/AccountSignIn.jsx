import React, { useEffect, useState } from 'react';
import Icon from '../common/Icon';
import { checkSession, loginAvailable, requestLoginCode, signOut, verifyLoginCode } from '../../api/auth';
import { loginEmail } from '../../api/session';

// Optional account: sign in with an emailed code to keep a list of your own reports.
// Analysing emails never requires it. The card stays hidden if the server cannot send codes.
export default function AccountSignIn() {
  const [available, setAvailable] = useState(false);
  const [email, setEmail] = useState(loginEmail() || '');
  const [signedIn, setSignedIn] = useState(Boolean(loginEmail()));
  const [step, setStep] = useState('email');
  const [draft, setDraft] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  useEffect(() => {
    loginAvailable().then(setAvailable);
    checkSession().then((who) => { setSignedIn(Boolean(who)); if (who) setEmail(who); });
  }, []);

  if (!available && !signedIn) return null;

  const run = async (task) => {
    setBusy(true); setMessage(null);
    try { await task(); } catch (error) { setMessage({ tone: 'bad', text: error.message }); } finally { setBusy(false); }
  };

  const sendCode = (event) => {
    event.preventDefault();
    run(async () => {
      await requestLoginCode(draft.trim());
      setEmail(draft.trim().toLowerCase());
      setStep('code');
      setMessage({ tone: 'ok', text: 'Code sent. Check your inbox (and spam). It works for 10 minutes.' });
    });
  };

  const confirmCode = (event) => {
    event.preventDefault();
    run(async () => {
      setEmail(await verifyLoginCode(email, code.trim()));
      setSignedIn(true); setStep('email'); setDraft(''); setCode('');
    });
  };

  const leave = () => run(async () => { await signOut(); setSignedIn(false); setEmail(''); });

  return (
    <section className="v2-card account-signin">
      <div className="v2-card-head">
        <div>
          <h3>Your account</h3>
          <p>Optional. Sign in with a code sent to your email to keep a list of the reports you create. Analysing emails never needs it.</p>
        </div>
      </div>
      {signedIn ? (
        <div className="settings-actions">
          <span className="settings-msg ok"><Icon name="check" size={14} /> Signed in as {email}</span>
          <button type="button" className="btn-ghost" onClick={leave} disabled={busy}>Sign out</button>
        </div>
      ) : step === 'email' ? (
        <form className="domain-add" onSubmit={sendCode}>
          <input type="email" value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="you@example.com" aria-label="Your email address" autoComplete="email" required />
          <button type="submit" className="btn-ghost" disabled={busy || !draft.trim()}>Email me a code</button>
        </form>
      ) : (
        <form className="domain-add" onSubmit={confirmCode}>
          <input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="6-digit code" aria-label="Sign-in code" required />
          <button type="submit" className="btn-primary-action" disabled={busy || code.length < 6}>Sign in</button>
          <button type="button" className="btn-ghost" onClick={() => { setStep('email'); setCode(''); setMessage(null); }} disabled={busy}>Use another email</button>
        </form>
      )}
      {message && <p className={`settings-msg ${message.tone}`} role="status">{message.text}</p>}
    </section>
  );
}
