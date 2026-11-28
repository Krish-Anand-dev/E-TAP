import React, { useEffect, useState } from 'react';
import Icon from '../components/common/Icon';
import WhatsAppLogo from '../components/common/WhatsAppLogo';
import WelcomeScene from '../components/welcome/WelcomeScene';
import { loginAvailable, requestLoginCode, verifyLoginCode } from '../api/auth';
import { loginEmail } from '../api/session';
import { getWhatsAppLink } from '../api/whatsappLink';

// The one place on this page to sign in: an emailed code, no password.
function SignInCard({ onSignedIn }) {
  const [available, setAvailable] = useState(true);
  const [step, setStep] = useState('email');
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  useEffect(() => { loginAvailable().then(setAvailable); }, []);

  const run = async (event, task) => {
    event.preventDefault();
    setBusy(true); setMessage(null);
    try { await task(); } catch (error) { setMessage({ tone: 'bad', text: error.message }); } finally { setBusy(false); }
  };
  const send = (event) => run(event, async () => {
    await requestLoginCode(email.trim());
    setStep('code');
    setMessage({ tone: 'ok', text: 'Code sent. Check your inbox and spam. It works for 10 minutes.' });
  });
  const confirm = (event) => run(event, async () => {
    await verifyLoginCode(email.trim().toLowerCase(), code);
    onSignedIn();
  });

  return (
    <section className="welcome-card" aria-label="Sign in">
      <span className="welcome-card-icon"><Icon name="mail" size={22} /></span>
      <h2>Sign in</h2>
      <p>Get a code by email. No password.</p>
      <p className="welcome-tip"><Icon name="alert" size={14} />Keep your reports together under My reports, and link WhatsApp.</p>
      <form className="welcome-card-action" onSubmit={step === 'email' ? send : confirm}>
        {step === 'email' ? (
          <>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" aria-label="Your email address" autoComplete="email" required />
            <button type="submit" className="btn-primary-action" disabled={busy || !email.trim() || !available}>Email me a code</button>
          </>
        ) : (
          <>
            <input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="6-digit code" aria-label="Sign-in code" required autoFocus />
            <button type="submit" className="btn-primary-action" disabled={busy || code.length < 6}>Sign in</button>
            <button type="button" className="welcome-link" onClick={() => { setStep('email'); setCode(''); setMessage(null); }} disabled={busy}>Use another email</button>
          </>
        )}
        {!available && <small className="settings-msg bad" role="status">Sign-in is not available right now. You can continue without it.</small>}
        {message && <small className={`settings-msg ${message.tone}`} role="status">{message.text}</small>}
      </form>
    </section>
  );
}

// In place of the sign-in form for someone who is signed in already.
function SignedInCard({ email }) {
  return (
    <section className="welcome-card" aria-label="Signed in">
      <span className="welcome-card-icon"><Icon name="user" size={22} /></span>
      <h2>You are signed in</h2>
      <p className="welcome-email">{email}</p>
      <p className="welcome-tip"><Icon name="alert" size={14} />Your reports are kept together under My reports.</p>
      <p className="welcome-card-action welcome-later">Nothing else to do here</p>
    </section>
  );
}

// Signed out: information only, so there is no second sign-in button. Signed in: connect from here.
function WhatsAppCard({ signedIn, onConnect }) {
  const [linked, setLinked] = useState(null); // null: not known (yet)

  useEffect(() => {
    if (!signedIn) return undefined;
    let active = true;
    getWhatsAppLink()
      .then((link) => { if (active) setLinked(link.linked); })
      .catch(() => { /* unknown: still offer the settings section */ });
    return () => { active = false; };
  }, [signedIn]);

  return (
    <section className="welcome-card" aria-label="Connect WhatsApp">
      <span className="welcome-card-icon is-whatsapp"><WhatsAppLogo size={44} /></span>
      <h2>Connect WhatsApp</h2>
      <p>Forward a suspicious message and read its report on this site.</p>
      <p className="welcome-tip"><Icon name="alert" size={14} />Approved test numbers only for now. No replies in the chat yet.</p>
      {!signedIn && <p className="welcome-card-action welcome-later">Available once you sign in</p>}
      {signedIn && linked === true && <p className="welcome-card-action welcome-later">Your number is connected</p>}
      {signedIn && linked !== true && (
        <div className="welcome-card-action">
          <button type="button" className="btn-primary-action" onClick={onConnect}>Connect WhatsApp</button>
        </div>
      )}
    </section>
  );
}

export default function WelcomePage({ onDone }) {
  const [email, setEmail] = useState(loginEmail());

  useEffect(() => {
    const sync = () => setEmail(loginEmail());
    window.addEventListener('etap-login-change', sync);
    return () => window.removeEventListener('etap-login-change', sync);
  }, []);

  return (
    <WelcomeScene
      headline={(
        <>
          <h1>Is that message safe?</h1>
          <p>Check an email or message and see why, and what to do next.</p>
          <ul>
            {[['user', 'Sender'], ['paperclip', 'Files'], ['link', 'Links'], ['globe', 'Reputation'], ['check', 'Verdict']].map(([icon, label]) => (
              <li key={label}><Icon name={icon} size={14} />{label}</li>
            ))}
          </ul>
        </>
      )}
      cards={[
        email ? <SignedInCard key="signin" email={email} /> : <SignInCard key="signin" onSignedIn={() => onDone()} />,
        <WhatsAppCard key="whatsapp" signedIn={Boolean(email)} onConnect={() => onDone('whatsapp')} />,
      ]}
      footer={(
        <button type="button" className="welcome-skip" onClick={() => onDone()}>
          {email ? 'Open the dashboard' : 'Continue without signing in'} <Icon name="arrow" size={16} />
        </button>
      )}
    />
  );
}
