import React, { useCallback, useEffect, useState } from 'react';
import Icon from '../common/Icon';
import { getWhatsAppLink, newWhatsAppLinkCode, unlinkWhatsApp } from '../../api/whatsappLink';
import { loginEmail } from '../../api/session';

// Send a one-time code to link your number to the account. Future reports appear under My reports.
export default function WhatsAppLink() {
  const [signedIn, setSignedIn] = useState(Boolean(loginEmail()));
  const [state, setState] = useState(null);
  const [issued, setIssued] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  useEffect(() => {
    const sync = () => setSignedIn(Boolean(loginEmail()));
    window.addEventListener('etap-login-change', sync);
    return () => window.removeEventListener('etap-login-change', sync);
  }, []);

  const refresh = useCallback(async () => {
    try { setState(await getWhatsAppLink()); } catch (error) { setMessage({ tone: 'bad', text: error.message }); }
  }, []);

  useEffect(() => {
    if (!signedIn) { setState(null); setIssued(null); return; }
    refresh();
  }, [signedIn, refresh]);

  if (!signedIn) return null;

  const run = async (task) => {
    setBusy(true); setMessage(null);
    try { await task(); } catch (error) { setMessage({ tone: 'bad', text: error.message }); } finally { setBusy(false); }
  };

  const getCode = () => run(async () => { setIssued(await newWhatsAppLinkCode()); });
  const checkNow = () => run(async () => {
    const next = await getWhatsAppLink();
    setState(next);
    if (next.linked) setIssued(null);
    else setMessage({ tone: 'bad', text: 'Not linked yet. Send the code to the bot on WhatsApp, then check again.' });
  });
  const unlink = () => run(async () => { await unlinkWhatsApp(); setIssued(null); await refresh(); });

  const bot = issued?.bot_number || state?.bot_number;

  return (
    <section className="v2-card account-signin">
      <div className="v2-card-head">
        <div>
          <h3>WhatsApp</h3>
          <p>Optional. Link your WhatsApp number, then forward a suspicious message or file to the E-TAP bot. The full analysis appears under <b>My reports</b>.</p>
        </div>
      </div>
      {state?.linked ? (
        <div className="settings-actions">
          <span className="settings-msg ok"><Icon name="check" size={14} /> A WhatsApp number is linked to this account</span>
          <button type="button" className="btn-ghost" onClick={unlink} disabled={busy}>Unlink</button>
        </div>
      ) : issued ? (
        <div>
          <ol className="settings-steps">
            <li>Open WhatsApp on the phone you want to link{bot ? <> and start a chat with <b>{bot}</b></> : ' and open the E-TAP bot chat'}.</li>
            <li>Send exactly this message: <b className="mono">{issued.code}</b></li>
            <li>Come back here and press <b>Check now</b>. The code works for {issued.expires_in_minutes} minutes.</li>
          </ol>
          <div className="settings-actions">
            <button type="button" className="btn-primary-action" onClick={checkNow} disabled={busy}>Check now</button>
            <button type="button" className="btn-ghost" onClick={getCode} disabled={busy}>New code</button>
          </div>
        </div>
      ) : (
        <div className="settings-actions">
          <button type="button" className="btn-ghost" onClick={getCode} disabled={busy || !state}>Link my WhatsApp</button>
        </div>
      )}
      {message && <p className={`settings-msg ${message.tone}`} role="status">{message.text}</p>}
    </section>
  );
}
