import React, { useEffect, useState } from 'react';
import Icon from './Icon';
import WhatsAppLogo from './WhatsAppLogo';
import { getWhatsAppLink } from '../../api/whatsappLink';
import { loginEmail } from '../../api/session';
import { dismissWhatsAppNotice, shouldShowWhatsAppNotice } from '../../utils/welcome';

/**
 * On the dashboard, drawn like a WhatsApp message: offer to link WhatsApp. Shown to
 * visitors who are not signed in and to accounts without a number; never once linked.
 */
export default function WhatsAppNotice({ navigate }) {
  const [email, setEmail] = useState(loginEmail());
  const [show, setShow] = useState(false);
  const [time] = useState(() => new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }));

  useEffect(() => {
    const sync = () => setEmail(loginEmail());
    window.addEventListener('etap-login-change', sync);
    return () => window.removeEventListener('etap-login-change', sync);
  }, []);

  useEffect(() => {
    let active = true;
    if (!email) {
      setShow(shouldShowWhatsAppNotice({ email }));
      return undefined;
    }
    setShow(false);
    getWhatsAppLink()
      .then((link) => { if (active) setShow(shouldShowWhatsAppNotice({ email, link })); })
      .catch(() => { /* unknown is not "not linked": say nothing */ });
    return () => { active = false; };
  }, [email]);

  if (!show) return null;
  // Linking belongs to an account, so a visitor is taken to sign-in first.
  const connect = () => navigate('account');
  const close = () => { dismissWhatsAppNotice(email); setShow(false); };

  return (
    <aside className="wa-notice" aria-label="Check messages through WhatsApp">
      <span className="wa-avatar"><WhatsAppLogo size={40} /></span>
      <div className="wa-bubble">
        <button type="button" className="wa-close" onClick={close} aria-label="Close this notice"><Icon name="x" size={14} /></button>
        <strong>E-TAP on WhatsApp</strong>
        <p>Got something suspicious? You can also check messages through WhatsApp.</p>
        <button type="button" className="wa-connect" onClick={connect}>{email ? 'Connect WhatsApp' : 'Sign in to connect'}</button>
        <span className="wa-time">{time}
          <svg viewBox="0 0 18 11" width="17" height="11" aria-hidden="true"><path d="M1 6l3.2 3.2L11 2M7.4 8.4l.8.8L15.5 2" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
        </span>
      </div>
    </aside>
  );
}
