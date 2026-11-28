import React, { useEffect, useState } from 'react';
import Icon from './Icon';
import { getWhatsAppLink } from '../../api/whatsappLink';
import { loginEmail } from '../../api/session';
import { dismissWhatsAppNotice, scrollWhenReady, shouldShowWhatsAppNotice } from '../../utils/welcome';

/** On the dashboard: offer to link WhatsApp. Never shown once a number is linked. */
export default function WhatsAppNotice({ navigate }) {
  const [email, setEmail] = useState(loginEmail());
  const [show, setShow] = useState(false);

  useEffect(() => {
    const sync = () => setEmail(loginEmail());
    window.addEventListener('etap-login-change', sync);
    return () => window.removeEventListener('etap-login-change', sync);
  }, []);

  useEffect(() => {
    let active = true;
    setShow(false);
    if (!email) return undefined;
    getWhatsAppLink()
      .then((link) => { if (active) setShow(shouldShowWhatsAppNotice({ email, link })); })
      .catch(() => { /* unknown is not "not linked": say nothing */ });
    return () => { active = false; };
  }, [email]);

  if (!show) return null;
  const connect = () => { navigate('settings'); scrollWhenReady('whatsapp-link'); };
  const close = () => { dismissWhatsAppNotice(email); setShow(false); };

  return (
    <div className="whatsapp-notice" role="status">
      <Icon name="message" size={18} />
      <span>You can also check messages through WhatsApp.</span>
      <button type="button" className="notice-connect" onClick={connect}>Connect</button>
      <button type="button" className="icon-button" onClick={close} aria-label="Close this notice"><Icon name="x" size={15} /></button>
    </div>
  );
}
