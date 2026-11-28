import React, { useEffect, useState } from 'react';
import AccountSignIn from '../components/settings/AccountSignIn';
import WhatsAppLink from '../components/settings/WhatsAppLink';
import WhatsAppLogo from '../components/common/WhatsAppLogo';
import { loginAvailable } from '../api/auth';
import { loginEmail } from '../api/session';

// Sign-in and the WhatsApp number that belongs to the account. Both are optional.
export default function AccountPage() {
  const [signedIn, setSignedIn] = useState(Boolean(loginEmail()));
  const [available, setAvailable] = useState(null); // null: still asking

  useEffect(() => {
    const sync = () => setSignedIn(Boolean(loginEmail()));
    window.addEventListener('etap-login-change', sync);
    loginAvailable().then(setAvailable);
    return () => window.removeEventListener('etap-login-change', sync);
  }, []);

  return (
    <div className="v2-page account-page">
      <div className="v2-section-head"><div>
        <h1 className="page-title">{signedIn ? 'Your account' : 'Sign in'}</h1>
        <p className="page-sub">Optional. Keep your reports together and link WhatsApp. Checking a message never needs an account.</p>
      </div></div>
      {available === false && !signedIn && <p className="settings-msg bad" role="status">Sign-in is not available right now. Try again in a moment.</p>}
      <AccountSignIn />
      {signedIn ? <WhatsAppLink /> : (
        <section className="v2-card account-signin whatsapp-later">
          <WhatsAppLogo size={36} />
          <div><h3>WhatsApp</h3><p>Sign in first, then link your number here.</p></div>
        </section>
      )}
    </div>
  );
}
