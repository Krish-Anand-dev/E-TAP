import React, { useState } from 'react';
import apiClient from '../../api/client';

export default function AuthGate({ children }) {
  const [authenticated, setAuthenticated] = useState(false);
  const [key, setKey] = useState('');
  const [error, setError] = useState('');
  async function login(event) {
    event.preventDefault();
    sessionStorage.clear();
    localStorage.removeItem('E-TAP_investigations_history_v1');
    sessionStorage.setItem('etap_api_key', key.trim());
    try { await apiClient.get('/me'); setAuthenticated(true); setKey(''); }
    catch { sessionStorage.clear(); setError('Authentication failed. Check your API key and backend connection.'); }
  }
  if (authenticated) return <><button onClick={() => { sessionStorage.clear(); window.location.reload(); }}>Sign out and clear this session</button>{children}</>;
  return <main style={{ maxWidth: 560, margin: '10vh auto', padding: 24 }}>
    <h1>E-TAP investigation access</h1>
    <p>Enter the personal API key issued by your administrator. This browser tab retains the key until you sign out or close it.</p>
    <form onSubmit={login}><label htmlFor="access-key">Personal API key</label>
      <input id="access-key" type="password" autoComplete="off" value={key} onChange={e => setKey(e.target.value)} required />
      <button type="submit">Sign in</button></form><p role="alert">{error}</p>
  </main>;
}
