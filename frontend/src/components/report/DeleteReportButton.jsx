import React, { useState } from 'react';
import apiClient from '../../api/client';
import Icon from '../common/Icon';

/** Delete one stored report, after asking. `onDeleted(id)` runs only when the server did it. */
export default function DeleteReportButton({ emailId, onDeleted, className = '' }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  if (!emailId) return null;

  const remove = async () => {
    if (!window.confirm('Delete this report? Its stored data and images are removed. This cannot be undone.')) return;
    setBusy(true);
    setError('');
    try {
      await apiClient.delete(`/investigations/${encodeURIComponent(emailId)}`);
      onDeleted(emailId);
    } catch (err) {
      // Already gone on the server counts as deleted.
      if (err.response?.status === 404) onDeleted(emailId);
      else setError('Could not delete the report. Try again in a moment.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button type="button" className={`delete-report ${className}`} onClick={remove} disabled={busy}>
        <Icon name="trash" size={15} /> {busy ? 'Deleting…' : 'Delete report'}
      </button>
      {error && <p className="delete-report-error" role="alert">{error}</p>}
    </>
  );
}
