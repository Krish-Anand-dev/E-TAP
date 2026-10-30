import React, { useRef, useState } from 'react';
import Icon from '../common/Icon';
import { MAX_ATTACHMENTS, buildMessageFile } from '../../utils/composeMessage';

/**
 * "Paste a message": the other way in, for text that never was an email (an SMS, a WhatsApp
 * message). The text and any files become a message with no headers; the sender and
 * authentication checks are skipped and do not count towards the score.
 */
export default function MessageComposer({ onReady, disabled }) {
  const [text, setText] = useState('');
  const [files, setFiles] = useState([]);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef(null);

  const addFiles = (list) => {
    const picked = Array.from(list || []);
    if (picked.length) setFiles((current) => [...current, ...picked].slice(0, MAX_ATTACHMENTS));
    if (inputRef.current) inputRef.current.value = '';
  };

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const built = await buildMessageFile(text, files);
      if (built.error) setError(built.error);
      else onReady(built.file);
    } catch {
      setError('That message could not be prepared. Try again with smaller files.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="v2-card message-composer" aria-label="Paste a message">
      <div className="message-composer-head">
        <span className="choice-icon"><Icon name="message" size={20} /></span>
        <div>
          <strong>Or paste a message you were sent</strong>
          <p>For a text message, a WhatsApp message or anything else that is not an email file. Paste all of it, links included, and add any attachment separately.</p>
        </div>
      </div>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={6}
        placeholder="Paste the complete message here, including any links."
        aria-label="Message text"
        spellCheck={false}
      />
      <div className="message-composer-files">
        <input ref={inputRef} type="file" multiple style={{ display: 'none' }} onChange={(e) => addFiles(e.target.files)} />
        <button type="button" className="btn-ghost" onClick={() => inputRef.current?.click()} disabled={files.length >= MAX_ATTACHMENTS}>
          <Icon name="paperclip" size={15} /> Add attachments
        </button>
        {files.map((file, i) => (
          <span key={`${file.name}-${i}`} className="message-file-chip">
            <b>{file.name}</b>
            <button type="button" aria-label={`Remove ${file.name}`} onClick={() => setFiles((current) => current.filter((_, j) => j !== i))}>
              <Icon name="x" size={12} />
            </button>
          </span>
        ))}
      </div>
      <p className="choice-note"><Icon name="alert" size={14} />A pasted message has no email headers. The sender and authentication checks are skipped and add nothing to the score, so the score can be lower than the same content would get as an email. Links, QR codes, images and attachments are checked the same way.</p>
      {error && <p className="choice-note" role="alert"><Icon name="alert" size={14} />{error}</p>}
      <div className="message-composer-actions">
        <button type="button" className="btn-primary-action" onClick={submit} disabled={busy || disabled || (!text.trim() && files.length === 0)}>
          {busy ? 'Preparing…' : 'Use this message'}
        </button>
      </div>
    </section>
  );
}
