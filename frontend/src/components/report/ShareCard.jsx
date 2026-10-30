import React, { useState } from 'react';
import Icon from '../common/Icon';

export function hasShareCard(data) {
  return Boolean(data?.share_card?.url);
}

export default function ShareCard({ data }) {
  const card = data?.share_card;
  const [broken, setBroken] = useState(false);
  const [copied, setCopied] = useState(false);
  if (!card?.url || broken) return null;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(card.url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* clipboard blocked: the Open link below still works */ }
  };

  return (
    <section id="sec-share" className="report-section">
      <div className="report-section-head">
        <h2>Share card</h2>
        <p>A picture of this result you can send to the person who asked. It shows only the verdict, score and reasons, nothing from the message itself.</p>
      </div>
      <article className="v2-card" style={{ display: 'flex', gap: '16px', alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <img
          src={card.url}
          alt={card.alt}
          width={480}
          height={252}
          loading="lazy"
          onError={() => setBroken(true)}
          style={{ display: 'block', width: '100%', maxWidth: '480px', height: 'auto', aspectRatio: '1200 / 630', border: '1px solid var(--border-hairline)', borderRadius: '8px' }}
        />
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px', minWidth: '220px', flex: 1 }}>
          <span>Made with Cloudinary. {card.key === 'limited' ? 'Some checks could not run, so the card says it is a limited check.' : 'It is created from a template, so nothing about this email is stored for it.'}</span>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <a className="btn-primary-action" href={card.download_url || card.url} download="etap-result.png"><Icon name="download" size={15} /> Download the card</a>
            <button type="button" className="btn-ghost" onClick={copy}>{copied ? 'Link copied' : 'Copy link'}</button>
          </div>
        </div>
      </article>
    </section>
  );
}
