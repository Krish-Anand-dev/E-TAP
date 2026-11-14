import React, { useState } from 'react';

export function hasImageEvidence(attachments = []) {
  return attachments.some((att) => att?.cloudinary?.preview_url);
}

function EvidenceImage({ att }) {
  const [shown, setShown] = useState(false);
  const c = att.cloudinary;
  const qr = att.qr_urls || [];
  return (
    <article className="v2-card image-evidence-card" style={{ display: 'flex', gap: '16px', alignItems: 'flex-start', flexWrap: 'wrap' }}>
      <button
        type="button"
        onClick={() => setShown((v) => !v)}
        title={shown ? 'Hide the image' : 'Click to show the image'}
        style={{ padding: 0, border: '1px solid var(--border-hairline)', borderRadius: '8px', overflow: 'hidden', cursor: 'pointer', background: 'none', lineHeight: 0 }}
      >
        <img
          src={shown ? c.preview_url : c.blurred_url}
          alt={shown ? `Image attachment ${att.filename}` : 'Blurred image attachment'}
          width={240}
          height={160}
          loading="lazy"
          style={{ display: 'block', width: '240px', height: '160px', objectFit: 'cover' }}
        />
      </button>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '13px', minWidth: '220px', flex: 1 }}>
        <strong>{att.filename}</strong>
        <span>{shown ? 'Showing the image. Click it to hide it again.' : 'Blurred for your safety. Click the image to show it.'}</span>
        {qr.length > 0 && <span><b>Hidden QR code</b> pointing to <span className="mono-val">{qr[0]}</span>{qr.length > 1 ? ` and ${qr.length - 1} more` : ''}</span>}
        {att.ocr_text && <span><b>Text read from the image:</b> {att.ocr_text.length > 140 ? `${att.ocr_text.slice(0, 140)}...` : att.ocr_text}</span>}
        {c.moderation?.status && (
          <span>Cloudinary moderation: {c.moderation.status}{c.moderation.labels?.length > 0 && ` (${c.moderation.labels.join(', ')})`}</span>
        )}
        {c.width && c.height && <span>{c.width} x {c.height} px{c.format ? `, ${c.format.toUpperCase()}` : ''}</span>}
        <a href={c.url} target="_blank" rel="noopener noreferrer">Open the full image</a>
      </div>
    </article>
  );
}

export default function ImageEvidence({ attachments = [] }) {
  const images = attachments.filter((att) => att?.cloudinary?.preview_url);
  if (images.length === 0) return null;
  return (
    <section id="sec-images" className="report-section">
      <div className="report-section-head">
        <h2>Image evidence</h2>
        <p>Images found in this email, saved with Cloudinary. They stay blurred until you click one, and they are deleted when this report is deleted.</p>
      </div>
      <div style={{ display: 'grid', gap: '12px' }}>
        {images.map((att, i) => <EvidenceImage key={`${att.sha256 || att.filename}-${i}`} att={att} />)}
      </div>
    </section>
  );
}
