import React, { useEffect } from 'react';
import { createPortal } from 'react-dom';

/**
 * PdfPreviewModal
 *
 * Displays a generated PDF (as a Blob object URL) inline in a modal overlay
 * so the user can review it before downloading. The object URL is created
 * by the caller (ExportButton) and revoked here on unmount / close to avoid
 * memory leaks.
 *
 * Rendered via createPortal directly on document.body with zIndex: 999999 so it
 * sits cleanly above all Leaflet map panes (z-index 400-1000) and ThreatGraph canvas.
 */
export function PdfPreviewModal({ pdfUrl, filename, onClose, onDownload }) {
  // Close on Escape key
  useEffect(() => {
    const handleKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [onClose]);

  // Lock background body scroll while preview modal is open
  useEffect(() => {
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = originalOverflow;
    };
  }, []);

  if (!pdfUrl) return null;

  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        width: '100vw',
        height: '100vh',
        backgroundColor: 'rgba(5, 8, 12, 0.88)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        zIndex: 999999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
        boxSizing: 'border-box',
      }}
      onClick={onClose}
    >
      <div
        style={{
          backgroundColor: 'var(--bg-surface, #151821)',
          border: '1px solid var(--border-hairline, rgba(255, 255, 255, 0.12))',
          borderRadius: 'var(--radius-md, 8px)',
          width: '100%',
          maxWidth: '1080px',
          height: '92vh',
          maxHeight: '94vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          boxShadow: '0 25px 60px -15px rgba(0, 0, 0, 0.95), 0 0 0 1px rgba(255, 255, 255, 0.08)',
          position: 'relative',
          zIndex: 1000000,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '14px 20px',
            borderBottom: '1px solid var(--border-hairline, rgba(255, 255, 255, 0.1))',
            backgroundColor: 'var(--bg-surface-elevated, #1B1F2B)',
            flexShrink: 0,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ fontSize: '18px' }}>📄</span>
            <div>
              <div style={{ fontSize: 'var(--fs-sm, 14px)', fontWeight: 600, color: 'var(--text-primary, #FFFFFF)' }}>
                Forensic Investigation Dossier &bull; PDF Preview
              </div>
              <div
                className="mono-val"
                style={{ fontSize: 'var(--fs-micro, 11px)', color: 'var(--text-muted, #8B949E)' }}
              >
                {filename}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button type="button" className="btn-primary-action" onClick={onDownload}>
              Download PDF
            </button>
            <button type="button" className="btn-ghost" onClick={onClose}>
              ✕ Close
            </button>
          </div>
        </div>

        <div style={{ flex: 1, minHeight: 0, backgroundColor: '#262A35', position: 'relative' }}>
          <iframe
            title="PDF report preview"
            src={pdfUrl}
            style={{ width: '100%', height: '100%', border: 'none', display: 'block' }}
          />
        </div>
      </div>
    </div>,
    document.body
  );
}

export default PdfPreviewModal;
