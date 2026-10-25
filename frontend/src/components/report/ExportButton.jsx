import React, { useState, useRef, useEffect } from 'react';
import html2canvas from 'html2canvas';
import { generatePdfPreviewUrl, downloadPdfReport, getReportFilename } from '../../utils/pdfGenerator';
import PdfPreviewModal from './PdfPreviewModal';

/**
 * Capture high-DPI screenshot of the rendered Leaflet GeoMap element
 */
async function captureMapScreenshot() {
  const mapElement =
    document.getElementById('geo-map-capture-container') ||
    document.querySelector('.leaflet-container');
  if (!mapElement) return null;

  try {
    const canvas = await html2canvas(mapElement, {
      useCORS: true,
      allowTaint: true,
      logging: false,
      backgroundColor: '#12151C',
      scale: 2, // 2x high resolution for crisp PDF render
      ignoreElements: (el) => {
        // Exclude zoom buttons from screenshot
        return el.classList && el.classList.contains('leaflet-control-zoom');
      },
    });
    return canvas.toDataURL('image/jpeg', 0.88);
  } catch (err) {
    console.warn('Could not capture GeoMap screenshot for PDF:', err);
    return null;
  }
}

export function ExportButton({ data = null }) {
  const [isGenerating, setIsGenerating] = useState(false);
  const [isPreviewing, setIsPreviewing] = useState(false);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [pdfError, setPdfError] = useState(null);
  const generatingRef = useRef(false); // guards against double-clicks/races

  // Revoke any outstanding object URL when the component unmounts,
  // or when the underlying report data changes (new analysis loaded).
  useEffect(() => {
    return () => {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    // If the investigation data changes while a preview is open, close it —
    // a stale PDF should never be shown for a different/newer report.
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      setPreviewUrl(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  const exportJson = () => {
    if (!data) return;
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `E-TAP_dossier_${data.email_id || Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handlePreviewPdf = async () => {
    if (!data || generatingRef.current) return;
    generatingRef.current = true;
    setPdfError(null);
    setIsGenerating(true);
    try {
      // Capture live visual Geo Footprint map screenshot from DOM
      const mapImage = await captureMapScreenshot();
      const url = generatePdfPreviewUrl(data, { mapImage });
      setPreviewUrl(url);
      setIsPreviewing(true);
    } catch (err) {
      console.error('PDF preview generation failed:', err);
      setPdfError('Unable to generate PDF. Please try again.');
    } finally {
      setIsGenerating(false);
      generatingRef.current = false;
    }
  };

  const handleExportPdf = async () => {
    if (!data || generatingRef.current) return;
    generatingRef.current = true;
    setPdfError(null);
    setIsGenerating(true);
    try {
      const mapImage = await captureMapScreenshot();
      downloadPdfReport(data, { mapImage });
    } catch (err) {
      console.error('PDF export failed:', err);
      setPdfError('Unable to generate PDF. Please try again.');
    } finally {
      setIsGenerating(false);
      generatingRef.current = false;
    }
  };

  const handleClosePreview = () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPreviewUrl(null);
    setIsPreviewing(false);
  };

  const handleDownloadFromPreview = async () => {
    if (!data) return;
    try {
      const mapImage = await captureMapScreenshot();
      downloadPdfReport(data, { mapImage });
    } catch (err) {
      console.error('PDF export failed:', err);
      setPdfError('Unable to generate PDF. Please try again.');
    }
  };

  const dataReady = Boolean(data);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%' }}>
      <div style={{ display: 'flex', gap: '8px', width: '100%' }}>
        <button
          type="button"
          className="btn-ghost"
          style={{ flex: 1, textAlign: 'center' }}
          onClick={handlePreviewPdf}
          disabled={!dataReady || isGenerating}
          title="Preview the formatted PDF report before downloading"
        >
          {isGenerating ? 'Generating PDF...' : 'Preview PDF'}
        </button>
        <button
          type="button"
          className="btn-primary-action"
          style={{ flex: 1, textAlign: 'center' }}
          onClick={handleExportPdf}
          disabled={!dataReady || isGenerating}
          title="Download this report as a formatted PDF"
        >
          {isGenerating ? 'Generating PDF...' : 'Export PDF'}
        </button>
      </div>

      <button
        type="button"
        className="btn-ghost"
        style={{ width: '100%', textAlign: 'center' }}
        onClick={exportJson}
        disabled={!dataReady}
        title="Download complete forensic JSON raw dossier"
      >
        Export Raw JSON
      </button>

      {pdfError && (
        <div
          style={{
            fontSize: 'var(--fs-micro)',
            color: 'var(--verdict-danger)',
            fontFamily: 'var(--font-mono)',
          }}
          role="alert"
        >
          {pdfError}
        </div>
      )}

      {isPreviewing && previewUrl && (
        <PdfPreviewModal
          pdfUrl={previewUrl}
          filename={data ? getReportFilename(data) : 'threat-report.pdf'}
          onClose={handleClosePreview}
          onDownload={handleDownloadFromPreview}
        />
      )}
    </div>
  );
}

export default ExportButton;
