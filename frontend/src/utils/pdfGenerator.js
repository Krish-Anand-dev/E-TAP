import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

/**
 * pdfGenerator.js
 *
 * Converts the SAME investigation data object that drives the dashboard
 * (see InvestigationContext / DashboardPage) into a professional, paginated
 * PDF report. There is deliberately no separate/duplicated data model here:
 * every value pulled below is read directly from the canonical report JSON
 * (email_id, risk_score, verdict, email, headers, attachments, iocs,
 * threat_intel, correlation, ai_analysis, historical_correlation), the same
 * fields DashboardPage.jsx destructures to render the UI.
 *
 * This is intentionally frontend-only: the backend has no PDF-generation
 * infrastructure (backend/reports/ is an empty placeholder), and the data
 * needed for the report is already fully loaded on the client once an
 * analysis succeeds, so there's no need for a round trip to the server.
 */

// ---- Palette (mirrors CSS custom properties in styles/index.css) ----
const COLORS = {
  bgBase: [18, 21, 28],
  textPrimary: [30, 33, 40],
  textSecondary: [90, 98, 115],
  textMuted: [130, 137, 153],
  border: [220, 222, 228],
  amber: [232, 162, 61],
  safe: [76, 175, 125],
  caution: [232, 162, 61],
  danger: [217, 83, 79],
  neutral: [140, 146, 160],
  headerDark: [27, 31, 42],
};

const PAGE_MARGIN = 40;
const BOTTOM_LIMIT = 780; // ~A4 at 72dpi-ish scale used by jsPDF pt units (842 tall)

// ---------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------

function safe(val, fallback = 'N/A') {
  if (val === null || val === undefined || val === '') return fallback;
  return String(val);
}

function pct(val) {
  if (typeof val !== 'number' || Number.isNaN(val)) return 'N/A';
  return `${Math.round(val * 100)}%`;
}

function statusColor(status) {
  if (status === 'danger') return COLORS.danger;
  if (status === 'caution') return COLORS.caution;
  if (status === 'safe') return COLORS.safe;
  return COLORS.neutral;
}

function verdictStatusClass(verdict = '', riskScore = 0) {
  const v = String(verdict || '');
  if (riskScore >= 70 || v.includes('HIGH') || v.includes('PHISH') || v.includes('MALICIOUS')) {
    return 'danger';
  }
  if (riskScore >= 40 || v.includes('SUSPICIOUS')) return 'caution';
  return 'safe';
}

/** Ensure there is enough vertical room left on the page; otherwise start a new page. */
function ensureSpace(doc, cursorY, needed) {
  if (cursorY + needed > BOTTOM_LIMIT) {
    doc.addPage();
    return PAGE_MARGIN;
  }
  return cursorY;
}

function sectionTitle(doc, title, subtitle, cursorY) {
  cursorY = ensureSpace(doc, cursorY, 40);
  doc.setDrawColor(...COLORS.amber);
  doc.setFillColor(...COLORS.amber);
  doc.rect(PAGE_MARGIN, cursorY, 3, 16, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(...COLORS.textPrimary);
  doc.text(title, PAGE_MARGIN + 10, cursorY + 11);

  if (subtitle) {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(...COLORS.textMuted);
    doc.text(subtitle, PAGE_MARGIN + 10, cursorY + 22);
    cursorY += 30;
  } else {
    cursorY += 22;
  }
  return cursorY;
}

function keyValueGrid(doc, pairs, cursorY, colWidth = 255) {
  const startX = PAGE_MARGIN;
  let col = 0;
  let rowStartY = cursorY;
  let maxRowHeight = 0;

  pairs.forEach(([label, value]) => {
    const x = startX + col * colWidth;
    cursorY = ensureSpace(doc, rowStartY, 30);
    if (cursorY !== rowStartY) {
      rowStartY = cursorY;
      col = 0;
    }

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(...COLORS.textMuted);
    doc.text(label.toUpperCase(), x, rowStartY);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(...COLORS.textPrimary);
    const valueLines = doc.splitTextToSize(safe(value), colWidth - 12);
    doc.text(valueLines, x, rowStartY + 11);

    const rowHeight = 14 + (valueLines.length - 1) * 10;
    maxRowHeight = Math.max(maxRowHeight, rowHeight);

    col += 1;
    if (col >= 2) {
      col = 0;
      rowStartY += maxRowHeight + 12;
      maxRowHeight = 0;
    }
  });

  if (col !== 0) rowStartY += maxRowHeight + 12;
  return rowStartY;
}

function bulletList(doc, items, cursorY, color = COLORS.textPrimary, bullet = '\u2022') {
  const maxWidth = 515;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(...color);

  items.forEach((item) => {
    const lines = doc.splitTextToSize(`${bullet} ${item}`, maxWidth);
    cursorY = ensureSpace(doc, cursorY, lines.length * 12 + 4);
    doc.text(lines, PAGE_MARGIN, cursorY);
    cursorY += lines.length * 12 + 4;
  });
  return cursorY;
}

function tableBlock(doc, cursorY, options) {
  cursorY = ensureSpace(doc, cursorY, 40);
  autoTable(doc, {
    startY: cursorY,
    margin: { left: PAGE_MARGIN, right: PAGE_MARGIN },
    styles: {
      fontSize: 8,
      cellPadding: 5,
      textColor: [40, 42, 50],
      lineColor: [225, 227, 232],
      lineWidth: 0.5,
      overflow: 'linebreak',
    },
    headStyles: {
      fillColor: COLORS.headerDark,
      textColor: [232, 234, 240],
      fontStyle: 'bold',
      fontSize: 7.5,
    },
    alternateRowStyles: { fillColor: [248, 249, 251] },
    ...options,
  });
  return doc.lastAutoTable.finalY + 16;
}

function pageFooter(doc, generatedAt) {
  const totalPages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= totalPages; i += 1) {
    doc.setPage(i);
    const pageHeight = doc.internal.pageSize.getHeight();
    const pageWidth = doc.internal.pageSize.getWidth();
    doc.setDrawColor(...COLORS.border);
    doc.setLineWidth(0.5);
    doc.line(PAGE_MARGIN, pageHeight - 30, pageWidth - PAGE_MARGIN, pageHeight - 30);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(...COLORS.textMuted);
    doc.text('Email Threat Analysis Platform', PAGE_MARGIN, pageHeight - 18);
    doc.text(`Generated ${generatedAt}`, pageWidth / 2, pageHeight - 18, { align: 'center' });
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - PAGE_MARGIN, pageHeight - 18, { align: 'right' });
  }
}

// ---------------------------------------------------------------------
// Filename helper
// ---------------------------------------------------------------------

export function getReportFilename(data) {
  const base =
    (data && (data.email_id || data.email?.message_id || data.email?.subject)) || 'report';
  const cleaned = String(base)
    .replace(/^urn:uuid:/i, '')
    .replace(/[^a-zA-Z0-9-_]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 48);
  return `threat-report-${cleaned || 'unknown'}.pdf`;
}

// ---------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------

/**
 * Build a jsPDF document from the investigation data object.
 * Returns the jsPDF instance (caller can .save(), .output('blob'), etc.)
 */
export function generatePdfDocument(data, options = {}) {
  if (!data || typeof data !== 'object') {
    throw new Error('Report data is not available yet.');
  }

  // Support both generatePdfDocument(data, activeFile) and generatePdfDocument(data, { activeFile, mapImage })
  const activeFile = options?.name ? options : options?.activeFile || null;
  const mapImage = options?.mapImage || null;

  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const generatedAt = new Date().toLocaleString();

  const {
    email_id,
    risk_score = 0,
    verdict = 'UNKNOWN',
    email = {},
    headers = {},
    attachments = [],
    iocs = {},
    threat_intel = {},
    correlation = {},
    ai_analysis = {},
  } = data;

  const historicalCorrelation =
    data.historical_correlation || correlation.historical_stats || {};
  const finalAssessment = ai_analysis.final_assessment || {};
  const contentClassification = ai_analysis.content_classification || {};
  const evidenceAssessments = finalAssessment.evidence_assessments || [];
  const mitreAttack =
    (finalAssessment.mitre_attack && finalAssessment.mitre_attack.length > 0
      ? finalAssessment.mitre_attack
      : data.mitre_attack) || [];
  const recommendedActions = finalAssessment.recommended_actions || [];

  let y = PAGE_MARGIN;

  // ---------- Title block ----------
  doc.setFillColor(...COLORS.headerDark);
  doc.rect(0, 0, doc.internal.pageSize.getWidth(), 90, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(17);
  doc.setTextColor(232, 234, 240);
  doc.text('EMAIL THREAT ANALYSIS REPORT', PAGE_MARGIN, 40);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(180, 185, 196);
  doc.text(
    `Dossier ${safe(email_id, 'N/A').slice(0, 60)}${activeFile?.name ? `  \u2022  ${activeFile.name}` : ''}`,
    PAGE_MARGIN,
    58
  );
  doc.text(`Generated ${generatedAt}`, PAGE_MARGIN, 72);
  y = 110;

  // ---------- Verdict banner ----------
  const vClass = verdictStatusClass(verdict, risk_score);
  const vColor = statusColor(vClass);
  doc.setFillColor(vColor[0], vColor[1], vColor[2]);
  doc.roundedRect(PAGE_MARGIN, y, 515, 56, 3, 3, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.text(safe(verdict), PAGE_MARGIN + 16, y + 26);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.text(
    `Risk Score: ${risk_score}/100      Confidence: ${pct(finalAssessment.confidence)}`,
    PAGE_MARGIN + 16,
    y + 42
  );
  y += 72;

  if (finalAssessment.explanation) {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(...COLORS.textSecondary);
    const lines = doc.splitTextToSize(finalAssessment.explanation, 515);
    y = ensureSpace(doc, y, lines.length * 12 + 10);
    doc.text(lines, PAGE_MARGIN, y);
    y += lines.length * 12 + 14;
  }

  // ---------- 1. Email Overview ----------
  y = sectionTitle(doc, '1. Email Overview', 'Envelope metadata extracted from the parsed message', y);
  y = keyValueGrid(
    doc,
    [
      ['Subject', email.subject],
      ['From', email.from_raw || email.from_email],
      ['Reply-To', email.reply_to || '(aligned with From address)'],
      ['To', email.to],
      ['Date', email.date],
      ['Message-ID', email.message_id],
      ['Source format', email.source_format],
      ['Attachments', attachments.length],
    ],
    y
  );
  y += 8;

  // ---------- 2. Header Forensics ----------
  y = sectionTitle(doc, '2. Header Forensics', 'Authentication results and routing chain', y);
  y = tableBlock(doc, y, {
    head: [['Check', 'Result']],
    body: [
      ['SPF', safe(headers.spf, 'none').toUpperCase()],
      ['DKIM', safe(headers.dkim, 'none').toUpperCase()],
      ['DMARC', safe(headers.dmarc, 'none').toUpperCase()],
      ['Originating IP', safe(headers.originating_ip)],
    ],
    columnStyles: { 0: { cellWidth: 120 } },
  });

  if (headers.red_flags && headers.red_flags.length > 0) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(...COLORS.danger);
    y = ensureSpace(doc, y, 16);
    doc.text(`HEADER RED FLAGS (${headers.red_flags.length})`, PAGE_MARGIN, y);
    y += 12;
    y = bulletList(doc, headers.red_flags, y, [80, 30, 30]);
    y += 6;
  }

  if (headers.received_chain && headers.received_chain.length > 0) {
    y = ensureSpace(doc, y, 16);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(...COLORS.textMuted);
    doc.text('RECEIVED / ROUTING CHAIN', PAGE_MARGIN, y);
    y += 12;
    y = tableBlock(doc, y, {
      head: [['Hop', 'Detail']],
      body: headers.received_chain.map((hop, idx) => [`${idx + 1}`, hop]),
      columnStyles: { 0: { cellWidth: 40 } },
    });
  }

  // ---------- 3. Attachment Forensics ----------
  y = sectionTitle(doc, '3. Attachment Forensics', 'Static file inspection and hash values', y);
  if (attachments.length === 0) {
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(9);
    doc.setTextColor(...COLORS.textMuted);
    y = ensureSpace(doc, y, 16);
    doc.text('No file attachments were present in this email.', PAGE_MARGIN, y);
    y += 20;
  } else {
    y = tableBlock(doc, y, {
      head: [['Filename', 'Declared', 'Actual', 'Mismatch', 'Macro', 'Suspicious', 'SHA-256']],
      body: attachments.map((att) => [
        safe(att.filename),
        safe(att.declared_type, 'unknown'),
        safe(att.actual_type, 'unknown'),
        att.type_mismatch ? 'YES' : 'NO',
        att.has_macro ? 'YES' : 'NO',
        att.suspicious ? 'YES' : 'NO',
        safe(att.sha256),
      ]),
      styles: { fontSize: 6.8, cellPadding: 4, overflow: 'linebreak' },
      columnStyles: { 6: { cellWidth: 130 } },
    });
  }

  // ---------- 4. AI Content Classification ----------
  y = sectionTitle(doc, '4. AI Content Classification', 'Linguistic and intent analysis of message body', y);
  y = keyValueGrid(
    doc,
    [
      ['Classification', contentClassification.content_verdict],
      ['Attack type', contentClassification.attack_type],
      ['Confidence', pct(contentClassification.confidence)],
      [
        'Categories',
        (contentClassification.categories || [])
          .map((c) => `${c.name} (${c.weight}%)`)
          .join(', ') || 'None classified',
      ],
    ],
    y
  );
  if (contentClassification.reasons && contentClassification.reasons.length > 0) {
    y = ensureSpace(doc, y, 16);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(...COLORS.textMuted);
    doc.text('CONTENT INDICATORS', PAGE_MARGIN, y);
    y += 12;
    y = bulletList(doc, contentClassification.reasons, y);
  }
  if (contentClassification.suspicious_indicators && contentClassification.suspicious_indicators.length > 0) {
    y = ensureSpace(doc, y, 16);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(...COLORS.danger);
    doc.text('SUSPICIOUS LINGUISTIC INDICATORS', PAGE_MARGIN, y);
    y += 12;
    y = bulletList(doc, contentClassification.suspicious_indicators, y, [80, 30, 30]);
  }
  y += 4;

  // ---------- 5. IOC Extraction ----------
  y = sectionTitle(doc, '5. Indicators of Compromise', 'IPs, domains, URLs and hashes extracted from headers, body and attachments', y);
  const iocRows = [];
  (iocs.ips || []).forEach((ip) => {
    const rep = threat_intel.ip_reputation?.[ip];
    iocRows.push([
      'IP',
      ip,
      rep?.malicious === true ? 'MALICIOUS' : rep?.malicious === false ? 'CLEAN' : 'UNCHECKED',
      rep ? `Reports: ${safe(rep.reports, '0')} | Country: ${safe(rep.country)}` : 'No threat reports',
    ]);
  });
  (iocs.domains || []).forEach((domain) => {
    const info = threat_intel.domain_info?.[domain];
    iocRows.push([
      'Domain',
      domain,
      info?.malicious === true ? 'MALICIOUS' : 'UNRATED',
      info ? `Age: ${safe(info.age_days, 'Unknown')} days | Registrar: ${safe(info.registrar)}` : 'No WHOIS data',
    ]);
  });
  (iocs.urls || []).forEach((url) => {
    const rep = threat_intel.url_reputation?.[url];
    iocRows.push([
      'URL',
      url,
      rep?.malicious === true ? 'MALICIOUS' : rep?.malicious === false ? 'CLEAN' : 'UNCHECKED',
      rep?.error || (rep ? `Malicious: ${safe(rep.malicious, 'unknown')}` : 'URL observed in payload'),
    ]);
  });
  (iocs.hashes || []).forEach((hash) => {
    const rep = threat_intel.hash_reputation?.[hash];
    iocRows.push([
      'Hash',
      hash,
      rep?.malicious === true ? 'MALICIOUS' : rep?.malicious === false ? 'CLEAN' : 'UNCHECKED',
      rep?.error || 'SHA-256 payload hash',
    ]);
  });

  if (iocRows.length === 0) {
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(9);
    doc.setTextColor(...COLORS.textMuted);
    y = ensureSpace(doc, y, 16);
    doc.text('No indicators of compromise were extracted for this email.', PAGE_MARGIN, y);
    y += 20;
  } else {
    y = tableBlock(doc, y, {
      head: [['Type', 'Indicator', 'Status', 'Details']],
      body: iocRows,
      styles: { fontSize: 7, cellPadding: 4, overflow: 'linebreak' },
      columnStyles: { 0: { cellWidth: 40 }, 1: { cellWidth: 170 }, 2: { cellWidth: 60 } },
    });
  }

  // ---------- 6. Geographic Threat Origin & Relay Footprint ----------
  if (threat_intel.geo && threat_intel.geo.length > 0) {
    y = sectionTitle(
      doc,
      '6. Geographic Threat Origin & Relay Footprint',
      'Stage B2 GeoIP Triangulation and visual relay infrastructure footprint',
      y
    );

    // Embed visual Geo Footprint map screenshot if captured
    if (mapImage) {
      const imgWidth = 515;
      const imgHeight = 220;
      y = ensureSpace(doc, y, imgHeight + 24);

      // Dark framing card with hairline border
      doc.setFillColor(18, 21, 28);
      doc.setDrawColor(45, 50, 65);
      doc.setLineWidth(1);
      doc.roundedRect(PAGE_MARGIN, y, imgWidth, imgHeight, 4, 4, 'FD');

      try {
        doc.addImage(
          mapImage,
          'JPEG',
          PAGE_MARGIN + 2,
          y + 2,
          imgWidth - 4,
          imgHeight - 4,
          undefined,
          'FAST'
        );
      } catch (err) {
        console.warn('Could not embed GeoMap screenshot in PDF:', err);
      }

      y += imgHeight + 10;
    }

    y = tableBlock(doc, y, {
      head: [['Observed IP', 'Triangulated Country', 'Latitude', 'Longitude']],
      body: threat_intel.geo.map((g) => [
        safe(g.ip),
        safe(g.country),
        safe(g.lat),
        safe(g.lon),
      ]),
    });
  }

  // ---------- 7. Evidence Breakdown ----------
  y = sectionTitle(doc, '7. Multi-Vector Evidence Breakdown', 'Weighted risk contribution per detection vector', y);
  if (evidenceAssessments.length === 0) {
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(9);
    doc.setTextColor(...COLORS.textMuted);
    y = ensureSpace(doc, y, 16);
    doc.text('No granular evidence-vector assessments were recorded for this dossier.', PAGE_MARGIN, y);
    y += 20;
  } else {
    y = tableBlock(doc, y, {
      head: [['Evidence Source', 'Risk', 'Summary']],
      body: evidenceAssessments.map((e) => [
        safe(e.source),
        e.risk_score != null ? `${e.risk_score}/100` : '\u2014',
        safe(e.summary),
      ]),
      columnStyles: { 0: { cellWidth: 130 }, 1: { cellWidth: 50 } },
    });
  }

  // ---------- 8. MITRE ATT&CK ----------
  y = sectionTitle(doc, '8. MITRE ATT&CK Mapping', 'Evidence-bound technique mappings', y);
  if (mitreAttack.length === 0) {
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(9);
    doc.setTextColor(...COLORS.textMuted);
    y = ensureSpace(doc, y, 16);
    doc.text('No MITRE ATT&CK techniques were matched for this email.', PAGE_MARGIN, y);
    y += 20;
  } else {
    y = tableBlock(doc, y, {
      head: [['Technique', 'Name', 'Tactic', 'Confidence', 'Evidence']],
      body: mitreAttack.map((t) => [
        safe(t.technique),
        safe(t.name),
        safe(t.tactic),
        pct(t.confidence),
        (t.evidence || []).join('; ') || '\u2014',
      ]),
      styles: { fontSize: 6.8, cellPadding: 4, overflow: 'linebreak' },
      columnStyles: { 0: { cellWidth: 55 }, 2: { cellWidth: 65 }, 3: { cellWidth: 55 } },
    });
  }

  // ---------- 9. Recommended Actions ----------
  if (recommendedActions.length > 0) {
    y = sectionTitle(doc, '9. Recommended Actions', 'Suggested remediation steps', y);
    y = bulletList(doc, recommendedActions, y);
    y += 6;
  }

  // ---------- 10. Historical Correlation & Campaign ----------
  y = sectionTitle(doc, '10. Historical Correlation & Campaign', 'Relationship to previously analyzed messages', y);
  const isNewCategory = historicalCorrelation.is_new_category ?? correlation.is_new_campaign ?? true;
  const campaignId = historicalCorrelation.assigned_campaign_id || correlation.campaign_id || 'N/A';
  const metrics = historicalCorrelation.metrics_summary || {
    total_overlapping_iocs: correlation.shared_infrastructure?.length || 0,
    total_prior_incidents: correlation.related_emails?.length || 0,
    max_repetition_this_week: 0,
    max_repetition_this_month: 0,
  };
  y = keyValueGrid(
    doc,
    [
      ['Campaign status', isNewCategory ? 'New threat cluster' : 'Recurring adversary activity'],
      ['Campaign ID', campaignId],
      ['Overlapping IOCs', metrics.total_overlapping_iocs],
      ['Prior incidents', metrics.total_prior_incidents],
      ['Seen this week', `${metrics.max_repetition_this_week || 0}x`],
      ['Seen this month', `${metrics.max_repetition_this_month || 0}x`],
    ],
    y
  );

  const indicators = historicalCorrelation.indicators || [];
  if (indicators.length > 0) {
    y = ensureSpace(doc, y, 16);
    y = tableBlock(doc, y, {
      head: [['Type', 'Indicator', 'This Week', 'This Month', 'All Time']],
      body: indicators.map((ind) => [
        safe(ind.type),
        safe(ind.value),
        safe(ind.this_week, '0'),
        safe(ind.this_month, '0'),
        safe(ind.all_time, '0'),
      ]),
      styles: { fontSize: 7, overflow: 'linebreak' },
      columnStyles: { 1: { cellWidth: 200 } },
    });
  }

  // ---------- Technical appendix ----------
  y = sectionTitle(doc, '11. Technical Appendix', 'Execution metadata for analyst traceability', y);
  y = keyValueGrid(
    doc,
    [
      ['Analysis ID', email_id],
      ['Source format', email.source_format],
      ['Report generated', generatedAt],
      ['Report type', 'Client-side PDF rendering of the canonical analysis JSON'],
    ],
    y
  );

  pageFooter(doc, generatedAt);

  return doc;
}

/**
 * Convenience wrapper: generate the PDF and return a Blob object URL for
 * previewing in an <iframe>/<embed>. Caller is responsible for calling
 * URL.revokeObjectURL(url) when done (see PdfPreviewModal.jsx).
 */
export function generatePdfPreviewUrl(data, options = {}) {
  const doc = generatePdfDocument(data, options);
  const blob = doc.output('blob');
  return URL.createObjectURL(blob);
}

/**
 * Generate the PDF and trigger a browser download.
 */
export function downloadPdfReport(data, options = {}) {
  const doc = generatePdfDocument(data, options);
  doc.save(getReportFilename(data));
}
