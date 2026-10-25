/**
 * Verdict bands for the web UI.
 *
 * The backend is the source of truth (backend/verdicts.py) and sends
 * `verdict_band` with every report. This file only exists for records that
 * were saved before that field existed (history, localStorage, old dossiers).
 * THRESHOLDS must match backend/verdicts.py -- backend/tests/test_verdicts.py
 * fails if they drift.
 */

// [minimum risk score, canonical label], ascending.
export const THRESHOLDS = [
  [0, 'LIKELY LEGITIMATE'],
  [20, 'LOW RISK'],
  [40, 'SUSPICIOUS'],
  [65, 'LIKELY PHISHING'],
  [85, 'HIGH-RISK PHISHING'],
];

const BAND_BY_LABEL = {
  'LIKELY LEGITIMATE': 'safe',
  'LOW RISK': 'safe',
  'SUSPICIOUS': 'caution',
  'LIKELY PHISHING': 'danger',
  'HIGH-RISK PHISHING': 'danger',
};

const SEVERITY = Object.fromEntries(THRESHOLDS.map(([, label], i) => [label, i]));

const SYNONYMS = {
  'likely legitimate': 'LIKELY LEGITIMATE',
  legitimate: 'LIKELY LEGITIMATE',
  clean: 'LIKELY LEGITIMATE',
  safe: 'LIKELY LEGITIMATE',
  'low risk': 'LOW RISK',
  suspicious: 'SUSPICIOUS',
  'likely phishing': 'LIKELY PHISHING',
  'likely malicious': 'LIKELY PHISHING',
  phishing: 'LIKELY PHISHING',
  malicious: 'LIKELY PHISHING',
  'high risk phishing': 'HIGH-RISK PHISHING',
  'highly suspicious malicious': 'HIGH-RISK PHISHING',
  'highly suspicious': 'HIGH-RISK PHISHING',
  'high risk': 'HIGH-RISK PHISHING',
};

const keyOf = (text) => String(text).toLowerCase().replace(/[^a-z]+/g, ' ').trim();

export function normalizeLabel(raw) {
  if (!raw || typeof raw !== 'string') return null;
  if (raw in SEVERITY) return raw;
  return SYNONYMS[keyOf(raw)] || null;
}

export function labelForScore(score) {
  const s = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
  let label = THRESHOLDS[0][1];
  for (const [min, name] of THRESHOLDS) if (s >= min) label = name;
  return label;
}

/** 'safe' | 'caution' | 'danger' */
export function bandFor({ verdictBand, verdict, riskScore } = {}) {
  if (verdictBand === 'safe' || verdictBand === 'caution' || verdictBand === 'danger') {
    return verdictBand;
  }
  const scoreLabel = labelForScore(riskScore);
  const given = normalizeLabel(verdict);
  const label =
    given && SEVERITY[given] > SEVERITY[scoreLabel] ? given : scoreLabel;
  return BAND_BY_LABEL[label] || 'caution';
}

/** Canonical display label (falls back to the score when the label is unknown). */
export function displayLabel(verdict, riskScore) {
  const given = normalizeLabel(verdict);
  const scoreLabel = labelForScore(riskScore);
  if (!given) return scoreLabel;
  return SEVERITY[given] >= SEVERITY[scoreLabel] ? given : scoreLabel;
}

/** Human-readable provenance chips for a report's `analysis_provenance`. */
export function provenanceChips(provenance, stageStatus) {
  const chips = [];
  const p = provenance || {};

  if (p.input_mode === 'quick_content_check') {
    chips.push({ key: 'input', tone: 'caution', text: 'Quick Content Check — original headers not available' });
  }

  const tiMode = p.threat_intel_mode || (stageStatus?.E === 'live' ? 'live' : stageStatus?.E === 'offline_placeholder' ? 'offline_placeholder' : null);
  if (tiMode === 'live') {
    if (p.threat_intel_unavailable > 0) {
      chips.push({ key: 'ti', tone: 'caution', text: `Threat intel: live — ${p.threat_intel_unavailable} of ${p.threat_intel_lookups} lookups unavailable` });
    } else {
      chips.push({ key: 'ti', tone: 'ok', text: 'Threat intel: live' });
    }
  } else if (tiMode === 'offline_placeholder') {
    chips.push({ key: 'ti', tone: 'caution', text: 'Threat intel: OFFLINE — reputation not checked' });
  } else {
    chips.push({ key: 'ti', tone: 'neutral', text: 'Threat intel: status unknown (older record)' });
  }

  if (p.gemini_skipped_by_triage) {
    chips.push({ key: 'ai', tone: 'neutral', text: 'AI: metadata triage only (Gemini skipped)' });
  } else if (p.fallback_used) {
    const why = p.fallback_reason ? ` (${p.fallback_reason})` : '';
    chips.push({ key: 'ai', tone: 'caution', text: `AI: offline fallback — Gemini unavailable${why}` });
  } else if (p.assessment_provider) {
    const model = p.assessment_model ? ` · ${p.assessment_model}` : '';
    chips.push({ key: 'ai', tone: 'ok', text: `AI: ${p.assessment_provider}${model}` });
  }

  if (p.verdict_reconciled) {
    chips.push({ key: 'rec', tone: 'neutral', text: `Label adjusted to match risk score (was “${p.verdict_original}”)` });
  }
  return chips;
}
