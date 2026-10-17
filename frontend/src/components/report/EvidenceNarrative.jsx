import React from 'react';

/**
 * "What we observed / Why it matters / What to do" (B1 + B9).
 *
 * Renders `evidence_report` from the backend (backend/evidence.py). All
 * judgements (which item is a reason, what is unknown, what to do) are made
 * server-side; this component only lays them out. Nothing here upgrades an
 * unavailable check to "safe".
 */

const KIND_LABEL = {
  observed: 'Observed',
  reputation: 'Reputation service',
  ai_inferred: 'AI-inferred',
};

const DIRECTION_LABEL = {
  raises_risk: 'Raises risk',
  lowers_risk: 'Lowers risk',
  neutral: '',
};

const CONFIDENCE_LABEL = { high: 'High', medium: 'Medium', low: 'Low' };

function KindChip({ kind }) {
  return <span className={`ev-chip ev-kind-${kind}`}>{KIND_LABEL[kind] || kind}</span>;
}

function DirectionTag({ item }) {
  const text = DIRECTION_LABEL[item.direction];
  if (!text || item.status !== 'present') return null;
  return (
    <span className={`ev-dir ev-dir-${item.direction}`}>
      {text}
      {item.weight === 'strong' ? ' · strong' : ' · weak'}
    </span>
  );
}

function EvidenceRow({ item }) {
  return (
    <li className={`ev-row ev-status-${item.status}`}>
      <div className="ev-row-head">
        <span className="ev-row-title">{item.title}</span>
        <span className="ev-row-tags">
          <KindChip kind={item.kind} />
          <DirectionTag item={item} />
        </span>
      </div>
      <details><summary>Evidence {item.id}: provenance and observation</summary>
        <p>{item.provenance_type || item.kind} · {item.source_type || item.source} · confidence: {item.confidence || 'unknown'}</p>
        <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(item.raw_observation ?? null, null, 2)}</pre>
        <p>{item.normalized_explanation || item.why}</p>
        <p>Supports: {(item.supports || []).join(', ') || 'None recorded'}; contradicts: {(item.contradicts || []).join(', ') || 'None recorded'}</p>
      </details>
      {item.detail ? <div className="ev-row-detail">{item.detail}</div> : null}
    </li>
  );
}

function ReasonRow({ item, byId }) {
  const grounded = (item.evidence_ids || []).map((id) => byId[id]).filter(Boolean);
  return (
    <li className="ev-reason">
      <div className="ev-row-head">
        <span className="ev-row-title">{item.title}</span>
        <span className="ev-row-tags">
          <KindChip kind={item.kind} />
          <DirectionTag item={item} />
        </span>
      </div>
      {item.why ? <div className="ev-why">{item.why}</div> : null}
      {grounded.length > 0 ? (
        <div className="ev-based-on">
          Based on: {grounded.map((g) => g.title).join(' · ')}
        </div>
      ) : null}
    </li>
  );
}

export function EvidenceNarrative({ report }) {
  if (!report || !Array.isArray(report.evidence)) return null;

  const { conclusion = {}, sections = {}, what_to_do: whatToDo = {} } = report;
  const byId = Object.fromEntries(report.evidence.map((i) => [i.id, i]));
  const pick = (ids = []) => ids.map((id) => byId[id]).filter(Boolean);

  const found = [...pick(sections.observed), ...pick(sections.reputation)];
  const notChecked = pick(sections.not_checked);
  const reasons = pick(report.top_reasons);
  const contradicting = pick(report.contradicting);
  const aiItems = pick(sections.ai_inferred);
  const limitations = conclusion.limitations || [];
  const steps = whatToDo.steps || [];
  const aiSuggestions = whatToDo.ai_suggestions || [];
  const band = conclusion.band || 'caution';

  return (
    <div className="forensic-panel evidence-narrative">
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">Verdict Evidence</span>
          <span className="panel-subtitle">{conclusion.state_text}</span>
        </div>
        <span className="rail-item-badge" title="How well the available evidence supports this verdict">
          Evidence confidence: {CONFIDENCE_LABEL[conclusion.confidence_level] || 'Unknown'}
        </span>
      </div>

      <p className={`ev-headline ev-headline-${band}`}>{report.headline}</p>

      {limitations.length > 0 && (
        <div className="ev-limits" role="note">
          <div className="ev-limits-title">What this verdict could not take into account</div>
          <ul>
            {limitations.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </div>
      )}

      {/* 1 — What we observed */}
      <section className="ev-block" aria-labelledby="ev-observed-h">
        <h3 id="ev-observed-h" className="ev-block-title">
          <span className="ev-step">1</span> What we observed
        </h3>
        <p className="ev-block-sub">
          Facts E-TAP found in the message, and what outside services reported. Each is labelled with where it came from.
        </p>
        <ul className="ev-list">
          {found.map((item) => (
            <EvidenceRow key={item.id} item={item} />
          ))}
        </ul>
        {notChecked.length > 0 && (
          <details className="ev-notchecked" open>
            <summary>Not checked or unknown ({notChecked.length}). Unknown is not the same as safe.</summary>
            <ul className="ev-list">
              {notChecked.map((item) => (
                <EvidenceRow key={item.id} item={item} />
              ))}
            </ul>
          </details>
        )}
      </section>

      {/* 2 — Why it matters */}
      <section className="ev-block" aria-labelledby="ev-why-h">
        <h3 id="ev-why-h" className="ev-block-title">
          <span className="ev-step">2</span> Why it matters
        </h3>
        {reasons.length > 0 ? (
          <ul className="ev-list">
            {reasons.map((item) => (
              <ReasonRow key={item.id} item={item} byId={byId} />
            ))}
          </ul>
        ) : (
          <p className="ev-block-sub">
            No single strong indicator stood out
            {band === 'safe' ? '.' : '; the overall risk score is what raised this verdict.'}
          </p>
        )}

        {contradicting.length > 0 && (
          <>
            <div className="ev-subhead">Evidence pointing the other way</div>
            <ul className="ev-list">
              {contradicting.map((item) => (
                <ReasonRow key={item.id} item={item} byId={byId} />
              ))}
            </ul>
          </>
        )}

        {(report.ai_summary || aiItems.length > 0) && (
          <details className="ev-ai">
            <summary>AI interpretation ({aiItems.length} statement{aiItems.length === 1 ? '' : 's'}). Not verified fact.</summary>
            {report.ai_summary && (
              <p className="ev-ai-summary">
                {report.ai_summary.text}
                <span className="ev-ai-source"> — {report.ai_summary.source}{report.ai_summary.model ? ` · ${report.ai_summary.model}` : ''}</span>
              </p>
            )}
            <ul className="ev-list">
              {aiItems.map((item) => (
                <li key={item.id} className="ev-row">
                  <div className="ev-row-head">
                    <span className="ev-row-title">{item.title}</span>
                    <span className="ev-row-tags">
                      <DirectionTag item={item} />
                      {item.grounding === 'ungrounded' ? (
                        <span className="ev-chip ev-ungrounded">Not tied to specific evidence</span>
                      ) : item.grounding === 'evidence' ? (
                        <span className="ev-chip ev-grounded">Tied to evidence</span>
                      ) : item.grounding === 'message_content' ? (
                        <span className="ev-chip">From message wording</span>
                      ) : null}
                    </span>
                  </div>
                  {item.why ? <div className="ev-why">{item.why}</div> : null}
                  {(item.evidence_ids || []).length > 0 ? (
                    <div className="ev-based-on">
                      Based on: {item.evidence_ids.map((id) => byId[id]?.title).filter(Boolean).join(' · ')}
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          </details>
        )}
      </section>

      {/* 3 — What to do */}
      <section className="ev-block" aria-labelledby="ev-todo-h">
        <h3 id="ev-todo-h" className="ev-block-title">
          <span className="ev-step">3</span> What you should do
        </h3>
        <ol className="ev-steps">
          {steps.map((s) => (
            <li key={s.text}>{s.text}</li>
          ))}
        </ol>
        {aiSuggestions.length > 0 && (
          <details className="ev-ai">
            <summary>Additional AI-suggested actions</summary>
            <ul>
              {aiSuggestions.map((a) => (
                <li key={a}>{a}</li>
              ))}
            </ul>
          </details>
        )}
      </section>

      {report.reconstructed && (
        <p className="ev-footnote">
          This record was saved before the evidence trail existed. The summary above was rebuilt from what was stored; some details (such as full campaign history and how the analysis was run) may be missing.
        </p>
      )}
    </div>
  );
}

export default EvidenceNarrative;
