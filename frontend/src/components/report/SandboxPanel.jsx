import React from 'react';
import Icon from '../common/Icon';
import { sandboxPlace } from '../../utils/sandbox';

const STATUS_LABELS = {
  queued: 'Waiting for the sandbox',
  starting: 'Starting VM…',
  interacting: 'Interacting with attachment…',
  collecting: 'Collecting telemetry…',
  evaluating: 'Evaluating detection rules…',
  restoring: 'Restoring clean VM…',
  done: 'Complete',
  partial: 'Complete with inspection gaps',
  error: 'Error',
  unavailable: 'Unavailable',
  not_requested: 'Not requested',
  not_applicable: 'No Eligible Attachments',
  pending: 'Pending',
  submitted: 'Submitted',
  unknown: 'Unknown',
};

const VERDICT_COLORS = {
  behavior_observed: '#b42338',
  no_behavior_observed_inconclusive: '#95620b',
  blocked_by_security_control: '#6d28d9',
  inspection_incomplete: '#667085',
  unsupported: '#667085',
  error: '#b42338',
};

export function SandboxPanel({ sandbox }) {
  if (!sandbox) {
    return null;
  }

  const status = sandbox.status || 'unknown';
  const isRunning = ['queued', 'starting', 'interacting', 'collecting', 'evaluating', 'restoring', 'pending'].includes(status);
  const isDone = status === 'done';
  const isError = status === 'error' || status === 'unavailable';
  const isNotApplicable = status === 'not_applicable' || status === 'not_requested';
  const mode = sandbox.mode || 'unknown';
  const modeLabel = { agent: 'YOUR SANDBOX', virtualbox: 'LOCAL VM', replay: 'RECORDED TRACE' }[mode] || mode.toUpperCase();
  const isReplay = mode === 'replay';

  return (
    <div className="forensic-panel sandbox-panel" style={{ borderLeft: isDone ? '3px solid #3B82F6' : isError ? '3px solid #b42338' : isNotApplicable ? '3px solid #667085' : '3px solid #95620b' }}>
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">
            Sandbox Analysis
            {isReplay && (
              <span style={{
                marginLeft: 8, padding: '2px 8px', borderRadius: 4,
                background: 'rgba(139, 92, 246, 0.2)', color: '#A78BFA',
                fontSize: '10px', fontWeight: 700, letterSpacing: '0.05em'
              }}>
                RECORDED TRACE
              </span>
            )}
          </span>
          <span className="panel-subtitle">
            {STATUS_LABELS[status] || status}
            {isRunning && <span className="spinner" style={{ marginLeft: 8, display: 'inline-flex', verticalAlign: 'middle' }}><Icon name="clock" size={13} /></span>}
          </span>
        </div>
        <span className="rail-item-badge" style={{
          background: isDone ? 'rgba(59, 130, 246, 0.15)' : isError ? 'rgba(239, 68, 68, 0.15)' : isNotApplicable ? 'rgba(107, 114, 128, 0.15)' : 'rgba(245, 158, 11, 0.15)',
          color: isDone ? '#245cb7' : isError ? '#b42338' : isNotApplicable ? '#667085' : '#8a5a08'
        }}>
          {modeLabel}
        </span>
      </div>

      {status === 'queued' && mode === 'agent' && (
        <div style={{ padding: '16px', color: 'var(--text-secondary)', fontSize: 'var(--fs-xs)' }}>
          The attachments are queued for {sandboxPlace(sandbox)}. Keep the E-TAP Sandbox Agent running on the PC with your VM; this report updates by itself when the run finishes.
          {sandbox.expires_at && <> The request is kept until {new Date(sandbox.expires_at).toLocaleTimeString()}.</>}
        </div>
      )}

      {status === 'not_requested' && (
        <div style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 'var(--fs-xs)' }}>
          This was a standard analysis, so the attachments were not opened. Choose Deeper attachment analysis to open them in your own paired sandbox.
        </div>
      )}

      {/* Not applicable message */}
      {status === 'not_applicable' && (
        <div style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 'var(--fs-xs)' }}>
          No attachments eligible for sandbox detonation. The sandbox analyzes scripts, executables, documents, and archives — not data files like JSON, CSV, or images.
        </div>
      )}

      {/* Unavailable message */}
      {status === 'unavailable' && (
        <div style={{ padding: '16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 'var(--fs-xs)' }}>
          Deeper attachment analysis is not set up on this E-TAP server.
        </div>
      )}

      {/* Coverage info */}
      {sandbox.message && !isNotApplicable && (
        <p style={{ padding: '8px 16px', color: 'var(--text-secondary)', fontSize: 'var(--fs-xs)' }}>{sandbox.message}</p>
      )}
      {sandbox.coverage && (
        <div style={{ padding: '8px 16px', fontSize: '11px', color: 'var(--text-muted)', borderBottom: '1px solid var(--border-hairline)' }}>
          Rules: {sandbox.coverage.rules_loaded || 0} of {sandbox.coverage.rules_total_unique_windows || 0} evaluable
          {sandbox.coverage.note && ` — ${sandbox.coverage.note}`}
        </div>
      )}

      {sandbox.defender_checked === false && (
        <div style={{ padding: '8px 16px', fontSize: '11px', color: '#8a5a08', borderBottom: '1px solid var(--border-hairline)' }}>
          {sandbox.defender_note || 'Windows Defender events could not be read in this run, so blocks by Defender were not checked.'}
        </div>
      )}

      {/* Error */}
      {sandbox.error && (
        <div style={{ padding: '8px 16px', color: '#b42338', fontSize: '11px' }}>
          Error: {sandbox.error}
        </div>
      )}

      {/* Items */}
      {sandbox.items && sandbox.items.length > 0 && (
        <div className="forensic-table-container">
          <table className="forensic-table">
            <thead>
              <tr>
                <th>FILE</th>
                <th>SAMPLE</th>
                <th>VERDICT</th>
                <th>RULES</th>
                <th>EVENTS</th>
              </tr>
            </thead>
            <tbody>
              {sandbox.items.map((item, idx) => (
                <React.Fragment key={idx}>
                  <tr className={item.matches?.length > 0 ? 'row-suspicious' : ''}>
                    <td className="mono-val" style={{ fontWeight: 600 }}>{item.filename}</td>
                    <td className="mono-val">{item.sample || '—'}</td>
                    <td>
                      <span style={{
                        color: VERDICT_COLORS[item.verdict] || '#667085',
                        fontWeight: 600, fontSize: '11px', textTransform: 'uppercase'
                      }}>
                        {(item.verdict || 'unknown').replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td>
                      {item.matches?.length > 0 ? (
                        <span style={{ color: '#b42338', fontWeight: 700 }}>
                          {item.matches.length} rule(s)
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>0</span>
                      )}
                    </td>
                    <td className="mono-val">{item.event_count || 0}</td>
                  </tr>

                  {/* Rule matches detail */}
                  {item.matches?.length > 0 && (
                    <tr>
                      <td colSpan={5} style={{ background: 'rgba(239, 68, 68, 0.05)', padding: '12px 16px' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                            Triggered Detection Rules
                          </span>
                          {item.matches.map((match, mi) => (
                            <div key={mi} style={{
                              padding: '8px 12px', borderLeft: '3px solid #b42338',
                              background: 'rgba(180, 35, 56, 0.06)', borderRadius: '0 4px 4px 0'
                            }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                                <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '12px' }}>
                                  {match.rule}
                                </span>
                                {match.prevention_grade && (
                                  <span style={{
                                    padding: '1px 6px', borderRadius: 3, fontSize: '9px',
                                    background: 'rgba(239, 68, 68, 0.3)', color: '#b42338', fontWeight: 700
                                  }}>
                                    PREVENTION-GRADE
                                  </span>
                                )}
                                <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                                  ID: {match.rule_id}
                                </span>
                              </div>
                              {match.mitre?.length > 0 && (
                                <div style={{ display: 'flex', gap: 6, marginTop: 4, flexWrap: 'wrap' }}>
                                  {match.mitre.map((m, ti) => (
                                    <span key={ti} style={{
                                      padding: '2px 8px', borderRadius: 3, fontSize: '10px',
                                      background: 'rgba(59, 130, 246, 0.15)', color: '#245cb7',
                                      fontFamily: 'var(--font-mono)'
                                    }}>
                                      {m.technique} — {m.name}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </td>
                    </tr>
                  )}

                  {/* Launch error */}
                  {item.launch_error && (
                    <tr>
                      <td colSpan={5} style={{ padding: '8px 16px', color: '#8a5a08', fontSize: '11px' }}>
                        Launch note: {item.launch_error}
                      </td>
                    </tr>
                  )}
                  {item.note && (
                    <tr>
                      <td colSpan={5} style={{ padding: '8px 16px', color: '#8a5a08', fontSize: '11px' }}>
                        {item.note}
                      </td>
                    </tr>
                  )}
                  {item.process_tree?.length > 0 && (
                    <tr>
                      <td colSpan={5} style={{ padding: '8px 16px', fontSize: '11px' }}>
                        <details>
                          <summary>Observed processes ({item.process_tree.length})</summary>
                          {item.process_tree.map((process, pi) => (
                            <div key={process.entity_id || pi} className="mono-val" style={{ marginTop: 6, overflowWrap: 'anywhere' }}>
                              {process.parent?.name && `${process.parent.name} → `}{process.name}: {process.command_line}
                            </div>
                          ))}
                        </details>
                      </td>
                    </tr>
                  )}
                  {item.security_events?.length > 0 && (
                    <tr>
                      <td colSpan={5} style={{ padding: '8px 16px', fontSize: '11px' }}>
                        <details>
                          <summary>Windows security evidence</summary>
                          {item.security_events.map((event, ei) => (
                            <div key={event.record_id || ei} style={{ marginTop: 8, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                              Event {event.event_id}: {event.message}
                            </div>
                          ))}
                        </details>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Timing */}
      {(sandbox.started_at || sandbox.finished_at) && (
        <div style={{ padding: '8px 16px', fontSize: '10px', color: 'var(--text-muted)', borderTop: '1px solid var(--border-hairline)' }}>
          {sandbox.started_at && <span>Started: {new Date(sandbox.started_at).toLocaleTimeString()}</span>}
          {sandbox.finished_at && <span> · Finished: {new Date(sandbox.finished_at).toLocaleTimeString()}</span>}
          {sandbox.job_id && <span> · Job: {sandbox.job_id}</span>}
        </div>
      )}
    </div>
  );
}

export default SandboxPanel;
