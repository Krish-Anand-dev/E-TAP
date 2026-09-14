import React, { useState } from 'react';

export function HistoricalCorrelationCard({
  correlation = {},
  historicalCorrelation = null,
}) {
  const [activeTab, setActiveTab] = useState('all');
  const [expandedIoc, setExpandedIoc] = useState(null);
  const [copiedText, setCopiedText] = useState(null);

  // Extract from historicalCorrelation or correlation.historical_stats
  const stats = historicalCorrelation || correlation.historical_stats || {};
  const isNewCategory = stats.is_new_category ?? correlation.is_new_campaign ?? true;
  const categoryStatus = stats.category_status || (isNewCategory ? 'NEW_THREAT_CLUSTER' : 'RECURRING_ADVERSARY_ACTIVITY');
  const categoryBadge = stats.category_badge || (isNewCategory ? 'NEW THREAT CATEGORY' : 'RECURRING THREAT');
  const campaignId = stats.assigned_campaign_id || correlation.campaign_id || 'campaign_001';
  const executiveSummary = stats.executive_summary || (
    isNewCategory
      ? `New Threat Cluster Identified. Zero prior occurrences of these indicators found in the database. A new category has been initialized (${campaignId}).`
      : `Recurring adversary activity detected. Infrastructure matches prior incidents in category ${campaignId}.`
  );

  const metrics = stats.metrics_summary || {
    total_overlapping_iocs: correlation.shared_infrastructure?.length || 0,
    total_prior_incidents: correlation.related_emails?.length || 0,
    max_repetition_this_week: isNewCategory ? 0 : 1,
    max_repetition_this_month: isNewCategory ? 0 : 1,
  };

  const indicators = stats.indicators || [];

  const filteredIndicators = indicators.filter((ind) => {
    if (activeTab === 'all') return true;
    if (activeTab === 'ips') return ind.type === 'ip';
    if (activeTab === 'domains') return ind.type === 'domain';
    if (activeTab === 'hashes') return ind.type === 'hash';
    if (activeTab === 'urls') return ind.type === 'url';
    return true;
  });

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const toggleExpand = (val) => {
    setExpandedIoc(expandedIoc === val ? null : val);
  };

  const statusColor = isNewCategory ? '#10B981' : '#E8A23D';
  const statusBg = isNewCategory ? 'rgba(16, 185, 129, 0.12)' : 'rgba(232, 162, 61, 0.14)';
  const statusBorder = isNewCategory ? 'rgba(16, 185, 129, 0.3)' : 'rgba(232, 162, 61, 0.35)';

  return (
    <div className="forensic-panel" style={{ position: 'relative' }}>
      {/* Panel Header */}
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">Database Correlation &amp; Indicator Repetition</span>
          <span className="panel-subtitle">
            Historical MongoDB Comparison &bull; Weekly/Monthly Repetition &bull; Category Tracking
          </span>
        </div>

        {/* Category Status Pill */}
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            backgroundColor: statusBg,
            border: `1px solid ${statusBorder}`,
            borderRadius: 'var(--radius-sm)',
            padding: '4px 12px',
            fontFamily: 'var(--font-mono)',
            fontSize: 'var(--fs-micro)',
            fontWeight: 600,
            color: statusColor,
            letterSpacing: '0.04em',
          }}
        >
          <span
            style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: statusColor,
              boxShadow: `0 0 8px ${statusColor}`,
            }}
          />
          {categoryBadge} &bull; {campaignId.toUpperCase()}
        </div>
      </div>

      {/* Executive Threat Summary Banner */}
      <div
        style={{
          backgroundColor: 'var(--bg-surface-elevated)',
          borderLeft: `4px solid ${statusColor}`,
          borderTop: '1px solid var(--border-hairline)',
          borderRight: '1px solid var(--border-hairline)',
          borderBottom: '1px solid var(--border-hairline)',
          borderRadius: 'var(--radius-xs)',
          padding: '14px 18px',
          marginBottom: '16px',
          display: 'flex',
          gap: '14px',
          alignItems: 'flex-start',
        }}
      >
        <div
          style={{
            color: statusColor,
            fontSize: '18px',
            marginTop: '2px',
          }}
        >
          {isNewCategory ? '🛡️' : '⚠️'}
        </div>
        <div style={{ flex: 1 }}>
          <div
            style={{
              fontSize: 'var(--fs-micro)',
              color: 'var(--text-muted)',
              fontFamily: 'var(--font-mono)',
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              marginBottom: '4px',
            }}
          >
            {isNewCategory ? 'NEW THREAT CLUSTER CLASSIFICATION' : 'RECURRING INFRASTRUCTURE INTELLIGENCE'}
          </div>
          <div
            style={{
              fontSize: 'var(--fs-sm)',
              color: 'var(--text-primary)',
              lineHeight: 1.5,
              fontWeight: 500,
            }}
          >
            {executiveSummary}
          </div>
        </div>
      </div>

      {/* Metrics Cards Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '12px',
          marginBottom: '18px',
        }}
      >
        <div
          style={{
            backgroundColor: 'var(--bg-surface-subtle)',
            border: '1px solid var(--border-hairline)',
            borderRadius: 'var(--radius-xs)',
            padding: '12px 14px',
          }}
        >
          <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            OVERLAPPING IOCs
          </div>
          <div style={{ fontSize: 'var(--fs-xl)', fontWeight: 700, color: '#E8EAF0', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {metrics.total_overlapping_iocs}
          </div>
          <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Indicators seen in prior records
          </div>
        </div>

        <div
          style={{
            backgroundColor: 'var(--bg-surface-subtle)',
            border: '1px solid var(--border-hairline)',
            borderRadius: 'var(--radius-xs)',
            padding: '12px 14px',
          }}
        >
          <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            PRIOR INCIDENTS
          </div>
          <div style={{ fontSize: 'var(--fs-xl)', fontWeight: 700, color: metrics.total_prior_incidents > 0 ? '#E8A23D' : '#8B92A5', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {metrics.total_prior_incidents}
          </div>
          <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Historical emails sharing indicators
          </div>
        </div>

        <div
          style={{
            backgroundColor: 'var(--bg-surface-subtle)',
            border: '1px solid var(--border-hairline)',
            borderRadius: 'var(--radius-xs)',
            padding: '12px 14px',
          }}
        >
          <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            SEEN THIS WEEK (7D)
          </div>
          <div style={{ fontSize: 'var(--fs-xl)', fontWeight: 700, color: metrics.max_repetition_this_week > 0 ? '#EF4444' : '#10B981', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {metrics.max_repetition_this_week}x
          </div>
          <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Max recurrence past 7 days
          </div>
        </div>

        <div
          style={{
            backgroundColor: 'var(--bg-surface-subtle)',
            border: '1px solid var(--border-hairline)',
            borderRadius: 'var(--radius-xs)',
            padding: '12px 14px',
          }}
        >
          <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            SEEN THIS MONTH (30D)
          </div>
          <div style={{ fontSize: 'var(--fs-xl)', fontWeight: 700, color: metrics.max_repetition_this_month > 0 ? '#E8A23D' : '#8B92A5', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            {metrics.max_repetition_this_month}x
          </div>
          <div style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Max recurrence past 30 days
          </div>
        </div>
      </div>

      {/* Tabs Filter */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', alignItems: 'center' }}>
        <span style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginRight: '4px' }}>
          FILTER BY TYPE:
        </span>
        {['all', 'ips', 'domains', 'hashes', 'urls'].map((tab) => (
          <button
            key={tab}
            type="button"
            className={`nav-button ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
            style={{
              fontSize: 'var(--fs-micro)',
              padding: '3px 10px',
              textTransform: 'uppercase',
              fontFamily: 'var(--font-mono)',
            }}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Indicator Repetition List */}
      {filteredIndicators.length === 0 ? (
        <div
          style={{
            padding: '24px',
            textAlign: 'center',
            color: 'var(--text-muted)',
            fontSize: 'var(--fs-sm)',
            fontFamily: 'var(--font-mono)',
            backgroundColor: 'var(--bg-surface-subtle)',
            border: '1px dashed var(--border-hairline)',
            borderRadius: 'var(--radius-xs)',
          }}
        >
          No extracted indicators match the selected filter.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {filteredIndicators.map((ind, idx) => {
            const hasMatches = ind.all_time > 0;
            const isExpanded = expandedIoc === ind.value;

            return (
              <div
                key={`${ind.type}-${ind.value}-${idx}`}
                style={{
                  backgroundColor: 'var(--bg-surface-subtle)',
                  border: `1px solid ${hasMatches ? 'var(--border-hairline)' : 'rgba(42, 47, 61, 0.6)'}`,
                  borderRadius: 'var(--radius-xs)',
                  padding: '10px 14px',
                  transition: 'border-color 0.2s',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '8px',
                  }}
                >
                  {/* Left: Type tag and indicator value */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: '280px', flex: 1 }}>
                    <span
                      style={{
                        fontSize: 'var(--fs-micro)',
                        fontFamily: 'var(--font-mono)',
                        padding: '2px 6px',
                        borderRadius: 'var(--radius-xs)',
                        textTransform: 'uppercase',
                        fontWeight: 600,
                        backgroundColor:
                          ind.type === 'ip'
                            ? 'rgba(239, 68, 68, 0.15)'
                            : ind.type === 'domain'
                            ? 'rgba(16, 185, 129, 0.15)'
                            : ind.type === 'hash'
                            ? 'rgba(139, 92, 246, 0.15)'
                            : 'rgba(59, 130, 246, 0.15)',
                        color:
                          ind.type === 'ip'
                            ? '#EF4444'
                            : ind.type === 'domain'
                            ? '#10B981'
                            : ind.type === 'hash'
                            ? '#A78BFA'
                            : '#3B82F6',
                        border: '1px solid currentColor',
                      }}
                    >
                      {ind.type}
                    </span>

                    <span
                      className="font-mono"
                      style={{
                        fontSize: 'var(--fs-xs)',
                        color: '#E8EAF0',
                        fontWeight: 600,
                        wordBreak: 'break-all',
                      }}
                      title={ind.value}
                    >
                      {ind.value}
                    </span>

                    <button
                      type="button"
                      onClick={() => handleCopy(ind.value)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: copiedText === ind.value ? '#10B981' : 'var(--text-muted)',
                        cursor: 'pointer',
                        fontSize: 'var(--fs-micro)',
                        fontFamily: 'var(--font-mono)',
                        padding: '2px 4px',
                      }}
                      title="Copy indicator"
                    >
                      {copiedText === ind.value ? 'COPIED' : 'COPY'}
                    </button>
                  </div>

                  {/* Right: Repetition badges & Flyout toggle */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {hasMatches ? (
                      <>
                        <span
                          style={{
                            fontSize: 'var(--fs-micro)',
                            fontFamily: 'var(--font-mono)',
                            padding: '2px 8px',
                            borderRadius: 'var(--radius-xs)',
                            backgroundColor: ind.this_week > 0 ? 'rgba(239, 68, 68, 0.18)' : 'var(--bg-surface-elevated)',
                            color: ind.this_week > 0 ? '#EF4444' : 'var(--text-secondary)',
                            border: `1px solid ${ind.this_week > 0 ? '#EF4444' : 'var(--border-hairline)'}`,
                            fontWeight: 600,
                          }}
                        >
                          WEEK: {ind.this_week}x
                        </span>

                        <span
                          style={{
                            fontSize: 'var(--fs-micro)',
                            fontFamily: 'var(--font-mono)',
                            padding: '2px 8px',
                            borderRadius: 'var(--radius-xs)',
                            backgroundColor: ind.this_month > 0 ? 'rgba(232, 162, 61, 0.18)' : 'var(--bg-surface-elevated)',
                            color: ind.this_month > 0 ? '#E8A23D' : 'var(--text-secondary)',
                            border: `1px solid ${ind.this_month > 0 ? '#E8A23D' : 'var(--border-hairline)'}`,
                            fontWeight: 600,
                          }}
                        >
                          MONTH: {ind.this_month}x
                        </span>

                        <span
                          style={{
                            fontSize: 'var(--fs-micro)',
                            fontFamily: 'var(--font-mono)',
                            padding: '2px 8px',
                            borderRadius: 'var(--radius-xs)',
                            backgroundColor: 'var(--bg-surface-elevated)',
                            color: 'var(--text-primary)',
                            border: '1px solid var(--border-hairline)',
                          }}
                        >
                          TOTAL: {ind.all_time}
                        </span>

                        {ind.prior_incidents && ind.prior_incidents.length > 0 && (
                          <button
                            type="button"
                            className="btn-ghost"
                            onClick={() => toggleExpand(ind.value)}
                            style={{
                              fontSize: 'var(--fs-micro)',
                              fontFamily: 'var(--font-mono)',
                              padding: '3px 8px',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                            }}
                          >
                            {isExpanded ? 'HIDE EMAILS ▲' : `SHOW EMAILS (${ind.prior_incidents.length}) ▼`}
                          </button>
                        )}
                      </>
                    ) : (
                      <span
                        style={{
                          fontSize: 'var(--fs-micro)',
                          fontFamily: 'var(--font-mono)',
                          padding: '2px 8px',
                          borderRadius: 'var(--radius-xs)',
                          backgroundColor: 'rgba(16, 185, 129, 0.1)',
                          color: '#10B981',
                          border: '1px solid rgba(16, 185, 129, 0.3)',
                          fontWeight: 600,
                        }}
                      >
                        FIRST TIME SEEN (NEW)
                      </span>
                    )}
                  </div>
                </div>

                {/* Expanded Prior Incidents List */}
                {isExpanded && ind.prior_incidents && ind.prior_incidents.length > 0 && (
                  <div
                    style={{
                      marginTop: '12px',
                      paddingTop: '10px',
                      borderTop: '1px dashed var(--border-hairline)',
                    }}
                  >
                    <div
                      style={{
                        fontSize: 'var(--fs-micro)',
                        color: 'var(--text-muted)',
                        fontFamily: 'var(--font-mono)',
                        marginBottom: '8px',
                        textTransform: 'uppercase',
                      }}
                    >
                      Prior Analyzed Emails Containing "{ind.value}":
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {ind.prior_incidents.map((inc, incIdx) => (
                        <div
                          key={`${inc.id}-${incIdx}`}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            backgroundColor: 'var(--bg-surface-elevated)',
                            padding: '6px 10px',
                            borderRadius: 'var(--radius-xs)',
                            fontSize: 'var(--fs-xs)',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, overflow: 'hidden' }}>
                            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-amber)', fontSize: 'var(--fs-micro)' }}>
                              #{inc.id.substring(0, 8)}
                            </span>
                            <span style={{ color: 'var(--text-primary)', fontWeight: 500, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                              {inc.subject || 'No Subject'}
                            </span>
                            <span style={{ color: 'var(--text-muted)', fontSize: 'var(--fs-micro)', whiteSpace: 'nowrap' }}>
                              ({inc.from_email})
                            </span>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            {inc.analyzed_at && (
                              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--fs-micro)', color: 'var(--text-muted)' }}>
                                {new Date(inc.analyzed_at).toLocaleDateString()}
                              </span>
                            )}
                            {inc.verdict && (
                              <span
                                style={{
                                  fontSize: 'var(--fs-micro)',
                                  fontFamily: 'var(--font-mono)',
                                  padding: '1px 6px',
                                  borderRadius: 'var(--radius-xs)',
                                  backgroundColor: inc.verdict.includes('PHISH') || (inc.risk_score && inc.risk_score > 60)
                                    ? 'rgba(217, 83, 79, 0.2)'
                                    : 'rgba(76, 175, 125, 0.2)',
                                  color: inc.verdict.includes('PHISH') || (inc.risk_score && inc.risk_score > 60)
                                    ? '#D9534F'
                                    : '#4CAF7D',
                                  fontWeight: 600,
                                }}
                              >
                                {inc.verdict} {inc.risk_score ? `(${inc.risk_score})` : ''}
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default HistoricalCorrelationCard;
