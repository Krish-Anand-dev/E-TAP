import React, { useState, useRef, useEffect } from 'react';
import { askSocAssistant } from '../../api/client';
import { useInvestigation } from '../../context/InvestigationContext';
import { bandFor } from '../../utils/verdict';

export function SocChatDrawer() {
  const { data } = useInvestigation();
  const [isOpen, setIsOpen] = useState(false);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [scopeMode, setScopeMode] = useState('active'); // 'active' | 'all'

  const activeEmailId = data?.email_id || data?._id;
  const activeFilename = data?.email?.filename || data?.filename || (activeEmailId ? `Incident ${String(activeEmailId).slice(-8)}` : null);
  const activeSubject = data?.email?.subject || data?.subject || '';

  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: "Hello, Analyst. I am the E-TAP SOC Assistant. Ask me anything about the currently opened email artifact, or switch scope to search across all historical database investigations.",
      sources: [],
    },
  ]);

  const messagesEndRef = useRef(null);

  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen]);

  const handleSend = async (queryText = null) => {
    const q = (queryText || input).trim();
    if (!q || isLoading) return;

    const isSingleFile = Boolean(activeEmailId && scopeMode === 'active');

    const userMsg = { role: 'user', text: q, isSingleFile };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    try {
      const res = await askSocAssistant(
        q,
        isSingleFile ? activeEmailId : null,
        isSingleFile ? data : null
      );
      const assistantMsg = {
        role: 'assistant',
        text: res.answer || 'No response returned.',
        sources: res.sources || [],
        scope: res.scope || (isSingleFile ? 'active_file' : 'all_database'),
        activeFile: isSingleFile ? (activeFilename || activeEmailId) : null,
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: `[Error querying SOC Assistant]: ${err.response?.data?.detail || err.message || 'Unable to connect to assistant endpoint.'}`,
          sources: [],
          isError: true,
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const isSingleFileActive = Boolean(activeEmailId && scopeMode === 'active');
  const suggestions = isSingleFileActive
    ? [
        "What are the MITRE ATT&CK techniques in this email?",
        "Are there suspicious attachments or QR codes?",
        "What header authentication red flags were detected?",
        "Summarize the threat verdict and recommended SOC actions",
      ]
    : [
        "Did we see any payroll phishing attacks?",
        "Show recurring threat campaigns this month",
        "List emails with failed SPF authentication",
      ];

  return (
    <>
      {/* Floating Trigger Button */}
      <button
        type="button"
        id="soc-assistant-trigger-btn"
        onClick={() => setIsOpen(!isOpen)}
        style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          zIndex: 1040,
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          backgroundColor: '#1E2330',
          color: '#E8A23D',
          border: '1px solid #E8A23D',
          borderRadius: '24px',
          padding: '10px 18px',
          fontSize: '12px',
          fontWeight: 600,
          fontFamily: 'Inter, sans-serif',
          cursor: 'pointer',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.5), 0 0 10px rgba(232, 162, 61, 0.25)',
          transition: 'all 0.2s ease',
        }}
        title="Open SOC Threat Intelligence Assistant"
      >
        <span style={{ fontSize: '14px' }}>🛡️</span>
        <span>SOC Assistant (RAG)</span>
        <span
          style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: '#10B981',
            boxShadow: '0 0 6px #10B981',
          }}
        />
      </button>

      {/* Slide-out Drawer */}
      {isOpen && (
        <div
          id="soc-assistant-drawer"
          style={{
            position: 'fixed',
            bottom: '80px',
            right: '24px',
            width: '420px',
            maxWidth: 'calc(100vw - 32px)',
            height: '560px',
            maxHeight: 'calc(100vh - 120px)',
            backgroundColor: 'rgba(18, 21, 28, 0.96)',
            backdropFilter: 'blur(16px)',
            border: '1px solid var(--border-hairline)',
            borderRadius: '12px',
            boxShadow: '0 12px 40px rgba(0,0,0,0.7), 0 0 1px rgba(255,255,255,0.1)',
            zIndex: 1050,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            animation: 'fadeIn 0.2s ease',
          }}
        >
          {/* Header */}
          <div
            style={{
              padding: '14px 16px',
              borderBottom: '1px solid var(--border-hairline)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              backgroundColor: 'rgba(27, 31, 42, 0.8)',
            }}
          >
            <div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span>🛡️</span> SOC Analyst Assistant
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                {isSingleFileActive ? 'Single Artifact Deep-Dive Forensic Mode' : 'RAG Vector Engine • MongoDB Similarity Search'}
              </div>
            </div>
            <button
              type="button"
              onClick={() => setIsOpen(false)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                fontSize: '18px',
                lineHeight: 1,
                padding: '4px',
              }}
              title="Close drawer"
            >
              &times;
            </button>
          </div>

          {/* Active File / Scope Selector Bar */}
          <div
            style={{
              padding: '8px 14px',
              backgroundColor: isSingleFileActive ? 'rgba(232, 162, 61, 0.09)' : 'rgba(0, 0, 0, 0.25)',
              borderBottom: '1px solid ' + (isSingleFileActive ? 'rgba(232, 162, 61, 0.2)' : 'rgba(255, 255, 255, 0.06)'),
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '8px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              <span style={{ fontSize: '12px' }}>{isSingleFileActive ? '🎯' : '🌐'}</span>
              <span style={{ fontSize: '11px', color: isSingleFileActive ? '#E8A23D' : 'var(--text-muted)' }}>
                {activeEmailId ? (
                  isSingleFileActive ? (
                    <>Target: <strong>{activeFilename || activeSubject}</strong> (Opened File)</>
                  ) : (
                    <>Scope: <strong>All Database Records</strong></>
                  )
                ) : (
                  <>Scope: <strong>Global Database</strong> (No active email)</>
                )}
              </span>
            </div>

            {activeEmailId && (
              <div style={{ display: 'flex', gap: '4px', flexShrink: 0 }}>
                <button
                  type="button"
                  onClick={() => setScopeMode('active')}
                  style={{
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '10px',
                    fontWeight: isSingleFileActive ? 700 : 400,
                    backgroundColor: isSingleFileActive ? '#E8A23D' : 'transparent',
                    color: isSingleFileActive ? '#12151C' : 'var(--text-muted)',
                    border: '1px solid ' + (isSingleFileActive ? '#E8A23D' : 'rgba(255,255,255,0.1)'),
                    cursor: 'pointer',
                  }}
                  title="Answer strictly for the currently opened file"
                >
                  This File Only
                </button>
                <button
                  type="button"
                  onClick={() => setScopeMode('all')}
                  style={{
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '10px',
                    fontWeight: !isSingleFileActive ? 700 : 400,
                    backgroundColor: !isSingleFileActive ? '#E8A23D' : 'transparent',
                    color: !isSingleFileActive ? '#12151C' : 'var(--text-muted)',
                    border: '1px solid ' + (!isSingleFileActive ? '#E8A23D' : 'rgba(255,255,255,0.1)'),
                    cursor: 'pointer',
                  }}
                  title="Search across all historical investigations in MongoDB"
                >
                  All Database
                </button>
              </div>
            )}
          </div>

          {/* Suggestion Chips */}
          <div
            style={{
              padding: '8px 12px',
              borderBottom: '1px solid rgba(255,255,255,0.05)',
              display: 'flex',
              gap: '6px',
              overflowX: 'auto',
              whiteSpace: 'nowrap',
              backgroundColor: 'rgba(0,0,0,0.2)',
            }}
          >
            {suggestions.map((s, i) => (
              <button
                key={i}
                type="button"
                onClick={() => handleSend(s)}
                disabled={isLoading}
                style={{
                  background: 'rgba(232, 162, 61, 0.08)',
                  border: '1px solid rgba(232, 162, 61, 0.25)',
                  color: '#E8A23D',
                  padding: '3px 8px',
                  borderRadius: '10px',
                  fontSize: '10px',
                  cursor: 'pointer',
                  flexShrink: 0,
                }}
              >
                {s}
              </button>
            ))}
          </div>

          {/* Messages Canvas */}
          <div
            style={{
              flex: 1,
              padding: '14px',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            {messages.map((msg, idx) => (
              <div
                key={idx}
                style={{
                  alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start',
                  maxWidth: '88%',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px',
                }}
              >
                {msg.scope === 'active_file' && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginBottom: '2px' }}>
                    <span
                      style={{
                        fontSize: '9px',
                        fontFamily: 'JetBrains Mono',
                        padding: '1px 6px',
                        borderRadius: '4px',
                        backgroundColor: 'rgba(232, 162, 61, 0.15)',
                        color: '#E8A23D',
                        border: '1px solid rgba(232, 162, 61, 0.3)',
                      }}
                    >
                      🎯 Scoped to Opened File
                    </span>
                  </div>
                )}
                <div
                  style={{
                    padding: '10px 14px',
                    borderRadius: msg.role === 'user' ? '12px 12px 2px 12px' : '12px 12px 12px 2px',
                    backgroundColor: msg.role === 'user' ? '#E8A23D' : 'rgba(27, 31, 42, 0.9)',
                    color: msg.role === 'user' ? '#12151C' : (msg.isError ? '#EF4444' : 'var(--text-primary)'),
                    fontSize: '12px',
                    lineHeight: '1.5',
                    fontWeight: msg.role === 'user' ? 600 : 400,
                    border: msg.role === 'user' ? 'none' : '1px solid var(--border-hairline)',
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {msg.text}
                </div>

                {/* Sources badges if citations exist */}
                {msg.sources && msg.sources.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '2px' }}>
                    <span style={{ fontSize: '9px', color: 'var(--text-muted)', alignSelf: 'center' }}>
                      {msg.scope === 'active_file' ? 'Target Artifact:' : 'Cited Incidents:'}
                    </span>
                    {msg.sources.map((src, sIdx) => (
                      <span
                        key={sIdx}
                        style={{
                          fontSize: '9px',
                          fontFamily: 'JetBrains Mono',
                          padding: '1px 6px',
                          borderRadius: '8px',
                          backgroundColor: src.is_active_file ? 'rgba(232, 162, 61, 0.15)' : 'rgba(255,255,255,0.06)',
                          color: src.is_active_file ? '#E8A23D' : (bandFor({ verdict: src.verdict, riskScore: src.risk_score }) === 'danger' ? '#F87171' : '#10B981'),
                          border: src.is_active_file ? '1px solid rgba(232, 162, 61, 0.4)' : '1px solid rgba(255,255,255,0.1)',
                        }}
                        title={`Verdict: ${src.verdict} | Risk: ${src.risk_score} | Similarity: ${src.similarity}`}
                      >
                        {src.email_id}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}

            {isLoading && (
              <div
                style={{
                  alignSelf: 'flex-start',
                  padding: '8px 14px',
                  borderRadius: '12px 12px 12px 2px',
                  backgroundColor: 'rgba(27, 31, 42, 0.9)',
                  color: 'var(--text-muted)',
                  fontSize: '11px',
                  border: '1px solid var(--border-hairline)',
                  fontFamily: 'JetBrains Mono',
                }}
              >
                {isSingleFileActive ? 'Analyzing opened email telemetry with Gemini...' : 'Retrieving incidents & querying Gemini...'}
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input Bar */}
          <div
            style={{
              padding: '10px 12px',
              borderTop: '1px solid var(--border-hairline)',
              backgroundColor: 'rgba(27, 31, 42, 0.8)',
              display: 'flex',
              gap: '8px',
            }}
          >
            <input
              type="text"
              id="soc-chat-input"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={isSingleFileActive ? "Ask about this opened email (MITRE, headers, IOCs)..." : "Ask about threats across database..."}
              disabled={isLoading}
              style={{
                flex: 1,
                padding: '8px 12px',
                borderRadius: '6px',
                border: '1px solid var(--border-hairline)',
                backgroundColor: 'rgba(18, 21, 28, 0.9)',
                color: 'var(--text-primary)',
                fontSize: '12px',
                fontFamily: 'Inter, sans-serif',
                outline: 'none',
              }}
            />
            <button
              type="button"
              id="soc-chat-send-btn"
              onClick={() => handleSend()}
              disabled={isLoading || !input.trim()}
              style={{
                padding: '8px 14px',
                borderRadius: '6px',
                backgroundColor: input.trim() ? '#E8A23D' : 'rgba(255,255,255,0.1)',
                color: input.trim() ? '#12151C' : 'var(--text-muted)',
                fontWeight: 600,
                fontSize: '12px',
                border: 'none',
                cursor: input.trim() && !isLoading ? 'pointer' : 'default',
              }}
            >
              Send
            </button>
          </div>
        </div>
      )}
    </>
  );
}

export default SocChatDrawer;
