import React, { useState, useRef, useEffect } from 'react';
import { askSocAssistant } from '../../api/client';
import { useInvestigation } from '../../context/InvestigationContext';
import { bandFor } from '../../utils/verdict';
import Icon from '../common/Icon';

/** Minimal, safe formatting for assistant answers: **bold**, _italic_, "- " lists, paragraphs. */
function inline(text) {
  return String(text).split(/(\*\*[^*]+\*\*|_[^_]+_|`[^`]+`)/g).map((part, i) => {
    if (/^\*\*[^*]+\*\*$/.test(part)) return <strong key={i}>{part.slice(2, -2)}</strong>;
    if (/^_[^_]+_$/.test(part)) return <em key={i}>{part.slice(1, -1)}</em>;
    if (/^`[^`]+`$/.test(part)) return <code key={i}>{part.slice(1, -1)}</code>;
    return part;
  });
}

function FormattedAnswer({ text }) {
  const blocks = String(text || '').split(/\n{2,}/);
  return blocks.map((block, b) => {
    const lines = block.split('\n').filter(Boolean);
    const bullets = lines.filter((l) => /^\s*[-*]\s+/.test(l));
    if (bullets.length && bullets.length === lines.length - (/^\s*[-*]\s+/.test(lines[0]) ? 0 : 1)) {
      const lead = /^\s*[-*]\s+/.test(lines[0]) ? null : lines[0];
      return <div key={b} className="chat-block">{lead && <p>{inline(lead)}</p>}<ul>{bullets.map((l, i) => <li key={i}>{inline(l.replace(/^\s*[-*]\s+/, ''))}</li>)}</ul></div>;
    }
    return <p key={b} className="chat-block">{lines.map((l, i) => <React.Fragment key={i}>{i > 0 && <br />}{inline(l)}</React.Fragment>)}</p>;
  });
}

const GREETING = 'Hi! I can explain the email you have open (why it was flagged, what to do) or search across all your past investigations.';

export function SocChatDrawer() {
  const { data } = useInvestigation();
  const [isOpen, setIsOpen] = useState(false);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [scopeMode, setScopeMode] = useState('active');
  const [messages, setMessages] = useState([{ role: 'assistant', text: GREETING, sources: [] }]);
  const endRef = useRef(null);

  const activeEmailId = data?.email_id || null;
  const activeSubject = data?.email?.subject || 'this email';
  const thisEmail = Boolean(activeEmailId && scopeMode === 'active');

  useEffect(() => { if (isOpen) endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages, isOpen]);

  const send = async (queryText) => {
    const q = (queryText ?? input).trim();
    if (!q || isLoading) return;
    setMessages((prev) => [...prev, { role: 'user', text: q }]);
    setInput('');
    setIsLoading(true);
    try {
      const res = await askSocAssistant(q, thisEmail ? activeEmailId : null);
      setMessages((prev) => [...prev, { role: 'assistant', text: res.answer || 'No response returned.', sources: res.sources || [], scope: res.scope }]);
    } catch (err) {
      setMessages((prev) => [...prev, { role: 'assistant', isError: true, sources: [], text: err.response?.data?.detail || 'The assistant could not be reached. Check that the analysis engine is online.' }]);
    } finally {
      setIsLoading(false);
    }
  };

  const suggestions = thisEmail
    ? ['Why was this email flagged?', 'Is the attachment dangerous?', 'Did the sender pass SPF, DKIM and DMARC?', 'What should I do now?']
    : ['Have we seen payroll phishing before?', 'Which recent emails were high risk?', 'Show repeat senders or campaigns'];

  return (
    <>
      <button type="button" className={`chat-launcher ${isOpen ? 'open' : ''}`} onClick={() => setIsOpen(!isOpen)} aria-expanded={isOpen} aria-controls="etap-assistant">
        <Icon name={isOpen ? 'x' : 'message'} size={18} />
        <span>Ask E-TAP</span>
      </button>

      {isOpen && (
        <section id="etap-assistant" className="chat-drawer" aria-label="E-TAP assistant">
          <header className="chat-header">
            <span className="chat-avatar"><Icon name="sparkle" size={18} /></span>
            <div>
              <strong>E-TAP Assistant</strong>
              <span>{thisEmail ? 'Answering about the open email' : 'Searching all your investigations'}</span>
            </div>
            <button type="button" className="chat-close" onClick={() => setIsOpen(false)} aria-label="Close assistant"><Icon name="x" size={18} /></button>
          </header>

          <div className="chat-scope" role="group" aria-label="Question scope">
            <button type="button" className={thisEmail ? 'active' : ''} disabled={!activeEmailId} onClick={() => setScopeMode('active')} title={activeEmailId ? activeSubject : 'Open an investigation first'}>
              <Icon name="mail" size={15} /><span>{activeEmailId ? 'This email' : 'No email open'}</span>
            </button>
            <button type="button" className={!thisEmail ? 'active' : ''} onClick={() => setScopeMode('all')}>
              <Icon name="layers" size={15} /><span>All investigations</span>
            </button>
          </div>

          <div className="chat-messages">
            {messages.map((msg, idx) => (
              <div key={idx} className={`chat-msg ${msg.role} ${msg.isError ? 'error' : ''}`}>
                <div className="chat-bubble">{msg.role === 'assistant' ? <FormattedAnswer text={msg.text} /> : msg.text}</div>
                {msg.role === 'assistant' && msg.scope === 'all_database' && msg.sources?.length > 0 && (
                  <div className="chat-sources">
                    <span>Based on</span>
                    {msg.sources.map((src, i) => (
                      <span key={i} className={`chat-source ${bandFor({ verdict: src.verdict, riskScore: src.risk_score })}`} title={`${src.verdict} · ${src.risk_score}/100`}>
                        {src.verdict} · {src.risk_score}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {isLoading && <div className="chat-msg assistant"><div className="chat-bubble chat-typing"><i /><i /><i /></div></div>}
            <div ref={endRef} />
          </div>

          <div className="chat-suggestions">
            {suggestions.map((s) => <button key={s} type="button" onClick={() => send(s)} disabled={isLoading}>{s}</button>)}
          </div>

          <form className="chat-input" onSubmit={(e) => { e.preventDefault(); send(); }}>
            <input id="soc-chat-input" value={input} onChange={(e) => setInput(e.target.value)} disabled={isLoading}
              placeholder={thisEmail ? 'Ask about this email…' : 'Ask about past investigations…'} aria-label="Your question" />
            <button type="submit" id="soc-chat-send-btn" disabled={isLoading || !input.trim()} aria-label="Send"><Icon name="send" size={17} /></button>
          </form>
        </section>
      )}
    </>
  );
}

export default SocChatDrawer;
