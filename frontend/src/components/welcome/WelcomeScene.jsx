import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { SCENE_SECONDS, sceneAt } from '../../utils/phishingScene';

const SINK = 150; // how far under its place a card starts, in pixels

function Boat() {
  return (
    <svg viewBox="0 0 200 150" aria-hidden="true">
      <path d="M92 12v82" stroke="#101731" strokeWidth="3" strokeLinecap="round" />
      <path d="M89 18C62 34 48 62 44 90h45z" fill="#fffef7" stroke="#101731" strokeWidth="2.5" strokeLinejoin="round" />
      <path d="M96 26c20 14 30 36 32 56H96z" fill="#cc3542" stroke="#101731" strokeWidth="2.5" strokeLinejoin="round" />
      <path d="M92 12l22 6-22 7z" fill="#ee414d" />
      <circle cx="144" cy="74" r="9" fill="#f3b48a" stroke="#101731" strokeWidth="2.5" />
      <path d="M133 70c2-13 20-13 23 0z" fill="#e3a33a" stroke="#101731" strokeWidth="2.5" strokeLinejoin="round" />
      <path d="M134 100c0-22 20-22 20 0z" fill="#2e9e6b" stroke="#101731" strokeWidth="2.5" />
      <path d="M146 90L190 42" stroke="#7a4b22" strokeWidth="3" strokeLinecap="round" />
      <path d="M18 98h164l-22 32a14 14 0 0 1-11 6H52a14 14 0 0 1-11-6z" fill="#101731" />
      <path d="M26 108h148" stroke="#ee414d" strokeWidth="4" />
    </svg>
  );
}

function Waves({ className, fill }) {
  // Two identical halves, so sliding by half a width loops without a seam.
  const crest = 'M0 30 Q 75 6 150 30 T 300 30 T 450 30 T 600 30 T 750 30 T 900 30 T 1050 30 T 1200 30';
  return (
    <div className={`wave ${className}`} aria-hidden="true">
      {[0, 1].map((i) => (
        <svg key={i} viewBox="0 0 1200 60" preserveAspectRatio="none"><path d={`${crest} V60 H0 Z`} fill={fill} /></svg>
      ))}
    </div>
  );
}

/**
 * The welcome page's sea: headline in the sky, and a boat that fishes the `cards` out
 * of the water. It plays on every visit, also when the computer asks for reduced motion
 * (the owner's choice); a click on the scenery or the Tab key shows the end at once.
 * `footer` (the skip button) is usable from the first moment.
 */
export default function WelcomeScene({ headline, cards, footer }) {
  const [playing, setPlaying] = useState(true);
  const scene = useRef(null);
  const boat = useRef(null);
  const slots = useRef([]);
  const lines = useRef([]);
  const flag = useRef(null);
  const finish = useCallback(() => setPlaying(false), []);
  const replay = (event) => { event.stopPropagation(); setPlaying(true); };

  useLayoutEffect(() => {
    if (!playing) return undefined;
    const started = performance.now();
    let frame = 0;
    // Held here because React empties the refs before the cleanup below runs on a skip.
    const cardSlots = [...slots.current];
    const fishingLines = [...lines.current];
    const draw = () => {
      const t = (performance.now() - started) / 1000;
      const now = sceneAt(t, cards.length);
      const root = scene.current;
      const ship = boat.current;
      if (!root || !ship) return;
      const centre = now.boat * root.clientWidth;
      const bob = Math.sin(t * 4) * 3;
      ship.style.transform = `translate(${centre - ship.offsetWidth / 2}px, ${bob}px)`;
      // the end of the rod in the drawing above
      const rod = { x: centre + ship.offsetWidth * 0.45, y: ship.offsetTop + ship.offsetHeight * 0.28 + bob };
      now.cards.forEach((state, i) => {
        const card = slots.current[i];
        const line = lines.current[i];
        if (!card || !line) return;
        const down = (1 - state.lift) * SINK;
        const turn = (1 - state.lift) * (i % 2 ? 12 : -12);
        card.style.transform = `translateY(${down}px) rotate(${turn}deg) scale(${0.55 + 0.45 * state.lift})`;
        card.style.opacity = String(Math.min(1, state.lift * 3));
        card.style.visibility = state.lift > 0 ? 'visible' : 'hidden';
        const box = card.getBoundingClientRect();
        const base = root.getBoundingClientRect();
        // offsetTop ignores transforms, so it is the card's resting place
        const hook = { x: box.left - base.left + box.width / 2, y: card.offsetParent.offsetTop + card.offsetTop + down };
        const x = rod.x + (hook.x - rod.x) * state.line;
        const y = rod.y + (hook.y - rod.y) * state.line;
        line.setAttribute('d', state.line > 0 ? `M${rod.x} ${rod.y} Q ${rod.x} ${rod.y + (y - rod.y) * 0.85} ${x} ${y}` : '');
      });
      if (flag.current) flag.current.style.opacity = now.fishing ? '1' : '0';
      if (now.done) finish();
      else frame = requestAnimationFrame(draw);
    };
    draw();
    // A hidden tab pauses animation frames; never leave the cards under water because of that.
    const backstop = setTimeout(finish, (SCENE_SECONDS + 1) * 1000);
    return () => {
      cancelAnimationFrame(frame);
      clearTimeout(backstop);
      cardSlots.forEach((card) => card?.removeAttribute('style'));
      fishingLines.forEach((line) => line?.setAttribute('d', ''));
    };
  }, [playing, cards.length, finish]);

  useEffect(() => {
    if (!playing) return undefined;
    const onKey = (event) => { if (event.key === 'Tab') finish(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [playing, finish]);

  return (
    <div className={`welcome ${playing ? 'is-playing' : ''}`} ref={scene}
      onClick={(event) => { if (playing && !event.target.closest('button, input, a')) finish(); }}>
      <div className="welcome-sky">
        <div className="welcome-brand">E-TAP<span>EMAIL THREAT ANALYSIS</span></div>
        <div className="sun" aria-hidden="true" />
        <div className="cloud cloud-a" aria-hidden="true" />
        <div className="cloud cloud-b" aria-hidden="true" />
        <div className="welcome-headline">{headline}</div>
        <div className="far-boat far-a" aria-hidden="true" />
        <div className="far-boat far-b" aria-hidden="true" />
        {playing && (
          <div className="phisher" ref={boat} aria-hidden="true">
            <span className="phisher-flag" ref={flag}>gone phishing</span>
            <Boat />
          </div>
        )}
      </div>
      <div className="welcome-sea">
        <Waves className="wave-back" fill="#8cc4dd" />
        <Waves className="wave-front" fill="#5ea9cc" />
        <div className="welcome-cards">
          {cards.map((card, i) => (
            <div className="welcome-slot" key={card.key} ref={(el) => { slots.current[i] = el; }}>{card}</div>
          ))}
        </div>
        <div className="welcome-footer">
          {footer}
          {!playing && <button type="button" className="welcome-replay" onClick={replay}>Play it again</button>}
        </div>
      </div>
      <svg className="fishing-lines" aria-hidden="true">
        {cards.map((card, i) => <path key={card.key} ref={(el) => { lines.current[i] = el; }} d="" />)}
      </svg>
    </div>
  );
}
