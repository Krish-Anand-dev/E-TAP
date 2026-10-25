import React from 'react';

/**
 * TimelineCat — an animated cat mascot for the Analyze timeline.
 *
 * Pure SVG + CSS (styles in styles/v2.css, classes prefixed `kc-`). The parent
 * positions it next to the active stage; this component only draws the cat and
 * the scene for that stage. `scene` is a pipeline stage key; `mood` is
 * 'working' | 'done' | 'error'. Respects prefers-reduced-motion via CSS.
 */

const INK = '#101731';
const FUR = '#f2a65a';
const FUR_DARK = '#d9813a';
const CREAM = '#fde9cf';
const PINK = '#f7a8b8';

function Paw({ x, y, className = '', color = FUR }) {
  return <ellipse className={`kc-paw ${className}`} cx={x} cy={y} rx="5.5" ry="4.5" fill={color} stroke={INK} strokeWidth="2" />;
}

function Arm({ x1, y1, x2, y2, className = '', color = FUR }) {
  return (
    <g className={className}>
      <path d={`M${x1} ${y1} Q ${(x1 + x2) / 2 + 2} ${Math.max(y1, y2) + 4} ${x2} ${y2}`} stroke={INK} strokeWidth="9.5" fill="none" strokeLinecap="round" />
      <path d={`M${x1} ${y1} Q ${(x1 + x2) / 2 + 2} ${Math.max(y1, y2) + 4} ${x2} ${y2}`} stroke={color} strokeWidth="6" fill="none" strokeLinecap="round" />
      <Paw x={x2} y={y2} color={color} />
    </g>
  );
}

function CatBody({ armored }) {
  return (
    <g className="kc-cat">
      {/* tail */}
      <path className="kc-tail" d="M24 98 C 4 98, 2 72, 16 64" stroke={INK} strokeWidth="10" fill="none" strokeLinecap="round" />
      <path className="kc-tail" d="M24 98 C 4 98, 2 72, 16 64" stroke={FUR} strokeWidth="6.5" fill="none" strokeLinecap="round" />
      {/* body */}
      <ellipse cx="40" cy="84" rx="22" ry="18" fill={armored ? '#c62f3b' : FUR} stroke={INK} strokeWidth="2.2" />
      {!armored && <ellipse cx="41" cy="89" rx="12" ry="11" fill={CREAM} />}
      {!armored && <path d="M24 78 q4 -3 7 0 M22 86 q4 -3 7 0" stroke={FUR_DARK} strokeWidth="2.2" fill="none" strokeLinecap="round" />}
      {armored && (
        <g>
          <path d="M26 76 Q40 70 54 76 L52 96 Q40 100 28 96 Z" fill="#e8b23e" stroke={INK} strokeWidth="1.6" />
          <circle className="kc-reactor" cx="40" cy="84" r="5" fill="#9be7ff" stroke={INK} strokeWidth="1.4" />
        </g>
      )}
      {/* feet */}
      <ellipse cx="29" cy="101" rx="8" ry="4.5" fill={armored ? '#c62f3b' : FUR} stroke={INK} strokeWidth="2" />
      <ellipse cx="51" cy="101" rx="8" ry="4.5" fill={armored ? '#c62f3b' : FUR} stroke={INK} strokeWidth="2" />
      {/* head */}
      <g className="kc-head">
        <polygon points="21,36 25,13 39,27" fill={FUR} stroke={INK} strokeWidth="2.2" strokeLinejoin="round" />
        <polygon points="45,27 59,13 63,36" fill={FUR} stroke={INK} strokeWidth="2.2" strokeLinejoin="round" />
        <polygon points="25,30 27,19 34,26" fill={PINK} />
        <polygon points="50,26 57,19 59,30" fill={PINK} />
        <ellipse cx="42" cy="41" rx="23" ry="19" fill={FUR} stroke={INK} strokeWidth="2.2" />
        <path d="M36 24 l1 6 M42 23 v7 M48 24 l-1 6" stroke={FUR_DARK} strokeWidth="2.2" strokeLinecap="round" />
        <g className="kc-eyes">
          <ellipse cx="34" cy="41" rx="3.2" ry="4.2" fill={INK} />
          <ellipse cx="50" cy="41" rx="3.2" ry="4.2" fill={INK} />
          <circle cx="35.2" cy="39.4" r="1.1" fill="#fff" />
          <circle cx="51.2" cy="39.4" r="1.1" fill="#fff" />
        </g>
        <circle cx="28" cy="48" r="3" fill={PINK} opacity=".7" />
        <circle cx="56" cy="48" r="3" fill={PINK} opacity=".7" />
        <path d="M40 46.5 h4 l-2 2.4 z" fill="#e0607a" stroke={INK} strokeWidth="1" strokeLinejoin="round" />
        <path d="M42 49 q-2.5 3.5 -5 1.2 M42 49 q2.5 3.5 5 1.2" stroke={INK} strokeWidth="1.5" fill="none" strokeLinecap="round" />
        <path d="M22 45 h-9 M22 49 l-8 2 M62 45 h9 M62 49 l8 2" stroke={INK} strokeWidth="1.2" strokeLinecap="round" opacity=".7" />
      </g>
    </g>
  );
}

/* ---------- per-stage scenes (props on the right of the cat) ---------- */

function SceneBook() {
  return (
    <g>
      <g className="kc-book">
        <path d="M60 64 L84 70 L84 94 L60 88 Z" fill="#fff" stroke={INK} strokeWidth="2" strokeLinejoin="round" />
        <path d="M84 70 L108 64 L108 88 L84 94 Z" fill="#fff" stroke={INK} strokeWidth="2" strokeLinejoin="round" />
        <path d="M64 72 l16 4 M64 77 l16 4 M64 82 l12 3 M88 76 l16 -4 M88 81 l16 -4 M88 86 l10 -2.5" stroke="#9aa3b5" strokeWidth="1.4" strokeLinecap="round" />
        <path className="kc-page" d="M84 70 L104 65 L104 89 L84 94 Z" fill="#fdf3e2" stroke={INK} strokeWidth="1.6" strokeLinejoin="round" />
        <rect x="58" y="86" width="52" height="5" rx="2" fill="#cc3542" stroke={INK} strokeWidth="1.6" transform="skewY(-3)" />
      </g>
      <Arm x1={52} y1={76} x2={62} y2={84} />
    </g>
  );
}

function SceneMagnifier() {
  return (
    <g>
      <g opacity=".85">
        <rect x="76" y="34" width="52" height="34" rx="4" fill="#fff" stroke={INK} strokeWidth="1.8" />
        <path d="M82 42 h30 M82 48 h38 M82 54 h26 M82 60 h34" stroke="#c4c9d4" strokeWidth="2.2" strokeLinecap="round" />
        <path d="M82 48 h16" stroke="#cc3542" strokeWidth="2.2" strokeLinecap="round" />
      </g>
      <g className="kc-mag">
        <line x1="88" y1="62" x2="74" y2="78" stroke="#7a4f2a" strokeWidth="6" strokeLinecap="round" />
        <circle cx="96" cy="52" r="13" fill="rgba(155,231,255,.35)" stroke={INK} strokeWidth="3.2" />
        <path d="M89 46 q4 -5 10 -4" stroke="#fff" strokeWidth="2.4" fill="none" strokeLinecap="round" />
        <Paw x={74} y={78} />
      </g>
      <path d="M54 76 Q66 82 72 78" stroke={INK} strokeWidth="9.5" fill="none" strokeLinecap="round" />
      <path d="M54 76 Q66 82 72 78" stroke={FUR} strokeWidth="6" fill="none" strokeLinecap="round" />
    </g>
  );
}

function Document({ className = '' }) {
  return (
    <g className={className}>
      <path d="M80 28 H110 L120 38 V86 H80 Z" fill="#fff" stroke={INK} strokeWidth="2" strokeLinejoin="round" />
      <path d="M110 28 V38 H120" fill="#eef0f5" stroke={INK} strokeWidth="1.8" strokeLinejoin="round" />
      <rect x="84" y="44" width="26" height="12" rx="2.5" fill="#cc3542" />
      <text x="97" y="53.4" textAnchor="middle" fontSize="9" fontWeight="800" fill="#fff" fontFamily="Inter, sans-serif">PDF</text>
      <path d="M85 64 h28 M85 70 h24 M85 76 h28" stroke="#c4c9d4" strokeWidth="2" strokeLinecap="round" />
    </g>
  );
}

function SceneScratch() {
  return (
    <g>
      <Document />
      <g className="kc-claws">
        <path className="kc-claw" d="M88 36 L106 70" />
        <path className="kc-claw" d="M95 33 L113 67" />
        <path className="kc-claw" d="M102 31 L118 61" />
      </g>
      <g className="kc-swipe">
        <path d="M52 74 Q70 66 84 52" stroke={INK} strokeWidth="9.5" fill="none" strokeLinecap="round" />
        <path d="M52 74 Q70 66 84 52" stroke={FUR} strokeWidth="6" fill="none" strokeLinecap="round" />
        <Paw x={85} y={51} />
        <path d="M88 47 l3 -3 M90 51 l4 -1 M89 55 l3 2" stroke={INK} strokeWidth="1.6" strokeLinecap="round" />
      </g>
    </g>
  );
}

function SceneTear() {
  return (
    <g>
      <g className="kc-half-left">
        <path d="M80 28 H99 L95 40 L101 50 L94 60 L100 72 L96 86 H80 Z" fill="#fff" stroke={INK} strokeWidth="2" strokeLinejoin="round" />
        <rect x="84" y="44" width="11" height="12" rx="2" fill="#cc3542" />
        <path d="M85 66 h9 M85 72 h8" stroke="#c4c9d4" strokeWidth="2" strokeLinecap="round" />
      </g>
      <g className="kc-half-right">
        <path d="M99 28 H110 L120 38 V86 H96 L100 72 L94 60 L101 50 L95 40 Z" fill="#fff" stroke={INK} strokeWidth="2" strokeLinejoin="round" />
        <rect x="100" y="44" width="10" height="12" rx="2" fill="#cc3542" />
        <path d="M102 66 h12 M102 72 h10" stroke="#c4c9d4" strokeWidth="2" strokeLinecap="round" />
      </g>
      <g className="kc-bits">
        <rect x="97" y="22" width="4" height="4" fill="#fff" stroke={INK} strokeWidth="1" />
        <rect x="104" y="18" width="3" height="3" fill="#cc3542" />
        <rect x="92" y="16" width="3" height="3" fill="#fff" stroke={INK} strokeWidth="1" />
      </g>
      <Arm x1={52} y1={74} x2={80} y2={58} className="kc-tug" />
    </g>
  );
}

function SceneLinks() {
  const link = (x) => <rect key={x} x={x} y="56" width="18" height="10" rx="5" fill="none" stroke="#5b6b8c" strokeWidth="3" />;
  return (
    <g>
      <g className="kc-chain">
        {[66, 80, 94, 108, 122].map(link)}
        <circle cx="136" cy="61" r="5" fill="#cc3542" stroke={INK} strokeWidth="1.6" />
      </g>
      <Arm x1={52} y1={76} x2={68} y2={62} className="kc-pull" />
    </g>
  );
}

function SceneComputer() {
  return (
    <g>
      <g className="kc-globe-wrap">
        <circle cx="120" cy="24" r="14" fill="#e3f2ff" stroke={INK} strokeWidth="2" />
        <ellipse className="kc-meridian" cx="120" cy="24" rx="6" ry="14" fill="none" stroke="#3b82c4" strokeWidth="1.6" />
        <path d="M106 24 h28 M108 16 h24 M108 32 h24" stroke="#3b82c4" strokeWidth="1.4" />
      </g>
      <path className="kc-wire" d="M98 58 C 104 48, 104 40, 108 34" />
      <path className="kc-wire kc-wire-2" d="M90 58 C 96 40, 100 30, 106 26" />
      <path d="M62 60 H98 V82 H62 Z" fill={INK} stroke={INK} strokeWidth="2" strokeLinejoin="round" />
      <rect className="kc-screen" x="65" y="63" width="30" height="16" rx="1.5" fill="#7dd3fc" />
      <path d="M68 68 h12 M68 72 h18 M68 76 h9" stroke="#0b3a5a" strokeWidth="1.5" strokeLinecap="round" />
      <path d="M56 82 H104 L100 90 H60 Z" fill="#c4c9d4" stroke={INK} strokeWidth="2" strokeLinejoin="round" />
      <Paw x={66} y={86} className="kc-type-a" />
      <Paw x={58} y={88} className="kc-type-b" />
    </g>
  );
}

function SceneBoard() {
  return (
    <g>
      <rect x="72" y="20" width="62" height="50" rx="4" fill="#c9935b" stroke="#7a4f2a" strokeWidth="3" />
      <rect x="78" y="26" width="16" height="12" fill="#fff" stroke={INK} strokeWidth="1.3" transform="rotate(-6 86 32)" />
      <rect x="112" y="27" width="16" height="12" fill="#fff" stroke={INK} strokeWidth="1.3" transform="rotate(5 120 33)" />
      <rect x="94" y="48" width="16" height="12" fill="#fff" stroke={INK} strokeWidth="1.3" transform="rotate(-3 102 54)" />
      <path d="M81 31 h10 M115 32 h10 M97 53 h10" stroke="#9aa3b5" strokeWidth="1.4" />
      <polyline className="kc-string" points="86,28 120,29 102,50 86,28" />
      <circle cx="86" cy="28" r="2.6" fill="#cc3542" stroke={INK} strokeWidth="1" />
      <circle cx="120" cy="29" r="2.6" fill="#cc3542" stroke={INK} strokeWidth="1" />
      <circle cx="102" cy="50" r="2.6" fill="#cc3542" stroke={INK} strokeWidth="1" />
      <g className="kc-pointer">
        <line x1="64" y1="72" x2="98" y2="48" stroke="#7a4f2a" strokeWidth="2.6" strokeLinecap="round" />
        <Arm x1={52} y1={76} x2={64} y2={72} />
      </g>
    </g>
  );
}

function SceneSuit() {
  return (
    <g>
      <g className="kc-helmet">
        <path d="M18 40 C 18 16, 66 16, 66 40 C 66 58, 54 62, 42 62 C 30 62, 18 58, 18 40 Z" fill="#c62f3b" stroke={INK} strokeWidth="2.2" />
        <path d="M26 36 C 30 30, 54 30, 58 36 L56 54 C 50 58, 34 58, 28 54 Z" fill="#e8b23e" stroke={INK} strokeWidth="1.6" />
        <path className="kc-visor" d="M30 41 l8 -1 l-1 3 l-7 0 z M54 41 l-8 -1 l1 3 l7 0 z" fill="#9be7ff" />
        <path d="M36 50 h12" stroke={INK} strokeWidth="1.4" strokeLinecap="round" />
      </g>
      <g className="kc-thrust">
        <path d="M24 106 l5 10 l5 -10 z" fill="#ffb347" />
        <path d="M46 106 l5 10 l5 -10 z" fill="#ffb347" />
      </g>
      <g>
        <circle className="kc-hud" cx="104" cy="44" r="18" fill="none" stroke="#3bb9e6" strokeWidth="1.6" strokeDasharray="4 3" />
        <circle cx="104" cy="44" r="10" fill="none" stroke="#3bb9e6" strokeWidth="1.2" />
        <text x="104" y="48" textAnchor="middle" fontSize="10" fontWeight="800" fill="#1e7fa8" fontFamily="Inter, sans-serif">AI</text>
      </g>
      <Arm x1={54} y1={76} x2={74} y2={60} className="kc-repulsor-arm" color="#c62f3b" />
      <circle className="kc-repulsor" cx="77" cy="58" r="4" fill="#9be7ff" />
    </g>
  );
}

function SceneNotebook({ done }) {
  return (
    <g>
      <g transform="rotate(-6 88 76)">
        <rect x="64" y="58" width="48" height="36" rx="3" fill="#fff" stroke={INK} strokeWidth="2" />
        <path d="M64 58 v36" stroke="#cc3542" strokeWidth="3" />
        {[66, 74, 82, 90].map((y) => <circle key={y} cx="64" cy={y} r="1.6" fill={INK} />)}
        <path className="kc-write kc-write-1" d="M72 66 h32" />
        <path className="kc-write kc-write-2" d="M72 74 h26" />
        <path className="kc-write kc-write-3" d="M72 82 h30" />
        {done && <path className="kc-tick" d="M94 84 l5 5 l10 -12" />}
      </g>
      <g className="kc-pencil">
        <path d="M84 64 L104 50 L108 55 L88 69 Z" fill="#e8b23e" stroke={INK} strokeWidth="1.6" strokeLinejoin="round" />
        <path d="M84 64 L80 71 L88 69 Z" fill="#fde9cf" stroke={INK} strokeWidth="1.4" strokeLinejoin="round" />
        <Arm x1={52} y1={76} x2={88} y2={66} />
      </g>
    </g>
  );
}

const SCENES = {
  parse: SceneBook,
  headers: SceneMagnifier,
  static_attachments: SceneScratch,
  sandbox: SceneTear,
  indicators: SceneLinks,
  reputation: SceneComputer,
  history: SceneBoard,
  ai: SceneSuit,
  verdict: SceneNotebook,
};

export default function TimelineCat({ scene = 'parse', mood = 'working' }) {
  const Scene = SCENES[scene] || SceneBook;
  return (
    <svg className={`kc-svg kc-scene-${scene} kc-mood-${mood}`} viewBox="0 -6 142 128" role="img" aria-label={`Cat mascot: ${scene.replace(/_/g, ' ')}`}>
      <ellipse className="kc-shadow" cx="42" cy="110" rx="26" ry="4" fill="rgba(16,23,49,.12)" />
      <g className="kc-bob">
        <CatBody armored={scene === 'ai'} />
        <Scene done={mood === 'done'} />
      </g>
      {mood === 'done' && (
        <g className="kc-hearts">
          <path d="M70 14 c-3 -5 -10 -1 -6 4 l6 5 l6 -5 c4 -5 -3 -9 -6 -4 z" fill="#f17e92" />
          <path d="M14 22 c-2 -3 -7 -1 -4 3 l4 3 l4 -3 c3 -4 -2 -6 -4 -3 z" fill="#f17e92" />
        </g>
      )}
    </svg>
  );
}
