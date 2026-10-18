import React from 'react';
const paths = {
  dashboard:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z', mail:'M3 5h18v14H3z M3 6l9 7 9-7',
  chart:'M4 3v17h17 M8 15v-4 M13 15V7 M18 15v-7', shield:'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6z M8 12l3 3 5-6',
  history:'M3 11a9 9 0 1 1 2 7 M3 4v7h7 M12 7v5l3 2', search:'M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14 M15 15l6 6',
  layers:'M12 3l10 5-10 5L2 8z M2 12l10 5 10-5 M2 16l10 5 10-5', settings:'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2',
  arrow:'M5 12h14 M13 6l6 6-6 6', plus:'M12 5v14 M5 12h14', menu:'M4 6h16 M4 12h16 M4 18h16', file:'M14 3H5v18h14V8z M14 3v5h5 M8 12h8 M8 16h6', activity:'M2 12h5l3-8 4 16 3-8h5',
};
export default function Icon({ name, size=20 }) { return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name] || paths.shield}/></svg>; }
