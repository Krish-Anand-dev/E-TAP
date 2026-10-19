import React from 'react';

// Line icons only (stroke = currentColor), so they follow each component's colour.
const paths = {
  dashboard:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z', mail:'M3 5h18v14H3z M3 6l9 7 9-7',
  chart:'M4 3v17h17 M8 15v-4 M13 15V7 M18 15v-7', shield:'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6z M8 12l3 3 5-6',
  history:'M3 11a9 9 0 1 1 2 7 M3 4v7h7 M12 7v5l3 2', search:'M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14 M15 15l6 6',
  layers:'M12 3l10 5-10 5L2 8z M2 12l10 5 10-5 M2 16l10 5 10-5', settings:'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2',
  arrow:'M5 12h14 M13 6l6 6-6 6', plus:'M12 5v14 M5 12h14', menu:'M4 6h16 M4 12h16 M4 18h16', file:'M14 3H5v18h14V8z M14 3v5h5 M8 12h8 M8 16h6', activity:'M2 12h5l3-8 4 16 3-8h5',
  check:'M5 12l5 5L20 7', x:'M6 6l12 12 M18 6L6 18', alert:'M12 3l10 18H2z M12 10v5 M12 18v.5',
  link:'M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1 M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1',
  paperclip:'M21 11l-9 9a5 5 0 0 1-7-7l9-9a3.5 3.5 0 0 1 5 5l-9 9a2 2 0 0 1-3-3l8-8',
  globe:'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M3 12h18 M12 3c3 3 3 15 0 18 M12 3c-3 3-3 15 0 18',
  clock:'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 7v5l3 2', send:'M4 12l16-8-6 16-3-7z M11 13l9-9',
  sparkle:'M12 3l2 6 6 2-6 2-2 6-2-6-6-2 6-2z', map:'M9 4l-6 2v14l6-2 6 2 6-2V4l-6 2z M9 4v14 M15 6v14',
  lock:'M6 11h12v10H6z M8 11V7a4 4 0 0 1 8 0v4', box:'M3 7l9-4 9 4v10l-9 4-9-4z M3 7l9 4 9-4 M12 11v10',
  user:'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M4 21c0-4 4-6 8-6s8 2 8 6', chevron:'M9 6l6 6-6 6',
  message:'M4 5h16v11H9l-5 4z', download:'M12 3v12 M7 10l5 5 5-5 M4 20h16', trash:'M4 7h16 M9 7V4h6v3 M6 7l1 13h10l1-13',
  copy:'M8 8h12v12H8z M4 16V4h12',
};
export default function Icon({ name, size=20, strokeWidth=1.7 }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name] || paths.shield}/></svg>;
}
