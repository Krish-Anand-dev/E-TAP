// How the Analyze timeline is revealed. "full" holds each stage on screen for a
// readable minimum time; "fast" shows the real backend progress as it happens so
// the report is available the moment the analysis finishes. The choice is a
// per-browser preference. VITE_TIMELINE_PACING=off forces "fast" for a build.
const KEY = 'etap.animationSpeed';

export const ANIMATION_SPEEDS = ['full', 'fast'];

export function animationSpeedLocked() {
  return import.meta.env?.VITE_TIMELINE_PACING === 'off';
}

export function getAnimationSpeed() {
  if (animationSpeedLocked()) return 'fast';
  try {
    return window.localStorage.getItem(KEY) === 'fast' ? 'fast' : 'full';
  } catch {
    return 'full';
  }
}

export function setAnimationSpeed(speed) {
  try {
    window.localStorage.setItem(KEY, ANIMATION_SPEEDS.includes(speed) ? speed : 'full');
  } catch { /* private mode: the choice lasts until the page is closed */ }
}
