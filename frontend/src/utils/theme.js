/**
 * Day sea or night sea. By default it follows the visitor's clock: light from 6 am to 6 pm,
 * dark after. The switch overrides that until the next 6 o'clock, then the clock takes over.
 */
const KEY = 'etap.theme';
const DAY_STARTS = 6;
const NIGHT_STARTS = 18;
export const THEME_EVENT = 'etap-theme-change';

const browserStorage = () => {
  try { return globalThis.localStorage; } catch { return null; }
};

export function timeTheme(now = new Date()) {
  const hour = now.getHours();
  return hour >= DAY_STARTS && hour < NIGHT_STARTS ? 'light' : 'dark';
}

/** Names the stretch of day or night that `now` falls in; it changes at each 6 o'clock. */
function periodOf(now) {
  const start = new Date(now);
  const hour = now.getHours();
  if (hour < DAY_STARTS) start.setDate(start.getDate() - 1);
  start.setHours(hour >= DAY_STARTS && hour < NIGHT_STARTS ? DAY_STARTS : NIGHT_STARTS, 0, 0, 0);
  return String(start.getTime());
}

export function themeFor(now = new Date(), storage = browserStorage()) {
  try {
    const [theme, period] = String(storage.getItem(KEY)).split('@');
    if ((theme === 'light' || theme === 'dark') && period === periodOf(now)) return theme;
  } catch { /* blocked storage: follow the clock */ }
  return timeTheme(now);
}

export const currentTheme = () => (globalThis.document?.documentElement.dataset.theme === 'dark' ? 'dark' : 'light');

export function applyTheme(theme, root = globalThis.document?.documentElement) {
  if (!root || root.dataset.theme === theme) return;
  root.dataset.theme = theme;
  globalThis.window?.dispatchEvent(new Event(THEME_EVENT));
}

export function chooseTheme(theme, now = new Date(), storage = browserStorage()) {
  try { storage.setItem(KEY, `${theme}@${periodOf(now)}`); } catch { /* lasts until the page is closed */ }
  applyTheme(theme);
}

/** Apply the theme now, and again when 6 o'clock passes while the page stays open. */
export function startTheme() {
  let period = periodOf(new Date());
  applyTheme(themeFor());
  setInterval(() => {
    const next = periodOf(new Date());
    if (next === period) return;
    period = next;
    applyTheme(themeFor());
  }, 30000);
}
