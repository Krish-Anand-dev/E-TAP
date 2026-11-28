import test from 'node:test';
import assert from 'node:assert/strict';
import { SCENE_SECONDS, sceneAt } from '../src/utils/phishingScene.js';
import { dismissWhatsAppNotice, shouldShowWelcome, shouldShowWhatsAppNotice } from '../src/utils/welcome.js';
import { applyTheme, chooseTheme, themeFor, timeTheme } from '../src/utils/theme.js';

const memory = () => {
  const data = new Map();
  return { getItem: (k) => data.get(k) ?? null, setItem: (k, v) => data.set(k, v) };
};
const blocked = { getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); } };

test('the scene lasts no longer than six seconds', () => {
  assert.ok(SCENE_SECONDS >= 5 && SCENE_SECONDS <= 6);
});

test('the boat arrives, both cards come up, and the boat leaves', () => {
  const start = sceneAt(0);
  assert.ok(start.boat < 0 && start.cards.every((c) => c.lift === 0 && c.line === 0));
  const middle = sceneAt(2.6);
  assert.equal(middle.boat, 0.5);
  assert.ok(middle.fishing && middle.cards[0].lift > middle.cards[1].lift);
  const end = sceneAt(SCENE_SECONDS);
  assert.ok(end.done && end.boat > 1.2);
  assert.ok(end.cards.every((c) => c.lift === 1 && c.line === 0));
});

test('cards only ever rise, and are all up before the boat has gone', () => {
  let last = [0, 0];
  for (let t = 0; t <= SCENE_SECONDS; t += 0.05) {
    const now = sceneAt(t).cards.map((c) => c.lift);
    now.forEach((lift, i) => assert.ok(lift >= last[i]));
    last = now;
  }
  assert.deepEqual(sceneAt(4).cards.map((c) => c.lift), [1, 1]);
});

test('the welcome page shows on every visit, except a direct link to a report', () => {
  assert.equal(shouldShowWelcome(), true);
  assert.equal(shouldShowWelcome(''), true);
  assert.equal(shouldShowWelcome('?dossier=abc'), false);
});

test('the WhatsApp notice shows to visitors and unlinked accounts, until closed', () => {
  const storage = memory();
  const email = 'a@b.test';
  assert.equal(shouldShowWhatsAppNotice({ email: null, storage }), true);
  dismissWhatsAppNotice(null, storage);
  assert.equal(shouldShowWhatsAppNotice({ email: null, storage }), false);
  assert.equal(shouldShowWhatsAppNotice({ email, link: { linked: true }, storage }), false);
  assert.equal(shouldShowWhatsAppNotice({ email, link: undefined, storage }), false);
  assert.equal(shouldShowWhatsAppNotice({ email, link: { linked: false }, storage }), true);
  dismissWhatsAppNotice(email, storage);
  assert.equal(shouldShowWhatsAppNotice({ email, link: { linked: false }, storage }), false);
});

const at = (day, hour, minute = 0) => new Date(2026, 10, day, hour, minute);

test('day from 6 am to 6 pm, night otherwise', () => {
  assert.equal(timeTheme(at(28, 5, 59)), 'dark');
  assert.equal(timeTheme(at(28, 6)), 'light');
  assert.equal(timeTheme(at(28, 17, 59)), 'light');
  assert.equal(timeTheme(at(28, 18)), 'dark');
  assert.equal(timeTheme(at(28, 0)), 'dark');
});

test('the switch wins until the next 6 o\'clock, then the clock takes over', () => {
  const storage = memory();
  chooseTheme('dark', at(28, 10), storage);
  assert.equal(themeFor(at(28, 17, 59), storage), 'dark');
  assert.equal(themeFor(at(29, 10), storage), 'light');
  chooseTheme('light', at(28, 23), storage);
  assert.equal(themeFor(at(29, 5, 59), storage), 'light'); // the same night, past midnight
  assert.equal(themeFor(at(29, 18), storage), 'dark');
});

test('blocked storage follows the clock and never throws', () => {
  assert.equal(themeFor(at(28, 12), blocked), 'light');
  assert.doesNotThrow(() => chooseTheme('dark', at(28, 12), blocked));
  const root = { dataset: {} };
  applyTheme('dark', root);
  assert.equal(root.dataset.theme, 'dark');
});

test('blocked browser storage never throws', () => {
  assert.equal(shouldShowWhatsAppNotice({ email: 'a@b.test', link: { linked: false }, storage: blocked }), true);
  assert.doesNotThrow(() => dismissWhatsAppNotice('a@b.test', blocked));
});
