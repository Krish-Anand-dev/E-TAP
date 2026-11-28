import test from 'node:test';
import assert from 'node:assert/strict';
import { SCENE_SECONDS, sceneAt } from '../src/utils/phishingScene.js';
import { dismissWhatsAppNotice, shouldShowWelcome, shouldShowWhatsAppNotice } from '../src/utils/welcome.js';

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

test('the WhatsApp notice shows only to a signed-in account without a number, until closed', () => {
  const storage = memory();
  const email = 'a@b.test';
  assert.equal(shouldShowWhatsAppNotice({ email: null, link: { linked: false }, storage }), false);
  assert.equal(shouldShowWhatsAppNotice({ email, link: { linked: true }, storage }), false);
  assert.equal(shouldShowWhatsAppNotice({ email, link: undefined, storage }), false);
  assert.equal(shouldShowWhatsAppNotice({ email, link: { linked: false }, storage }), true);
  dismissWhatsAppNotice(email, storage);
  assert.equal(shouldShowWhatsAppNotice({ email, link: { linked: false }, storage }), false);
});

test('blocked browser storage never throws', () => {
  assert.equal(shouldShowWhatsAppNotice({ email: 'a@b.test', link: { linked: false }, storage: blocked }), true);
  assert.doesNotThrow(() => dismissWhatsAppNotice('a@b.test', blocked));
});
