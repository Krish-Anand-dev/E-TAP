import test from 'node:test';
import assert from 'node:assert/strict';
import { getAnimationSpeed, setAnimationSpeed } from '../src/utils/animationSpeed.js';
import { stageSummaries } from '../src/utils/reportSummary.js';

function withStorage(initial = {}) {
  const store = { ...initial };
  globalThis.window = {
    localStorage: {
      getItem: (key) => (key in store ? store[key] : null),
      setItem: (key, value) => { store[key] = String(value); },
    },
  };
  return store;
}

test('the analysis animation is full by default and remembers a fast choice', () => {
  const store = withStorage();
  assert.equal(getAnimationSpeed(), 'full');
  setAnimationSpeed('fast');
  assert.equal(store['etap.animationSpeed'], 'fast');
  assert.equal(getAnimationSpeed(), 'fast');
  setAnimationSpeed('full');
  assert.equal(getAnimationSpeed(), 'full');
});

test('the animation setting survives blocked browser storage', () => {
  globalThis.window = { localStorage: { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } } };
  assert.equal(getAnimationSpeed(), 'full');
  assert.doesNotThrow(() => setAnimationSpeed('fast'));
  delete globalThis.window;
  assert.equal(getAnimationSpeed(), 'full');
});

const keys = (report) => stageSummaries(report).map((stage) => stage.key);

test('a standard run without attachments has no sandbox stage card', () => {
  assert.ok(!keys({ sandbox: { status: 'not_requested', mode: 'agent' } }).includes('sandbox'));
  assert.ok(!keys({}).includes('sandbox'));
});

test('a standard run with attachments says they were inspected, not opened, without pushing deeper analysis', () => {
  const report = { attachments: [{ filename: 'invoice.pdf' }], sandbox: { status: 'not_requested', mode: 'agent' } };
  const card = stageSummaries(report).find((stage) => stage.key === 'sandbox');
  assert.equal(card.status, 'not_run');
  assert.match(card.summary, /without being opened/);
  assert.doesNotMatch(card.summary, /Choose Deeper/);
});

test('a deeper run still shows its sandbox stage card', () => {
  const report = { attachments: [{ filename: 'invoice.js' }], sandbox: { status: 'queued', mode: 'agent', items: [] } };
  assert.ok(keys(report).includes('sandbox'));
});
