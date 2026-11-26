import test from 'node:test';
import assert from 'node:assert/strict';
import { saveHistory } from '../src/utils/sessionHistory.js';

const storageWithLimit = (limit) => {
  const data = new Map();
  return {
    data,
    setItem(k, v) { if (v.length > limit) throw new Error('QuotaExceededError'); data.set(k, v); },
    removeItem(k) { data.delete(k); },
  };
};
const records = [{ id: 'newest', body: 'x'.repeat(40) }, { id: 'older', body: 'y'.repeat(40) }];

test('keeps every report when they fit', () => {
  assert.equal(saveHistory('k', records, storageWithLimit(1000)), 2);
});

test('drops the oldest reports when storage is full', () => {
  const storage = storageWithLimit(80);
  assert.equal(saveHistory('k', records, storage), 1);
  assert.equal(JSON.parse(storage.data.get('k'))[0].id, 'newest');
});

test('never throws, even when nothing fits or storage is missing', () => {
  assert.equal(saveHistory('k', records, storageWithLimit(5)), 0);
  assert.equal(saveHistory('k', records, undefined), 0);
});
