import test from 'node:test';
import assert from 'node:assert/strict';
import { flagText } from '../src/utils/flagText.js';
import { stageSummaries } from '../src/utils/reportSummary.js';

test('header flags are shown in plain words', () => {
  assert.equal(flagText('lookalike_of_paypal.com'), 'Sender domain looks like an imitation of paypal.com');
  assert.match(flagText('reply_to_domain_mismatch'), /^Replies would go/);
  assert.equal(flagText('some_new_code'), 'Some new code');
});

test('an email with no related emails is not marked for checking', () => {
  const stage = stageSummaries({ historical_correlation: { category_status: 'RECURRING_ADVERSARY_ACTIVITY' }, correlation: { related_emails: [] } })
    .find((s) => s.key === 'history');
  assert.equal(stage.status, 'good');
  assert.equal(stage.summary, 'Not seen before.');
});
