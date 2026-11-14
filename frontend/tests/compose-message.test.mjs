import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMessageFile, linkify, subjectFor, MESSAGE_SOURCE, MAX_ATTACHMENTS } from '../src/utils/composeMessage.js';
import { attachmentNames, sandboxPreview } from '../src/utils/attachmentPreview.js';

const script = new File(['// harmless\nvar x = 1;\n'], 'invoice.js', { type: 'application/javascript' });

test('a pasted message becomes an .eml with no sender, route or date lines', async () => {
  const { file, error } = await buildMessageFile('Your account is suspended. Verify at http://kyc-update.example.top/login now.', [script]);
  assert.equal(error, undefined);
  assert.equal(file.name, 'pasted-message.eml');
  assert.equal(file.etapSource, MESSAGE_SOURCE);
  const text = await file.text();
  for (const header of ['From:', 'To:', 'Date:', 'Received:', 'Authentication-Results:', 'Reply-To:']) {
    assert.ok(!text.includes(`\r\n${header}`) && !text.startsWith(header), `${header} must not be present`);
  }
  assert.match(text, /^MIME-Version: 1\.0/);
  assert.match(text, /Subject: Pasted message: Your account is suspended/);
});

test('attachments are listed for the sandbox preview exactly as for an email', async () => {
  const { file } = await buildMessageFile('see attached', [script, new File(['x'], 'photo.png', { type: 'image/png' })]);
  const names = attachmentNames(await file.text());
  assert.deepEqual(names, ['invoice.js', 'photo.png']);
  assert.deepEqual(sandboxPreview(names).opened, ['invoice.js']);
});

test('links become clickable html and are not altered', () => {
  const html = linkify('Pay at www.pay-now.example.top/x, or http://a.example.top/b?q=1&r=2.');
  assert.match(html, /<a href="http:\/\/www\.pay-now\.example\.top\/x">www\.pay-now\.example\.top\/x<\/a>,/);
  assert.match(html, /<a href="http:\/\/a\.example\.top\/b\?q=1&amp;r=2">/);
  assert.ok(!linkify('<script>alert(1)</script>').includes('<script>'));
});

test('empty input and too many files are refused with a reason', async () => {
  assert.match((await buildMessageFile('   ', [])).error, /Paste/);
  const many = Array.from({ length: MAX_ATTACHMENTS + 1 }, (_, i) => new File(['x'], `f${i}.txt`));
  assert.match((await buildMessageFile('hi', many)).error, /at most/);
});

test('file names cannot break out of the header', async () => {
  const sneaky = new File(['x'], 'a"; filename="b.exe\r\nX-Evil: 1.pdf');
  const { file } = await buildMessageFile('hi', [sneaky]);
  const text = await file.text();
  assert.ok(!/\r\nX-Evil:/.test(text));
  assert.equal(subjectFor('line one\nline two').includes('\n'), false);
});
