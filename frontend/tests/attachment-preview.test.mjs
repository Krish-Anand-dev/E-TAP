import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  attachmentNames, sandboxPreview, whyNotOpened, previewEmailFile, OPENABLE_EXTENSIONS,
} from '../src/utils/attachmentPreview.js';

const eml = (...parts) => [
  'From: a@example.test', 'To: b@example.test', 'Subject: test', 'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="b"', '',
  '--b', 'Content-Type: text/plain', '', 'Content-Disposition: attachment; filename="fake-in-body.exe"', '',
  ...parts, '--b--', ''].join('\r\n');

const part = (name, type = 'application/octet-stream') => [
  '--b', `Content-Type: ${type}`, `Content-Disposition: attachment; filename="${name}"`,
  'Content-Transfer-Encoding: base64', '', 'AAAA', ''].join('\r\n');

test('finds attachment names from the MIME headers only', () => {
  assert.deepEqual(attachmentNames(eml(part('invoice.js'), part('photo.png', 'image/png'))), ['invoice.js', 'photo.png']);
  assert.deepEqual(attachmentNames('From: a\r\nSubject: none\r\n\r\njust text'), []);
});

test('handles folded headers, name= parameters and RFC 2231 names', () => {
  const folded = 'Content-Type: application/octet-stream;\r\n name="report final.pdf"\r\nContent-Disposition: attachment;\r\n filename*=utf-8\'\'my%20file.js\r\n';
  assert.deepEqual(attachmentNames(folded), ['report final.pdf', 'my file.js']);
});

test('says which attachments the sandbox would open and why the others are not', () => {
  const names = ['vk_swiftshader_icd.json', 'invoice.js', 'logo.png'];
  const preview = sandboxPreview(names);
  assert.deepEqual(preview.opened, ['invoice.js']);
  assert.deepEqual(preview.skipped, ['vk_swiftshader_icd.json', 'logo.png']);
  assert.match(whyNotOpened('vk_swiftshader_icd.json'), /data or text file/);
  assert.match(whyNotOpened('logo.png'), /image/);
  assert.equal(sandboxPreview(['a.js', 'b.js', 'c.js', 'd.js']).opened.length, 3);
  assert.deepEqual(sandboxPreview([]), { total: 0, opened: [], skipped: [] });
});

test('only .eml files are previewed in the browser', async () => {
  assert.equal(await previewEmailFile({ name: 'mail.msg', text: async () => 'x' }), null);
  const preview = await previewEmailFile({ name: 'mail.eml', text: async () => eml(part('vk_swiftshader_icd.json', 'application/json')) });
  assert.deepEqual(preview, { total: 1, opened: [], skipped: ['vk_swiftshader_icd.json'] });
});

test('the browser list of openable types matches the server policy', () => {
  const policy = readFileSync(new URL('../../backend/sandbox/policy.py', import.meta.url), 'utf8');
  const block = policy.match(/DETONATABLE_EXTENSIONS = frozenset\(\{([\s\S]*?)\}\)/)[1];
  const server = new Set([...block.matchAll(/"(\.[a-z0-9]+)"/g)].map((m) => m[1]));
  assert.deepEqual([...OPENABLE_EXTENSIONS].sort(), [...server].sort());
});
