/**
 * Package a message the user pasted (an SMS, a WhatsApp message, a forwarded text) and any
 * files they add into one .eml, in the browser, so it goes through the same analysis as an email.
 *
 * The file carries no From, To, Date or Received lines, because the message never had them.
 * It is sent with source "forwarded_message", which tells the server to skip the sender and
 * authentication checks and leave them out of the score, and to inspect the links, QR codes
 * and attachments exactly as it does for an email.
 */

export const MESSAGE_SOURCE = 'forwarded_message';
export const MAX_ATTACHMENTS = 5;
export const MAX_TOTAL_BYTES = 15 * 1024 * 1024; // base64 adds a third; the server accepts 25 MB

const CRLF = '\r\n';
const URL_PATTERN = /\bhttps?:\/\/[^\s<>"')]+|\bwww\.[^\s<>"')]+/gi;

const escapeHtml = (text) => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** The pasted text as simple HTML with every link clickable, so link checks run on it like on an email. */
export function linkify(text) {
  let html = '';
  let last = 0;
  for (const match of text.matchAll(URL_PATTERN)) {
    const url = match[0].replace(/[.,;:!?]+$/, '');
    const href = /^www\./i.test(url) ? `http://${url}` : url;
    html += escapeHtml(text.slice(last, match.index));
    html += `<a href="${escapeHtml(href)}">${escapeHtml(url)}</a>`;
    last = match.index + url.length;
  }
  html += escapeHtml(text.slice(last));
  return `<html><body><p>${html.replace(/\r?\n/g, '<br>\n')}</p></body></html>`;
}

function toBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  return btoa(binary);
}

const wrap76 = (b64) => b64.replace(/(.{76})/g, `$1${CRLF}`);
const asciiOnly = (text) => text.replace(/[^\x20-\x7e]+/g, ' ').replace(/\s+/g, ' ').trim();
const boundary = (tag) => `----=_etap_${tag}_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;

/** A header-safe file name (quotes and slashes removed). */
function safeName(name) {
  return asciiOnly(String(name || 'attachment')).replace(/["\\/]/g, '_') || 'attachment';
}

export function subjectFor(text) {
  const first = asciiOnly(text.split(/\r?\n/).find((line) => line.trim()) || '').slice(0, 60);
  return first ? `Pasted message: ${first}` : 'Pasted message';
}

/**
 * { file } on success, { error } when the input is not usable. `attachments` are File objects.
 * The returned File is named pasted-message.eml and remembers its source in `etapSource`.
 */
export async function buildMessageFile(text, attachments = []) {
  const body = String(text || '').replace(/\r\n?/g, '\n').trim();
  if (!body && attachments.length === 0) return { error: 'Paste the message text or add at least one file.' };
  if (attachments.length > MAX_ATTACHMENTS) return { error: `Add at most ${MAX_ATTACHMENTS} files.` };
  if (attachments.reduce((n, f) => n + f.size, 0) > MAX_TOTAL_BYTES) {
    return { error: `The files are larger than ${MAX_TOTAL_BYTES / (1024 * 1024)} MB together.` };
  }

  const outer = boundary('mixed');
  const inner = boundary('alt');
  const encoder = new TextEncoder();
  const lines = [
    'MIME-Version: 1.0',
    `Subject: ${subjectFor(body)}`,
    `Message-ID: <pasted-${Math.random().toString(36).slice(2, 12)}${Date.now().toString(36)}@etap.local>`,
    `Content-Type: multipart/mixed; boundary="${outer}"`,
    '',
    `--${outer}`,
    `Content-Type: multipart/alternative; boundary="${inner}"`,
    '',
    `--${inner}`,
    'Content-Type: text/plain; charset="utf-8"',
    'Content-Transfer-Encoding: base64',
    '',
    wrap76(toBase64(encoder.encode(body || '(no text, files only)'))),
    `--${inner}`,
    'Content-Type: text/html; charset="utf-8"',
    'Content-Transfer-Encoding: base64',
    '',
    wrap76(toBase64(encoder.encode(linkify(body)))),
    `--${inner}--`,
  ];
  for (const attachment of attachments) {
    const name = safeName(attachment.name);
    const bytes = new Uint8Array(await attachment.arrayBuffer());
    lines.push(
      `--${outer}`,
      `Content-Type: ${attachment.type || 'application/octet-stream'}; name="${name}"`,
      'Content-Transfer-Encoding: base64',
      `Content-Disposition: attachment; filename="${name}"`,
      '',
      wrap76(toBase64(bytes)),
    );
  }
  lines.push(`--${outer}--`, '');

  const file = new File([lines.join(CRLF)], 'pasted-message.eml', { type: 'message/rfc822' });
  file.etapSource = MESSAGE_SOURCE;
  return { file };
}
