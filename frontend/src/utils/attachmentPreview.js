/**
 * A quick look at an .eml before it is sent, so "Deeper attachment analysis" can say up front
 * which attachments the sandbox would open and which it would not.
 *
 * This is only a preview, read from the MIME headers in the browser. The server's own
 * analysis (backend/sandbox/policy.py, which this list mirrors; a test keeps them equal)
 * remains the authority on what is actually opened.
 */

/** Extensions the sandbox opens (mirror of DETONATABLE_EXTENSIONS in backend/sandbox/policy.py). */
export const OPENABLE_EXTENSIONS = new Set([
  '.js', '.jse', '.vbs', '.vbe', '.wsf', '.wsh',
  '.hta', '.bat', '.cmd', '.ps1', '.psh',
  '.exe', '.msi', '.dll', '.scr',
  '.lnk', '.url',
  '.zip', '.rar', '.7z',
  '.iso', '.img',
  '.one', '.onepkg',
  '.doc', '.docx', '.docm', '.dotm',
  '.xls', '.xlsx', '.xlsm', '.xltm',
  '.ppt', '.pptx', '.pptm', '.potm',
  '.rtf',
  '.pdf',
  '.html', '.htm', '.mhtml', '.mht',
  '.svg', '.xml',
  '.eml', '.msg',
]);

/** The sandbox opens at most this many attachments per email. */
export const MAX_OPENED = 3;

const LINE_BREAK = /\r?\n/;

function extensionOf(name) {
  const dot = String(name).lastIndexOf('.');
  return dot >= 0 ? String(name).slice(dot).toLowerCase() : '';
}

function decodeName(raw) {
  let name = raw.trim().replace(/^"|"$/g, '');
  const rfc2231 = name.match(/^[\w-]+'[\w-]*'(.*)$/); // filename*=utf-8''my%20file.js
  if (rfc2231) {
    try { name = decodeURIComponent(rfc2231[1]); } catch { name = rfc2231[1]; }
  }
  return name;
}

/** File names of the attachments declared in an .eml's text; [] when there are none. */
export function attachmentNames(emlText) {
  // A header folded onto continuation lines (leading space or tab) is joined back into one line.
  const lines = [];
  for (const raw of String(emlText || '').split(LINE_BREAK)) {
    if (/^[ \t]+\S/.test(raw) && lines.length) lines[lines.length - 1] += ` ${raw.trim()}`;
    else lines.push(raw);
  }
  const names = [];
  // Only MIME header blocks count: the start of the message and the lines after each
  // boundary, up to the blank line. Body text that merely looks like a header is ignored.
  let inHeaders = true;
  for (const line of lines) {
    if (line.trim() === '') { inHeaders = false; continue; }
    if (line.startsWith('--')) { inHeaders = true; continue; }
    if (!inHeaders) continue;
    const isAttachment = /^Content-Disposition:\s*attachment/i.test(line)
      || (/^Content-Disposition:\s*inline/i.test(line) && /filename/i.test(line));
    const named = /^Content-Type:/i.test(line) && /;\s*name\*?=/i.test(line)
      && !/^Content-Type:\s*(?:text\/|multipart\/|message\/)/i.test(line);
    if (!isAttachment && !named) continue;
    const match = line.match(/(?:file)?name\*?=\s*("[^"]*"|[^;\s]+)/i);
    if (match) names.push(decodeName(match[1]));
  }
  return [...new Set(names)];
}

/**
 * { total, opened: [names], skipped: [names] } for the sandbox: the first MAX_OPENED openable
 * files (the server prefers scripts and programs) are opened; data files and images are not.
 */
export function sandboxPreview(names) {
  const openable = names.filter((n) => OPENABLE_EXTENSIONS.has(extensionOf(n)));
  const opened = openable.slice(0, MAX_OPENED);
  return { total: names.length, opened, skipped: names.filter((n) => !opened.includes(n)) };
}

/** Plain-language reason a file is not opened. */
export function whyNotOpened(name) {
  const ext = extensionOf(name);
  if (OPENABLE_EXTENSIONS.has(ext)) return 'only the first three files are opened';
  if (['.json', '.csv', '.txt', '.log', '.md', '.yml', '.yaml', '.ini', '.cfg'].includes(ext)) return 'a data or text file; it cannot run anything';
  if (['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tif', '.tiff', '.ico'].includes(ext)) return 'an image; it cannot run anything';
  return 'not a type the sandbox opens';
}

/** Read an email file in the browser and preview it. Null when it cannot be read (e.g. Outlook .msg). */
export async function previewEmailFile(file) {
  if (!file || !/\.eml$/i.test(file.name || '')) return null;
  try {
    const text = await file.text();
    return sandboxPreview(attachmentNames(text));
  } catch {
    return null;
  }
}
