/** When to show the welcome page and the WhatsApp notice. Browser storage may be blocked; nothing here throws. */
const dismissKey = (email) => `etap.whatsappNotice.dismissed:${email || 'visitor'}`;

const read = (storage, key) => {
  try { return storage.getItem(key); } catch { return null; }
};
const write = (storage, key) => {
  try { storage.setItem(key, '1'); } catch { /* remembered for this page only */ }
};
const browserStorage = () => {
  try { return globalThis.localStorage; } catch { return null; }
};

/** On every visit; a direct link to a report goes straight to the report. */
export const shouldShowWelcome = (search = '') => !new URLSearchParams(search).has('dossier');

/** For visitors, and for accounts known to have no WhatsApp number, until they close it. */
export function shouldShowWhatsAppNotice({ email, link, storage = browserStorage() }) {
  if (read(storage, dismissKey(email)) === '1') return false;
  return email ? link?.linked === false : true;
}
export const dismissWhatsAppNotice = (email, storage = browserStorage()) => write(storage, dismissKey(email));
