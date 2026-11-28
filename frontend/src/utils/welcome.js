/** Who sees the welcome page and the WhatsApp notice. Browser storage may be blocked; nothing here throws. */
const SEEN_KEY = 'etap.welcomeSeen';
const dismissKey = (email) => `etap.whatsappNotice.dismissed:${email}`;

const read = (storage, key) => {
  try { return storage.getItem(key); } catch { return null; }
};
const write = (storage, key) => {
  try { storage.setItem(key, '1'); } catch { /* remembered for this page only */ }
};
const browserStorage = () => {
  try { return globalThis.localStorage; } catch { return null; }
};

/** First visit only: never for a signed-in person or a direct link to a report. */
export function shouldShowWelcome({ search = '', signedIn = false, storage = browserStorage() }) {
  if (signedIn || new URLSearchParams(search).has('dossier')) return false;
  return read(storage, SEEN_KEY) !== '1';
}
export const markWelcomeSeen = (storage = browserStorage()) => write(storage, SEEN_KEY);

/** Only for someone signed in whose account has no WhatsApp number, until they close it. */
export function shouldShowWhatsAppNotice({ email, link, storage = browserStorage() }) {
  return Boolean(email) && link?.linked === false && read(storage, dismissKey(email)) !== '1';
}
export const dismissWhatsAppNotice = (email, storage = browserStorage()) => write(storage, dismissKey(email));

/** Scroll to a section that may appear a moment after its page does. */
export function scrollWhenReady(id, tries = 40) {
  const target = globalThis.document?.getElementById(id);
  if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  else if (tries > 0) setTimeout(() => scrollWhenReady(id, tries - 1), 100);
}
