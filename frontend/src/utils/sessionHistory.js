/**
 * Save this session's report list. Browser storage is small (about 5 MB) and one
 * large email can fill it, so the oldest reports are left out until the rest fits.
 * Never throws: the list is a convenience, and the server keeps the reports.
 * Returns how many records were saved.
 */
export function saveHistory(key, records, storage = globalThis.sessionStorage) {
  for (let count = records.length; count > 0; count -= 1) {
    try {
      storage.setItem(key, JSON.stringify(records.slice(0, count)));
      return count;
    } catch { /* too big, or storage is blocked: try fewer */ }
  }
  try { storage.removeItem(key); } catch { /* storage is blocked */ }
  return 0;
}
