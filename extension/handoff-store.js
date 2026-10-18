// Email content stays in extension-origin IndexedDB until submission, never in
// a URL or page localStorage. No extra permissions or storage quota are needed.
const EtapHandoffStore = (() => {
    const MAX_AGE_MS = 60 * 60 * 1000;
    let database;
    function open() {
        if (!database) database = new Promise((resolve, reject) => {
            const request = indexedDB.open('etap-email-handoffs', 1);
            request.onupgradeneeded = () => request.result.createObjectStore('jobs', { keyPath: 'id' });
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
        return database;
    }
    async function transaction(mode, operation) {
        const db = await open();
        return new Promise((resolve, reject) => {
            const tx = db.transaction('jobs', mode);
            let result;
            tx.oncomplete = () => resolve(result);
            tx.onerror = tx.onabort = () => reject(tx.error || new Error('Could not save the email handoff.'));
            operation(tx.objectStore('jobs'), (value) => { result = value; });
        });
    }
    function update(id, mutate) {
        return transaction('readwrite', (store, done) => {
            const request = store.get(id);
            request.onsuccess = () => {
                const current = request.result;
                if (!current || Date.now() - current.createdAt > MAX_AGE_MS) {
                    store.delete(id);
                    done(null);
                    return;
                }
                const next = mutate(current);
                if (next) store.put(next);
                done(next || current);
            };
        });
    }
    async function create(job) {
        await transaction('readwrite', (store) => {
            const request = store.openCursor();
            request.onsuccess = () => {
                const cursor = request.result;
                if (!cursor) return;
                if (Date.now() - cursor.value.createdAt > MAX_AGE_MS) cursor.delete();
                cursor.continue();
            };
            store.put(job);
        });
        return job;
    }
    return {
        create, update,
        get: async (id) => {
            const job = await transaction('readonly', (store, done) => {
                const request = store.get(id);
                request.onsuccess = () => done(request.result);
            });
            if (job && Date.now() - job.createdAt > MAX_AGE_MS) {
                await transaction('readwrite', (store) => store.delete(id));
                return null;
            }
            return job || null;
        },
        remove: (id) => transaction('readwrite', (store) => store.delete(id)),
    };
})();
