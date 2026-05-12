/**
 * AuthForge — Page-side injection functions (shared/storage-injector.js)
 *
 * Each function in PAGE_FUNCTIONS is serialized by chrome.scripting and run
 * in the *page's* MAIN world. Constraints (since these are stringified and
 * cross a process boundary):
 *
 *   1. NO closure access. They cannot reference module-scope variables.
 *      Everything they need must come in via arguments.
 *   2. Return values must be JSON-serializable, or a Promise resolving to
 *      one.
 *   3. Errors thrown synchronously become rejected results; for tighter
 *      control we sometimes return { __error: "..." } so the caller can
 *      decide what to do.
 */

export const PAGE_FUNCTIONS = {
  // -------- localStorage --------------------------------------------------

  localStorageGetAll() {
    try {
      const out = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        out.push({ key, value: localStorage.getItem(key) });
      }
      // Stable, predictable order helps diffing in the UI.
      out.sort((a, b) => a.key.localeCompare(b.key));
      return out;
    } catch (e) {
      return { __error: 'localStorage: ' + e.message };
    }
  },

  localStorageSet(key, value) {
    try {
      localStorage.setItem(key, value);
      return true;
    } catch (e) {
      return { __error: 'localStorage.setItem: ' + e.message };
    }
  },

  localStorageRemove(key) {
    try {
      localStorage.removeItem(key);
      return true;
    } catch (e) {
      return { __error: 'localStorage.removeItem: ' + e.message };
    }
  },

  localStorageClear() {
    try {
      localStorage.clear();
      return true;
    } catch (e) {
      return { __error: 'localStorage.clear: ' + e.message };
    }
  },

  // -------- sessionStorage ------------------------------------------------

  sessionStorageGetAll() {
    try {
      const out = [];
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        out.push({ key, value: sessionStorage.getItem(key) });
      }
      out.sort((a, b) => a.key.localeCompare(b.key));
      return out;
    } catch (e) {
      return { __error: 'sessionStorage: ' + e.message };
    }
  },

  sessionStorageSet(key, value) {
    try {
      sessionStorage.setItem(key, value);
      return true;
    } catch (e) {
      return { __error: 'sessionStorage.setItem: ' + e.message };
    }
  },

  sessionStorageRemove(key) {
    try {
      sessionStorage.removeItem(key);
      return true;
    } catch (e) {
      return { __error: 'sessionStorage.removeItem: ' + e.message };
    }
  },

  sessionStorageClear() {
    try {
      sessionStorage.clear();
      return true;
    } catch (e) {
      return { __error: 'sessionStorage.clear: ' + e.message };
    }
  },

  // -------- IndexedDB -----------------------------------------------------
  //
  // IndexedDB is async-by-nature, so these return Promises. Note that the
  // injected function MUST return the promise (return value of an async
  // function or an explicit `return new Promise(...)`); chrome.scripting
  // awaits it before sending the result back.

  async idbListDatabases() {
    try {
      if (!indexedDB.databases) {
        // Older browsers / some Firefox builds lack databases() — return [].
        return [];
      }
      const dbs = await indexedDB.databases();
      return dbs.map((d) => ({ name: d.name, version: d.version }));
    } catch (e) {
      return { __error: 'indexedDB.databases: ' + e.message };
    }
  },

  /**
   * Read a database in full: returns [{ storeName, keyPath, autoIncrement,
   * records: [{ key, value }] }, ...]. Values are JSON-serialized so that
   * structured-clone-only types (Date, Blob, etc.) make it through the
   * chrome.scripting boundary as plain JSON.
   */
  idbReadDatabase(dbName) {
    return new Promise((resolve) => {
      const open = indexedDB.open(dbName);
      open.onerror = () =>
        resolve({ __error: 'open ' + dbName + ': ' + open.error?.message });
      open.onsuccess = async () => {
        const db = open.result;
        const out = [];
        const storeNames = Array.from(db.objectStoreNames);
        try {
          for (const storeName of storeNames) {
            const tx = db.transaction(storeName, 'readonly');
            const store = tx.objectStore(storeName);
            const records = await new Promise((res, rej) => {
              const rows = [];
              const cursorReq = store.openCursor();
              cursorReq.onerror = () => rej(cursorReq.error);
              cursorReq.onsuccess = (ev) => {
                const cursor = ev.target.result;
                if (!cursor) return res(rows);
                let safeValue;
                try {
                  // Use structuredClone-then-stringify to handle Date/Map/etc.
                  safeValue = JSON.parse(
                    JSON.stringify(cursor.value, (_, v) => {
                      if (v instanceof Date) return { __date: v.toISOString() };
                      if (v instanceof Blob)
                        return { __blob: { size: v.size, type: v.type } };
                      if (v instanceof ArrayBuffer)
                        return { __arrayBuffer: { byteLength: v.byteLength } };
                      return v;
                    })
                  );
                } catch (e) {
                  safeValue = { __unserializable: String(e) };
                }
                rows.push({
                  key: cursor.key,
                  value: safeValue,
                });
                cursor.continue();
              };
            });
            out.push({
              storeName,
              keyPath: store.keyPath,
              autoIncrement: store.autoIncrement,
              records,
            });
          }
          db.close();
          resolve(out);
        } catch (e) {
          db.close();
          resolve({ __error: 'read ' + dbName + ': ' + e.message });
        }
      };
    });
  },

  idbPutRecord(dbName, storeName, key, value) {
    return new Promise((resolve) => {
      const open = indexedDB.open(dbName);
      open.onerror = () => resolve({ __error: 'open: ' + open.error?.message });
      open.onsuccess = () => {
        const db = open.result;
        try {
          const tx = db.transaction(storeName, 'readwrite');
          const store = tx.objectStore(storeName);
          // If the store uses an in-line key (keyPath), put() ignores the
          // explicit key — the key must live inside `value`. We respect
          // whatever the caller passed.
          const req = store.keyPath == null ? store.put(value, key) : store.put(value);
          req.onerror = () => {
            db.close();
            resolve({ __error: 'put: ' + req.error?.message });
          };
          req.onsuccess = () => {
            tx.oncomplete = () => {
              db.close();
              resolve(true);
            };
          };
        } catch (e) {
          db.close();
          resolve({ __error: 'put: ' + e.message });
        }
      };
    });
  },

  idbDeleteRecord(dbName, storeName, key) {
    return new Promise((resolve) => {
      const open = indexedDB.open(dbName);
      open.onerror = () => resolve({ __error: 'open: ' + open.error?.message });
      open.onsuccess = () => {
        const db = open.result;
        try {
          const tx = db.transaction(storeName, 'readwrite');
          const req = tx.objectStore(storeName).delete(key);
          req.onerror = () => {
            db.close();
            resolve({ __error: 'delete: ' + req.error?.message });
          };
          tx.oncomplete = () => {
            db.close();
            resolve(true);
          };
        } catch (e) {
          db.close();
          resolve({ __error: 'delete: ' + e.message });
        }
      };
    });
  },

  idbDeleteDatabase(dbName) {
    return new Promise((resolve) => {
      const req = indexedDB.deleteDatabase(dbName);
      req.onsuccess = () => resolve(true);
      req.onerror = () =>
        resolve({ __error: 'deleteDatabase: ' + req.error?.message });
      // `blocked` fires when another tab has the DB open; we resolve with an
      // informative error so the user knows to close other tabs.
      req.onblocked = () =>
        resolve({
          __error:
            'deleteDatabase blocked — another tab has the database open',
        });
    });
  },
};
