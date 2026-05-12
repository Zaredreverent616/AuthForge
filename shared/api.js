/**
 * AuthForge — Public API (shared/api.js)
 *
 * Thin async wrapper over chrome.runtime.sendMessage. All UI code talks to
 * the service worker through this module so we have one place to add
 * retries, error normalisation, or instrumentation later.
 */

function send(type, params = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, params }, (response) => {
      const lastError = chrome.runtime.lastError;
      if (lastError) {
        return reject(new Error(lastError.message));
      }
      if (!response) {
        return reject(new Error('No response from background'));
      }
      if (!response.ok) {
        return reject(new Error(response.error || 'Unknown error'));
      }
      resolve(response.data);
    });
  });
}

// ---------- Tabs --------------------------------------------------------------

export const tabs = {
  current: () => send('getCurrentTab'),
  get: (tabId) => send('getTabById', { tabId }),
  all: () => send('getAllTabs'),
};

// ---------- Cookies -----------------------------------------------------------

export const cookies = {
  getAll: (params) => send('cookies.getAll', params),
  // CHIPS partitioned cookies — separate call so failures here can't
  // break the primary list. The SW-side handler is timeout-protected.
  getAllPartitioned: (params) => send('cookies.getAllPartitioned', params),
  set: (cookie) => send('cookies.set', { cookie }),
  remove: ({ name, url, storeId, partitionKey }) =>
    send('cookies.remove', { name, url, storeId, partitionKey }),
  getAllStores: () => send('cookies.getAllStores'),
};

// ---------- LocalStorage ------------------------------------------------------

export const localStorageApi = {
  getAll: (tabId) => send('page.localStorage.getAll', { tabId }),
  getAllAcrossTabs: () => send('page.localStorage.getAllAcrossTabs'),
  set: (tabId, key, value) =>
    send('page.localStorage.set', { tabId, key, value }),
  remove: (tabId, key) => send('page.localStorage.remove', { tabId, key }),
  clear: (tabId) => send('page.localStorage.clear', { tabId }),
};

// ---------- SessionStorage ----------------------------------------------------

export const sessionStorageApi = {
  getAll: (tabId) => send('page.sessionStorage.getAll', { tabId }),
  getAllAcrossTabs: () => send('page.sessionStorage.getAllAcrossTabs'),
  set: (tabId, key, value) =>
    send('page.sessionStorage.set', { tabId, key, value }),
  remove: (tabId, key) => send('page.sessionStorage.remove', { tabId, key }),
  clear: (tabId) => send('page.sessionStorage.clear', { tabId }),
};

// ---------- IndexedDB ---------------------------------------------------------

export const indexedDBApi = {
  list: (tabId) => send('page.indexedDB.listDatabases', { tabId }),
  listAcrossTabs: () => send('page.indexedDB.listAcrossTabs'),
  read: (tabId, dbName) => send('page.indexedDB.readDatabase', { tabId, dbName }),
  putRecord: (tabId, dbName, storeName, key, value) =>
    send('page.indexedDB.putRecord', { tabId, dbName, storeName, key, value }),
  deleteRecord: (tabId, dbName, storeName, key) =>
    send('page.indexedDB.deleteRecord', { tabId, dbName, storeName, key }),
  deleteDatabase: (tabId, dbName) =>
    send('page.indexedDB.deleteDatabase', { tabId, dbName }),
};

// ---------- Snapshots ---------------------------------------------------------

export const snapshotsApi = {
  list: () => send('snapshot.list'),
  save: (id, snapshot) => send('snapshot.save', { id, snapshot }),
  delete: (id) => send('snapshot.delete', { id }),
  capture: (tabId, url) => send('snapshot.capture', { tabId, url }),
};

// ---------- Profiles ----------------------------------------------------------
//
// Reusable, portable credential bundles. Unlike snapshots (point-in-time,
// per-domain backups), profiles travel across environments and can be applied
// with domain remapping. Designed for QA / DevOps workflows: "log in as the
// admin on staging using the dev creds I captured yesterday."

export const profilesApi = {
  list: () => send('profiles.list'),
  save: (id, profile) => send('profiles.save', { id, profile }),
  delete: (id) => send('profiles.delete', { id }),
  capture: (tabId, url) => send('profiles.capture', { tabId, url }),
  apply: ({ profile, tabId, targetUrl, remapDomain, sourceHost, clearFirst, includeStorage }) =>
    send('profiles.apply', {
      profile,
      tabId,
      targetUrl,
      remapDomain,
      sourceHost,
      clearFirst,
      includeStorage,
    }),
};

// ---------- Settings ----------------------------------------------------------

export const settingsApi = {
  get: () => send('settings.get'),
  set: (settings) => send('settings.set', { settings }),
};

// ---------- Network capture ---------------------------------------------------
//
// Passive observation of HTTP(S) traffic for auth artifacts. Header-level
// only (request bodies and response bodies are not exposed by chrome.webRequest
// in MV3). The DevTools panel layers in response-body scanning via
// chrome.devtools.network when DevTools is open.

export const networkApi = {
  status: () => send('network.status'),
  start: () => send('network.start'),
  stop: () => send('network.stop'),
  clear: () => send('network.clear'),
  list: (params = {}) => send('network.list', params),
  addBodyFinding: (entry) => send('network.addBodyFinding', { entry }),
};

// ---------- Debugger-based deep capture ---------------------------------------
//
// Opt-in third layer: uses chrome.debugger (Chrome DevTools Protocol) to
// access response bodies on a tab without needing DevTools open. Triggers the
// yellow "is being debugged" banner — user-visible, dismissible.

export const debuggerApi = {
  status: () => send('debugger.status'),
  attach: (tabId) => send('debugger.attach', { tabId }),
  detach: (tabId) => send('debugger.detach', { tabId }),
  detachAll: () => send('debugger.detachAll'),
};

// ---------- Request replay ---------------------------------------------------
//
// Re-fire a request from a target tab's page context, with optionally
// mutated headers. Used by the JWT Attack Replay feature to test whether
// a server is vulnerable to common JWT attacks (alg:none acceptance,
// signature bypass, claim tampering, etc.) against a real endpoint.

export const replayApi = {
  request: ({
    tabId, url, method, headers, body, credentials,
    redirect, cache, mode, referrer, referrerPolicy,
    integrity, keepalive, timeoutMs, fullResponse,
  }) =>
    send('replay.request', {
      tabId, url, method, headers, body, credentials,
      redirect, cache, mode, referrer, referrerPolicy,
      integrity, keepalive, timeoutMs, fullResponse,
    }),
};

// ---------- Microsoft Entra / Graph -------------------------------------------
//
// Authenticated read-only fetches against Microsoft Graph and other AAD
// endpoints. Used by the Entra Inspector to enumerate what a captured
// token actually unlocks (recon, not exploitation).
export const entraApi = {
  graphFetch: ({ url, token, method }) =>
    send('entra.graphFetch', { url, token, method }),
  refreshFOCI: ({ refreshToken, clientId, scope, tenantId }) =>
    send('entra.refreshFOCI', { refreshToken, clientId, scope, tenantId }),
};

// ---------- Live updates ------------------------------------------------------
//
// The popup/panel can subscribe to broadcast messages (cookies changed in any
// tab, settings updated, etc.) via a long-lived port. Returns a function that
// disconnects the port.

export function subscribe(onMessage) {
  const port = chrome.runtime.connect();
  port.onMessage.addListener(onMessage);
  return () => {
    try {
      port.disconnect();
    } catch {
      // Already gone — ignore.
    }
  };
}
